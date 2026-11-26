#!/usr/bin/env python3
"""
API de alta de EscudoBit (servidor VPN).

El móvil genera sus llaves de WireGuard (la privada no sale nunca del móvil) y envía aquí
solo la pública, junto con la prueba de Play Integrity de que es la app EscudoBit original
en un móvil de verdad. El servidor le asigna una dirección dentro de la VPN, lo añade a
WireGuard y le devuelve lo que necesita para conectarse.

No guarda nada de la persona: solo su llave pública, su dirección de la VPN y la fecha de alta.
Sin dependencias: solo la biblioteca estándar de Python 3 (y openssl para Play Integrity).

Configuración por variables de entorno (ver /etc/escudobit/api.env):
  LISTEN=127.0.0.1:8080          dónde escucha (detrás de Caddy, que pone el HTTPS)
  WG_INTERFACE=wg0
  WG_SUBNET=10.66.0.0/16         red de la VPN (la .1 es el servidor)
  SERVER_PUBLIC_KEY=...          llave pública del servidor WireGuard
  ENDPOINT=1.2.3.4:51820         dirección pública del servidor
  DNS=10.66.0.1                  AdGuard Home dentro de la VPN
  DB=/var/lib/escudobit/peers.json
  INTEGRITY=on|off               exigir Play Integrity (off solo para pruebas)
  INTEGRITY_ALLOW_UNRECOGNIZED=0 aceptar la app aunque aún no esté publicada en Play
  PACKAGE=com.escudobit.app
  GOOGLE_KEY=/etc/escudobit/google.json   cuenta de servicio de Google Cloud
  RATE_PER_HOUR=10               altas por IP y hora
  WG_CMD=wg                      (en pruebas se cambia por un programa falso)
"""

import base64
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def env(name, default=""):
    return os.environ.get(name, default)


# ---------------------------------------------------------------------------
# Reglas puras (se prueban en test_api.py)
# ---------------------------------------------------------------------------

def valid_public_key(key):
    """Llave pública de WireGuard: 32 bytes en base64 (44 caracteres)."""
    if not isinstance(key, str) or len(key) != 44:
        return False
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except Exception:
        return False


def nonce_for(public_key):
    """Nonce de Play Integrity ligado a la llave: así un token robado no sirve para otra llave."""
    digest = hashlib.sha256(public_key.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def next_address(subnet, used):
    """Primera dirección libre de la red (la primera es el servidor)."""
    net = ipaddress.ip_network(subnet)
    server = next(net.hosts())
    taken = set(used) | {str(server)}
    for host in net.hosts():
        if str(host) not in taken:
            return str(host)
    return None


def check_verdict(payload, expected_nonce, package, allow_unrecognized=False, now_ms=None):
    """
    Revisa el veredicto de Play Integrity ya descifrado por Google.
    Devuelve None si todo está bien, o el motivo del rechazo.
    """
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    req = payload.get("requestDetails", {})
    if req.get("nonce", "").rstrip("=") != expected_nonce:
        return "nonce"
    if req.get("requestPackageName") != package:
        return "paquete"
    ts = int(req.get("timestampMillis", "0") or 0)
    if abs(now_ms - ts) > 10 * 60 * 1000:
        return "caducado"
    app = payload.get("appIntegrity", {})
    verdict = app.get("appRecognitionVerdict")
    if verdict != "PLAY_RECOGNIZED" and not (allow_unrecognized and verdict == "UNRECOGNIZED_VERSION"):
        return "app"
    if app.get("packageName") not in (None, package):
        return "paquete"
    device = payload.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
    if not any(v in device for v in ("MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY", "MEETS_BASIC_INTEGRITY")):
        return "dispositivo"
    return None


class RateLimiter:
    """Como mucho N altas por IP cada hora."""

    def __init__(self, per_hour):
        self.per_hour = per_hour
        self.hits = {}
        self.lock = threading.Lock()

    def allow(self, ip, now=None):
        now = now if now is not None else time.time()
        with self.lock:
            recent = [t for t in self.hits.get(ip, []) if now - t < 3600]
            if len(recent) >= self.per_hour:
                self.hits[ip] = recent
                return False
            recent.append(now)
            self.hits[ip] = recent
            return True


# ---------------------------------------------------------------------------
# Base de datos de equipos (un JSON pequeño)
# ---------------------------------------------------------------------------

class PeerDb:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        try:
            with open(path, encoding="utf-8") as f:
                self.peers = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.peers = {}

    def save(self):
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.peers, f)
        os.replace(tmp, self.path)

    def get_or_add(self, public_key, subnet):
        with self.lock:
            if public_key in self.peers:
                return self.peers[public_key]["address"], False
            address = next_address(subnet, [p["address"] for p in self.peers.values()])
            if address is None:
                return None, False
            self.peers[public_key] = {"address": address, "since": int(time.time())}
            self.save()
            return address, True


# ---------------------------------------------------------------------------
# WireGuard y Play Integrity
# ---------------------------------------------------------------------------

def wg_add_peer(public_key, address):
    cmd = [env("WG_CMD", "wg"), "set", env("WG_INTERFACE", "wg0"), "peer", public_key, "allowed-ips", address + "/32"]
    subprocess.run(cmd, check=True, timeout=10)


def google_access_token(key_path):
    """Token de acceso de Google con la cuenta de servicio (JWT firmado con openssl)."""
    with open(key_path, encoding="utf-8") as f:
        sa = json.load(f)
    now = int(time.time())

    def b64(data):
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    header = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = b64(json.dumps({
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/playintegrity",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3000,
    }).encode())
    unsigned = f"{header}.{claims}".encode()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as k:
        k.write(sa["private_key"])
        key_file = k.name
    try:
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_file], input=unsigned, capture_output=True, check=True).stdout
    finally:
        os.unlink(key_file)
    jwt = unsigned.decode() + "." + b64(sig)
    body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt}).encode()
    with urllib.request.urlopen("https://oauth2.googleapis.com/token", body, timeout=10) as r:
        return json.load(r)["access_token"]


def decode_integrity(token, package, key_path):
    url = f"https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken"
    req = urllib.request.Request(
        url,
        data=json.dumps({"integrity_token": token}).encode(),
        headers={"Authorization": "Bearer " + google_access_token(key_path), "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r).get("tokenPayloadExternal", {})


# ---------------------------------------------------------------------------
# Servidor HTTP
# ---------------------------------------------------------------------------

DB = None
LIMITER = None


class Handler(BaseHTTPRequestHandler):
    server_version = "EscudoBit"

    def log_message(self, fmt, *args):
        # Sin IPs ni datos en el registro: solo qué se pidió y cómo acabó.
        status = args[1] if len(args) > 1 else ""
        sys.stderr.write(f"{self.command} {self.path} {status}\n")

    def reply(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def client_ip(self):
        # Caddy pone la IP real en X-Forwarded-For.
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def do_GET(self):
        if self.path == "/v1/estado":
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "no existe"})

    def do_POST(self):
        if self.path != "/v1/alta":
            return self.reply(404, {"error": "no existe"})
        if not LIMITER.allow(self.client_ip()):
            return self.reply(429, {"error": "demasiadas altas"})
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 16384)
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self.reply(400, {"error": "petición no válida"})

        public_key = data.get("publicKey", "")
        if not valid_public_key(public_key):
            return self.reply(400, {"error": "llave no válida"})

        if env("INTEGRITY", "on") == "on":
            token = data.get("integrityToken", "")
            if not token:
                return self.reply(403, {"error": "falta la comprobación de integridad"})
            try:
                payload = decode_integrity(token, env("PACKAGE", "com.escudobit.app"), env("GOOGLE_KEY"))
            except Exception:
                return self.reply(503, {"error": "no se pudo comprobar la integridad"})
            reason = check_verdict(
                payload, nonce_for(public_key), env("PACKAGE", "com.escudobit.app"),
                allow_unrecognized=env("INTEGRITY_ALLOW_UNRECOGNIZED", "0") == "1",
            )
            if reason:
                return self.reply(403, {"error": "integridad: " + reason})

        address, new = DB.get_or_add(public_key, env("WG_SUBNET", "10.66.0.0/16"))
        if address is None:
            return self.reply(503, {"error": "servidor lleno"})
        if new:
            try:
                wg_add_peer(public_key, address)
            except Exception:
                return self.reply(500, {"error": "no se pudo dar de alta"})
        self.reply(200, {
            "address": address + "/32",
            "dns": env("DNS", "10.66.0.1"),
            "serverPublicKey": env("SERVER_PUBLIC_KEY"),
            "endpoint": env("ENDPOINT"),
            "allowedIps": "0.0.0.0/0, ::/0",
            "keepalive": 25,
        })


def main():
    global DB, LIMITER
    DB = PeerDb(env("DB", "/var/lib/escudobit/peers.json"))
    LIMITER = RateLimiter(int(env("RATE_PER_HOUR", "10")))
    # Tras reiniciar el servidor, WireGuard arranca vacío: se vuelven a añadir todos los móviles.
    for key, peer in DB.peers.items():
        try:
            wg_add_peer(key, peer["address"])
        except Exception as e:  # noqa: BLE001
            print(f"No se pudo restaurar un equipo: {e}", file=sys.stderr)
    host, port = env("LISTEN", "127.0.0.1:8080").rsplit(":", 1)
    print(f"API de EscudoBit escuchando en {host}:{port}", flush=True)
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()
