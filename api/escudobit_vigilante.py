#!/usr/bin/env python3
"""Vigilante del servidor de EscudoBit: que nunca cueste dinero y que el dueño lo sepa todo.

- Cuenta el tráfico de salida del mes (lo único que Oracle podría cobrar: 10 TB/mes gratis).
- Avisa al móvil del dueño (ntfy) al 50 %, 80 % y 90 %.
- Al 90 % pausa la VPN hasta el día 1; ese día la vuelve a encender sola.
- "semanal": resumen de tráfico, personas y estado de la máquina.

Uso:  escudobit_vigilante.py revisar   (cada 5 minutos, con un temporizador)
      escudobit_vigilante.py semanal   (los lunes)
      escudobit_vigilante.py estado    (para mirarlo a mano)
      escudobit_vigilante.py prueba    (manda un aviso de prueba)
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

ENV = "/etc/escudobit/avisos.env"
STATE = "/var/lib/escudobit/trafico.json"
LEVELS = (50, 80, 90)
PAUSE_AT = 90


def load_env(path=ENV):
    env = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    except OSError:
        pass
    return env


def new_state(month, tx):
    return {"month": month, "total": 0, "last_tx": tx, "alerted": [], "paused": False}


def step(state, month, tx, limit):
    """Lógica pura (probada): devuelve (estado nuevo, avisos, acción) con acción en {None, 'pausar', 'reanudar'}."""
    if state is None:
        return new_state(month, tx), [], None
    s = dict(state)
    alerts, action = [], None
    # Si el contador bajó, la máquina se reinició: lo leído ahora es todo tráfico nuevo.
    delta = tx - s["last_tx"] if tx >= s["last_tx"] else tx
    if s["month"] != month:
        was_paused = s.get("paused")
        s = new_state(month, s["last_tx"])
        alerts.append(("nuevo_mes", 0))
        if was_paused:
            action = "reanudar"
    s["total"] += delta
    s["last_tx"] = tx
    pct = s["total"] * 100 / limit
    for lvl in LEVELS:
        if pct >= lvl and lvl not in s["alerted"]:
            s["alerted"] = s["alerted"] + [lvl]
            alerts.append(("nivel", lvl))
    if pct >= PAUSE_AT and not s.get("paused"):
        s["paused"] = True
        action = "pausar"
    return s, alerts, action


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1000


def notify(env, title, msg, priority="default"):
    topic = env.get("NTFY_TOPIC")
    if not topic:
        print(f"[sin ntfy] {title}: {msg}")
        return
    server = env.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    # Publicar en JSON: así los acentos del título llegan bien.
    body = {"topic": topic, "title": title, "message": msg, "tags": ["shield"],
            "priority": {"default": 3, "high": 4, "urgent": 5}.get(priority, 3)}
    req = urllib.request.Request(server, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:  # sin internet un momento: lo vuelve a intentar el siguiente aviso
        print(f"No se pudo avisar: {e}", file=sys.stderr)


def iface():
    out = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True).stdout.split()
    return out[out.index("dev") + 1] if "dev" in out else "eth0"


def read_tx(dev):
    with open(f"/sys/class/net/{dev}/statistics/tx_bytes") as f:
        return int(f.read().strip())


def load_state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_state(s):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f)
    os.replace(tmp, STATE)


def wg(cmd):
    subprocess.run(["systemctl", cmd, "wg-quick@wg0"], check=False)


def limit_bytes(env):
    return int(float(env.get("LIMITE_TB", "10")) * 10**12)


def revisar(env):
    limit = limit_bytes(env)
    month = time.strftime("%Y-%m")
    s, alerts, action = step(load_state(), month, read_tx(iface()), limit)
    if action == "pausar":
        wg("stop")
    elif action == "reanudar":
        wg("start")
    elif s.get("paused"):
        wg("stop")  # aunque se reinicie la máquina, sigue en pausa hasta el día 1
    save_state(s)
    used = f"{human(s['total'])} de {human(limit)}"
    for kind, lvl in alerts:
        if kind == "nuevo_mes":
            notify(env, "EscudoBit: mes nuevo", "El contador de tráfico vuelve a cero." + (" La VPN está encendida otra vez." if action == "reanudar" else ""))
        elif lvl >= PAUSE_AT:
            notify(env, "EscudoBit: VPN en pausa", f"Llevas el {lvl} % del tráfico gratis del mes ({used}). La VPN se ha pausado para que no cueste nada; vuelve sola el día 1. La app sigue protegiendo mensajes, QR y apps.", "urgent")
        else:
            notify(env, f"EscudoBit: {lvl} % del tráfico", f"Este mes van {used} del tráfico gratis. Todo sigue gratis; te aviso otra vez al {LEVELS[LEVELS.index(lvl) + 1]} %.", "high" if lvl >= 80 else "default")


def peers():
    out = subprocess.run(["wg", "show", "wg0", "latest-handshakes"], capture_output=True, text=True).stdout
    now = time.time()
    total = active = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            total += 1
            if parts[1].isdigit() and now - int(parts[1]) < 7 * 86400:
                active += 1
    return total, active


def summary(env):
    s = load_state() or {"total": 0, "paused": False}
    limit = limit_bytes(env)
    total, active = peers()
    disk = shutil.disk_usage("/")
    with open("/proc/uptime") as f:
        days = int(float(f.read().split()[0]) // 86400)
    pct = s["total"] * 100 / limit
    return (
        f"Tráfico del mes: {human(s['total'])} de {human(limit)} ({pct:.1f} %).\n"
        f"VPN: {'EN PAUSA hasta el día 1' if s.get('paused') else 'funcionando'}.\n"
        f"Móviles dados de alta: {total} (usaron la VPN esta semana: {active}).\n"
        f"Disco: {disk.used * 100 // disk.total} % ocupado. Encendida desde hace {days} días.\n"
        f"Coste: 0 € (todo dentro de lo gratuito)."
    )


def main():
    env = load_env()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "estado"
    if cmd == "revisar":
        revisar(env)
    elif cmd == "semanal":
        notify(env, "EscudoBit: resumen semanal", summary(env))
    elif cmd == "prueba":
        notify(env, "EscudoBit: prueba", "Si lees esto, los avisos del servidor llegan a tu móvil.")
    else:
        print(summary(env))


if __name__ == "__main__":
    main()
