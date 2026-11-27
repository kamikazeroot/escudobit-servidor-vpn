#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Instalador del servidor VPN de EscudoBit (Oracle Cloud "Always Free", Ubuntu 22.04/24.04).
#
# Deja funcionando, en una sola máquina:
#   - WireGuard: la VPN a la que se conectan los móviles en wifis públicas.
#   - AdGuard Home: DNS sin publicidad + la lista de estafas de EscudoBit.
#   - API de alta: los móviles piden aquí su configuración (con Play Integrity).
#   - Caddy: HTTPS automático para la API (con un nombre gratuito de sslip.io).
#   - Vigilante: avisos al móvil del dueño y pausa de la VPN antes de pasar del tráfico gratis.
#
# Uso (en la máquina de Oracle):   sudo bash instalar.sh
# Se puede volver a ejecutar: no rompe lo que ya está instalado.
# ---------------------------------------------------------------------------
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WG_PORT=51820
WG_NET="10.66.0.0/16"
WG_IP="10.66.0.1"
# Panel de AdGuard Home (solo dentro de la máquina). El asistente de instalación usa el 3000.
AG_PORT=3003
LISTS_URL="https://kamikazeroot.github.io/escudobit-listas/v1/blacklist.txt"
DATOS=/root/escudobit-datos.txt

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Ejecútalo con sudo: sudo bash instalar.sh"; exit 1; }

say "Datos de la máquina"
PUBLIC_IP="$(curl -4 -fsS https://api.ipify.org || curl -4 -fsS https://ifconfig.me)"
IFACE="$(ip -4 route show default | awk '{print $5; exit}')"
DOMAIN="${PUBLIC_IP//./-}.sslip.io"
echo "IP pública: $PUBLIC_IP   Interfaz: $IFACE   Nombre: $DOMAIN"

say "Memoria de reserva (para las máquinas pequeñas de 1 GB)"
if [ ! -f /swapfile ] && [ "$(awk '/MemTotal/ {print $2}' /proc/meminfo)" -lt 3000000 ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
free -h | head -3

say "Paquetes (WireGuard, Caddy, Python)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard iptables iptables-persistent python3 curl openssl debian-keyring debian-archive-keyring apt-transport-https gnupg
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi

say "Cortafuegos (Oracle bloquea todo por defecto)"
# Las imágenes de Ubuntu de Oracle traen una regla REJECT al final: se abren los puertos antes.
for rule in "-p udp --dport $WG_PORT" "-p tcp --dport 80" "-p tcp --dport 443"; do
  iptables -C INPUT $rule -j ACCEPT 2>/dev/null || iptables -I INPUT 1 $rule -j ACCEPT
done
# Desde la VPN, el servidor solo atiende el DNS (ni SSH ni nada más).
iptables -C INPUT -i wg0 -j DROP 2>/dev/null || iptables -A INPUT -i wg0 -j DROP
# DNS solo desde dentro de la VPN.
iptables -C INPUT -i wg0 -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i wg0 -p udp --dport 53 -j ACCEPT
iptables -C INPUT -i wg0 -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i wg0 -p tcp --dport 53 -j ACCEPT
netfilter-persistent save

say "Reenvío de tráfico"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-escudobit.conf
sysctl -p /etc/sysctl.d/99-escudobit.conf

say "WireGuard"
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
if [ ! -f /etc/wireguard/server.key ]; then
  umask 077
  wg genkey > /etc/wireguard/server.key
  wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
fi
SERVER_PUB="$(cat /etc/wireguard/server.pub)"
cat > /etc/wireguard/wg0.conf <<EOF
# VPN de EscudoBit. Los móviles se añaden solos desde la API de alta.
[Interface]
Address = $WG_IP/16
ListenPort = $WG_PORT
PrivateKey = $(cat /etc/wireguard/server.key)
# Seguridad: los móviles solo pueden salir a internet. Nada de la red interna de Oracle (ni su servicio
# de metadatos 169.254.169.254, que guarda la identidad de la máquina), ni de otros móviles de la VPN.
PostUp = iptables -t nat -A POSTROUTING -s $WG_NET -o $IFACE -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -o $IFACE -j ACCEPT; iptables -I FORWARD 1 -i $IFACE -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -I FORWARD 1 -i wg0 -d 10.0.0.0/8 -j DROP; iptables -I FORWARD 1 -i wg0 -d 172.16.0.0/12 -j DROP; iptables -I FORWARD 1 -i wg0 -d 192.168.0.0/16 -j DROP; iptables -I FORWARD 1 -i wg0 -d 169.254.0.0/16 -j DROP; iptables -I FORWARD 1 -i wg0 -o wg0 -j DROP; iptables -I INPUT 1 -i wg0 -d 169.254.0.0/16 -j DROP
PostDown = iptables -t nat -D POSTROUTING -s $WG_NET -o $IFACE -j MASQUERADE; iptables -D FORWARD -i wg0 -o $IFACE -j ACCEPT; iptables -D FORWARD -i $IFACE -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -D FORWARD -i wg0 -d 10.0.0.0/8 -j DROP; iptables -D FORWARD -i wg0 -d 172.16.0.0/12 -j DROP; iptables -D FORWARD -i wg0 -d 192.168.0.0/16 -j DROP; iptables -D FORWARD -i wg0 -d 169.254.0.0/16 -j DROP; iptables -D FORWARD -i wg0 -o wg0 -j DROP; iptables -D INPUT -i wg0 -d 169.254.0.0/16 -j DROP
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
systemctl restart wg-quick@wg0

say "AdGuard Home (DNS sin publicidad + lista de estafas)"
if [ ! -x /opt/AdGuardHome/AdGuardHome ]; then
  curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
fi
if [ ! -f /root/.escudobit-adguard ]; then
  AG_PASS="$(openssl rand -base64 18 | tr -d '/+=')"
  # Configuración inicial por su propia API (vale para cualquier versión de AdGuard Home).
  for i in $(seq 1 30); do curl -fsS http://127.0.0.1:3000/control/install/get_addresses >/dev/null 2>&1 && break; sleep 2; done
  curl -fsS -X POST http://127.0.0.1:3000/control/install/configure -H 'Content-Type: application/json' \
    -d "{\"web\":{\"ip\":\"127.0.0.1\",\"port\":$AG_PORT},\"dns\":{\"ip\":\"$WG_IP\",\"port\":53},\"username\":\"admin\",\"password\":\"$AG_PASS\"}"
  for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:$AG_PORT/ && break; sleep 2; done
  JAR="$(mktemp)"
  curl -fsS -c "$JAR" -X POST http://127.0.0.1:$AG_PORT/control/login -H 'Content-Type: application/json' \
    -d "{\"name\":\"admin\",\"password\":\"$AG_PASS\"}"
  # Lista de estafas de EscudoBit (se actualiza sola cada 6 horas en GitHub).
  curl -fsS -b "$JAR" -X POST http://127.0.0.1:$AG_PORT/control/filtering/add_url -H 'Content-Type: application/json' \
    -d "{\"name\":\"EscudoBit - webs de estafa\",\"url\":\"$LISTS_URL\",\"whitelist\":false}"
  # Preguntar fuera de forma cifrada al servicio de seguridad de Cloudflare (bloquea estafas y virus; es el mismo que usa la app).
  # Quad9 (también bloquea) queda de reserva por si Cloudflare no responde. Repartir entre los dos no suma los filtros. Sin registros.
  curl -fsS -b "$JAR" -X POST http://127.0.0.1:$AG_PORT/control/dns_config -H 'Content-Type: application/json' \
    -d '{"upstream_dns":["https://security.cloudflare-dns.com/dns-query"],"fallback_dns":["https://dns.quad9.net/dns-query"],"bootstrap_dns":["1.1.1.2","9.9.9.9"],"upstream_mode":"load_balance"}'
  curl -fsS -b "$JAR" -X POST http://127.0.0.1:$AG_PORT/control/querylog/config/update -H 'Content-Type: application/json' \
    -d '{"enabled":false,"interval":3600000,"anonymize_client_ip":true}' || true
  rm -f "$JAR"
  echo "$AG_PASS" > /root/.escudobit-adguard && chmod 600 /root/.escudobit-adguard
fi

say "API de alta"
mkdir -p /opt/escudobit /etc/escudobit /var/lib/escudobit
cp "$DIR/api/escudobit_api.py" /opt/escudobit/
if [ ! -f /etc/escudobit/api.env ]; then
  cat > /etc/escudobit/api.env <<EOF
LISTEN=127.0.0.1:8080
WG_INTERFACE=wg0
WG_SUBNET=$WG_NET
SERVER_PUBLIC_KEY=$SERVER_PUB
ENDPOINT=$PUBLIC_IP:$WG_PORT
DNS=$WG_IP
DB=/var/lib/escudobit/peers.json
# Play Integrity: ponlo en "on" cuando la app esté en Google Play (ver README).
INTEGRITY=off
INTEGRITY_ALLOW_UNRECOGNIZED=0
PACKAGE=com.escudobit.app
GOOGLE_KEY=/etc/escudobit/google.json
RATE_PER_HOUR=10
EOF
  chmod 600 /etc/escudobit/api.env
fi
cat > /etc/systemd/system/escudobit-api.service <<EOF
[Unit]
Description=API de alta de EscudoBit
After=network-online.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
EnvironmentFile=/etc/escudobit/api.env
ExecStart=/usr/bin/python3 /opt/escudobit/escudobit_api.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now escudobit-api
systemctl restart escudobit-api

say "HTTPS (Caddy + $DOMAIN)"
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    request_body {
        max_size 16KB
    }
    # La IP real del móvil (nunca la que invente quien hace la petición), para el límite de altas.
    handle /v1/* {
        reverse_proxy 127.0.0.1:8080 {
            header_up X-Forwarded-For {remote_host}
        }
    }
    # Todo lo demás: nada que ver (con "handle" el orden es el que se escribe).
    handle {
        respond 404
    }
}
EOF
systemctl enable caddy
systemctl restart caddy

say "Vigilante (topes de tráfico y avisos al móvil del dueño)"
timedatectl set-timezone Europe/Madrid || true
cp "$DIR/api/escudobit_vigilante.py" /opt/escudobit/
if [ ! -f /etc/escudobit/avisos.env ]; then
  cat > /etc/escudobit/avisos.env <<EOF
# Avisos al móvil con la app gratuita ntfy: suscríbete a este tema (es la única llave, no lo compartas).
NTFY_SERVER=https://ntfy.sh
NTFY_TOPIC=escudobit-$(openssl rand -hex 12)
# Tráfico gratis de Oracle al mes (TB). Avisa al 50 y 80 %, y al 90 % pausa la VPN hasta el día 1.
LIMITE_TB=10
EOF
  chmod 600 /etc/escudobit/avisos.env
fi
NTFY_TOPIC="$(grep '^NTFY_TOPIC=' /etc/escudobit/avisos.env | cut -d= -f2)"
for unit in revisar semanal; do
  cat > /etc/systemd/system/escudobit-$unit.service <<EOF
[Unit]
Description=Vigilante de EscudoBit ($unit)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/escudobit/escudobit_vigilante.py $unit
EOF
done
cat > /etc/systemd/system/escudobit-revisar.timer <<EOF
[Unit]
Description=Revisar el tráfico de EscudoBit cada 5 minutos

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/escudobit-semanal.timer <<EOF
[Unit]
Description=Resumen semanal de EscudoBit

[Timer]
OnCalendar=Mon *-*-* 10:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now escudobit-revisar.timer escudobit-semanal.timer

say "Comprobación"
sleep 5
curl -fsS "https://$DOMAIN/v1/estado" && echo " <- API OK" || echo "La API aún no responde por HTTPS (el certificado puede tardar un minuto)."
wg show wg0 | head -5

cat > "$DATOS" <<EOF
EscudoBit - datos del servidor ($(date))
API de alta:               https://$DOMAIN
Llave pública WireGuard:   $SERVER_PUB
Punto de conexión:         $PUBLIC_IP:$WG_PORT
AdGuard Home (solo desde el servidor): http://127.0.0.1:$AG_PORT  usuario admin, contraseña en /root/.escudobit-adguard
Avisos al móvil (app ntfy, suscríbete a este tema): $NTFY_TOPIC
EOF
chmod 600 "$DATOS"

say "¡Listo!"
echo "Pásale estos dos datos a la app (no son secretos):"
echo "  API de alta:             https://$DOMAIN"
echo "  Llave pública WireGuard: $SERVER_PUB"
echo ""
echo "Avisos del servidor en tu móvil: instala la app gratuita ntfy y suscríbete a este tema:"
echo "  $NTFY_TOPIC"
echo "(Guardados también en $DATOS)"
/usr/bin/python3 /opt/escudobit/escudobit_vigilante.py prueba || true
