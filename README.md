# Servidor VPN de EscudoBit (Oracle Cloud, gratis)

Cuando una persona se conecta a una **wifi pública** (bar, hotel, estación), la app EscudoBit
enciende sola una VPN contra este servidor: todo lo que hace va cifrado, sin publicidad y sin
webs de estafa. Al salir de esa wifi, la VPN se apaga sola y vuelve el escudo ligero del móvil.

| Pieza | Para qué |
|---|---|
| **WireGuard** | La VPN. Rápida y moderna; gasta poca batería. |
| **AdGuard Home** | DNS sin publicidad ni rastreadores, con la lista de estafas de EscudoBit. |
| **API de alta** (`api/escudobit_api.py`) | Cada móvil pide aquí su plaza en la VPN. |
| **Caddy** | Pone HTTPS a la API con un nombre gratuito (`IP.sslip.io`). |

**Coste: 0 €.** Oracle "Always Free" da para siempre una máquina ARM de hasta 4 núcleos y 24 GB,
y 10 TB de tráfico al mes: sobra para miles de personas.

**Privacidad:** el servidor no guarda qué webs se visitan (el registro de AdGuard está apagado).
De cada móvil solo guarda su llave pública, su dirección dentro de la VPN y la fecha de alta.

---

## Puesta en marcha (unos 30 minutos, una sola vez)

### 1. Crear la cuenta de Oracle Cloud (esto lo tienes que hacer tú)

1. Entra en <https://www.oracle.com/es/cloud/free/> y pulsa **Empieza gratis**.
2. Rellena tus datos. Pide una tarjeta **solo para comprobar que eres una persona**: no cobra nada
   mientras uses lo gratuito ("Always Free").
3. Como **región de inicio** elige **Spain Central (Madrid)**. No se puede cambiar después.

### 2. Crear la máquina

1. Menú ☰ → **Compute** → **Instances** → **Create instance**.
2. **Name:** `escudobit`.
3. **Image:** pulsa *Change image* → **Ubuntu** → *Canonical Ubuntu 24.04*.
4. **Shape:** pulsa *Change shape* → **Ampere** → `VM.Standard.A1.Flex` con **1 OCPU y 6 GB**
   (si no hay hueco, vale `VM.Standard.E2.1.Micro`).
5. **SSH keys:** deja *Generate a key pair* y pulsa **Save private key** (guárdala bien).
6. Pulsa **Create**. En un par de minutos estará en verde (*Running*). Apunta la **Public IP**.

### 3. Abrir los puertos en la red de Oracle

1. En la página de la máquina, pulsa en la **Subnet** → en la **Security List** por defecto.
2. **Add Ingress Rules**, tres reglas, todas con *Source CIDR* `0.0.0.0/0`:
   - Protocolo **UDP**, puerto **51820** (la VPN)
   - Protocolo **TCP**, puerto **80** (para el certificado HTTPS)
   - Protocolo **TCP**, puerto **443** (la API)

### 4. Instalar todo con un comando

1. En la página de la máquina pulsa **Cloud Shell** (arriba a la derecha, icono `>_`), o conéctate
   por SSH con la llave que guardaste: `ssh -i llave.key ubuntu@IP_PUBLICA`.
2. Descarga el instalador e instálalo todo (copia y pega estas dos líneas):
   ```bash
   git clone https://github.com/kamikazeroot/escudobit-servidor-vpn.git
   sudo bash escudobit-servidor-vpn/instalar.sh
   ```
3. Al terminar te muestra **dos datos** (también quedan en `/root/escudobit-datos.txt`):
   ```
   API de alta:             https://1-2-3-4.sslip.io
   Llave pública WireGuard: AbCd...=
   ```

### 5. Meter esos dos datos en la app

En `gradle.properties` del proyecto (no son secretos):

```properties
escudobit.vpnApi=https://1-2-3-4.sslip.io
escudobit.vpnKey=AbCd...=
```

Al compilar, la app ya tiene la VPN automática. Sin estos datos, la app funciona igual pero solo
con el escudo ligero (la sección "VPN en wifis públicas" no aparece).

---

## Seguridad de las altas

- **La llave del servidor va dentro de la app.** Si alguien se hiciera pasar por el servidor,
  la app lo detecta y no activa la VPN.
- **Límite de altas:** como mucho 10 por IP y hora (`RATE_PER_HOUR`).
- **Play Integrity** (comprueba que quien pide plaza es la app EscudoBit original en un móvil de verdad,
  gratis hasta 10.000 comprobaciones al día). Necesita que la app esté en **Google Play Console**.
  Mientras no lo esté, se queda en `INTEGRITY=off`. Para activarlo:
  1. En Play Console, *Integridad de la app* → vincula un proyecto de Google Cloud.
  2. En Google Cloud crea una *cuenta de servicio*, descarga su llave JSON y súbela al servidor como
     `/etc/escudobit/google.json`.
  3. En `/etc/escudobit/api.env` pon `INTEGRITY=on` y reinicia: `sudo systemctl restart escudobit-api`.
  4. En la app, activar la petición del token (pendiente: se añade cuando la app esté en Play).

## Mantenimiento

| Qué | Cómo |
|---|---|
| Ver si la API funciona | `curl https://TU-NOMBRE.sslip.io/v1/estado` |
| Ver los móviles conectados | `sudo wg show` |
| Registro de la API | `sudo journalctl -u escudobit-api -f` |
| Actualizar el sistema | `sudo apt update && sudo apt upgrade -y` |
| Ajustes de AdGuard Home | `ssh -L 3000:127.0.0.1:3000 ubuntu@IP` y abrir `http://localhost:3000` (usuario `admin`, contraseña en `/root/.escudobit-adguard`) |

## Pruebas

```bash
cd api && python3 -m unittest test_api
```

Prueban las reglas (llaves, direcciones, Play Integrity, límite de altas) y una alta real contra la API
arrancada en local (con un WireGuard simulado).
