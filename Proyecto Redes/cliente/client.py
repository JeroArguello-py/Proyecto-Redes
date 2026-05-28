# =============================================================================
#  CLIENTE REPLICABLE SDN — Proyecto Final Redes de Computadores
#  Universidad del Rosario
# =============================================================================
#
#  Uso:
#    pip install requests
#    python client.py                        # usa config.json por defecto
#    python client.py --config config_nodo_C.json   # config personalizada
#
#  Para replicar en otro equipo, sólo cambia el archivo config.json:
#    - node_name  → nombre único de este nodo
#    - server_ip  → IP del laptop donde corre el servidor controlador
#    - listen_port → puerto UDP/TCP donde este nodo escucha tráfico
#
# =============================================================================

import json
import socket
import threading
import time
import logging
import os
import argparse
import struct
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[ERROR] Falta el paquete 'requests'. Ejecuta:  pip install requests")
    exit(1)

# ── Motor de reglas (Fase 5) ──────────────────────────────────────────────────
from rule_engine import evaluate_packet as _evaluate_packet, apply_action as _apply_action

# ── Argumentos de línea de comandos ──────────────────────────────────────────

parser = argparse.ArgumentParser(description="Cliente SDN replicable")
parser.add_argument(
    "--config", default="config.json",
    help="Ruta al archivo de configuración (default: config.json)"
)
args = parser.parse_args()

# ── Cargar configuración ──────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, args.config)

if not os.path.exists(CONFIG_PATH):
    print(f"[ERROR] No se encontró el archivo de configuración: {CONFIG_PATH}")
    exit(1)

with open(CONFIG_PATH, encoding="utf-8") as f:
    CONFIG = json.load(f)

SERVER_IP         = CONFIG["server_ip"]
SERVER_PORT       = int(CONFIG.get("server_port",       5000))
NODE_NAME         = CONFIG["node_name"]
LISTEN_PORT       = int(CONFIG.get("listen_port",       9000))
POLL_INTERVAL     = int(CONFIG.get("poll_interval",     5))
HEARTBEAT_INTERVAL= int(CONFIG.get("heartbeat_interval", 10))

# listen_all: true  → raw socket, captura TODOS los puertos (requiere admin)
# listen_ports: [...] → puertos específicos
# listen_port: N    → un solo puerto (modo original)
LISTEN_ALL   = CONFIG.get("listen_all", False)
_ports_raw   = CONFIG.get("listen_ports", None)
LISTEN_PORTS = [int(p) for p in _ports_raw] if _ports_raw else [LISTEN_PORT]

SERVER_BASE_URL   = f"http://{SERVER_IP}:{SERVER_PORT}"

# ── Directorio de logs ────────────────────────────────────────────────────────

LOGS_DIR = os.path.join(BASE_DIR, "data", "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

log_file = os.path.join(LOGS_DIR, f"{NODE_NAME}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(f"SDN-Client:{NODE_NAME}")

# ── Estado del nodo ───────────────────────────────────────────────────────────

node_id    = None          # Asignado por el servidor al registrarse
rules      = []            # Tabla de reglas (actualizada periódicamente)
_rules_lock = threading.Lock()

# Estadísticas locales
stats = {
    "packets_received": 0,
    "packets_forwarded": 0,
    "packets_dropped":   0,
    "packets_reported":  0,
    "packets_no_match":  0,
}


# ── Utilidades ────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def my_local_ip():
    """Obtiene la IP local de esta máquina en la LAN."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((SERVER_IP, SERVER_PORT))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


MY_IP = my_local_ip()


# ── Motor de reglas (Match Engine) — delegado a rule_engine.py (Fase 5) ───────

def evaluate_packet(packet):
    """Evalúa el paquete contra las reglas activas. Ver rule_engine.py."""
    with _rules_lock:
        current_rules = list(rules)
    return _evaluate_packet(packet, current_rules)


def apply_action(rule, packet):
    """Aplica la acción de la regla. Ver rule_engine.py."""
    return _apply_action(rule, packet, stats, send_event)


# ── Comunicación con el servidor ──────────────────────────────────────────────

def api_post(endpoint, payload, timeout=5):
    """POST al servidor controlador. Retorna el JSON de respuesta o None."""
    try:
        r = requests.post(
            f"{SERVER_BASE_URL}{endpoint}",
            json=payload,
            timeout=timeout
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        logger.error(f"No se pudo conectar al servidor ({SERVER_BASE_URL}). ¿Está corriendo?")
    except requests.exceptions.Timeout:
        logger.error(f"Timeout al contactar {SERVER_BASE_URL}{endpoint}")
    except Exception as e:
        logger.error(f"Error en POST {endpoint}: {e}")
    return None


def api_get(endpoint, timeout=5):
    """GET al servidor controlador. Retorna el JSON de respuesta o None."""
    try:
        r = requests.get(f"{SERVER_BASE_URL}{endpoint}", timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        logger.error(f"No se pudo conectar al servidor ({SERVER_BASE_URL}). ¿Está corriendo?")
    except Exception as e:
        logger.error(f"Error en GET {endpoint}: {e}")
    return None


def register_with_server():
    """
    Registra este nodo con el servidor controlador.
    Reintenta cada 5 segundos hasta conseguirlo.
    """
    global node_id
    logger.info(f"Intentando registrar '{NODE_NAME}' en {SERVER_BASE_URL} ...")

    while True:
        resp = api_post("/register", {
            "name": NODE_NAME,
            "ip":   MY_IP,
            "port": LISTEN_PORT,
        })
        if resp and "node_id" in resp:
            node_id = resp["node_id"]
            logger.info(
                f"Registrado correctamente. node_id={node_id} | "
                f"Reglas disponibles en servidor: {resp.get('rules_count', 0)}"
            )
            return
        logger.warning("Registro fallido. Reintentando en 5 segundos...")
        time.sleep(5)


def send_event(event_type, rule, detail):
    """Envía un evento (bloqueo, reporte) al servidor controlador."""
    if not node_id:
        return
    api_post("/events", {
        "node_id":   node_id,
        "type":      event_type,
        "rule_id":   rule.get("id")   if rule else None,
        "rule_name": rule.get("name") if rule else "",
        "detail":    detail,
    })


# ── Hilo: Heartbeat ───────────────────────────────────────────────────────────

def heartbeat_loop():
    """Envía señal de vida al servidor cada HEARTBEAT_INTERVAL segundos."""
    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        if node_id:
            resp = api_post("/heartbeat", {"node_id": node_id})
            if resp:
                logger.debug(f"Heartbeat enviado. Hora servidor: {resp.get('server_time','?')}")
            else:
                logger.warning("Heartbeat fallido (servidor no responde)")


# ── Hilo: Polling de reglas ───────────────────────────────────────────────────

def rules_poll_loop():
    """Consulta las reglas activas al servidor cada POLL_INTERVAL segundos."""
    global rules
    while True:
        time.sleep(POLL_INTERVAL)
        resp = api_get("/rules")
        if resp and "rules" in resp:
            new_rules = resp["rules"]
            # Solo loguear si las reglas realmente cambiaron
            with _rules_lock:
                changed = (
                    len(new_rules) != len(rules) or
                    {r["id"] for r in new_rules} != {r["id"] for r in rules} or
                    {(r["id"], r["priority"], r["action"]) for r in new_rules} !=
                    {(r["id"], r["priority"], r["action"]) for r in rules}
                )
                rules = new_rules
            if changed:
                logger.info(
                    f"Reglas actualizadas: {resp['total']} regla(s) | "
                    + (", ".join(
                        f"'{r['name']}'({r['priority']})→{r['action']}"
                        for r in new_rules
                    ) if new_rules else "sin reglas")
                )


# ── Hilo: Estadísticas ────────────────────────────────────────────────────────

def stats_loop():
    """Imprime estadísticas locales cada 30 segundos."""
    while True:
        time.sleep(30)
        logger.info(
            f"ESTADÍSTICAS | recibidos={stats['packets_received']} | "
            f"permitidos={stats['packets_forwarded']} | "
            f"bloqueados={stats['packets_dropped']} | "
            f"reportados={stats['packets_reported']} | "
            f"sin_regla={stats['packets_no_match']}"
        )


# ── Listener UDP ──────────────────────────────────────────────────────────────

def udp_listener(port):
    """
    Escucha tráfico UDP en el puerto indicado.
    Por cada datagrama recibido, construye el descriptor del paquete
    y lo pasa al motor de reglas.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    logger.info(f"Escuchando UDP en 0.0.0.0:{port}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            ip_src   = addr[0]
            port_src = str(addr[1])

            packet = {
                "ip_src":   ip_src,
                "ip_dst":   MY_IP,
                "protocol": "UDP",
                "port_src": port_src,
                "port_dst": str(port),
                "size":     len(data),
                "payload":  data.decode("utf-8", errors="replace"),
            }

            rule   = evaluate_packet(packet)
            action = apply_action(rule, packet)

            if rule is None:
                stats["packets_no_match"] += 1

        except Exception as e:
            logger.error(f"Error en listener UDP:{port}: {e}")


# ── Listener TCP ──────────────────────────────────────────────────────────────

def handle_tcp_client(conn, addr, port):
    """Maneja una conexión TCP entrante en el puerto indicado."""
    try:
        ip_src   = addr[0]
        port_src = str(addr[1])
        data     = conn.recv(4096)

        packet = {
            "ip_src":   ip_src,
            "ip_dst":   MY_IP,
            "protocol": "TCP",
            "port_src": port_src,
            "port_dst": str(port),
            "size":     len(data),
            "payload":  data.decode("utf-8", errors="replace"),
        }

        rule   = evaluate_packet(packet)
        action = apply_action(rule, packet)

        if rule is None:
            stats["packets_no_match"] += 1

        # Responder al cliente con el resultado
        response = json.dumps({
            "action":    action,
            "rule_name": rule["name"] if rule else "(sin regla)",
            "node":      NODE_NAME,
        }).encode()
        conn.sendall(response)

    except Exception as e:
        logger.error(f"Error manejando TCP desde {addr} en puerto {port}: {e}")
    finally:
        conn.close()


def tcp_listener(port):
    """Escucha conexiones TCP en el puerto indicado."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(10)
    logger.info(f"Escuchando TCP en 0.0.0.0:{port}")

    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(
                target=handle_tcp_client, args=(conn, addr, port), daemon=True
            )
            t.start()
        except Exception as e:
            logger.error(f"Error en listener TCP:{port}: {e}")


# ── Raw Socket: todos los puertos ────────────────────────────────────────────

def _process_raw_packet(raw_data):
    """Parsea un paquete IP crudo y lo pasa al motor de reglas."""
    if len(raw_data) < 20:
        return

    # Header IP
    iph        = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
    ihl        = (iph[0] & 0xF) * 4      # longitud header IP en bytes
    proto_num  = iph[6]                   # 6=TCP, 17=UDP
    src_ip     = socket.inet_ntoa(iph[8])
    dst_ip     = socket.inet_ntoa(iph[9])

    # Solo paquetes destinados a este nodo
    if dst_ip != MY_IP:
        return

    if proto_num == 17:          # UDP
        if len(raw_data) < ihl + 8:
            return
        udph     = struct.unpack('!HHHH', raw_data[ihl:ihl+8])
        src_port = str(udph[0])
        dst_port = str(udph[1])
        payload  = raw_data[ihl+8:]
        proto    = "UDP"

    elif proto_num == 6:         # TCP
        if len(raw_data) < ihl + 20:
            return
        tcph        = struct.unpack('!HHLLBBHHH', raw_data[ihl:ihl+20])
        src_port    = str(tcph[0])
        dst_port    = str(tcph[1])
        tcp_offset  = (tcph[4] >> 4) * 4
        payload     = raw_data[ihl + tcp_offset:]
        proto       = "TCP"
        # Ignorar paquetes de control sin datos (SYN, ACK vacíos)
        if len(payload) == 0:
            return
    else:
        return   # Ignorar otros protocolos (ICMP, etc.)

    packet = {
        "ip_src":   src_ip,
        "ip_dst":   dst_ip,
        "protocol": proto,
        "port_src": src_port,
        "port_dst": dst_port,
        "size":     len(raw_data),
        "payload":  payload.decode("utf-8", errors="replace")[:200],
    }

    rule   = evaluate_packet(packet)
    action = apply_action(rule, packet)
    if rule is None:
        stats["packets_no_match"] += 1


def raw_listener():
    """
    Captura TODO el tráfico UDP y TCP entrante en CUALQUIER puerto
    usando un raw socket a nivel IP.

    Requisito en Windows: ejecutar PowerShell / CMD como Administrador.
    Requisito en Linux:   ejecutar con sudo o con CAP_NET_RAW.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((MY_IP, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Windows: activar modo promiscuo para recibir todos los paquetes
        if os.name == 'nt':
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        logger.info(f"🌐 Raw socket activo — capturando TODOS los puertos en {MY_IP}")

        while True:
            try:
                raw_data, _ = sock.recvfrom(65535)
                _process_raw_packet(raw_data)
            except Exception as e:
                logger.error(f"Error procesando paquete raw: {e}")

    except PermissionError:
        logger.error(
            "⚠️  Sin permisos para raw socket. "
            "Ejecuta PowerShell como ADMINISTRADOR, o usa 'listen_ports' en el config."
        )
    except Exception as e:
        logger.error(f"Error iniciando raw socket: {e}")


# ── Arranque principal ────────────────────────────────────────────────────────

def main():
    modo_puertos = "TODOS (raw socket)" if LISTEN_ALL else ", ".join(str(p) for p in LISTEN_PORTS)
    logger.info("=" * 60)
    logger.info(f"  CLIENTE SDN — '{NODE_NAME}'")
    logger.info(f"  IP local:         {MY_IP}")
    logger.info(f"  Servidor:         {SERVER_BASE_URL}")
    logger.info(f"  Puertos escucha:  {modo_puertos}")
    logger.info(f"  Poll reglas:      cada {POLL_INTERVAL}s")
    logger.info(f"  Heartbeat:        cada {HEARTBEAT_INTERVAL}s")
    logger.info(f"  Config usada:     {CONFIG_PATH}")
    logger.info(f"  Log:              {log_file}")
    logger.info("=" * 60)

    # 1. Registrarse con el servidor (bloquea hasta lograrlo)
    register_with_server()

    # 2. Obtener reglas iniciales
    resp = api_get("/rules")
    if resp and "rules" in resp:
        with _rules_lock:
            rules.extend(resp["rules"])
        logger.info(f"Reglas iniciales cargadas: {resp['total']}")

    # 3. Lanzar hilos de fondo
    threads = [
        threading.Thread(target=heartbeat_loop,  daemon=True, name="heartbeat"),
        threading.Thread(target=rules_poll_loop, daemon=True, name="rules-poll"),
        threading.Thread(target=stats_loop,      daemon=True, name="stats"),
    ]

    # Modo escucha: raw socket (todos los puertos) o puertos específicos
    if LISTEN_ALL:
        threads.append(threading.Thread(
            target=raw_listener, daemon=True, name="raw-all-ports"
        ))
    else:
        for p in LISTEN_PORTS:
            threads.append(threading.Thread(
                target=udp_listener, args=(p,), daemon=True, name=f"udp-{p}"
            ))
            threads.append(threading.Thread(
                target=tcp_listener, args=(p,), daemon=True, name=f"tcp-{p}"
            ))

    for t in threads:
        t.start()
        logger.info(f"Hilo '{t.name}' iniciado")

    logger.info(f"Cliente '{NODE_NAME}' listo. Esperando tráfico...")

    # 4. Mantener el proceso principal vivo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info(f"Cliente '{NODE_NAME}' detenido por el usuario.")
        logger.info(
            f"Resumen final | recibidos={stats['packets_received']} | "
            f"permitidos={stats['packets_forwarded']} | "
            f"bloqueados={stats['packets_dropped']} | "
            f"reportados={stats['packets_reported']}"
        )


if __name__ == "__main__":
    main()
