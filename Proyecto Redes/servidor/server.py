# =============================================================================
#  SERVIDOR CONTROLADOR SDN — Proyecto Final Redes de Computadores
#  Universidad del Rosario
# =============================================================================
#
#  Uso:
#    pip install flask flask-cors
#    python server.py
#
#  Endpoints disponibles:
#    POST   /register        — Registrar un nuevo nodo cliente
#    POST   /heartbeat       — Señal de vida de un nodo
#    GET    /nodes           — Listar nodos registrados
#    GET    /rules           — Obtener reglas activas (JSON)
#    POST   /rules           — Crear una nueva regla
#    DELETE /rules/<rule_id> — Eliminar una regla
#    POST   /events          — Recibir reporte/alerta de un cliente
#    GET    /events          — Consultar historial de eventos
#    GET    /status          — Estado general del servidor
# =============================================================================

import json
import uuid
import logging
import os
import threading
import time
import socket
import ipaddress
import struct
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# ── Configuración ─────────────────────────────────────────────────────────────

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_DIR  = os.path.join(BASE_DIR, "data")
LOGS_DIR  = os.path.join(DATA_DIR, "logs")
RULES_FILE = os.path.join(DATA_DIR, "rules.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Cargar configuración
with open(os.path.join(BASE_DIR, "config.json")) as f:
    CONFIG = json.load(f)

HOST               = CONFIG.get("host", "0.0.0.0")
PORT               = CONFIG.get("port", 5000)
NODE_TIMEOUT_SEC   = CONFIG.get("node_timeout_seconds", 30)
MAX_EVENTS         = CONFIG.get("max_events_stored", 500)

# ── Logging ───────────────────────────────────────────────────────────────────

log_file = os.path.join(LOGS_DIR, f"server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler()          # También imprime en consola
    ]
)
logger = logging.getLogger("SDN-Server")

# ── Almacenamiento en memoria ─────────────────────────────────────────────────
#
#  nodes  : { node_id: { id, name, ip, port, status, registered_at, last_seen } }
#  rules  : [ { id, name, priority, match:{...}, action, packets, bytes, created_at } ]
#  events : [ { id, node_id, node_name, type, detail, timestamp } ]

nodes  = {}
rules  = []
events = []

# Lock para acceso seguro desde múltiples hilos
_lock = threading.Lock()

# ── Persistencia de reglas ────────────────────────────────────────────────────

def load_rules():
    """Carga las reglas desde disco al arrancar el servidor."""
    global rules
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                rules = json.load(f)
            logger.info(f"Reglas cargadas desde disco: {len(rules)} regla(s).")
        except Exception as e:
            logger.warning(f"No se pudieron cargar las reglas: {e}")
            rules = []


def save_rules():
    """Persiste las reglas en disco cada vez que se modifican."""
    try:
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error al guardar reglas: {e}")


# ── Utilidades ────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def priority_order(rule):
    """
    Ordena reglas por prioridad descendente (la mayor prioridad va primero).
    Acepta texto (Alta/Media/Baja) o número entero (mayor número = mayor prioridad).
    Devuelve valor negativo para que sorted() ponga la mayor prioridad primero.
    """
    p = rule.get("priority", "Baja")
    try:
        return -int(p)                    # numérico: mayor número → mayor prioridad
    except (ValueError, TypeError):
        return {"Alta": -100, "Media": -50, "Baja": -10}.get(str(p), -10)


def rules_sorted():
    """Devuelve las reglas ordenadas por prioridad descendente."""
    return sorted(rules, key=priority_order)


# ── Hilo de monitoreo de nodos ────────────────────────────────────────────────

def monitor_nodes():
    """
    Hilo de fondo: cada 10 segundos revisa qué nodos no han enviado
    heartbeat en NODE_TIMEOUT_SEC segundos y los marca como 'inactivo'.
    """
    while True:
        time.sleep(10)
        now = datetime.now(timezone.utc)
        with _lock:
            for node in nodes.values():
                if node["status"] == "activo":
                    last = datetime.fromisoformat(node["last_seen"])
                    diff = (now - last).total_seconds()
                    if diff > NODE_TIMEOUT_SEC:
                        node["status"] = "inactivo"
                        logger.warning(
                            f"Nodo '{node['name']}' ({node['ip']}) marcado INACTIVO "
                            f"(sin heartbeat por {int(diff)}s)"
                        )


# ── Flask app ─────────────────────────────────────────────────────────────────

STATIC_DIR = os.path.join(BASE_DIR, "static")
app = Flask(__name__, static_folder=STATIC_DIR)
CORS(app)   # Permite peticiones desde la interfaz HTML en cualquier origen


# ── Interfaz HTML ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ── /register ─────────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register_node():
    """
    Registra un nodo cliente en la red SDN.

    Body JSON esperado:
      { "name": "nodo-laptop-B", "ip": "192.168.1.101", "port": 9000 }

    Respuesta:
      { "node_id": "...", "message": "...", "rules_count": N }
    """
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name", "").strip()
    ip   = data.get("ip",   request.remote_addr).strip()
    port = int(data.get("port", 9000))

    if not name:
        return jsonify({"error": "El campo 'name' es obligatorio"}), 400

    with _lock:
        # Si ya existe un nodo con ese nombre, actualizar en vez de duplicar
        existing = next((n for n in nodes.values() if n["name"] == name), None)
        if existing:
            existing["ip"]        = ip
            existing["port"]      = port
            existing["status"]    = "activo"
            existing["last_seen"] = now_iso()
            node_id = existing["id"]
            logger.info(f"Nodo re-registrado: '{name}' — {ip}:{port}")
        else:
            node_id = str(uuid.uuid4())[:8]
            nodes[node_id] = {
                "id":            node_id,
                "name":          name,
                "ip":            ip,
                "port":          port,
                "status":        "activo",
                "registered_at": now_iso(),
                "last_seen":     now_iso(),
            }
            logger.info(f"Nuevo nodo registrado: '{name}' — {ip}:{port} (id={node_id})")

    return jsonify({
        "node_id":     node_id,
        "message":     f"Nodo '{name}' registrado correctamente",
        "rules_count": len(rules),
        "server_time": now_iso(),
    }), 201


# ── /heartbeat ────────────────────────────────────────────────────────────────

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    """
    El cliente envía esta señal periódicamente para indicar que sigue activo.

    Body JSON:  { "node_id": "abc12345" }
    """
    data    = request.get_json(force=True, silent=True) or {}
    node_id = data.get("node_id", "").strip()

    with _lock:
        node = nodes.get(node_id)
        if not node:
            return jsonify({"error": "Nodo no encontrado"}), 404
        node["status"]    = "activo"
        node["last_seen"] = now_iso()

    return jsonify({"ok": True, "server_time": now_iso()}), 200


# ── /nodes ────────────────────────────────────────────────────────────────────

@app.route("/nodes", methods=["GET"])
def list_nodes():
    """Devuelve la lista de todos los nodos registrados con su estado."""
    with _lock:
        node_list = list(nodes.values())
    return jsonify({
        "total":  len(node_list),
        "active": sum(1 for n in node_list if n["status"] == "activo"),
        "nodes":  node_list,
    }), 200


# ── /rules  GET ───────────────────────────────────────────────────────────────

@app.route("/rules", methods=["GET"])
def get_rules():
    """
    Devuelve las reglas activas ordenadas por prioridad (Alta > Media > Baja).
    Los clientes consultan este endpoint periódicamente.
    """
    with _lock:
        sorted_rules = rules_sorted()
    return jsonify({
        "total": len(sorted_rules),
        "rules": sorted_rules,
    }), 200


# ── /rules  POST ──────────────────────────────────────────────────────────────

@app.route("/rules", methods=["POST"])
def create_rule():
    """
    Crea una nueva regla de flujo SDN/Firewall.

    Body JSON mínimo:
    {
      "name":     "Bloquear SSH",
      "priority": "Alta",           // "Alta" | "Media" | "Baja"
      "action":   "drop",           // "forward" | "drop" | "report"
      "match": {
        "ip_src":   "*",
        "ip_dst":   "*",
        "protocol": "TCP",          // "TCP" | "UDP" | "*"
        "port_src": "*",
        "port_dst": "22"
      }
    }
    """
    data = request.get_json(force=True, silent=True) or {}

    # Validaciones básicas
    name     = data.get("name", "").strip()
    priority = data.get("priority", "Media")
    action   = data.get("action",   "forward")
    match    = data.get("match",    {})

    if not name:
        return jsonify({"error": "El campo 'name' es obligatorio"}), 400
    # Acepta "Alta"/"Media"/"Baja" o cualquier número entero (ej: "10", "50")
    texto_valido = str(priority) in ("Alta", "Media", "Baja")
    try:
        int(priority)
        numerico_valido = True
    except (ValueError, TypeError):
        numerico_valido = False
    if not texto_valido and not numerico_valido:
        return jsonify({"error": "priority debe ser 'Alta','Media','Baja' o un número entero"}), 400
    if action not in ("forward", "drop", "report"):
        return jsonify({"error": "action debe ser 'forward', 'drop' o 'report'"}), 400

    # Construir objeto regla con wildcards en campos faltantes
    rule = {
        "id":         str(uuid.uuid4())[:8],
        "name":       name,
        "priority":   priority,
        "action":     action,
        "match": {
            "ip_src":   match.get("ip_src",   "*"),
            "ip_dst":   match.get("ip_dst",   "*"),
            "protocol": match.get("protocol", "*"),
            "port_src": match.get("port_src", "*"),
            "port_dst": match.get("port_dst", "*"),
            # Campos opcionales extendidos
            "ingress":  match.get("ingress",  "*"),
            "mac_src":  match.get("mac_src",  "*"),
            "mac_dst":  match.get("mac_dst",  "*"),
        },
        "packets":    0,
        "bytes":      0,
        "created_at": now_iso(),
    }

    with _lock:
        rules.append(rule)
        save_rules()

    logger.info(
        f"Regla creada: '{name}' | action={action} | priority={priority} "
        f"| match={json.dumps(rule['match'])}"
    )

    return jsonify({
        "message": f"Regla '{name}' creada correctamente",
        "rule":    rule,
    }), 201


# ── /rules/<id>  DELETE ───────────────────────────────────────────────────────

@app.route("/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    """Elimina una regla por su ID."""
    with _lock:
        original_len = len(rules)
        remaining = [r for r in rules if r["id"] != rule_id]
        if len(remaining) == original_len:
            return jsonify({"error": f"Regla '{rule_id}' no encontrada"}), 404
        rules.clear()
        rules.extend(remaining)
        save_rules()

    logger.info(f"Regla eliminada: id={rule_id}")
    return jsonify({"message": f"Regla '{rule_id}' eliminada"}), 200


# ── /events  POST ─────────────────────────────────────────────────────────────

@app.route("/events", methods=["POST"])
def receive_event():
    """
    Recibe un reporte o alerta generado por un cliente.

    Body JSON:
    {
      "node_id":   "abc12345",
      "type":      "block" | "report" | "forward" | "error",
      "rule_id":   "xyz98765",        // regla que disparó el evento
      "rule_name": "Bloquear SSH",
      "detail": {
        "ip_src": "192.168.1.105", "ip_dst": "192.168.1.100",
        "protocol": "TCP", "port_dst": "22",
        "packet_size": 64
      }
    }
    """
    data    = request.get_json(force=True, silent=True) or {}
    node_id = data.get("node_id", "unknown")

    with _lock:
        node_name = nodes.get(node_id, {}).get("name", node_id)

        # Actualizar contadores en la regla correspondiente
        rule_id = data.get("rule_id")
        if rule_id:
            rule = next((r for r in rules if r["id"] == rule_id), None)
            if rule:
                rule["packets"] += 1
                rule["bytes"]   += int(data.get("detail", {}).get("packet_size", 0))
                save_rules()

        event = {
            "id":        str(uuid.uuid4())[:8],
            "node_id":   node_id,
            "node_name": node_name,
            "type":      data.get("type", "info"),
            "rule_id":   data.get("rule_id",   None),
            "rule_name": data.get("rule_name", ""),
            "detail":    data.get("detail",    {}),
            "timestamp": now_iso(),
        }
        events.append(event)

        # Limitar memoria: conservar solo los últimos MAX_EVENTS
        if len(events) > MAX_EVENTS:
            del events[0]

    level = logging.WARNING if event["type"] in ("block", "report") else logging.INFO
    logger.log(level,
        f"EVENTO [{event['type'].upper()}] nodo='{node_name}' "
        f"regla='{event['rule_name']}' detalle={json.dumps(event['detail'])}"
    )

    return jsonify({"message": "Evento registrado", "event_id": event["id"]}), 201


# ── /events  GET ──────────────────────────────────────────────────────────────

@app.route("/events", methods=["GET"])
def get_events():
    """
    Devuelve el historial de eventos.
    Parámetros opcionales:
      ?limit=50        — Últimos N eventos  (default: 100)
      ?type=block      — Filtrar por tipo   (block|report|forward|error)
      ?node_id=abc123  — Filtrar por nodo
    """
    limit   = int(request.args.get("limit",   100))
    ftype   = request.args.get("type",    None)
    fnode   = request.args.get("node_id", None)

    with _lock:
        result = list(events)

    if ftype:
        result = [e for e in result if e["type"] == ftype]
    if fnode:
        result = [e for e in result if e["node_id"] == fnode]

    result = result[-limit:]   # Los más recientes

    return jsonify({
        "total":  len(result),
        "events": result,
    }), 200


# ── /status ───────────────────────────────────────────────────────────────────

@app.route("/status", methods=["GET"])
def server_status():
    """Resumen del estado actual del servidor (útil para monitoreo)."""
    with _lock:
        active  = sum(1 for n in nodes.values() if n["status"] == "activo")
        blocks  = sum(1 for e in events if e["type"] == "block")
        reports = sum(1 for e in events if e["type"] == "report")

    return jsonify({
        "server":        "SDN Controlador",
        "version":       "1.0.0",
        "time":          now_iso(),
        "nodes_total":   len(nodes),
        "nodes_active":  active,
        "rules_total":   len(rules),
        "events_total":  len(events),
        "events_blocks": blocks,
        "events_reports":reports,
    }), 200


# ── Motor de reglas embebido (para listeners de tráfico) ─────────────────────
#
#  Permite que el SERVIDOR reciba tráfico UDP/TCP en los puertos de prueba
#  y aplique las reglas, sin necesitar que los nodos cliente tengan el
#  firewall abierto. Los nodos envían tráfico SALIENTE al servidor
#  (sin restricciones de firewall) y el servidor registra el resultado.

TRAFFIC_PORTS = [5001, 5002, 5003, 6000, 6001, 6002,
                 7000, 7700, 8000, 8080, 8081, 9000, 9999]

MATCH_FIELDS = ["ip_src","ip_dst","protocol","port_src","port_dst","ingress","mac_src","mac_dst"]

def _srv_priority_key(rule):
    p = rule.get("priority", "Baja")
    try:
        return -int(p)
    except (ValueError, TypeError):
        return {"Alta": -100, "Media": -50, "Baja": -10}.get(str(p), -10)

def _field_matches(field, rule_val, packet_val):
    if rule_val in ("*", "", None):
        return True
    if field in ("ip_src", "ip_dst"):
        if str(rule_val).endswith("*"):
            return str(packet_val).startswith(str(rule_val)[:-1])
        if "/" in str(rule_val):
            try:
                return ipaddress.ip_address(packet_val) in ipaddress.ip_network(rule_val, strict=False)
            except Exception:
                pass
        return str(rule_val).lower() == str(packet_val).lower()
    if field in ("port_src", "port_dst"):
        if "-" in str(rule_val):
            try:
                lo, hi = str(rule_val).split("-", 1)
                return int(lo) <= int(packet_val) <= int(hi)
            except Exception:
                pass
        try:
            return int(rule_val) == int(packet_val)
        except Exception:
            return str(rule_val) == str(packet_val)
    if field in ("mac_src", "mac_dst"):
        return str(rule_val).lower() == str(packet_val).lower()
    if str(rule_val).endswith("*"):
        return str(packet_val).lower().startswith(str(rule_val)[:-1].lower())
    return str(rule_val).lower() == str(packet_val).lower()

def _evaluate(packet):
    with _lock:
        current_rules = list(rules)
    sorted_rules = sorted(current_rules, key=_srv_priority_key)
    for rule in sorted_rules:
        m = rule.get("match", {})
        if all(_field_matches(f, m.get(f, "*"), packet.get(f, "")) for f in MATCH_FIELDS):
            return rule
    return None

def _apply_and_log(rule, packet):
    action  = rule["action"] if rule else "forward"
    name    = rule["name"]   if rule else "(sin regla — forward por defecto)"
    src = f"{packet.get('ip_src')}:{packet.get('port_src')}"
    dst = f"{packet.get('ip_dst')}:{packet.get('port_dst')}"
    proto = packet.get("protocol", "?")

    detail = {
        "ip_src":      packet.get("ip_src"),
        "ip_dst":      packet.get("ip_dst"),
        "protocol":    proto,
        "port_src":    packet.get("port_src"),
        "port_dst":    packet.get("port_dst"),
        "packet_size": packet.get("size", 0),
    }

    if action == "forward":
        logger.info(f"[TRAFFIC] PERMITIDO | regla='{name}' | {src} → {dst} [{proto}]")
    elif action == "drop":
        logger.warning(f"[TRAFFIC] BLOQUEADO | regla='{name}' | {src} → {dst} [{proto}]")
        _store_event("block", rule, detail)
    elif action == "report":
        logger.warning(f"[TRAFFIC] REPORTADO | regla='{name}' | {src} → {dst} [{proto}]")
        _store_event("report", rule, detail)

    return action

def _store_event(etype, rule, detail):
    with _lock:
        rule_id   = rule.get("id")   if rule else None
        rule_name = rule.get("name") if rule else ""
        if rule_id:
            r = next((x for x in rules if x["id"] == rule_id), None)
            if r:
                r["packets"] += 1
                r["bytes"]   += int(detail.get("packet_size", 0))
                save_rules()
        event = {
            "id":        str(uuid.uuid4())[:8],
            "node_id":   "server-listener",
            "node_name": "servidor",
            "type":      etype,
            "rule_id":   rule_id,
            "rule_name": rule_name,
            "detail":    detail,
            "timestamp": now_iso(),
        }
        events.append(event)
        if len(events) > MAX_EVENTS:
            del events[0]

def _handle_traffic_packet(ip_src, port_src, ip_dst, port_dst, proto, data):
    packet = {
        "ip_src":   ip_src,
        "ip_dst":   ip_dst,
        "protocol": proto,
        "port_src": str(port_src),
        "port_dst": str(port_dst),
        "ingress":  "*",
        "mac_src":  "*",
        "mac_dst":  "*",
        "size":     len(data),
        "payload":  data.decode("utf-8", errors="replace")[:200],
    }
    rule = _evaluate(packet)
    _apply_and_log(rule, packet)

def _udp_listener(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        logger.info(f"[TRAFFIC] Escuchando UDP en 0.0.0.0:{port}")
        my_ip = socket.gethostbyname(socket.gethostname())
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                _handle_traffic_packet(addr[0], addr[1], my_ip, port, "UDP", data)
            except Exception as e:
                logger.error(f"[TRAFFIC] Error UDP:{port}: {e}")
    except Exception as e:
        logger.error(f"[TRAFFIC] No se pudo abrir UDP:{port}: {e}")

def _tcp_handler(conn, addr, port):
    try:
        data = conn.recv(4096)
        my_ip = socket.gethostbyname(socket.gethostname())
        if data:
            _handle_traffic_packet(addr[0], addr[1], my_ip, port, "TCP", data)
        resp = json.dumps({"status": "ok", "port": port}).encode()
        conn.sendall(resp)
    except Exception as e:
        logger.error(f"[TRAFFIC] Error TCP:{port} desde {addr}: {e}")
    finally:
        conn.close()

def _tcp_listener(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(10)
        logger.info(f"[TRAFFIC] Escuchando TCP en 0.0.0.0:{port}")
        while True:
            try:
                conn, addr = sock.accept()
                threading.Thread(target=_tcp_handler, args=(conn, addr, port), daemon=True).start()
            except Exception as e:
                logger.error(f"[TRAFFIC] Error accept TCP:{port}: {e}")
    except Exception as e:
        logger.error(f"[TRAFFIC] No se pudo abrir TCP:{port}: {e}")

def start_traffic_listeners():
    """Inicia un listener UDP + TCP por cada puerto de prueba."""
    for port in TRAFFIC_PORTS:
        threading.Thread(target=_udp_listener, args=(port,), daemon=True, name=f"srv-udp-{port}").start()
        threading.Thread(target=_tcp_listener, args=(port,), daemon=True, name=f"srv-tcp-{port}").start()
    logger.info(f"[TRAFFIC] Listeners activos en {len(TRAFFIC_PORTS)} puertos: {TRAFFIC_PORTS}")


# ── Arranque ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_rules()

    # Iniciar hilo de monitoreo de nodos en segundo plano
    monitor_thread = threading.Thread(target=monitor_nodes, daemon=True)
    monitor_thread.start()

    # Iniciar listeners de tráfico de prueba
    start_traffic_listeners()

    logger.info("=" * 60)
    logger.info("  SERVIDOR CONTROLADOR SDN iniciando...")
    logger.info(f"  Escuchando en: http://{HOST}:{PORT}")
    logger.info(f"  Reglas cargadas: {len(rules)}")
    logger.info(f"  Timeout de nodos: {NODE_TIMEOUT_SEC}s")
    logger.info(f"  Log: {log_file}")
    logger.info("=" * 60)

    app.run(host=HOST, port=PORT, debug=False)
