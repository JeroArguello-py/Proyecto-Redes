# =============================================================================
#  rule_engine.py  —  cliente/
#
#  Motor de reglas SDN — Fase 5
#  Universidad del Rosario — Proyecto Final Redes de Computadores
#
#  Responsabilidades:
#    1. field_matches()    — coincidencia individual de un campo
#    2. evaluate_packet()  — seleccionar la regla ganadora (primera coincidencia
#                            en orden de prioridad Alta > Media > Baja)
#    3. apply_action()     — ejecutar la acción: forward, drop o report
#
#  Campos de coincidencia soportados:
#    ip_src / ip_dst   → valor exacto, wildcard (*), prefijo (192.168.*),
#                        o notación CIDR (192.168.1.0/24)
#    protocol          → UDP, TCP, ICMP o * (cualquiera)
#    port_src / port_dst → número exacto, wildcard (*) o rango (8000-9000)
#    ingress           → nombre de interfaz de entrada o *
#    mac_src / mac_dst → dirección MAC exacta (AA:BB:CC:DD:EE:FF) o *
# =============================================================================

import ipaddress
import logging

logger = logging.getLogger("SDN-Client")

# ── Orden de prioridad ────────────────────────────────────────────────────────

PRIORITY_ORDER = {"Alta": 1, "Media": 2, "Baja": 3}

def _priority_key(rule):
    """
    Clave de ordenamiento. Soporta texto (Alta/Media/Baja) y números enteros.
    Mayor número = mayor prioridad → retorna negativo para sorted() ascendente.
    """
    p = rule.get("priority", "Baja")
    try:
        return -int(p)
    except (ValueError, TypeError):
        return {"Alta": -100, "Media": -50, "Baja": -10}.get(str(p), -10)


# ── Coincidencia de campos individuales ──────────────────────────────────────

def _match_ip(rule_val, packet_val):
    """
    Coincidencia de dirección IP.
    Soporta:
      *              → cualquier IP
      192.168.1.*    → wildcard de prefijo
      192.168.1.0/24 → subred CIDR
      192.168.1.5    → IP exacta
    """
    if rule_val in ("*", ""):
        return True

    # Wildcard de prefijo: "192.168.*"
    if rule_val.endswith("*"):
        prefix = rule_val[:-1]
        return str(packet_val).startswith(prefix)

    # Notación CIDR: "10.0.0.0/8"
    if "/" in rule_val:
        try:
            network = ipaddress.ip_network(rule_val, strict=False)
            return ipaddress.ip_address(packet_val) in network
        except ValueError:
            pass

    # IP exacta
    return str(rule_val).lower() == str(packet_val).lower()


def _match_port(rule_val, packet_val):
    """
    Coincidencia de puerto.
    Soporta:
      *         → cualquier puerto
      9000      → puerto exacto
      8000-9000 → rango de puertos (inclusivo)
    """
    if rule_val in ("*", ""):
        return True

    # Rango: "8000-9000"
    if "-" in str(rule_val):
        try:
            lo, hi = rule_val.split("-", 1)
            return int(lo) <= int(packet_val) <= int(hi)
        except (ValueError, TypeError):
            pass

    # Puerto exacto
    try:
        return int(rule_val) == int(packet_val)
    except (ValueError, TypeError):
        return str(rule_val) == str(packet_val)


def _match_mac(rule_val, packet_val):
    """
    Coincidencia de dirección MAC (insensible a mayúsculas).
      *                 → cualquier MAC
      AA:BB:CC:DD:EE:FF → MAC exacta
    """
    if rule_val in ("*", ""):
        return True
    return str(rule_val).lower() == str(packet_val).lower()


def _match_generic(rule_val, packet_val):
    """
    Coincidencia genérica (protocolo, ingress, etc.).
      * → cualquier valor
      valor exacto (insensible a mayúsculas)
    """
    if rule_val in ("*", ""):
        return True
    if rule_val.endswith("*"):
        prefix = rule_val[:-1]
        return str(packet_val).lower().startswith(prefix.lower())
    return str(rule_val).lower() == str(packet_val).lower()


def field_matches(field, rule_val, packet_val):
    """
    Despacha la coincidencia al comparador correcto según el campo.

    Parámetros:
      field      — nombre del campo ("ip_src", "port_dst", "mac_src", ...)
      rule_val   — valor definido en la regla (puede ser "*")
      packet_val — valor extraído del paquete
    """
    if field in ("ip_src", "ip_dst"):
        return _match_ip(rule_val, packet_val)
    elif field in ("port_src", "port_dst"):
        return _match_port(rule_val, packet_val)
    elif field in ("mac_src", "mac_dst"):
        return _match_mac(rule_val, packet_val)
    else:
        return _match_generic(rule_val, packet_val)


# ── Evaluación de paquete contra tabla de reglas ──────────────────────────────

# Campos que se evalúan en cada regla, en orden
MATCH_FIELDS = [
    "ip_src", "ip_dst",
    "protocol",
    "port_src", "port_dst",
    "ingress",
    "mac_src", "mac_dst",
]


def evaluate_packet(packet, rules):
    """
    Selecciona la regla que aplica al paquete usando semántica first-match
    con ordenación por prioridad (Alta > Media > Baja).

    Parámetros:
      packet — dict con campos del paquete:
               {ip_src, ip_dst, protocol, port_src, port_dst,
                ingress, mac_src, mac_dst, size, payload}
      rules  — lista de reglas activas (copia reciente de la tabla)

    Retorna:
      La regla (dict) que coincide primero, o None si ninguna aplica.
      Sin coincidencia → el cliente aplica 'forward' por defecto.
    """
    sorted_rules = sorted(rules, key=_priority_key)

    for rule in sorted_rules:
        m = rule.get("match", {})
        match = all(
            field_matches(f, m.get(f, "*"), packet.get(f, ""))
            for f in MATCH_FIELDS
        )
        if match:
            return rule

    return None


# ── Aplicación de acción ──────────────────────────────────────────────────────

def apply_action(rule, packet, stats, send_event_fn):
    """
    Ejecuta la acción definida por la regla y actualiza las estadísticas.

    Acciones:
      forward → PERMITIDO  — el paquete pasa normalmente
      drop    → BLOQUEADO  — el paquete se descarta
      report  → REPORTADO  — el paquete pasa pero se alerta al controlador

    Parámetros:
      rule          — regla ganadora (o None si no hubo match)
      packet        — dict del paquete
      stats         — dict de contadores compartido con el cliente
      send_event_fn — función callable para reportar eventos al servidor

    Retorna:
      str — acción aplicada: "forward", "drop" o "report"
    """
    action = rule["action"] if rule else "forward"
    name   = rule["name"]   if rule else "(sin regla — forward por defecto)"

    stats["packets_received"] += 1

    # Detalle del paquete para el evento
    detail = {
        "ip_src":          packet.get("ip_src"),
        "ip_dst":          packet.get("ip_dst"),
        "protocol":        packet.get("protocol"),
        "port_src":        packet.get("port_src"),
        "port_dst":        packet.get("port_dst"),
        "ingress":         packet.get("ingress", "*"),
        "mac_src":         packet.get("mac_src", "*"),
        "mac_dst":         packet.get("mac_dst", "*"),
        "packet_size":     packet.get("size", 0),
        "payload_preview": packet.get("payload", "")[:80],
    }

    src = f"{packet.get('ip_src')}:{packet.get('port_src')}"
    dst = f"{packet.get('ip_dst')}:{packet.get('port_dst')}"
    proto = packet.get("protocol", "?")

    if action == "forward":
        stats["packets_forwarded"] += 1
        logger.info(
            f"PERMITIDO | regla='{name}' | {src} → {dst} [{proto}]"
        )

    elif action == "drop":
        stats["packets_dropped"] += 1
        logger.warning(
            f"BLOQUEADO | regla='{name}' | {src} → {dst} [{proto}]"
        )
        send_event_fn("block", rule, detail)

    elif action == "report":
        stats["packets_reported"] += 1
        logger.warning(
            f"REPORTADO | regla='{name}' | {src} → {dst} [{proto}]"
        )
        send_event_fn("report", rule, detail)

    else:
        # Acción desconocida → forward por seguridad
        stats["packets_forwarded"] += 1
        logger.warning(
            f"ACCIÓN DESCONOCIDA '{action}' | regla='{name}' | aplicando forward"
        )

    return action
