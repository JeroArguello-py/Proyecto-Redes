# =============================================================================
#  validacion_lan.py  —  Proyecto Redes/
#
#  Fase 7 — Validación Experimental en LAN
#  Universidad del Rosario — Proyecto Final Redes de Computadores
#
#  Ejecuta las 5 pruebas requeridas contra todos los nodos online y
#  genera un reporte de resultados con timestamp.
#
#  Uso:
#    python validacion_lan.py            ← valida todos los nodos online
#    python validacion_lan.py --nodo B   ← valida solo un nodo
# =============================================================================

import requests
import subprocess
import sys
import os
import time
import json
import argparse
from datetime import datetime

SERVER    = "http://10.23.36.87:5000"
GENERATOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generador", "generator.py")

# ── Colores ────────────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"; BOLD  = "\033[1m"
    GREEN  = "\033[92m"; RED   = "\033[91m"
    YELLOW = "\033[93m"; CYAN  = "\033[96m"
    BLUE   = "\033[94m"; GRAY  = "\033[90m"

def c(text, color): return f"{color}{text}{C.RESET}"

# ── Helpers API ────────────────────────────────────────────────────────────────

def get_rules_list():
    r = requests.get(f"{SERVER}/rules", timeout=5)
    d = r.json()
    return d.get("rules", d) if isinstance(d, dict) else d

def clear_rules():
    for rule in get_rules_list():
        requests.delete(f"{SERVER}/rules/{rule['id']}", timeout=5)

def add_rule(name, priority, action, match):
    base = {"ip_src":"*","ip_dst":"*","protocol":"*","port_src":"*",
            "port_dst":"*","ingress":"*","mac_src":"*","mac_dst":"*"}
    base.update(match)
    r = requests.post(f"{SERVER}/rules", json={
        "name": name, "priority": priority, "action": action, "match": base
    }, timeout=5)
    return r.status_code == 201

def get_events_since(timestamp):
    r = requests.get(f"{SERVER}/events", timeout=5)
    d = r.json()
    events = d.get("events", d) if isinstance(d, dict) else d
    if isinstance(events, dict):
        events = list(events.values())
    return [e for e in events
            if e.get("timestamp","") >= timestamp]

def get_nodes_online():
    r = requests.get(f"{SERVER}/nodes", timeout=5)
    d = r.json()
    nodes = d.get("nodes", d)
    if isinstance(nodes, dict):
        nodes = list(nodes.values())
    return [n for n in nodes if n.get("status") in ("online","activo")]

def wait_client(seconds=7):
    print(c(f"    ⏳ Esperando {seconds}s para sincronización de reglas...", C.GRAY))
    time.sleep(seconds)

def run_gen(ip, port, proto, count, interval, msg):
    cmd = [sys.executable, GENERATOR,
           "--ip", ip, "--port", str(port), "--proto", proto,
           "--count", str(count), "--interval", str(interval), "--msg", msg]
    subprocess.run(cmd, capture_output=True)

# ── Pruebas individuales ───────────────────────────────────────────────────────

def prueba_permitir_udp(nodo_ip, nodo_nombre):
    """Prueba 1: Regla que PERMITE tráfico UDP hacia puerto autorizado."""
    clear_rules()
    add_rule(f"[{nodo_nombre}] Permitir UDP 9000", "Alta", "forward",
             {"ip_dst": nodo_ip, "protocol": "UDP", "port_dst": "9000"})
    wait_client()
    t0 = datetime.utcnow().isoformat()
    run_gen(nodo_ip, 9000, "UDP", 8, 0.3, "validacion_permitir_udp")
    time.sleep(2)
    return {"prueba": "1 — Permitir UDP puerto autorizado",
            "regla": "forward | UDP | port_dst=9000",
            "esperado": "PERMITIDO × 8",
            "timestamp": t0}

def prueba_bloquear_puerto(nodo_ip, nodo_nombre):
    """Prueba 2: Regla que BLOQUEA tráfico UDP hacia puerto definido."""
    clear_rules()
    add_rule(f"[{nodo_nombre}] Bloquear UDP puerto 9000", "Alta", "drop",
             {"protocol": "UDP", "port_dst": "9000"})
    wait_client()
    t0 = datetime.utcnow().isoformat()
    run_gen(nodo_ip, 9000, "UDP", 8, 0.3, "validacion_bloquear_puerto")
    time.sleep(2)
    return {"prueba": "2 — Bloquear UDP hacia puerto definido",
            "regla": "drop | UDP | port_dst=9000",
            "esperado": "BLOQUEADO × 8",
            "timestamp": t0}

def prueba_bloquear_ip(nodo_ip, nodo_nombre):
    """Prueba 3: Regla que BLOQUEA por dirección IP origen."""
    clear_rules()
    add_rule(f"[{nodo_nombre}] Bloquear IP servidor", "Alta", "drop",
             {"ip_src": "10.23.36.87", "ip_dst": nodo_ip, "protocol": "UDP"})
    wait_client()
    t0 = datetime.utcnow().isoformat()
    run_gen(nodo_ip, 9000, "UDP", 8, 0.3, "validacion_bloquear_ip")
    time.sleep(2)
    return {"prueba": "3 — Bloquear por IP origen",
            "regla": "drop | ip_src=10.23.36.87 | UDP",
            "esperado": "BLOQUEADO × 8",
            "timestamp": t0}

def prueba_reportar(nodo_ip, nodo_nombre):
    """Prueba 4: Regla que REPORTA/ALERTA al controlador."""
    clear_rules()
    add_rule(f"[{nodo_nombre}] Reportar IP sospechosa", "Alta", "report",
             {"ip_src": "10.23.36.87", "ip_dst": nodo_ip, "protocol": "UDP"})
    wait_client()
    t0 = datetime.utcnow().isoformat()
    run_gen(nodo_ip, 9000, "UDP", 6, 0.4, "validacion_reportar")
    time.sleep(3)
    eventos = get_events_since(t0)
    reportes = [e for e in eventos if e.get("type") in ("report","REPORT")]
    return {"prueba": "4 — Reportar/alertar al controlador",
            "regla": "report | ip_src=10.23.36.87 | UDP",
            "esperado": "REPORTADO × 6 + eventos en servidor",
            "eventos_recibidos": len(reportes),
            "timestamp": t0}

def prueba_conflicto(nodo_ip, nodo_nombre):
    """Prueba 5: Conflicto entre dos reglas resuelto por prioridad."""
    resultados = []

    # Fase A: DROP Alta gana sobre FORWARD Baja
    clear_rules()
    add_rule(f"[{nodo_nombre}] Conflicto DROP Alta",    "Alta", "drop",
             {"protocol": "UDP", "port_dst": "9000"})
    add_rule(f"[{nodo_nombre}] Conflicto FORWARD Baja", "Baja", "forward",
             {"protocol": "UDP", "port_dst": "9000"})
    wait_client()
    t0 = datetime.utcnow().isoformat()
    run_gen(nodo_ip, 9000, "UDP", 5, 0.4, "conflicto_faseA")
    time.sleep(2)
    resultados.append("Fase A: DROP(Alta) vs FORWARD(Baja) → esperado BLOQUEADO × 5")

    # Fase B: FORWARD Alta gana sobre DROP Baja
    clear_rules()
    add_rule(f"[{nodo_nombre}] Conflicto FORWARD Alta", "Alta", "forward",
             {"protocol": "UDP", "port_dst": "9000"})
    add_rule(f"[{nodo_nombre}] Conflicto DROP Baja",    "Baja", "drop",
             {"protocol": "UDP", "port_dst": "9000"})
    wait_client()
    run_gen(nodo_ip, 9000, "UDP", 5, 0.4, "conflicto_faseB")
    time.sleep(2)
    resultados.append("Fase B: FORWARD(Alta) vs DROP(Baja) → esperado PERMITIDO × 5")

    return {"prueba": "5 — Conflicto resuelto por prioridad",
            "regla": "DROP vs FORWARD con prioridades inversas",
            "esperado": "Fase A: BLOQUEADO × 5 | Fase B: PERMITIDO × 5",
            "fases": resultados,
            "timestamp": t0}

# ── Validación de un nodo ──────────────────────────────────────────────────────

PRUEBAS = [
    prueba_permitir_udp,
    prueba_bloquear_puerto,
    prueba_bloquear_ip,
    prueba_reportar,
    prueba_conflicto,
]

def validar_nodo(nodo):
    ip     = nodo["ip"]
    nombre = nodo["name"]

    print()
    print(c("╔══════════════════════════════════════════════════════════╗", C.BOLD + C.BLUE))
    print(c(f"║  VALIDANDO: {nombre:<20} ({ip})         ║", C.BOLD + C.BLUE))
    print(c("╚══════════════════════════════════════════════════════════╝", C.BOLD + C.BLUE))

    resultados = []
    for i, prueba_fn in enumerate(PRUEBAS, 1):
        print(c(f"\n  [{i}/5] {prueba_fn.__doc__.strip()}", C.CYAN))
        try:
            res = prueba_fn(ip, nombre)
            res["nodo"]   = nombre
            res["nodo_ip"]= ip
            res["ok"]     = True
            resultados.append(res)
            print(c(f"        ✓ Enviado | Esperado: {res['esperado']}", C.GREEN))
            if "eventos_recibidos" in res:
                color = C.GREEN if res["eventos_recibidos"] > 0 else C.YELLOW
                print(c(f"        📡 Eventos recibidos en servidor: {res['eventos_recibidos']}", color))
        except Exception as e:
            print(c(f"        ✗ Error: {e}", C.RED))
            resultados.append({"prueba": f"Prueba {i}", "nodo": nombre, "ok": False, "error": str(e)})
        time.sleep(2)

    clear_rules()
    print(c(f"\n  ✅ Validación de {nombre} completada. Reglas limpiadas.", C.GREEN))
    return resultados

# ── Reporte final ──────────────────────────────────────────────────────────────

def generar_reporte(todos_resultados):
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"reporte_fase7_{ts}.json")

    reporte = {
        "fase":        "Fase 7 — Validación Experimental en LAN",
        "proyecto":    "SDN Firewall — Universidad del Rosario",
        "servidor":    SERVER,
        "timestamp":   datetime.now().isoformat(),
        "total_nodos": len(set(r["nodo"] for r in todos_resultados)),
        "total_pruebas": len(todos_resultados),
        "resultados":  todos_resultados,
    }

    with open(out, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    return out

def imprimir_resumen(todos_resultados):
    print()
    print(c("=" * 62, C.BOLD + C.GREEN))
    print(c("  RESUMEN — FASE 7: VALIDACIÓN EXPERIMENTAL EN LAN", C.BOLD + C.GREEN))
    print(c("=" * 62, C.BOLD + C.GREEN))

    nodos = {}
    for r in todos_resultados:
        n = r.get("nodo","?")
        if n not in nodos: nodos[n] = []
        nodos[n].append(r)

    for nodo, pruebas in nodos.items():
        print(c(f"\n  📡 {nodo}", C.BOLD + C.CYAN))
        for p in pruebas:
            estado = c("✓", C.GREEN) if p.get("ok") else c("✗", C.RED)
            print(f"    {estado} {p['prueba']}")
            print(c(f"       Esperado : {p.get('esperado','?')}", C.GRAY))
            if "eventos_recibidos" in p:
                print(c(f"       Eventos  : {p['eventos_recibidos']}", C.YELLOW))

    print()
    print(c(f"  Total nodos validados : {len(nodos)}", C.BOLD))
    print(c(f"  Total pruebas ejecutadas: {len(todos_resultados)}", C.BOLD))
    print(c("=" * 62, C.BOLD + C.GREEN))

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.name == "nt":
        os.system("color")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nodo", default=None, help="Nombre del nodo (B, C, D) o vacío para todos")
    args = parser.parse_args()

    print(c("\n  FASE 7 — VALIDACIÓN EXPERIMENTAL EN LAN SDN", C.BOLD + C.BLUE))
    print(c(f"  Servidor: {SERVER}", C.GRAY))
    print(c(f"  Inicio  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", C.GRAY))

    # Obtener nodos
    try:
        nodos_online = get_nodes_online()
    except Exception as e:
        print(c(f"  [ERROR] No se pudo conectar al servidor: {e}", C.RED))
        sys.exit(1)

    if not nodos_online:
        print(c("  No hay nodos online. Verifica que los clientes estén corriendo.", C.RED))
        sys.exit(1)

    # Filtrar por nodo si se especificó
    NODOS_MAP = {"B":"nodo-laptop-B","C":"nodo-laptop-C","D":"nodo-laptop-D"}
    if args.nodo:
        nombre_buscado = NODOS_MAP.get(args.nodo.upper(), args.nodo)
        nodos_online = [n for n in nodos_online if n["name"] == nombre_buscado]
        if not nodos_online:
            print(c(f"  Nodo '{args.nodo}' no está online.", C.RED))
            sys.exit(1)

    print(c(f"  Nodos a validar: {len(nodos_online)}", C.BOLD))
    for n in nodos_online:
        print(c(f"    • {n['name']}  ({n['ip']})", C.CYAN))

    input(c("\n  Presiona ENTER para comenzar la validación...", C.BOLD))

    # Ejecutar validación
    todos_resultados = []
    for nodo in nodos_online:
        resultados_nodo = validar_nodo(nodo)
        todos_resultados.extend(resultados_nodo)
        if len(nodos_online) > 1:
            print(c("  Pausa entre nodos (5s)...", C.GRAY))
            time.sleep(5)

    # Resumen y reporte
    imprimir_resumen(todos_resultados)
    ruta = generar_reporte(todos_resultados)
    print(c(f"\n  📄 Reporte guardado en: {os.path.basename(ruta)}\n", C.YELLOW))
