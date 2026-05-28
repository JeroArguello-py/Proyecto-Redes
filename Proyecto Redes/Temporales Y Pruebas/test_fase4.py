# =============================================================================
#  test_fase4.py  —  Proyecto Redes/
#
#  Orquestador completo de la Fase 4 — Generador de Tráfico
#  Ejecuta las 4 pruebas de forma aislada: cada una limpia las reglas
#  y carga solo las suyas antes de enviar tráfico.
#
#  Uso:
#    python test_fase4.py                        ← menú interactivo (Nodo B por defecto)
#    python test_fase4.py --all                  ← todas las pruebas (Nodo B)
#    python test_fase4.py --nodo C               ← menú apuntando a Nodo C
#    python test_fase4.py --nodo C --all         ← todas las pruebas hacia Nodo C
#    python test_fase4.py --nodo all             ← prueba TODOS los nodos online
#    python test_fase4.py --ip 10.23.33.23       ← IP manual
# =============================================================================

import requests
import subprocess
import sys
import time
import os
import argparse

NODOS = {
    "B": "10.23.41.58",
    "C": "10.23.61.50",
    "D": "10.23.41.103",
}

SERVER = "http://10.23.36.87:5000"

# Parsear argumentos antes de definir CLIENTE_IP
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--nodo", default="B")
_parser.add_argument("--ip",   default=None)
_parser.add_argument("--all",  action="store_true")
_args, _ = _parser.parse_known_args()

CLIENTE_IP = _args.ip if _args.ip else NODOS.get(_args.nodo.upper(), NODOS["B"])
MODO_ALL_NODOS = _args.nodo.lower() == "all"
GENERATOR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generador", "generator.py")

# ── Colores ────────────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    GRAY   = "\033[90m"

def c(text, color):
    return f"{color}{text}{C.RESET}"

# ── Helpers ────────────────────────────────────────────────────────────────────

WILDCARD = {
    "ip_src": "*", "ip_dst": "*", "protocol": "*",
    "port_src": "*", "port_dst": "*",
    "ingress": "*", "mac_src": "*", "mac_dst": "*"
}

def make_match(**kwargs):
    m = WILDCARD.copy()
    m.update(kwargs)
    return m

def clear_rules():
    """Elimina TODAS las reglas del servidor."""
    r = requests.get(f"{SERVER}/rules")
    r.raise_for_status()
    rules = r.json()["rules"]
    for rule in rules:
        requests.delete(f"{SERVER}/rules/{rule['id']}")
    print(c(f"  ✓ {len(rules)} regla(s) eliminadas", C.GRAY))

def add_rule(name, priority, action, match):
    r = requests.post(f"{SERVER}/rules", json={
        "name": name, "priority": priority,
        "action": action, "match": match
    })
    if r.status_code == 201:
        print(c(f"  ✓ [{priority:5}] {name} → {action}", C.GREEN))
    else:
        print(c(f"  [ERROR] No se pudo crear regla: {r.text}", C.RED))

def show_rules():
    r = requests.get(f"{SERVER}/rules")
    rules = r.json()["rules"]
    print(c("\n  Reglas activas:", C.BOLD))
    for rule in rules:
        print(f"    [{c(rule['priority'],C.YELLOW):14}] {rule['name']} → {c(rule['action'],C.CYAN)}")

def show_events():
    r = requests.get(f"{SERVER}/events")
    events_data = r.json()
    # Acepta lista directa o dict con clave "events"
    if isinstance(events_data, dict):
        events_data = events_data.get("events", [])
    reports = [e for e in events_data if e.get("type") in ("report", "REPORT", "alerta")][-8:]
    if reports:
        print(c("\n  Eventos REPORT recibidos por el servidor:", C.BOLD))
        for e in reports:
            ts   = e.get("timestamp", "")[:19]
            node = e.get("node_name", e.get("node_id", "?"))
            det  = e.get("detail", str(e))
            print(f"    {c(ts, C.GRAY)}  nodo={c(node, C.CYAN)}  {det}")
    else:
        print(c("\n  ⚠  No hay eventos de reporte registrados aún.", C.YELLOW))
        print(c("     Verifica que el cliente esté enviando eventos al endpoint /events", C.GRAY))

def run_generator(ip, port, proto, count, interval, msg):
    """Lanza el generador como subproceso."""
    cmd = [
        sys.executable, GENERATOR,
        "--ip", ip, "--port", str(port), "--proto", proto,
        "--count", str(count), "--interval", str(interval),
        "--msg", msg
    ]
    subprocess.run(cmd)

def wait_for_client(seconds=6):
    """Espera a que el cliente haga poll y cargue las nuevas reglas."""
    print(c(f"\n  ⏳ Esperando {seconds}s para que el cliente actualice las reglas...", C.GRAY))
    for i in range(seconds, 0, -1):
        print(c(f"     {i}s...", C.GRAY), end="\r")
        time.sleep(1)
    print(c("  ✓ Cliente listo con las reglas nuevas.            ", C.GREEN))

def pause(msg):
    print()
    print(c(f"  👉  {msg}", C.BOLD))
    input(c("  Presiona ENTER cuando estés listo para continuar...", C.CYAN))

def header(num, titulo):
    print()
    print(c("=" * 62, C.BOLD + C.BLUE))
    print(c(f"  PRUEBA {num} — {titulo}", C.BOLD + C.BLUE))
    print(c("=" * 62, C.BOLD + C.BLUE))

# ── Pruebas ────────────────────────────────────────────────────────────────────

def test1_permitir():
    header(1, "PERMITIR tráfico UDP al puerto 9000")
    print(c("  Regla: forward | Alta | UDP → puerto 9000", C.GRAY))
    print()

    clear_rules()
    add_rule("Prueba1 Permitir UDP 9000", "Alta", "forward",
             make_match(protocol="UDP", port_dst="9000"))
    show_rules()
    wait_for_client()

    pause("Observa la consola de Nodo B — se enviarán 8 paquetes UDP al puerto 9000")
    run_generator(CLIENTE_IP, 9000, "UDP", 8, 0.4, "paquete_permitido_prueba1")

    print()
    print(c("  ✅ Esperado en Nodo B: PERMITIDO × 8 (regla 'Prueba1 Permitir UDP 9000')", C.GREEN))


def test2_bloquear_ip():
    header(2, "BLOQUEAR por IP origen")
    print(c("  Regla: drop | Alta | ip_src=10.23.36.87 | UDP → 9000", C.GRAY))
    print()

    clear_rules()
    add_rule("Prueba2 Bloquear IP origen", "Alta", "drop",
             make_match(ip_src="10.23.36.87", protocol="UDP", port_dst="9000"))
    show_rules()
    wait_for_client()

    pause("Observa la consola de Nodo B — se enviarán 8 paquetes desde este equipo (10.23.36.87)")
    run_generator(CLIENTE_IP, 9000, "UDP", 8, 0.4, "paquete_bloqueado_prueba2")

    print()
    print(c("  ✅ Esperado en Nodo B: BLOQUEADO × 8 (regla 'Prueba2 Bloquear IP origen')", C.RED))


def test2b_bloquear_puerto():
    header("2B", "BLOQUEAR tráfico UDP hacia puerto definido")
    print(c("  Regla: drop | Alta | protocolo=UDP | port_dst=9000 (cualquier IP)", C.GRAY))
    print()

    clear_rules()
    add_rule("Prueba2B Bloquear UDP puerto 9000", "Alta", "drop",
             make_match(protocol="UDP", port_dst="9000"))
    show_rules()
    wait_for_client()

    pause("Observa el nodo — se enviarán 8 paquetes UDP al puerto 9000 desde cualquier IP")
    run_generator(CLIENTE_IP, 9000, "UDP", 8, 0.4, "paquete_bloqueado_por_puerto")

    print()
    print(c("  ✅ Esperado: BLOQUEADO × 8 (regla bloquea TODO UDP al puerto 9000)", C.RED))


def test3_reportar():
    header(3, "REPORTAR IP sospechosa al controlador")
    print(c("  Regla: report | Alta | ip_src=10.23.36.87 | UDP → 9000", C.GRAY))
    print()

    clear_rules()
    add_rule("Prueba3 Reportar IP sospechosa", "Alta", "report",
             make_match(ip_src="10.23.36.87", protocol="UDP", port_dst="9000"))
    show_rules()
    wait_for_client()

    pause("Observa la consola de Nodo B — se enviarán 6 paquetes que deben generar reportes")
    run_generator(CLIENTE_IP, 9000, "UDP", 6, 0.5, "paquete_sospechoso_prueba3")

    print()
    print(c("  ✅ Esperado en Nodo B: REPORTADO × 6", C.YELLOW))
    time.sleep(2)
    print(c("  Verificando eventos en el servidor...", C.GRAY))
    show_events()


def test4_conflicto():
    header(4, "CONFLICTO de prioridad entre reglas opuestas")
    print(c("  Dos reglas compiten por el mismo tráfico UDP → 9000", C.GRAY))
    print()

    # ── FASE A: DROP Alta vs FORWARD Baja ─────────────────────────────────────
    print(c("  ── FASE A: DROP (Alta)  vs  FORWARD (Baja)  →  debe ganar DROP", C.BOLD))
    clear_rules()
    add_rule("Conflicto DROP Alta",     "Alta", "drop",    make_match(protocol="UDP", port_dst="9000"))
    add_rule("Conflicto FORWARD Baja",  "Baja", "forward", make_match(protocol="UDP", port_dst="9000"))
    show_rules()
    wait_for_client()

    pause("FASE A — Nodo B debe mostrar BLOQUEADO (DROP Alta gana sobre FORWARD Baja)")
    run_generator(CLIENTE_IP, 9000, "UDP", 5, 0.5, "conflicto_faseA_debe_bloquear")

    print()
    print(c("  ✅ Esperado FASE A: BLOQUEADO × 5 (DROP Alta gana)", C.RED))
    time.sleep(3)

    # ── FASE B: DROP Baja vs FORWARD Alta ─────────────────────────────────────
    print()
    print(c("  ── FASE B: DROP (Baja)  vs  FORWARD (Alta)  →  debe ganar FORWARD", C.BOLD))
    clear_rules()
    add_rule("Conflicto DROP Baja",     "Baja", "drop",    make_match(protocol="UDP", port_dst="9000"))
    add_rule("Conflicto FORWARD Alta",  "Alta", "forward", make_match(protocol="UDP", port_dst="9000"))
    show_rules()
    wait_for_client()

    pause("FASE B — Nodo B debe mostrar PERMITIDO (FORWARD Alta gana sobre DROP Baja)")
    run_generator(CLIENTE_IP, 9000, "UDP", 5, 0.5, "conflicto_faseB_debe_permitir")

    print()
    print(c("  ✅ Esperado FASE B: PERMITIDO × 5 (FORWARD Alta gana)", C.GREEN))


# ── Menú ───────────────────────────────────────────────────────────────────────

def menu():
    print()
    print(c("╔══════════════════════════════════════════════════════════╗", C.CYAN))
    print(c("║      FASE 4 — PRUEBAS DEL GENERADOR DE TRÁFICO SDN      ║", C.CYAN))
    print(c("╚══════════════════════════════════════════════════════════╝", C.CYAN))
    print(c(f"  Nodo destino: {CLIENTE_IP}", C.YELLOW))
    print()
    print(f"  {c('1', C.YELLOW)}  Prueba 1  — PERMITIR UDP hacia puerto autorizado")
    print(f"  {c('2', C.YELLOW)}  Prueba 2  — BLOQUEAR por IP origen")
    print(f"  {c('6', C.YELLOW)}  Prueba 2B — BLOQUEAR UDP hacia puerto definido")
    print(f"  {c('3', C.YELLOW)}  Prueba 3  — REPORTAR/ALERTAR al controlador")
    print(f"  {c('4', C.YELLOW)}  Prueba 4  — CONFLICTO de prioridad (Fase A y B)")
    print(f"  {c('5', C.YELLOW)}  Ejecutar TODAS las pruebas en secuencia")
    print(f"  {c('0', C.RED  )}  Salir (limpia reglas)")
    print()
    return input(c("  Elige opción: ", C.BOLD)).strip()


def run_all():
    print(c("\n  ▶▶  Ejecutando las 5 pruebas en secuencia...", C.BOLD + C.BLUE))
    test1_permitir()
    time.sleep(3)
    test2_bloquear_ip()
    time.sleep(3)
    test2b_bloquear_puerto()
    time.sleep(3)
    test3_reportar()
    time.sleep(3)
    test4_conflicto()
    print()
    print(c("  Limpiando reglas del servidor...", C.GRAY))
    clear_rules()
    print()
    print(c("=" * 62, C.BOLD + C.GREEN))
    print(c("  🎉  FASE 4 COMPLETA — Todas las pruebas ejecutadas", C.BOLD + C.GREEN))
    print(c("=" * 62, C.BOLD + C.GREEN))
    print()


# ── Punto de entrada ───────────────────────────────────────────────────────────

def get_nodos_online():
    """Consulta el servidor y retorna solo los nodos con status activo/online."""
    try:
        r = requests.get(f"{SERVER}/nodes", timeout=5)
        data = r.json()
        nodes = data.get("nodes", data)
        if isinstance(nodes, dict):
            nodes = list(nodes.values())
        online = [n for n in nodes if n.get("status") in ("online", "activo")]
        return online
    except Exception as e:
        print(c(f"  [ERROR] No se pudo consultar nodos: {e}", C.RED))
        return []


def run_all_nodos():
    """Ejecuta todas las pruebas contra cada nodo online."""
    global CLIENTE_IP
    nodos = get_nodos_online()
    if not nodos:
        print(c("\n  No hay nodos online. Verifica que los clientes estén corriendo.\n", C.RED))
        return

    print(c(f"\n  Nodos online encontrados: {len(nodos)}", C.BOLD + C.CYAN))
    for n in nodos:
        print(c(f"    • {n['name']} — {n['ip']}", C.CYAN))

    for nodo in nodos:
        CLIENTE_IP = nodo["ip"]
        print()
        print(c("=" * 62, C.BOLD + C.BLUE))
        print(c(f"  ▶▶  PRUEBAS → {nodo['name']} ({nodo['ip']})", C.BOLD + C.BLUE))
        print(c("=" * 62, C.BOLD + C.BLUE))
        run_all()
        time.sleep(5)

    print(c("\n  🎉  PRUEBAS COMPLETADAS EN TODOS LOS NODOS\n", C.BOLD + C.GREEN))


if __name__ == "__main__":
    # Habilitar colores en Windows
    if os.name == "nt":
        os.system("color")

    if MODO_ALL_NODOS:
        run_all_nodos()
        sys.exit(0)

    if "--all" in sys.argv:
        run_all()
        sys.exit(0)

    while True:
        op = menu()

        if op == "0":
            print(c("\n  Limpiando reglas...", C.GRAY))
            clear_rules()
            print(c("  ¡Hasta luego!\n", C.CYAN))
            break
        elif op == "1":
            test1_permitir()
        elif op == "2":
            test2_bloquear_ip()
        elif op == "3":
            test3_reportar()
        elif op == "4":
            test4_conflicto()
        elif op == "5":
            run_all()
        elif op == "6":
            test2b_bloquear_puerto()
        else:
            print(c("  Opción no válida.", C.RED))
