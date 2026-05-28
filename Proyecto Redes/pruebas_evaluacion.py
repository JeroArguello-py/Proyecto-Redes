# =============================================================================
#  pruebas_evaluacion.py  —  Proyecto Redes/
#
#  Script de las 10 pruebas oficiales de evaluación SDN Firewall
#  Universidad del Rosario — Proyecto Final Redes de Computadores
#
#  Arquitectura de prueba:
#    • El script (en el servidor) envía tráfico a los nodos cliente reales.
#    • Cada nodo corre client.py que aplica las reglas SDN y reporta al servidor.
#    • Para pruebas que requieren ip_src específico (P6, P10) se imprimen
#      instrucciones para ejecutar el generador desde cada laptop.
#
#  Uso:
#    python pruebas_evaluacion.py            ← menú interactivo
#    python pruebas_evaluacion.py --prueba 2 ← ejecuta solo la prueba 2
#    python pruebas_evaluacion.py --todas    ← ejecuta las 10 pruebas en orden
# =============================================================================

import requests, subprocess, sys, os, time, json, socket, argparse
from datetime import datetime, timezone

# ── Configuración de red ───────────────────────────────────────────────────────
SERVER    = "http://10.23.36.87:5000"
SERVER_IP = "10.23.36.87"
GENERATOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generador", "generator.py")

# IPs de los nodos cliente (data plane)
NODO_A  = "10.23.62.167"   # nodo-laptop-B
NODO_B  = "10.23.41.58"    # nodo-laptop-C
NODO_C  = "10.23.55.191"   # nodo-laptop-D

# Timeout para esperar eventos de los nodos (segundos)
EVENT_TIMEOUT = 40

# ── Colores ────────────────────────────────────────────────────────────────────
class C:
    R="\033[0m"; BOLD="\033[1m"; GREEN="\033[92m"; RED="\033[91m"
    YELLOW="\033[93m"; CYAN="\033[96m"; BLUE="\033[94m"; GRAY="\033[90m"
    ORANGE="\033[38;5;208m"

def c(t, col): return f"{col}{t}{C.R}"

def sep(title="", color=C.BLUE):
    line = "═" * 62
    if title:
        pad = (60 - len(title)) // 2
        print(c(f"╔{line}╗", color))
        print(c(f"║{' '*pad}{title}{' '*(62-pad-len(title))}║", color))
        print(c(f"╚{line}╝", color))
    else:
        print(c(f"{'─'*64}", color))

# ── Helpers API ────────────────────────────────────────────────────────────────
def get_rules():
    r = requests.get(f"{SERVER}/rules", timeout=5).json()
    return r.get("rules", r) if isinstance(r, dict) else r

def clear_rules():
    for rule in get_rules():
        requests.delete(f"{SERVER}/rules/{rule['id']}", timeout=5)
    print(c("  🗑  Reglas limpiadas", C.GRAY))

def add_rule(name, priority, action, **match):
    base = {"ip_src":"*","ip_dst":"*","protocol":"*","port_src":"*",
            "port_dst":"*","ingress":"*","mac_src":"*","mac_dst":"*"}
    base.update(match)
    r = requests.post(f"{SERVER}/rules", json={
        "name": name, "priority": priority, "action": action, "match": base
    }, timeout=5)
    ok = r.status_code == 201
    rid = r.json().get("rule",{}).get("id","?") if ok else "ERR"
    estado = c("✓", C.GREEN) if ok else c("✗ "+str(r.text), C.RED)
    print(f"  {estado} Regla '{name}' | {action.upper()} | prio={priority} | id={rid}")
    return rid

def get_events():
    try:
        r = requests.get(f"{SERVER}/events", timeout=5).json()
        evs = r.get("events", r) if isinstance(r, dict) else r
        if isinstance(evs, dict): evs = list(evs.values())
        return evs or []
    except Exception:
        return []

def get_events_since(ts):
    return [e for e in get_events() if e.get("timestamp","") >= ts]

def show_rules():
    rules = get_rules()
    if not rules:
        print(c("  (tabla vacía)", C.GRAY)); return
    for r in rules:
        m = r.get("match",{})
        ac = c(r['action'].upper(), C.GREEN if r['action']=='forward' else
               C.RED if r['action']=='drop' else C.YELLOW)
        print(f"  • [{r['priority']}] {r['name']}  →  {ac}  "
              f"proto={m.get('protocol','*')} dst_port={m.get('port_dst','*')} "
              f"ip_src={m.get('ip_src','*')} ip_dst={m.get('ip_dst','*')}")

def wait(s=7, msg="Esperando sincronización de reglas con los nodos"):
    print(c(f"  ⏳ {msg} ({s}s)...", C.GRAY))
    time.sleep(s)

# ── Envío de tráfico (servidor → nodo cliente) ─────────────────────────────────
def send(ip, port, proto, count=6, interval=0.5, msg="sdn-test"):
    """Envía tráfico desde el servidor hacia el nodo cliente (ip:port)."""
    print(c(f"  📤 Enviando {count} pkt {proto} → {ip}:{port} ...", C.CYAN))
    result = subprocess.run(
        [sys.executable, GENERATOR,
         "--ip", ip, "--port", str(port), "--proto", proto,
         "--count", str(count), "--interval", str(interval),
         "--msg", msg],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(c(f"  ⚠  generator error: {result.stderr[:120]}", C.YELLOW))

# ── Polling de eventos para verificación automática ───────────────────────────
def poll_events(ts_start, expected_action, expected_count,
                timeout=EVENT_TIMEOUT, node_ip=None):
    """
    Espera hasta `timeout` segundos a que lleguen `expected_count` eventos
    del tipo `expected_action` desde `ts_start`.
    Retorna (encontrados, lista_eventos).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        evs = get_events_since(ts_start)
        if node_ip:
            evs = [e for e in evs if e.get("node_ip") == node_ip
                   or e.get("ip_src") == node_ip]
        matching = [e for e in evs
                    if e.get("type","").lower() in
                       {expected_action.lower(), expected_action.upper()}]
        if len(matching) >= expected_count:
            return matching, evs
        remaining = int(deadline - time.time())
        print(c(f"  ⏳ [{remaining}s] Eventos {expected_action.upper()} recibidos: "
                f"{len(matching)}/{expected_count}", C.GRAY), end="\r")
        time.sleep(1.5)
    print()
    evs = get_events_since(ts_start)
    matching = [e for e in evs
                if e.get("type","").lower() in
                   {expected_action.lower(), expected_action.upper()}]
    return matching, evs

def show_event_result(matching, total_evs, expected_action, expected_count):
    """Muestra cuántos eventos se capturaron vs lo esperado."""
    print()
    got = len(matching)
    col = C.GREEN if got >= expected_count else C.YELLOW if got > 0 else C.RED
    print(c(f"  📊 Eventos {expected_action.upper()} recibidos: {got}/{expected_count}", col))
    for e in matching[:6]:
        ts = e.get("timestamp","")[:19]
        rule = e.get("rule_name", e.get("rule","?"))
        src  = e.get("detail",{}).get("ip_src", e.get("ip_src","?"))
        dst_p= e.get("detail",{}).get("port_dst", e.get("port_dst","?"))
        print(c(f"    [{ts}] regla='{rule}' ip_src={src} port_dst={dst_p}", C.GRAY))

def resultado(esperado, nota=""):
    print()
    print(c(f"  ✅ Resultado esperado: {esperado}", C.GREEN))
    if nota:
        print(c(f"  📋 {nota}", C.GRAY))
    print(c(f"  🌐 Interfaz web: {SERVER}", C.GRAY))

def manual_hint(ip_src, ip_dst, port, proto, count=6):
    """Imprime el comando a ejecutar desde la laptop del nodo ip_src."""
    print(c(f"\n  ⚠️  Ejecuta también desde la laptop {ip_src}:", C.YELLOW))
    print(c(f"  python .\\generator.py --ip {ip_dst} --port {port} "
            f"--proto {proto} --count {count}", C.BOLD))

# ── PRUEBA 1: Registro de nodos ───────────────────────────────────────────────
def prueba_1():
    sep("PRUEBA 1 — Registro de nodos  [2.5 pts]")
    print(c("\n  Verifica que los 3 nodos estén activos y reportando heartbeat.\n", C.CYAN))
    r = requests.get(f"{SERVER}/nodes", timeout=5).json()
    nodos = r.get("nodes", r) if isinstance(r, dict) else r
    if isinstance(nodos, dict): nodos = list(nodos.values())
    activos = [n for n in nodos if n.get("status") in ("activo","online","active")]
    for n in nodos:
        online = n.get("status") in ("activo","online","active")
        ico = c("✓", C.GREEN) if online else c("✗", C.RED)
        print(f"  {ico} {n['name']:<22} {n['ip']}:{n.get('port',9000)}"
              f"  [{n.get('status','?')}]  HB:{n.get('last_seen','?')[:19]}")
    print()
    if len(activos) >= 3:
        print(c(f"  ✅ {len(activos)} nodos activos — PRUEBA 1 APROBADA", C.GREEN))
    else:
        print(c(f"  ⚠️  Solo {len(activos)} nodo(s) activo(s) — necesitas al menos 3", C.YELLOW))

# ── PRUEBA 2: Permiso UDP puerto 5001 ─────────────────────────────────────────
def prueba_2():
    sep("PRUEBA 2 — Permiso UDP puerto 5001  [4 pts]")
    clear_rules()
    add_rule("Permitir UDP 5001", "10", "forward", protocol="UDP", port_dst="5001")
    show_rules()
    wait()

    ts = datetime.now(timezone.utc).isoformat()
    # Servidor envía al nodo B
    send(NODO_B, 5001, "UDP", count=6, msg="prueba2-permitir-udp")
    manual_hint(NODO_A, NODO_B, 5001, "UDP", 6)

    print(c("\n  Acción esperada en nodo B: PERMITIDO (forward)\n", C.GREEN))
    print(c("  La acción 'forward' no genera evento al servidor — verifica en", C.GRAY))
    print(c(f"  la consola del cliente (laptop B) o en los contadores: {SERVER}", C.GRAY))
    resultado("Nodo B muestra 'PERMITIDO | regla=Permitir UDP 5001' en su consola",
              "forward no reporta al servidor — revisar log del cliente directamente")

# ── PRUEBA 3: Bloqueo UDP puerto 5002 ─────────────────────────────────────────
def prueba_3():
    sep("PRUEBA 3 — Bloqueo UDP puerto 5002  [4 pts]")
    clear_rules()
    add_rule("Bloquear UDP 5002", "20", "drop", protocol="UDP", port_dst="5002")
    show_rules()
    wait()

    ts = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 5002, "UDP", count=6, msg="prueba3-bloquear-udp")
    manual_hint(NODO_A, NODO_B, 5002, "UDP", 6)

    # Drop genera evento 'block' en el servidor
    print()
    matching, all_evs = poll_events(ts, "block", 6)
    show_event_result(matching, all_evs, "block", 6)
    resultado("BLOQUEADO × 6 — Nodo B descarta paquetes y envía evento 'block' al servidor",
              "Verifica eventos en la web → pestaña Eventos")

# ── PRUEBA 4: Permiso TCP puerto 8080 ─────────────────────────────────────────
def prueba_4():
    sep("PRUEBA 4 — Permiso TCP puerto 8080  [4 pts]")
    clear_rules()
    add_rule("Permitir TCP 8080", "10", "forward", protocol="TCP", port_dst="8080")
    show_rules()
    wait()

    ts = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 8080, "TCP", count=5, msg="prueba4-permitir-tcp")
    manual_hint(NODO_A, NODO_B, 8080, "TCP", 5)

    print(c("\n  Acción esperada en nodo B: PERMITIDO (forward TCP)\n", C.GREEN))
    resultado("Nodo B acepta la conexión TCP y muestra 'PERMITIDO | regla=Permitir TCP 8080'",
              "forward no reporta al servidor — revisar log del cliente directamente")

# ── PRUEBA 5: Bloqueo TCP puerto 8081 ─────────────────────────────────────────
def prueba_5():
    sep("PRUEBA 5 — Bloqueo TCP puerto 8081  [4 pts]")
    clear_rules()
    add_rule("Bloquear TCP 8081", "20", "drop", protocol="TCP", port_dst="8081")
    show_rules()
    wait()

    ts = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 8081, "TCP", count=5, msg="prueba5-bloquear-tcp")
    manual_hint(NODO_A, NODO_B, 8081, "TCP", 5)

    print()
    matching, all_evs = poll_events(ts, "block", 5)
    show_event_result(matching, all_evs, "block", 5)
    resultado("BLOQUEADO × 5 — Conexión TCP rechazada, evento 'block' enviado al servidor",
              "Verifica en la web → Eventos")

# ── PRUEBA 6: Bloqueo por IP origen ───────────────────────────────────────────
def prueba_6():
    sep("PRUEBA 6 — Bloqueo por IP origen  [5 pts]")
    clear_rules()
    print(c(f"\n  Cliente A = {NODO_A} (nodo-laptop-B)", C.GRAY))
    print(c(f"  Cliente B = {NODO_B} (nodo-laptop-C)  ← destino del tráfico", C.GRAY))
    print(c(f"  Cliente C = {NODO_C} (nodo-laptop-D)\n", C.GRAY))

    add_rule("Bloquear A→B puerto 5003", "30", "drop",
             ip_src=NODO_A, ip_dst=NODO_B, port_dst="5003")
    show_rules()
    wait()

    ts = datetime.now(timezone.utc).isoformat()

    # ── Fase A: Servidor simula origen NODO_A enviando a NODO_B ──
    # Nota: el ip_src real del paquete será SERVER_IP (limitación).
    # Para demostración real con ip_src=NODO_A, el estudiante debe ejecutar
    # el generador desde la laptop A.
    print(c(f"\n  [Fase A] Tráfico desde A ({NODO_A}) → B ({NODO_B}) puerto 5003", C.RED))
    print(c("  ⚠️  IMPORTANTE — Ejecuta esto desde la laptop del Nodo A:", C.YELLOW))
    print(c(f"  python .\\generator.py --ip {NODO_B} --port 5003 --proto UDP --count 5", C.BOLD))
    print(c("  Esperado: BLOQUEADO × 5 (ip_src=NODO_A coincide con la regla)", C.RED))

    print()
    print(c(f"  [Fase B] Tráfico desde C ({NODO_C}) → B ({NODO_B}) puerto 5003", C.GREEN))
    print(c("  ⚠️  IMPORTANTE — Ejecuta esto desde la laptop del Nodo C:", C.YELLOW))
    print(c(f"  python .\\generator.py --ip {NODO_B} --port 5003 --proto UDP --count 5", C.BOLD))
    print(c("  Esperado: PERMITIDO × 5 (ip_src=NODO_C no coincide, sin regla que lo bloquee)", C.GREEN))

    print()
    input(c("  Presiona ENTER cuando hayas ejecutado ambas fases...", C.BOLD))
    print()
    evs = get_events_since(ts)
    blocks = [e for e in evs if e.get("type","").lower() == "block"]
    print(c(f"  📊 Eventos BLOCK recibidos: {len(blocks)}", C.GREEN if blocks else C.YELLOW))
    for e in blocks[:6]:
        src = e.get("detail",{}).get("ip_src","?")
        print(c(f"    ip_src={src} → BLOQUEADO", C.RED))

    resultado("A→B bloqueado (ip_src=NODO_A) | C→B permitido (sin regla que bloquee a C)",
              "La clave SDN: misma regla, diferente ip_src, diferente resultado")

# ── PRUEBA 7: Reporte sin bloqueo UDP 6000 ────────────────────────────────────
def prueba_7():
    sep("PRUEBA 7 — Reporte sin bloqueo UDP 6000  [5 pts]")
    clear_rules()
    add_rule("Reportar UDP 6000", "15", "report", protocol="UDP", port_dst="6000")
    show_rules()
    wait()

    ts = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 6000, "UDP", count=6, msg="prueba7-reportar-udp")
    manual_hint(NODO_A, NODO_B, 6000, "UDP", 6)

    print()
    matching, all_evs = poll_events(ts, "report", 6)
    show_event_result(matching, all_evs, "report", 6)
    resultado("REPORTADO × 6 — El paquete PASA (no se descarta) pero se genera alerta",
              "Diferencia con drop: el tráfico llega al destino Y el servidor recibe evento")

# ── PRUEBA 8: Conflicto por prioridad UDP 8000 ────────────────────────────────
def prueba_8():
    sep("PRUEBA 8 — Conflicto por prioridad UDP 8000  [6.5 pts]")

    # Fase A: R2-Bloquear(50) gana a R1-Permitir(10)
    print(c("\n  [Fase A] R2-Bloquear(prio 50) debe ganar a R1-Permitir(prio 10)", C.CYAN))
    clear_rules()
    add_rule("R1 Permitir UDP 8000", "10", "forward", protocol="UDP", port_dst="8000")
    add_rule("R2 Bloquear UDP 8000", "50", "drop",    protocol="UDP", port_dst="8000")
    show_rules()
    wait()

    ts_a = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 8000, "UDP", count=5, msg="conflicto-faseA")
    manual_hint(NODO_A, NODO_B, 8000, "UDP", 5)

    print()
    matching_a, _ = poll_events(ts_a, "block", 5)
    show_event_result(matching_a, [], "block", 5)
    print(c("  Esperado: BLOQUEADO × 5 (R2 prio 50 > R1 prio 10)", C.RED))

    print()
    input(c("  Presiona ENTER para invertir prioridades (Fase B)...", C.BOLD))

    # Fase B: R1-Permitir(60) gana a R2-Bloquear(50)
    print(c("\n  [Fase B] R1-Permitir(prio 60) debe ganar a R2-Bloquear(prio 50)", C.CYAN))
    clear_rules()
    add_rule("R1 Permitir UDP 8000", "60", "forward", protocol="UDP", port_dst="8000")
    add_rule("R2 Bloquear UDP 8000", "50", "drop",    protocol="UDP", port_dst="8000")
    show_rules()
    wait()

    ts_b = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 8000, "UDP", count=5, msg="conflicto-faseB")
    manual_hint(NODO_A, NODO_B, 8000, "UDP", 5)

    print()
    # En Fase B la acción es forward (no genera evento block) — verificar en cliente
    matching_b, _ = poll_events(ts_b, "block", 1, timeout=8)
    col = C.GREEN if len(matching_b) == 0 else C.YELLOW
    print(c(f"  📊 Eventos BLOCK en Fase B: {len(matching_b)} (esperado: 0 — ahora permite)", col))
    print(c("  Esperado: PERMITIDO × 5 (R1 prio 60 > R2 prio 50)", C.GREEN))

    resultado("Fase A: BLOQUEADO | Fase B: PERMITIDO — mismo tráfico, comportamiento inverso al cambiar prioridades",
              "Principio SDN: el controlador modifica reglas en tiempo real sin tocar los nodos")

# ── PRUEBA 9: Actualización dinámica sin reiniciar clientes ───────────────────
def prueba_9():
    sep("PRUEBA 9 — Actualización dinámica sin reinicio  [7.5 pts]")

    print(c("\n  [Paso 1] Sin regla — tráfico debe PASAR (forward por defecto)", C.CYAN))
    clear_rules()
    wait(s=6)
    ts1 = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 9000, "UDP", count=4, msg="paso1-sin-regla")
    manual_hint(NODO_A, NODO_B, 9000, "UDP", 4)
    print(c("  Esperado: PERMITIDO × 4 — sin regla → forward por defecto", C.GREEN))
    print(c("  (forward no genera evento — verifica en log del cliente)", C.GRAY))

    print()
    input(c("  Presiona ENTER para crear la regla de bloqueo...", C.BOLD))

    print(c("\n  [Paso 2] Creando regla UDP 9000 → DROP", C.CYAN))
    add_rule("Bloquear UDP 9000 dinamico", "20", "drop", protocol="UDP", port_dst="9000")
    show_rules()
    wait(s=8, msg="Esperando que los clientes descarguen la nueva regla (sin reinicio)")

    print(c("\n  [Paso 3] Mismo tráfico — ahora debe BLOQUEARSE", C.CYAN))
    ts3 = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 9000, "UDP", count=4, msg="paso3-con-regla")
    manual_hint(NODO_A, NODO_B, 9000, "UDP", 4)
    print()
    matching3, _ = poll_events(ts3, "block", 4)
    show_event_result(matching3, [], "block", 4)
    print(c("  Esperado: BLOQUEADO × 4 (sin reiniciar el cliente)", C.RED))

    print()
    input(c("  Presiona ENTER para eliminar la regla...", C.BOLD))

    print(c("\n  [Paso 4] Eliminando regla...", C.CYAN))
    clear_rules()
    wait(s=8, msg="Esperando que los clientes actualicen (sin reinicio)")

    print(c("\n  [Paso 5] Tráfico debe volver a PASAR", C.CYAN))
    ts5 = datetime.now(timezone.utc).isoformat()
    send(NODO_B, 9000, "UDP", count=4, msg="paso5-sin-regla")
    manual_hint(NODO_A, NODO_B, 9000, "UDP", 4)
    matching5, _ = poll_events(ts5, "block", 1, timeout=8)
    col = C.GREEN if len(matching5) == 0 else C.YELLOW
    print(c(f"  📊 Eventos BLOCK en Paso 5: {len(matching5)} (esperado: 0 — vuelve a forward)", col))
    print(c("  Esperado: PERMITIDO × 4 (regla eliminada → forward por defecto)", C.GREEN))

    resultado("P1: PASS → P3: BLOCKED → P5: PASS — sin reiniciar ningún cliente en ningún paso",
              "Este es el principio fundamental SDN: separación control/datos en tiempo real")

# ── PRUEBA 10: Prueba integral multicliente ────────────────────────────────────
def prueba_10():
    sep("PRUEBA 10 — Prueba integral multicliente  [7.5 pts]")
    print(c(f"\n  A = {NODO_A}  |  B = {NODO_B}  |  C = {NODO_C}\n", C.GRAY))

    clear_rules()
    add_rule("R1 A→B UDP 6001 Permitir", "10", "forward",
             ip_src=NODO_A, ip_dst=NODO_B, protocol="UDP", port_dst="6001")
    add_rule("R2 A→C UDP 6002 Bloquear", "30", "drop",
             ip_src=NODO_A, ip_dst=NODO_C, protocol="UDP", port_dst="6002")
    add_rule("R3 *→B TCP 8080 Reportar", "20", "report",
             ip_dst=NODO_B, protocol="TCP", port_dst="8080")
    add_rule("R4 C→A UDP 7000 Bloquear", "40", "drop",
             ip_src=NODO_C, ip_dst=NODO_A, protocol="UDP", port_dst="7000")
    add_rule("R5 * UDP 9999 Reportar",   "5",  "report",
             protocol="UDP", port_dst="9999")
    show_rules()
    wait(s=8)

    print(c("\n  Ejecuta cada flujo desde la laptop indicada:\n", C.BOLD))

    flujos = [
        # (label,         src_ip,  dst_ip,  port, proto,  esperado,     col,       regla)
        ("A→B UDP 6001",  NODO_A, NODO_B, 6001, "UDP", "PERMITIDO",  C.GREEN,  "R1"),
        ("A→C UDP 6002",  NODO_A, NODO_C, 6002, "UDP", "BLOQUEADO",  C.RED,    "R2"),
        ("A→B TCP 8080",  NODO_A, NODO_B, 8080, "TCP", "REPORTADO",  C.YELLOW, "R3"),
        ("C→B TCP 8080",  NODO_C, NODO_B, 8080, "TCP", "REPORTADO",  C.YELLOW, "R3"),
        ("C→A UDP 7000",  NODO_C, NODO_A, 7000, "UDP", "BLOQUEADO",  C.RED,    "R4"),
        ("B→A UDP 9999",  NODO_B, NODO_A, 9999, "UDP", "REPORTADO",  C.YELLOW, "R5"),
    ]

    for nombre, src, dst, port, proto, esperado, col, regla in flujos:
        print(c(f"  [{nombre}]  Regla: {regla}  →  {esperado}", col))
        print(c(f"    Desde laptop {src}:", C.GRAY))
        print(c(f"    python .\\generator.py --ip {dst} --port {port} --proto {proto} --count 4", C.BOLD))
        print()

    print()
    input(c("  Presiona ENTER cuando hayas ejecutado todos los flujos...", C.BOLD))

    ts = datetime.now(timezone.utc).isoformat()
    # El servidor envía flujos que puede (desde server, ip_src será SERVER_IP,
    # pero sirve para probar filtros de puerto).
    # Los flujos con ip_src específico DEBEN venir de las laptops.
    print(c("\n  Verificando eventos recibidos...", C.CYAN))
    time.sleep(3)
    evs = get_events()
    blocks  = [e for e in evs if e.get("type","").lower() == "block"]
    reports = [e for e in evs if e.get("type","").lower() == "report"]

    print(c(f"\n  📊 Resumen de eventos en servidor:", C.BOLD))
    print(c(f"    BLOCK   : {len(blocks)} evento(s)", C.RED))
    print(c(f"    REPORT  : {len(reports)} evento(s)", C.YELLOW))
    print(c(f"    Total   : {len(evs)} evento(s)", C.CYAN))

    resultado("6 flujos con resultados distintos según ip_src, ip_dst, protocolo y puerto",
              "Demuestra el SDN completo: reglas combinadas, prioridades y 3 acciones")

# ── Menú y main ───────────────────────────────────────────────────────────────

PRUEBAS = {
    1:  ("Registro de nodos (2.5 pts)",               prueba_1),
    2:  ("Permiso UDP puerto 5001 (4 pts)",            prueba_2),
    3:  ("Bloqueo UDP puerto 5002 (4 pts)",            prueba_3),
    4:  ("Permiso TCP puerto 8080 (4 pts)",            prueba_4),
    5:  ("Bloqueo TCP puerto 8081 (4 pts)",            prueba_5),
    6:  ("Bloqueo por IP origen puerto 5003 (5 pts)",  prueba_6),
    7:  ("Reporte sin bloqueo UDP 6000 (5 pts)",       prueba_7),
    8:  ("Conflicto por prioridad UDP 8000 (6.5 pts)", prueba_8),
    9:  ("Actualización dinámica sin reinicio (7.5 pts)", prueba_9),
    10: ("Prueba integral multicliente (7.5 pts)",     prueba_10),
}

def menu():
    if os.name == "nt": os.system("color")
    while True:
        print()
        sep("EVALUACIÓN SDN FIREWALL — Universidad del Rosario", C.BOLD + C.BLUE)
        print(c(f"  Servidor : {SERVER}", C.GRAY))
        print(c(f"  Nodo A   : {NODO_A}   (nodo-laptop-B)", C.GRAY))
        print(c(f"  Nodo B   : {NODO_B}   (nodo-laptop-C)", C.GRAY))
        print(c(f"  Nodo C   : {NODO_C}  (nodo-laptop-D)", C.GRAY))
        sep()
        for num, (desc, _) in PRUEBAS.items():
            print(f"  {c(str(num),''):<4} {desc}")
        print(f"  {c('0',''):<4} Salir")
        sep()
        try:
            op = int(input(c("  Selecciona prueba: ", C.BOLD)))
        except (ValueError, KeyboardInterrupt):
            print(); break
        if op == 0: break
        if op in PRUEBAS:
            print()
            try:
                PRUEBAS[op][1]()
            except Exception as e:
                print(c(f"\n  ✗ Error: {e}", C.RED))
            input(c("\n  Presiona ENTER para continuar...", C.GRAY))
        else:
            print(c("  Opción inválida", C.RED))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prueba", type=int, help="Número de prueba (1-10)")
    parser.add_argument("--todas",  action="store_true", help="Ejecutar las 10 pruebas")
    args = parser.parse_args()

    if os.name == "nt": os.system("color")

    try:
        requests.get(f"{SERVER}/status", timeout=3)
    except Exception:
        print(c(f"\n  ✗ No se puede conectar al servidor {SERVER}", C.RED))
        sys.exit(1)

    if args.prueba:
        if args.prueba in PRUEBAS:
            PRUEBAS[args.prueba][1]()
        else:
            print(c(f"  Prueba {args.prueba} no existe (1-10)", C.RED))
    elif args.todas:
        for num in range(1, 11):
            PRUEBAS[num][1]()
            print()
            if num < 10:
                input(c("  Presiona ENTER para la siguiente prueba...", C.GRAY))
    else:
        menu()
