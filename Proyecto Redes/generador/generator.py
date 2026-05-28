# =============================================================================
#  GENERADOR DE TRÁFICO SDN — Proyecto Final Redes de Computadores
#  Universidad del Rosario
# =============================================================================
#
#  Modos de uso:
#
#  1. Argumentos directos (un solo envío):
#       python generator.py --ip 192.168.1.101 --port 9000 --proto UDP
#       python generator.py --ip 192.168.1.101 --port 9000 --proto UDP --count 10 --interval 0.5
#
#  2. Escenario predefinido (de scenarios.json):
#       python generator.py --scenario permitir_udp
#       python generator.py --scenario bloquear_udp
#       python generator.py --scenario bloquear_ip
#       python generator.py --scenario reportar_ip
#       python generator.py --scenario conflicto_prioridad
#
#  3. Modo interactivo (menú en consola):
#       python generator.py --interactive
#
#  4. Listar escenarios disponibles:
#       python generator.py --list
#
# =============================================================================

import socket
import time
import json
import argparse
import os
import sys
from datetime import datetime

# ── Configuración de rutas ────────────────────────────────────────────────────

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
SCENARIOS_FILE = os.path.join(BASE_DIR, "scenarios.json")

# ── Colores para consola (funcionan en Windows 10+ y Mac/Linux) ───────────────

class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    GRAY   = "\033[90m"

def c(text, color):
    return f"{color}{text}{Color.RESET}"

# ── Utilidades ────────────────────────────────────────────────────────────────

def timestamp():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def my_ip():
    """Obtiene la IP local de esta máquina."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ── Envío UDP ─────────────────────────────────────────────────────────────────

def send_udp(ip, port, payload, timeout=3):
    """
    Envía un datagrama UDP y espera respuesta opcional.
    Retorna True si se envió correctamente.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        data = payload.encode("utf-8")
        sock.sendto(data, (ip, port))
        sock.close()
        return True
    except socket.gaierror:
        print(c(f"  [ERROR] No se puede resolver la IP: {ip}", Color.RED))
        return False
    except OSError as e:
        print(c(f"  [ERROR] {e}", Color.RED))
        return False

# ── Envío TCP ─────────────────────────────────────────────────────────────────

def send_tcp(ip, port, payload, timeout=3):
    """
    Abre una conexión TCP, envía el payload y lee la respuesta del cliente SDN.
    Retorna la respuesta del nodo o None si falló.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(payload.encode("utf-8"))
        # El cliente SDN responde con el resultado de la regla aplicada
        try:
            response = sock.recv(1024).decode("utf-8", errors="replace")
        except socket.timeout:
            response = None
        sock.close()
        return response
    except ConnectionRefusedError:
        print(c(f"  [ERROR] Conexión rechazada en {ip}:{port}. ¿Está corriendo el cliente?", Color.RED))
        return None
    except socket.timeout:
        print(c(f"  [ERROR] Timeout conectando a {ip}:{port}", Color.RED))
        return None
    except OSError as e:
        print(c(f"  [ERROR] {e}", Color.RED))
        return None

# ── Motor de envío ────────────────────────────────────────────────────────────

def run_burst(ip, port, protocol, count, interval, message, label=""):
    """
    Envía 'count' paquetes del protocolo indicado con 'interval' segundos entre cada uno.
    Imprime el resultado de cada envío en tiempo real.
    """
    protocol = protocol.upper()
    src_ip   = my_ip()

    # Encabezado del burst
    print()
    print(c("=" * 62, Color.BOLD))
    if label:
        print(c(f"  {label}", Color.BOLD))
    print(c(f"  Destino  : {ip}:{port}", Color.CYAN))
    print(c(f"  Protocolo: {protocol}", Color.CYAN))
    print(c(f"  Paquetes : {count}  |  Intervalo: {interval}s", Color.CYAN))
    print(c(f"  Mensaje  : {message[:60]}", Color.GRAY))
    print(c(f"  IP origen: {src_ip}", Color.GRAY))
    print(c("=" * 62, Color.BOLD))

    sent = 0
    failed = 0

    for i in range(1, count + 1):
        # Construir payload con número de secuencia
        payload = f"[SEQ={i}/{count}] [{protocol}] {message}"
        ts = timestamp()

        if protocol == "UDP":
            ok = send_udp(ip, port, payload)
            if ok:
                sent += 1
                print(c(f"  [{ts}] pkt #{i:>3}  →  {ip}:{port}  ✓ enviado", Color.GREEN))
            else:
                failed += 1
                print(c(f"  [{ts}] pkt #{i:>3}  →  {ip}:{port}  ✗ error", Color.RED))

        elif protocol == "TCP":
            response = send_tcp(ip, port, payload)
            if response is not None:
                sent += 1
                try:
                    resp_json = json.loads(response)
                    action    = resp_json.get("action", "?")
                    rule_name = resp_json.get("rule_name", "?")
                    node      = resp_json.get("node", "?")
                    if action == "drop":
                        status = c(f"BLOQUEADO por '{rule_name}'", Color.RED)
                    elif action == "report":
                        status = c(f"REPORTADO por '{rule_name}'", Color.YELLOW)
                    else:
                        status = c(f"PERMITIDO por '{rule_name}'", Color.GREEN)
                    print(c(f"  [{ts}] pkt #{i:>3}  →  {ip}:{port}  ✓  {status}  (nodo: {node})", Color.RESET))
                except Exception:
                    print(c(f"  [{ts}] pkt #{i:>3}  →  {ip}:{port}  ✓ respuesta: {response[:60]}", Color.GREEN))
            else:
                failed += 1
                print(c(f"  [{ts}] pkt #{i:>3}  →  {ip}:{port}  ✗ sin respuesta", Color.RED))

        else:
            print(c(f"  [ERROR] Protocolo '{protocol}' no soportado. Usa UDP o TCP.", Color.RED))
            break

        if i < count:
            time.sleep(interval)

    # Resumen
    print(c("-" * 62, Color.GRAY))
    print(c(f"  Resumen: {sent} enviados  |  {failed} fallidos  |  total: {count}", Color.BOLD))
    print(c("=" * 62, Color.BOLD))
    print()

    return sent, failed

# ── Carga de escenarios ───────────────────────────────────────────────────────

def load_scenarios():
    if not os.path.exists(SCENARIOS_FILE):
        print(c(f"[ERROR] No se encontró {SCENARIOS_FILE}", Color.RED))
        return {}
    with open(SCENARIOS_FILE, encoding="utf-8") as f:
        return json.load(f)

# ── Modo escenario ────────────────────────────────────────────────────────────

def run_scenario(name):
    scenarios = load_scenarios()
    if name not in scenarios:
        print(c(f"[ERROR] Escenario '{name}' no encontrado.", Color.RED))
        print(c("Escenarios disponibles:", Color.YELLOW))
        for k, v in scenarios.items():
            print(f"  {c(k, Color.CYAN):<30} — {v.get('description', '')}")
        return

    s = scenarios[name]
    print()
    print(c(f"▶  Escenario: {s.get('description', name)}", Color.BOLD + Color.BLUE))

    for step in s.get("steps", []):
        run_burst(
            ip       = step["ip"],
            port     = int(step["port"]),
            protocol = step.get("protocol", "UDP"),
            count    = int(step.get("count", 5)),
            interval = float(step.get("interval", 0.5)),
            message  = step.get("message", "test packet"),
            label    = step.get("label", ""),
        )
        pause = step.get("pause_after", 0)
        if pause:
            print(c(f"  ⏸  Pausa de {pause}s entre pasos...", Color.GRAY))
            time.sleep(pause)

# ── Modo interactivo ──────────────────────────────────────────────────────────

def interactive_mode():
    """Menú interactivo para configurar y lanzar envíos sin tocar el código."""

    # Habilitar colores en Windows
    os.system("color" if os.name == "nt" else "")

    print()
    print(c("╔══════════════════════════════════════════════════════════╗", Color.CYAN))
    print(c("║         GENERADOR DE TRÁFICO SDN — Modo Interactivo      ║", Color.CYAN))
    print(c("╚══════════════════════════════════════════════════════════╝", Color.CYAN))

    scenarios = load_scenarios()

    while True:
        print()
        print(c("── Menú principal ──────────────────────────────────", Color.BOLD))
        print(f"  {c('1', Color.YELLOW)} Envío manual (configuras IP, puerto, protocolo...)")
        print(f"  {c('2', Color.YELLOW)} Ejecutar escenario predefinido")
        print(f"  {c('3', Color.YELLOW)} Listar escenarios")
        print(f"  {c('0', Color.RED)} Salir")
        print()

        opcion = input(c("  Elige opción: ", Color.BOLD)).strip()

        if opcion == "0":
            print(c("  Generador detenido. ¡Hasta luego!", Color.GRAY))
            break

        elif opcion == "1":
            print()
            ip       = input(c("  IP destino       : ", Color.CYAN)).strip() or "127.0.0.1"
            port     = input(c("  Puerto destino   : ", Color.CYAN)).strip() or "9000"
            protocol = input(c("  Protocolo (UDP/TCP) [UDP]: ", Color.CYAN)).strip().upper() or "UDP"
            count    = input(c("  Cantidad paquetes [5]: ", Color.CYAN)).strip() or "5"
            interval = input(c("  Intervalo segundos [0.5]: ", Color.CYAN)).strip() or "0.5"
            message  = input(c("  Mensaje [test packet]: ", Color.CYAN)).strip() or "test packet"

            run_burst(
                ip=ip, port=int(port), protocol=protocol,
                count=int(count), interval=float(interval),
                message=message, label="Envío manual"
            )

        elif opcion == "2":
            if not scenarios:
                print(c("  No hay escenarios cargados.", Color.RED))
                continue
            print()
            print(c("  Escenarios disponibles:", Color.BOLD))
            keys = list(scenarios.keys())
            for i, k in enumerate(keys, 1):
                desc = scenarios[k].get("description", "")
                print(f"    {c(str(i), Color.YELLOW)}. {c(k, Color.CYAN):<28} — {desc}")
            print()
            sel = input(c("  Número o nombre del escenario: ", Color.BOLD)).strip()
            # Aceptar número o nombre
            if sel.isdigit() and 1 <= int(sel) <= len(keys):
                sel = keys[int(sel) - 1]
            run_scenario(sel)

        elif opcion == "3":
            print()
            print(c("  Escenarios disponibles:", Color.BOLD))
            for k, v in scenarios.items():
                print(f"    {c(k, Color.CYAN):<28} — {v.get('description', '')}")

        else:
            print(c("  Opción no válida.", Color.RED))

# ── Listado de escenarios ─────────────────────────────────────────────────────

def list_scenarios():
    scenarios = load_scenarios()
    if not scenarios:
        print("No hay escenarios cargados.")
        return
    print()
    print(c("Escenarios disponibles en scenarios.json:", Color.BOLD))
    print()
    for k, v in scenarios.items():
        print(f"  {c(k, Color.CYAN)}")
        print(f"    {v.get('description', '')}")
        for step in v.get("steps", []):
            print(c(f"    → {step.get('protocol','UDP')} a {step.get('ip','?')}:{step.get('port','?')} "
                    f"× {step.get('count',5)} pkts  [{step.get('label','')}]", Color.GRAY))
        print()

# ── CLI principal ─────────────────────────────────────────────────────────────

def main():
    # Habilitar colores ANSI en Windows
    if os.name == "nt":
        os.system("color")
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )

    parser = argparse.ArgumentParser(
        description="Generador de tráfico UDP/TCP para pruebas SDN",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ip",          default=None,      help="IP destino")
    parser.add_argument("--port",        type=int,          help="Puerto destino")
    parser.add_argument("--proto",       default="UDP",     help="Protocolo: UDP o TCP (default: UDP)")
    parser.add_argument("--count",       type=int, default=5, help="Cantidad de paquetes (default: 5)")
    parser.add_argument("--interval",    type=float, default=0.5, help="Intervalo en segundos (default: 0.5)")
    parser.add_argument("--msg",         default="test packet SDN", help="Mensaje/payload")
    parser.add_argument("--scenario",    default=None,      help="Nombre del escenario predefinido")
    parser.add_argument("--interactive", action="store_true", help="Modo interactivo con menú")
    parser.add_argument("--list",        action="store_true", help="Listar escenarios disponibles")

    args = parser.parse_args()

    if args.list:
        list_scenarios()

    elif args.interactive:
        interactive_mode()

    elif args.scenario:
        run_scenario(args.scenario)

    elif args.ip and args.port:
        run_burst(
            ip=args.ip, port=args.port, protocol=args.proto,
            count=args.count, interval=args.interval,
            message=args.msg, label="Envío por argumentos"
        )

    else:
        parser.print_help()
        print()
        print(c("Ejemplos:", Color.BOLD))
        print(c("  python generator.py --ip 192.168.1.101 --port 9000 --proto UDP --count 10", Color.CYAN))
        print(c("  python generator.py --scenario bloquear_udp", Color.CYAN))
        print(c("  python generator.py --interactive", Color.CYAN))
        print(c("  python generator.py --list", Color.CYAN))
        print()

if __name__ == "__main__":
    main()
