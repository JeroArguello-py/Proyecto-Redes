# =============================================================================
#  regla.py  —  Proyecto Redes/
#
#  Crea, lista o elimina reglas en el servidor SDN desde la terminal.
#
#  Uso:
#    python regla.py listar
#    python regla.py crear --nombre "Permitir UDP" --prioridad Media --accion forward --proto UDP --dst 10.23.41.58 --puerto 9000
#    python regla.py borrar --id abc12345
#    python regla.py limpiar
#
# =============================================================================

import argparse
import json
import requests
import sys

SERVER = "http://10.23.36.87:5000"

COLORS = {
    "forward": "\033[92m",
    "drop":    "\033[91m",
    "report":  "\033[93m",
    "Alta":    "\033[91m",
    "Media":   "\033[93m",
    "Baja":    "\033[94m",
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "gray":    "\033[90m",
}
def c(text, key): return f"{COLORS.get(key,'')}{text}{COLORS['reset']}"


def get_rules():
    r = requests.get(f"{SERVER}/rules", timeout=5)
    d = r.json()
    return d.get("rules", d) if isinstance(d, dict) else d


def cmd_listar(args):
    rules = get_rules()
    if not rules:
        print(c("  Sin reglas en el servidor.", "gray"))
        return
    print(c(f"\n  {'#':<3} {'Prioridad':<8} {'Acción':<9} {'Nombre':<30} {'IP Src':<16} {'IP Dst':<16} {'Proto':<6} {'Pto Dst'}", "bold"))
    print("  " + "─" * 105)
    for i, r in enumerate(rules, 1):
        m = r.get("match", {})
        prio   = c(f"{r['priority']:<8}", r['priority'])
        accion = c(f"{r['action']:<9}", r['action'])
        print(f"  {i:<3} {prio} {accion} {r['name']:<30} "
              f"{m.get('ip_src','*'):<16} {m.get('ip_dst','*'):<16} "
              f"{m.get('protocol','*'):<6} {m.get('port_dst','*')}")
    print()


def cmd_crear(args):
    regla = {
        "name":     args.nombre,
        "priority": args.prioridad,
        "action":   args.accion,
        "match": {
            "ip_src":   args.src   or "*",
            "ip_dst":   args.dst   or "*",
            "protocol": args.proto or "*",
            "port_src": args.psrc  or "*",
            "port_dst": args.puerto or "*",
            "ingress":  "*",
            "mac_src":  "*",
            "mac_dst":  "*",
        }
    }
    r = requests.post(f"{SERVER}/rules", json=regla, timeout=5)
    if r.status_code == 201:
        rid = r.json().get("rule", {}).get("id", "?")
        print(c(f"\n  ✓ Regla creada: '{args.nombre}' (id={rid})\n", "forward"))
    else:
        print(c(f"\n  ✗ Error: {r.json()}\n", "drop"))


def cmd_borrar(args):
    r = requests.delete(f"{SERVER}/rules/{args.id}", timeout=5)
    if r.ok:
        print(c(f"\n  ✓ Regla '{args.id}' eliminada.\n", "forward"))
    else:
        print(c(f"\n  ✗ Error: {r.json()}\n", "drop"))


def cmd_limpiar(args):
    rules = get_rules()
    if not rules:
        print("  Sin reglas que eliminar.")
        return
    for rule in rules:
        requests.delete(f"{SERVER}/rules/{rule['id']}", timeout=5)
    print(c(f"\n  ✓ {len(rules)} regla(s) eliminadas.\n", "forward"))


# ── Argumentos ────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(
    description="Gestión de reglas SDN desde la terminal",
    formatter_class=argparse.RawTextHelpFormatter
)
sub = parser.add_subparsers(dest="cmd")

# listar
sub.add_parser("listar", help="Listar reglas activas")

# crear
p_crear = sub.add_parser("crear", help="Crear una nueva regla")
p_crear.add_argument("--nombre",    required=True,  help="Nombre de la regla")
p_crear.add_argument("--prioridad", default="Media",
                     help="Prioridad: Alta, Media, Baja  o número entero (ej: 10, 50, 100)")
p_crear.add_argument("--accion",    default="forward", choices=["forward","drop","report"])
p_crear.add_argument("--proto",     default="*",    help="Protocolo: UDP, TCP o *")
p_crear.add_argument("--src",       default="*",    help="IP origen  (ej: 10.23.55.16)")
p_crear.add_argument("--dst",       default="*",    help="IP destino (ej: 10.23.41.58)")
p_crear.add_argument("--psrc",      default="*",    help="Puerto origen")
p_crear.add_argument("--puerto",    default="*",    help="Puerto destino (ej: 9000)")

# borrar
p_borrar = sub.add_parser("borrar", help="Eliminar una regla por ID")
p_borrar.add_argument("--id", required=True, help="ID de la regla (ej: abc12345)")

# limpiar
sub.add_parser("limpiar", help="Eliminar TODAS las reglas")

args = parser.parse_args()

CMDS = {
    "listar":  cmd_listar,
    "crear":   cmd_crear,
    "borrar":  cmd_borrar,
    "limpiar": cmd_limpiar,
}

if args.cmd not in CMDS:
    parser.print_help()
    sys.exit(0)

try:
    CMDS[args.cmd](args)
except requests.exceptions.ConnectionError:
    print(c(f"\n  ✗ No se pudo conectar al servidor {SERVER}\n", "drop"))
    sys.exit(1)
