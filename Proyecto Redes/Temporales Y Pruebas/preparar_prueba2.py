# =============================================================================
#  preparar_prueba2.py  —  Proyecto Redes/
#
#  Ajusta prioridades para Prueba 2 (BLOQUEAR por IP origen):
#    - "Prueba1 Permitir UDP 9000"       Alta → Baja   (cede el paso)
#    - "Prueba2 Bloquear IP generador"   Baja → Alta   (gana el match)
#
#  Uso:
#    python preparar_prueba2.py          ← prepara para Prueba 2
#    python preparar_prueba2.py --restaurar  ← vuelve al estado original
# =============================================================================

import requests
import sys
import json

SERVER = "http://10.23.36.87:5000"

ID_PRUEBA1 = "18551ade"   # Permitir UDP 9000
ID_PRUEBA2 = "454b73dc"   # Bloquear IP generador

def get_rules_list():
    r = requests.get(f"{SERVER}/rules")
    r.raise_for_status()
    data = r.json()
    # El servidor devuelve {"total": N, "rules": [...]}
    if isinstance(data, dict):
        return data.get("rules", [])
    return data  # por si acaso devuelve lista directamente

def get_rule(rule_id):
    for rule in get_rules_list():
        if rule["id"] == rule_id:
            return rule
    return None

def set_priority(rule_id, priority, label):
    rule = get_rule(rule_id)
    if not rule:
        print(f"[ERROR] No se encontró la regla {rule_id}")
        return False

    current = rule["priority"]
    if current == priority:
        print(f"  {label}: ya tiene prioridad '{priority}' — sin cambios")
        return True

    # Eliminar y recrear con nueva prioridad (el servidor no tiene PATCH /rules)
    requests.delete(f"{SERVER}/rules/{rule_id}")

    rule["priority"] = priority
    rule.pop("id", None)          # el servidor asigna nuevo id...
    # Mejor: modificar el rules.json directamente no es ideal desde aquí.
    # Usamos DELETE + POST y aceptamos que el ID cambia.
    r = requests.post(f"{SERVER}/rules", json=rule)
    if r.status_code == 201:
        new_id = r.json().get("id", "?")
        print(f"  ✓ {label}: '{current}' → '{priority}'  (nuevo id: {new_id})")
        return True
    else:
        print(f"  [ERROR] No se pudo actualizar {label}: {r.text}")
        return False

def preparar():
    print("\n=== Preparando Prueba 2: BLOQUEAR por IP origen ===\n")
    set_priority(ID_PRUEBA1, "Baja",  "Prueba1 Permitir UDP 9000")
    set_priority(ID_PRUEBA2, "Alta",  "Prueba2 Bloquear IP generador")
    print("\nAhora ejecuta:")
    print("  cd generador")
    print("  python generator.py --scenario bloquear_ip")
    print("\nNodo B debe mostrar BLOQUEADO para todos los paquetes.\n")

def restaurar():
    print("\n=== Restaurando prioridades originales ===\n")
    # Después de preparar(), los IDs cambiaron — buscamos por nombre
    for rule in get_rules_list():
        name = rule.get("name", "")
        if "Prueba1" in name or "Permitir UDP 9000" in name:
            set_priority(rule["id"], "Alta", rule["name"])
        elif "Prueba2" in name or "Bloquear IP generador" in name:
            set_priority(rule["id"], "Baja", rule["name"])

    print("\nPrioridades restauradas. Reglas actuales:")
    for rule in get_rules_list():
        print(f"  [{rule['priority']:5}] {rule['name']} → {rule['action']}")
    print()

if __name__ == "__main__":
    if "--restaurar" in sys.argv:
        restaurar()
    else:
        preparar()
