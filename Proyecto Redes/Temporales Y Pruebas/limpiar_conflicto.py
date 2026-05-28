import requests

SERVER = "http://10.23.36.87:5000"

r = requests.get(f"{SERVER}/rules")
rules = r.json()["rules"]

for rule in rules:
    if "Conflicto" in rule["name"]:
        rid = rule["id"]
        requests.delete(f"{SERVER}/rules/{rid}")
        print(f"Eliminada: {rule['name']} (id={rid})")

print("\nReglas actuales:")
r2 = requests.get(f"{SERVER}/rules")
for rule in r2.json()["rules"]:
    print(f"  [{rule['priority']:5}] {rule['name']} → {rule['action']}")
