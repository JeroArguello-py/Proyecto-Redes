import requests

SERVER = "http://10.23.36.87:5000"

r = requests.get(f"{SERVER}/nodes")
data = r.json()

# El servidor puede devolver lista o dict
nodes = data.get("nodes", data)
if isinstance(nodes, dict):
    nodes = list(nodes.values())

if not nodes:
    print("No hay nodos registrados.")
else:
    print(f"\n{'Nombre':<20} {'IP':<16} {'Puerto':<8} {'Estado'}")
    print("-" * 55)
    for n in nodes:
        print(f"{n['name']:<20} {n['ip']:<16} {str(n.get('port','?')):<8} {n['status']}")
    print(f"\nTotal: {len(nodes)} nodo(s)\n")
