# reorganizar_reglas.py
import requests

url = 'http://10.23.36.87:5000'

# Primero eliminar las reglas actuales
reglas = requests.get(f'{url}/rules').json()['rules']
for r in reglas:
    requests.delete(f'{url}/rules/{r["id"]}')
    print(f'Eliminada: {r["name"]}')

# Crear reglas bien separadas para cada prueba
nuevas = [
    # Prueba 1: permitir UDP 9000 desde cualquier IP
    {'name':'Prueba1 Permitir UDP 9000', 'priority':'Alta',  'action':'forward',
     'match':{'protocol':'UDP','port_dst':'9000'}},

    # Prueba 2: bloquear UDP desde IP del generador al puerto 9000
    # (se activa cambiando su prioridad a Alta cuando quieras probarla)
    {'name':'Prueba2 Bloquear IP generador', 'priority':'Baja', 'action':'drop',
     'match':{'ip_src':'10.23.36.87','protocol':'UDP'}},

    # Prueba 4: reportar cuando el mensaje contiene "sospechoso"
    {'name':'Prueba4 Reportar IP sospechosa', 'priority':'Media', 'action':'report',
     'match':{'ip_src':'10.23.36.87','port_dst':'8888'}},
]

for r in nuevas:
    resp = requests.post(f'{url}/rules', json=r)
    print(f'Creada: {resp.json().get("message", resp.json())}')