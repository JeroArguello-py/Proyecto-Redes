# agregar_conflicto.py
import requests


requests.post('http://10.23.36.87:5000/rules', json={
    'name': 'Conflicto Bloquear UDP 9000',
    'priority': 'Alta',
    'action': 'drop',
    'match': {'protocol': 'UDP', 'port_dst': '9000'}
})
print('Regla de conflicto creada')