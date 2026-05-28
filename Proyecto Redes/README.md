# SDN Firewall — Proyecto Final Redes de Computadores
**Universidad del Rosario**

Sistema de firewall basado en principios SDN (Software-Defined Networking) donde el plano de control (servidor) está separado del plano de datos (nodos cliente). El controlador distribuye reglas de filtrado en tiempo real a los nodos sin necesidad de reiniciarlos.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│              PLANO DE CONTROL (servidor)             │
│  server.py — Flask REST API en puerto 5000          │
│  • Gestión de reglas (crear / eliminar / listar)    │
│  • Registro de nodos y heartbeat                    │
│  • Recepción de eventos (block / report)            │
│  • Interfaz web en http://<server_ip>:5000          │
└────────────────────┬────────────────────────────────┘
                     │ HTTP REST (poll cada 5s)
        ┌────────────┼────────────┐
        ▼            ▼            ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ Nodo B   │ │ Nodo C   │ │ Nodo D   │
  │client.py │ │client.py │ │client.py │
  │ data     │ │ data     │ │ data     │
  │ plane    │ │ plane    │ │ plane    │
  └──────────┘ └──────────┘ └──────────┘
```

Cada nodo descarga las reglas del controlador cada 5 segundos y aplica la política de **primera coincidencia por prioridad** (mayor número = mayor prioridad) sobre el tráfico que recibe.

---

## Estructura del proyecto

```
Proyecto Redes/
├── servidor/
│   ├── server.py           # Controlador SDN (Flask)
│   ├── config.json         # Configuración del servidor
│   ├── requirements.txt
│   └── static/
│       └── index.html      # Interfaz web de monitoreo
│
├── cliente/
│   ├── client.py           # Nodo cliente (data plane)
│   ├── rule_engine.py      # Motor de reglas SDN
│   ├── config_nodo_B.json  # Configuración nodo-laptop-B
│   ├── config_nodo_C.json  # Configuración nodo-laptop-C
│   ├── config_nodo_D.json  # Configuración nodo-laptop-D
│   └── requirements.txt
│
├── generador/
│   ├── generator.py        # Generador de tráfico UDP/TCP
│   ├── scenarios.json      # Escenarios de prueba predefinidos
│   └── requirements.txt
│
├── regla.py                # CLI para gestión de reglas desde terminal
└── pruebas_evaluacion.py   # Script de las 10 pruebas oficiales
```

---

## Requisitos

- Python 3.9 o superior
- Instalar dependencias en cada componente:

```bash
# Servidor
pip install -r servidor/requirements.txt

# Clientes
pip install -r cliente/requirements.txt

# Generador
pip install -r generador/requirements.txt
```

---

## Cómo ejecutar

### 1. Servidor (PC controlador)

```bash
cd servidor
python server.py
```

El servidor queda disponible en `http://<ip_servidor>:5000`  
La interfaz web de monitoreo se abre en esa misma dirección desde cualquier navegador.

### 2. Nodo cliente (cada laptop)

Cada nodo usa su propio archivo de configuración. Edita el `config_nodo_X.json` correspondiente con la IP del servidor antes de ejecutar:

```bash
cd cliente
python client.py --config config_nodo_B.json   # en laptop B
python client.py --config config_nodo_C.json   # en laptop C
python client.py --config config_nodo_D.json   # en laptop D
```

El cliente se registra automáticamente en el servidor, descarga reglas cada 5 segundos y escucha tráfico en los puertos configurados.

### 3. Generador de tráfico

```bash
# Envío directo por argumentos
python generador/generator.py --ip <ip_destino> --port <puerto> --proto UDP --count 6

# Modo interactivo
python generador/generator.py --interactive

# Escenario predefinido
python generador/generator.py --scenario bloquear_udp

# Listar escenarios disponibles
python generador/generator.py --list
```

### 4. Gestión de reglas desde terminal

```bash
# Listar reglas activas
python regla.py listar

# Crear una regla
python regla.py crear --nombre "Bloquear UDP 5002" --prioridad 20 --accion drop --proto UDP --puerto 5002

# Crear regla con IP origen/destino
python regla.py crear --nombre "Bloquear A hacia B" --prioridad 30 --accion drop --src 10.23.62.167 --dst 10.23.41.58 --puerto 5003

# Eliminar una regla por ID
python regla.py borrar --id <rule_id>

# Eliminar todas las reglas
python regla.py limpiar
```

---

## Campos de una regla

| Campo | Descripción | Ejemplo |
|-------|-------------|---------|
| `nombre` | Identificador de la regla | `"Bloquear UDP 5002"` |
| `prioridad` | Mayor número = mayor prioridad. También acepta Alta/Media/Baja | `20`, `Alta` |
| `accion` | Qué hacer con el paquete | `forward`, `drop`, `report` |
| `proto` | Protocolo | `UDP`, `TCP`, `*` |
| `src` | IP origen | `10.23.62.167`, `*` |
| `dst` | IP destino | `10.23.41.58`, `*` |
| `psrc` | Puerto origen | `9000`, `*` |
| `puerto` | Puerto destino | `5001`, `8000-9000` |

---

## Acciones SDN

| Acción | Comportamiento | Genera evento en servidor |
|--------|---------------|--------------------------|
| `forward` | El paquete pasa normalmente | No |
| `drop` | El paquete se descarta | Sí (`block`) |
| `report` | El paquete pasa pero se alerta al controlador | Sí (`report`) |

Sin regla coincidente → se aplica `forward` por defecto.

---

## Pruebas de evaluación

El script `pruebas_evaluacion.py` contiene las 10 pruebas oficiales:

```bash
python pruebas_evaluacion.py            # menú interactivo
python pruebas_evaluacion.py --prueba 3 # ejecuta solo la prueba 3
python pruebas_evaluacion.py --todas    # ejecuta las 10 en orden
```

| # | Prueba | Pts |
|---|--------|-----|
| 1 | Registro de nodos activos | 2.5 |
| 2 | Permiso UDP puerto 5001 | 4 |
| 3 | Bloqueo UDP puerto 5002 | 4 |
| 4 | Permiso TCP puerto 8080 | 4 |
| 5 | Bloqueo TCP puerto 8081 | 4 |
| 6 | Bloqueo por IP origen (puerto 5003) | 5 |
| 7 | Reporte sin bloqueo UDP 7700 | 5 |
| 8 | Conflicto resuelto por prioridad UDP 8000 | 6.5 |
| 9 | Actualización dinámica sin reiniciar clientes | 7.5 |
| 10 | Prueba integral multicliente | 7.5 |

---

## IPs de la red de prueba

| Nodo | IP | Puerto |
|------|----|--------|
| Servidor / Controlador | `10.23.36.87` | `5000` |
| nodo-laptop-B (Cliente A) | `10.23.62.167` | `9000` |
| nodo-laptop-C (Cliente B) | `10.23.41.58` | `9000` |
| nodo-laptop-D (Cliente C) | `10.23.55.191` | `9000` |

---

## Autores

Universidad del Rosario — Proyecto Final Redes de Computadores  
2026
