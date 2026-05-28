# =============================================================================
#  test_fase5.py  —  Proyecto Redes/
#
#  Pruebas unitarias del Motor de Reglas SDN — Fase 5
#  Valida field_matches(), evaluate_packet() y apply_action()
#  sin necesidad de red ni servidor activo.
#
#  Uso:
#    python test_fase5.py
# =============================================================================

import sys
import os

# Agregar la carpeta cliente al path para importar rule_engine
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "cliente"))

from rule_engine import field_matches, evaluate_packet, apply_action

# ── Colores ────────────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"

def c(text, color): return f"{color}{text}{C.RESET}"

# ── Utilidades de test ─────────────────────────────────────────────────────────

passed = 0
failed = 0

def check(nombre, resultado, esperado):
    global passed, failed
    ok = resultado == esperado
    if ok:
        passed += 1
        print(c(f"  ✓ {nombre}", C.GREEN))
    else:
        failed += 1
        print(c(f"  ✗ {nombre}", C.RED))
        print(c(f"      Esperado: {esperado}  |  Obtenido: {resultado}", C.YELLOW))

def seccion(titulo):
    print()
    print(c(f"── {titulo} {'─' * (55 - len(titulo))}", C.BOLD + C.CYAN))

# ── Regla de prueba helper ─────────────────────────────────────────────────────

def regla(nombre, prioridad, accion, **match_fields):
    base = {"ip_src":"*","ip_dst":"*","protocol":"*",
            "port_src":"*","port_dst":"*","ingress":"*",
            "mac_src":"*","mac_dst":"*"}
    base.update(match_fields)
    return {"id": nombre, "name": nombre, "priority": prioridad,
            "action": accion, "match": base}

def paquete(**kwargs):
    base = {"ip_src":"10.0.0.1","ip_dst":"10.0.0.2","protocol":"UDP",
            "port_src":"5000","port_dst":"9000","ingress":"eth0",
            "mac_src":"AA:BB:CC:DD:EE:01","mac_dst":"AA:BB:CC:DD:EE:02",
            "size":64,"payload":"test"}
    base.update(kwargs)
    return base

# =============================================================================
#  BLOQUE 1 — field_matches: Wildcards y valores exactos
# =============================================================================

seccion("BLOQUE 1 — Wildcards y valores exactos")

check("Wildcard * coincide con cualquier IP",
      field_matches("ip_src", "*", "10.23.36.87"), True)

check("IP exacta coincide",
      field_matches("ip_src", "10.23.36.87", "10.23.36.87"), True)

check("IP exacta NO coincide con diferente",
      field_matches("ip_src", "10.23.36.87", "10.23.36.88"), False)

check("Protocolo exacto UDP coincide",
      field_matches("protocol", "UDP", "UDP"), True)

check("Protocolo insensible a mayúsculas",
      field_matches("protocol", "udp", "UDP"), True)

check("Puerto exacto coincide",
      field_matches("port_dst", "9000", "9000"), True)

check("Puerto exacto NO coincide",
      field_matches("port_dst", "9000", "8080"), False)

# =============================================================================
#  BLOQUE 2 — field_matches: Wildcards de prefijo
# =============================================================================

seccion("BLOQUE 2 — Wildcards de prefijo (192.168.*)")

check("Prefijo 10.23.* coincide con 10.23.36.87",
      field_matches("ip_src", "10.23.*", "10.23.36.87"), True)

check("Prefijo 10.23.* NO coincide con 10.24.0.1",
      field_matches("ip_src", "10.23.*", "10.24.0.1"), False)

check("Prefijo 10.* coincide con cualquier 10.x.x.x",
      field_matches("ip_src", "10.*", "10.99.1.254"), True)

# =============================================================================
#  BLOQUE 3 — field_matches: Notación CIDR
# =============================================================================

seccion("BLOQUE 3 — Notación CIDR (192.168.0.0/24)")

check("CIDR 10.23.0.0/16 contiene 10.23.36.87",
      field_matches("ip_src", "10.23.0.0/16", "10.23.36.87"), True)

check("CIDR 10.23.0.0/16 NO contiene 10.24.0.1",
      field_matches("ip_src", "10.23.0.0/16", "10.24.0.1"), False)

check("CIDR 10.0.0.0/8 contiene 10.23.36.87",
      field_matches("ip_src", "10.0.0.0/8", "10.23.36.87"), True)

check("CIDR 192.168.0.0/16 NO contiene 10.23.36.87",
      field_matches("ip_src", "192.168.0.0/16", "10.23.36.87"), False)

# =============================================================================
#  BLOQUE 4 — field_matches: Rangos de puertos
# =============================================================================

seccion("BLOQUE 4 — Rangos de puertos (8000-9000)")

check("Rango 8000-9000 contiene 9000",
      field_matches("port_dst", "8000-9000", "9000"), True)

check("Rango 8000-9000 contiene 8000 (límite inferior)",
      field_matches("port_dst", "8000-9000", "8000"), True)

check("Rango 8000-9000 NO contiene 9001",
      field_matches("port_dst", "8000-9000", "9001"), False)

check("Rango 1-1024 contiene 80",
      field_matches("port_dst", "1-1024", "80"), True)

# =============================================================================
#  BLOQUE 5 — field_matches: Direcciones MAC
# =============================================================================

seccion("BLOQUE 5 — Direcciones MAC")

check("MAC exacta coincide",
      field_matches("mac_src", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:01"), True)

check("MAC insensible a mayúsculas",
      field_matches("mac_src", "aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:01"), True)

check("MAC diferente NO coincide",
      field_matches("mac_src", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:FF"), False)

check("MAC wildcard * coincide con cualquier MAC",
      field_matches("mac_src", "*", "AA:BB:CC:DD:EE:01"), True)

# =============================================================================
#  BLOQUE 6 — evaluate_packet: Prioridad (first-match)
# =============================================================================

seccion("BLOQUE 6 — Prioridad Alta > Media > Baja")

reglas_prioridad = [
    regla("Drop Baja",    "Baja",  "drop",    port_dst="9000"),
    regla("Report Media", "Media", "report",  port_dst="9000"),
    regla("Forward Alta", "Alta",  "forward", port_dst="9000"),
]

resultado = evaluate_packet(paquete(port_dst="9000"), reglas_prioridad)
check("Con Alta+Media+Baja gana Alta (forward)",
      resultado["name"] if resultado else None, "Forward Alta")

reglas_sin_alta = [
    regla("Drop Baja",    "Baja",  "drop",   port_dst="9000"),
    regla("Report Media", "Media", "report", port_dst="9000"),
]
resultado = evaluate_packet(paquete(port_dst="9000"), reglas_sin_alta)
check("Sin Alta, gana Media (report)",
      resultado["name"] if resultado else None, "Report Media")

resultado = evaluate_packet(paquete(port_dst="9000"), [regla("Drop Baja","Baja","drop",port_dst="9000")])
check("Solo Baja, gana Baja (drop)",
      resultado["name"] if resultado else None, "Drop Baja")

# =============================================================================
#  BLOQUE 7 — evaluate_packet: Sin coincidencia
# =============================================================================

seccion("BLOQUE 7 — Sin coincidencia (None)")

reglas_tcp = [regla("Solo TCP","Alta","drop", protocol="TCP")]
resultado  = evaluate_packet(paquete(protocol="UDP"), reglas_tcp)
check("Paquete UDP no coincide con regla TCP → None",
      resultado, None)

resultado = evaluate_packet(paquete(), [])
check("Sin reglas → None",
      resultado, None)

# =============================================================================
#  BLOQUE 8 — evaluate_packet: Coincidencia por campos específicos
# =============================================================================

seccion("BLOQUE 8 — Coincidencia multifcampo")

reglas_multi = [
    regla("Match exacto", "Alta", "drop",
          ip_src="10.23.36.87", protocol="UDP", port_dst="9000"),
]

check("Paquete que cumple todos los campos → coincide",
      evaluate_packet(
          paquete(ip_src="10.23.36.87", protocol="UDP", port_dst="9000"),
          reglas_multi
      )["name"], "Match exacto")

check("Paquete con IP diferente → no coincide",
      evaluate_packet(
          paquete(ip_src="10.23.36.88", protocol="UDP", port_dst="9000"),
          reglas_multi
      ), None)

check("Paquete con protocolo diferente → no coincide",
      evaluate_packet(
          paquete(ip_src="10.23.36.87", protocol="TCP", port_dst="9000"),
          reglas_multi
      ), None)

# =============================================================================
#  BLOQUE 9 — apply_action: Las tres acciones
# =============================================================================

seccion("BLOQUE 9 — Acciones: forward, drop, report")

stats = {"packets_received":0,"packets_forwarded":0,
         "packets_dropped":0,"packets_reported":0,"packets_no_match":0}
eventos = []

def mock_event(tipo, rule, detail):
    eventos.append({"tipo": tipo, "rule": rule["name"] if rule else None})

# forward
r_forward = regla("Permitir todo","Alta","forward")
apply_action(r_forward, paquete(), stats, mock_event)
check("forward → packets_forwarded incrementa",
      stats["packets_forwarded"], 1)
check("forward → no genera evento",
      len(eventos), 0)

# drop
r_drop = regla("Bloquear todo","Alta","drop")
apply_action(r_drop, paquete(), stats, mock_event)
check("drop → packets_dropped incrementa",
      stats["packets_dropped"], 1)
check("drop → genera evento 'block'",
      eventos[-1]["tipo"], "block")

# report
r_report = regla("Reportar todo","Alta","report")
apply_action(r_report, paquete(), stats, mock_event)
check("report → packets_reported incrementa",
      stats["packets_reported"], 1)
check("report → genera evento 'report'",
      eventos[-1]["tipo"], "report")

# Sin regla → forward por defecto
apply_action(None, paquete(), stats, mock_event)
check("Sin regla (None) → forward por defecto",
      stats["packets_forwarded"], 2)

# =============================================================================
#  RESUMEN FINAL
# =============================================================================

total = passed + failed
print()
print(c("=" * 62, C.BOLD))
print(c(f"  RESULTADO FASE 5 — Motor de Reglas SDN", C.BOLD))
print(c("=" * 62, C.BOLD))
print(c(f"  ✓ Pruebas pasadas : {passed}/{total}", C.GREEN))
if failed:
    print(c(f"  ✗ Pruebas fallidas: {failed}/{total}", C.RED))
else:
    print(c("  🎉 Todas las pruebas pasaron correctamente", C.GREEN))
print(c("=" * 62, C.BOLD))
print()

sys.exit(0 if failed == 0 else 1)
