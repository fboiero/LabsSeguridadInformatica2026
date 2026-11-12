#!/usr/bin/env python3
"""P2 evidence: measure the offline crack, reproducibly and without touching the
server. Imports the group's own crackear_secreto from jwt_tool.py and times it.

Usage:  python3 parte2-medir-crack.py <token> <diccionario>
"""
import importlib.util
import os
import sys
import time

AQUI = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(AQUI, "..", "..", "src", "jwt_tool.py")
spec = importlib.util.spec_from_file_location("jwt_tool", TOOL)
jwt_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jwt_tool)

token, diccionario = sys.argv[1], sys.argv[2]

with open(diccionario, encoding="utf-8") as fh:
    palabras = [ln.strip() for ln in fh if ln.strip()]

# position of the hit (over the raw words), for the report
hit = next((i + 1 for i, w in enumerate(palabras)
            if jwt_tool.firma_es_valida(token, w.encode())), None)

N = 1000

# (1) Full operation as the CLI runs it: open+read the dictionary, iterate words
#     with mangling until the HMAC matches.
t0 = time.perf_counter()
for _ in range(N):
    secreto = jwt_tool.crackear_secreto(token, diccionario)
dt_full = (time.perf_counter() - t0) / N

# (2) Pure crypto only: the HMAC verifications up to the hit, dictionary already
#     in memory, no file I/O. This is what dominates once the wordlist is loaded.
t0 = time.perf_counter()
for _ in range(N):
    for w in palabras:
        if jwt_tool.firma_es_valida(token, w.encode()):
            break
dt_cripto = (time.perf_counter() - t0) / N

print("### P2 - medicion del crack offline (cero requests al servidor)")
print(f"secreto encontrado : {secreto}")
print(f"palabras en el diccionario: {len(palabras)}")
print(f"palabra cruda #{hit} es el secreto (sin reglas de mangling)")
print(f"(1) operacion completa (abre+lee el diccionario cada vez): "
      f"{dt_full*1000:.3f} ms")
print(f"(2) solo las verificaciones HMAC hasta el acierto (sin I/O): "
      f"{dt_cripto*1000:.4f} ms")
print(f"promedio de {N} corridas. python: {sys.version.split()[0]}")
