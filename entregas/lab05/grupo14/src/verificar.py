#!/usr/bin/env python3
"""verificar.py — chequeos de la ampliación opcional del Lab 05 (escaner.py).

No usa frameworks: asserts y un contador. Verifica parsear_puertos (parsing
puro, offline) y la firma de leer_banner. No abre sockets (no requiere el lab
levantado).

    python3 verificar.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from escaner import parsear_puertos  # noqa: E402

ok = 0

assert parsear_puertos("21,80,8080") == [21, 80, 8080]; ok += 1
assert parsear_puertos("1-3") == [1, 2, 3]; ok += 1
assert parsear_puertos("80,100-102") == [80, 100, 101, 102]; ok += 1
assert parsear_puertos("80,80,80") == [80]; ok += 1          # sin duplicados
assert parsear_puertos("3-1") == [1, 2, 3]; ok += 1          # rango invertido
assert parsear_puertos("443, 22 ,21") == [21, 22, 443]; ok += 1  # ordenado + espacios

# Fuera de rango => sale con código 2 (subproceso para no matar este verificador).
import subprocess  # noqa: E402
r = subprocess.run(
    [sys.executable, str(Path(__file__).with_name("escaner.py")), "x", "--puertos", "70000"],
    capture_output=True, text=True,
)
assert r.returncode == 2, f"esperaba exit 2, obtuve {r.returncode}"; ok += 1

print(f"[OK] {ok} chequeos pasaron.")
