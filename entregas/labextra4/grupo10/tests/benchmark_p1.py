#!/usr/bin/env python3
"""Benchmark sintético para P1 del Lab Extra 4.

Compara 20 candidatos de diccionario puro y 20 variantes generadas por una
regla, usando el mismo salt y las mismas condiciones. Incluye MD5/SHA-256 como
referencia rápida y PBKDF2-HMAC-SHA-256 con 200.000 iteraciones. No lee el caso
del laboratorio ni ejecuta una búsqueda exhaustiva.
"""

from __future__ import annotations

import platform
import sys
import time
from pathlib import Path


DELIVERY_ROOT = Path(__file__).resolve().parents[1]
if str(DELIVERY_ROOT) not in sys.path:
    sys.path.insert(0, str(DELIVERY_ROOT))
from src.cracker import ITER_PBKDF2, hash_de


SALT = bytes.fromhex("a4" * 16)  # Sintético y reproducible; no usar en producción.
SALT_HEX = SALT.hex()
FAST_REPEATS = 1_000
DICTIONARY_CANDIDATES = [
    "mate", "rio", "luna", "nube", "cafe", "libro", "teclado", "cielo",
    "campo", "verde", "mar", "sol", "faro", "pampa", "sur", "delta",
    "puente", "roble", "arco", "norte",
]
RULE_CANDIDATES = [
    f"{lemma}{year}"
    for lemma in ("mate", "rio", "luna", "nube", "cafe", "libro", "teclado", "cielo", "campo", "verde")
    for year in (2024, 2025)
]


def measure(algorithm: str, label: str, candidates: list[str], repeats: int) -> tuple[float, int, float]:
    started = time.perf_counter()
    for _ in range(repeats):
        for candidate in candidates:
            hash_de(algorithm, SALT_HEX, candidate)
    elapsed = time.perf_counter() - started
    count = len(candidates) * repeats
    rate = count / elapsed if elapsed else float("inf")
    print(f"{algorithm:12} | {label:22} | únicos={len(candidates):2} | evaluaciones={count:6} | segundos={elapsed:.6f} | evaluaciones/s={rate:.3f}")
    return elapsed, count, rate


def main() -> int:
    for label, candidates in (("diccionario puro", DICTIONARY_CANDIDATES), ("con regla de año", RULE_CANDIDATES)):
        if len(candidates) != 20 or len(set(candidates)) != 20:
            raise RuntimeError(f"El conjunto '{label}' debe tener exactamente 20 candidatos únicos")

    print("Benchmark sintético Lab Extra 4 — no exhaustivo")
    print(f"Python: {sys.version.split()[0]} | SO: {platform.platform()} | CPU: {platform.processor() or 'no informado'}")
    print(f"Salt común: {SALT_HEX} | Candidatos únicos por conjunto: 20 | PBKDF2 iteraciones: {ITER_PBKDF2}")
    print(f"MD5/SHA-256 repiten la muestra {FAST_REPEATS} veces para estabilizar el cronómetro; PBKDF2 procesa cada candidato una vez.")
    for algorithm in ("md5", "sha256"):
        measure(algorithm, "diccionario puro", DICTIONARY_CANDIDATES, FAST_REPEATS)
        measure(algorithm, "con regla de año", RULE_CANDIDATES, FAST_REPEATS)
    measure("pbkdf2", "diccionario puro", DICTIONARY_CANDIDATES, 1)
    measure("pbkdf2", "con regla de año", RULE_CANDIDATES, 1)
    print("PBKDF2 procesa exactamente 20 candidatos por conjunto; esa muestra no se extrapola a una búsqueda exhaustiva.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
