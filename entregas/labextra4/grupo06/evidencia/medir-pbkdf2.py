#!/usr/bin/env python3
"""Mide 20 cálculos PBKDF2-HMAC-SHA256 de prueba para el aporte P4.

Usa el salt de root del caso, pero no compara candidatos con el hash ni busca
recuperar esa contraseña. Solo requiere Python y la biblioteca estándar.
"""
import hashlib
import platform
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SOMBRA = ROOT / "labs/labextra4-cracking/caso/sombra.txt"
DICCIONARIO = ROOT / "labs/labextra4-cracking/caso/diccionario.txt"
ITERACIONES = 200_000
CANTIDAD = 20


def datos_root():
    with SOMBRA.open(encoding="utf-8-sig") as archivo:
        for linea in archivo:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            usuario, algoritmo, salt_hex, _hash_hex = linea.split(":")
            if usuario == "root":
                if "pbkdf2" not in algoritmo.lower():
                    raise ValueError("El registro root no declara PBKDF2")
                return bytes.fromhex(salt_hex)
    raise ValueError("No se encontró el registro root en el caso")


def contar_candidatos():
    with DICCIONARIO.open(encoding="utf-8-sig") as archivo:
        return sum(
            1 for linea in archivo
            if linea.strip() and not linea.lstrip().startswith("#")
        )


def main():
    salt = datos_root()
    candidatos = [f"p4-control-{i:02d}".encode("utf-8") for i in range(CANTIDAD)]

    inicio = time.perf_counter()
    for candidato in candidatos:
        hashlib.pbkdf2_hmac("sha256", candidato, salt, ITERACIONES)
    segundos = time.perf_counter() - inicio

    print(f"Python: {platform.python_version()}")
    print(f"Sistema: {platform.platform()}")
    print(f"Procesador: {platform.processor() or 'no informado'}")
    print(f"Algoritmo: PBKDF2-HMAC-SHA256, iteraciones={ITERACIONES}")
    print(f"Sample: {CANTIDAD} synthetic candidates; no comparison or cracking")
    print(f"Dictionary candidates: {contar_candidatos()}")
    print(f"Measured total time: {segundos:.6f} s")
    print(f"Measured rate: {CANTIDAD / segundos:.2f} candidates/s")
    print(f"Average: {segundos * 1000 / CANTIDAD:.3f} ms/candidate")


if __name__ == "__main__":
    main()
