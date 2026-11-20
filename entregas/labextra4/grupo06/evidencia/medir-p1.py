#!/usr/bin/env python3
"""Valida hash_de() y mide tasas locales para el aporte P1.

Usa los salts y hashes del caso solo para comprobar el contrato de hash. Las
mediciones calculan candidatos sintéticos con hash_de(), sin buscar secretos.
"""
import importlib.util
import platform
import statistics
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CRACKER = ROOT / "entregas/labextra4/grupo06/cracker.py"
SOMBRA = ROOT / "labs/labextra4-cracking/caso/sombra.txt"
DICCIONARIO = ROOT / "labs/labextra4-cracking/caso/diccionario.txt"
# Cada serie respeta la muestra acotada indicada por la consigna. La mediana de
# varias series reduce la influencia del reloj y de la planificación del SO.
MUESTRAS = {
    "md5": (100, 25),
    "sha256": (100, 25),
    "pbkdf2": (20, 3),
}
VECTORES = {
    "md5": "2d339ff09afe6e9ebaa6fe6cfca43c3d",
    "sha256": "3a1514e7852c75e159ee1823adbc73d5810421845b2532ec320cb3661633546e",
    "pbkdf2": "183272f5e383f7d4a2020854968d47759c1e4d6a5e2765661a09f18e1eb632ad",
}
SALT_VECTOR = "00112233"
PASSWORD_VECTOR = "Clave-ß"


def cargar_modulo():
    spec = importlib.util.spec_from_file_location("cracker_p1", CRACKER)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def cargar_registros():
    registros = {}
    with SOMBRA.open(encoding="utf-8-sig") as archivo:
        for linea in archivo:
            linea = linea.strip()
            if linea and not linea.startswith("#"):
                usuario, algoritmo, salt, hash_hex = linea.split(":")
                registros[algoritmo] = (usuario, salt, hash_hex)
    return registros


def candidatos_diccionario():
    with DICCIONARIO.open(encoding="utf-8-sig") as archivo:
        return sum(bool(linea.strip()) and not linea.lstrip().startswith("#")
                   for linea in archivo)


def main():
    cracker = cargar_modulo()
    registros = cargar_registros()
    print(f"Python: {platform.python_version()}")
    print(f"Sistema: {platform.platform()}")
    print(f"Procesador: {platform.processor() or 'no informado'}")
    print(f"Candidatos del diccionario: {candidatos_diccionario()}")

    for algoritmo, (_usuario, salt, esperado) in registros.items():
        obtenido = cracker.hash_de(algoritmo, salt, "p1-control")
        print(f"Contrato {algoritmo}: salida hexadecimal de {len(obtenido)} caracteres")
        if algoritmo != "pbkdf2":
            assert obtenido != esperado, "El candidato de control no debe coincidir"

    for algoritmo, esperado in VECTORES.items():
        obtenido = cracker.hash_de(algoritmo, SALT_VECTOR, PASSWORD_VECTOR)
        assert obtenido == esperado, f"Vector {algoritmo} incorrecto"
        print(f"Vector {algoritmo}: OK")

    for algoritmo, (cantidad, series) in MUESTRAS.items():
        _usuario, salt, _esperado = registros[algoritmo]
        tasas = []
        for serie in range(series):
            inicio = time.perf_counter()
            for indice in range(cantidad):
                cracker.hash_de(
                    algoritmo, salt, f"p1-medicion-{serie:02d}-{indice:03d}"
                )
            segundos = time.perf_counter() - inicio
            tasas.append(cantidad / segundos)
        tasa = statistics.median(tasas)
        print(
            f"Medicion {algoritmo}: {series} series de {cantidad} intentos, "
            f"mediana {tasa:.2f} intentos/s, "
            f"estimacion 49 candidatos: {49 / tasa:.6f} s"
        )

    try:
        cracker.hash_de("invalido", "00", "x")
    except ValueError as error:
        print(f"Algoritmo invalido: {error}")
    else:
        raise AssertionError("Se esperaba ValueError para un algoritmo invalido")


if __name__ == "__main__":
    main()
