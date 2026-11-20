#!/usr/bin/env python3
"""Medición CPU local de las operaciones de hash descritas por el lab."""
import hashlib
import platform
import statistics
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
DICTIONARY = ROOT / "labs" / "labextra4-cracking" / "caso" / "diccionario.txt"
ITERATIONS = 200_000
SALT = bytes.fromhex("73346c372d3031")
REPEATS = 3


def md5_candidate(password: bytes) -> bytes:
    return hashlib.md5(SALT + password).digest()


def sha256_candidate(password: bytes) -> bytes:
    return hashlib.sha256(SALT + password).digest()


def pbkdf2_candidate(password: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, SALT, ITERATIONS)


def measure(function, attempts: int) -> tuple[float, list[float]]:
    candidates = [f"lab-candidate-{index:03d}".encode() for index in range(attempts)]
    function(candidates[0])  # Calentar hashlib antes de medir.
    rates = []
    for _ in range(REPEATS):
        started = time.perf_counter()
        for candidate in candidates:
            function(candidate)
        elapsed = time.perf_counter() - started
        rates.append(attempts / elapsed)
    return statistics.median(rates), rates


def main() -> None:
    dictionary_size = sum(1 for line in DICTIONARY.read_text(encoding="utf-8").splitlines() if line.strip())
    specs = (("MD5(salt||password)", md5_candidate, 1_000),
             ("SHA-256(salt||password)", sha256_candidate, 1_000),
             ("PBKDF2-HMAC-SHA256, 200000 iter", pbkdf2_candidate, 20))

    print(f"CPU: {platform.processor() or platform.machine()}")
    print(f"Python: {platform.python_version()} | Sistema: {platform.platform()}")
    print(f"Método: {REPEATS} repeticiones, mediana de intentos/s; sin E/S ni comparación del cracker.")
    print(f"Candidatos medidos por repetición: 1000 para MD5/SHA-256; 20 para PBKDF2-200000.")
    print(f"Diccionario real: {dictionary_size} entradas no vacías ({DICTIONARY.name}).")
    print("Sal para prueba: 73346c372d3031 (solo dato público de laboratorio).")
    print()
    for label, function, count in specs:
        median_rate, rates = measure(function, count)
        estimate = dictionary_size / median_rate
        print(f"{label}: {median_rate:.2f} intentos/s; repeticiones={','.join(f'{rate:.2f}' for rate in rates)}")
        print(f"  proyección CPU para {dictionary_size} candidatos: {estimate:.6f} s")


if __name__ == "__main__":
    main()
