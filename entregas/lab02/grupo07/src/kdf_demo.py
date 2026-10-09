#!/usr/bin/env python3
"""Mini-research Lab 02 — Demo: por que sha256(password) no alcanza.

Compara, solo con biblioteca estandar, cuanto cuesta verificar UNA contrasena
con cada esquema. Ese costo es el que paga el atacante por cada intento en un
ataque offline sobre una base de datos filtrada.

Uso:
    python3 src/kdf_demo.py
"""
import hashlib
import secrets
import time

PASSWORD = b"Phantom-Guest-2026"
SALT = secrets.token_bytes(16)
REPETICIONES = 20


def medir(nombre, fn):
    t0 = time.perf_counter()
    for _ in range(REPETICIONES):
        fn()
    por_intento = (time.perf_counter() - t0) / REPETICIONES
    intentos_seg = 1 / por_intento
    print(f"{nombre:<34} {por_intento*1000:>9.3f} ms/intento  ~{intentos_seg:>12,.0f} intentos/s")


def main():
    print(f"Contrasena de prueba: {PASSWORD.decode()}  (salt de {len(SALT)} bytes)\n")

    # 1) Lo que NO hay que hacer: hash rapido, sin salt.
    medir("sha256(password)", lambda: hashlib.sha256(PASSWORD).digest())

    # 2) Salt sola: evita tablas precalculadas, pero sigue siendo rapido.
    medir("sha256(salt || password)", lambda: hashlib.sha256(SALT + PASSWORD).digest())

    # 3) PBKDF2-HMAC-SHA256, 600.000 iteraciones (OWASP 2024).
    medir("pbkdf2_hmac sha256, c=600000",
          lambda: hashlib.pbkdf2_hmac("sha256", PASSWORD, SALT, 600_000))

    # 4) scrypt, N=2^17, r=8, p=1 (128 MiB, OWASP). Memory-hard.
    medir("scrypt N=2^17 r=8 p=1 (128 MiB)",
          lambda: hashlib.scrypt(PASSWORD, salt=SALT, n=2**17, r=8, p=1,
                                 maxmem=256 * 1024 * 1024))

    print("\nLectura: el atacante paga el mismo costo por cada intento que el")
    print("servidor por cada login. Con sha256 puro, un solo GPU hace ~2e10")
    print("intentos/s; con una KDF lenta y memory-hard, unos pocos miles.")


if __name__ == "__main__":
    main()
