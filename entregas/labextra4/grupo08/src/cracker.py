#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
cracker.py — Lab Extra 4. Cracker de contraseñas del grupo08. Solo stdlib.

Looteamos `caso/sombra.txt` de phantomcorp-web: un volcado de hashes con sus
algoritmos y salts. El trabajo: recuperar las contraseñas y con ellas abrir el
loot cifrado de cada usuario (`caso/loot/<usuario>.enc`).

Uso:
  python3 cracker.py crackear caso/sombra.txt caso/diccionario.txt
  python3 cracker.py crackear caso/sombra.txt caso/diccionario.txt --reglas
  python3 cracker.py descifrar caso/loot/operador.enc --password riverplate
"""
import argparse
import hashlib
import sys

ITER_PBKDF2 = 200_000   # tiene que coincidir con sombra.txt


# ---------------------------------------------------------------------------
# REFERENCIA (venía implementada). XOR involutivo contra sha256(password).
# ---------------------------------------------------------------------------
def descifrar_loot(hex_cifrado: str, password: str) -> str:
    """El loot se cifró con XOR contra sha256(password) repetido.
    XOR es involutivo: con la contraseña correcta, esto devuelve el texto."""
    clave = hashlib.sha256(password.encode()).digest()
    datos = bytes.fromhex(hex_cifrado.strip())
    return bytes(b ^ clave[i % len(clave)] for i, b in enumerate(datos)).decode("utf-8", "ignore")


def hash_de(algo: str, salt_hex: str, password: str) -> str:
    """Calcula el hash de un candidato EXACTAMENTE como lo hizo el servidor.
    md5/sha256: hash(salt_bytes + password). pbkdf2: pbkdf2_hmac sobre sha256
    con ITER_PBKDF2 iteraciones. El salt viaja en hex en sombra.txt."""
    salt = bytes.fromhex(salt_hex)
    if algo == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITER_PBKDF2).hex()
    h = hashlib.new(algo)
    h.update(salt + password.encode())
    return h.hexdigest()


def cargar_sombra(ruta: str) -> list:
    """Parsea sombra.txt → lista de tuplas (usuario, algo, salt_hex, hash_hex).
    Ignora líneas vacías y comentarios (#). Formato: usuario:algo:salt:hash."""
    filas = []
    with open(ruta, encoding="utf-8") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            usuario, algo, salt_hex, hash_hex = linea.split(":")
            filas.append((usuario, algo, salt_hex, hash_hex))
    return filas


def aplicar_reglas(palabra: str) -> list:
    """Dado un lemma del diccionario, genera variantes probables (mangling):
    la palabra tal cual, capitalizada, en mayúsculas, y con sufijos típicos que
    la gente agrega para "cumplir la política" (año, 123, !, etc.).
    Es una versión mini de lo que hace john con --rules y hashcat con -r.
    `phantom` no da la del admin, pero `phantom`+`2026` = `phantom2026` sí."""
    variantes = []

    def add(x):
        if x and x not in variantes:
            variantes.append(x)

    bases = [palabra, palabra.capitalize(), palabra.upper()]
    # sufijos que cubren "palabra + año" y "palabra + números/símbolo"
    sufijos = ["", "1", "12", "123", "1234", "12345", "!", "123!", "01", "00",
               "007", "2023", "2024", "2025", "2026"]
    for base in bases:
        for suf in sufijos:
            add(base + suf)
    return variantes


def crackear(sombra: list, diccionario: str, con_reglas: bool = False) -> dict:
    """Ataque de diccionario (+ reglas si con_reglas) contra cada usuario.
    pbkdf2 se OMITE a propósito: 200.000 iteraciones por intento hacen inviable
    el diccionario entero (es la P4). Devuelve {usuario: password}."""
    with open(diccionario, encoding="utf-8") as fh:
        palabras = [l.strip() for l in fh if l.strip()]

    halladas = {}
    for usuario, algo, salt_hex, hash_hex in sombra:
        if algo == "pbkdf2":
            print(f"  … {usuario} ({algo}): 200k iteraciones/intento — diccionario "
                  f"entero inviable, se omite (ver P4)")
            continue
        encontrada = None
        intentos = 0
        for palabra in palabras:
            candidatos = aplicar_reglas(palabra) if con_reglas else [palabra]
            for cand in candidatos:
                intentos += 1
                if hash_de(algo, salt_hex, cand) == hash_hex:
                    encontrada = cand
                    break
            if encontrada:
                break
        if encontrada:
            halladas[usuario] = encontrada
            print(f"  ✓ {usuario} ({algo}) cayó en {intentos} intentos: {encontrada}")
        else:
            print(f"  ✗ {usuario} ({algo}) no cayó tras {intentos} intentos")
    return halladas


def main() -> int:
    ap = argparse.ArgumentParser(description="Cracker de contraseñas (Lab Extra 4)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("crackear", help="atacar un volcado de hashes")
    c.add_argument("sombra")
    c.add_argument("diccionario")
    c.add_argument("--reglas", action="store_true", help="aplicar reglas de mangling")
    d = sub.add_parser("descifrar", help="abrir un loot con la contraseña crackeada")
    d.add_argument("loot")
    d.add_argument("--password", required=True)
    args = ap.parse_args()

    if args.cmd == "crackear":
        sombra = cargar_sombra(args.sombra)
        halladas = crackear(sombra, args.diccionario, args.reglas)
        for usuario, _algo, _salt, _h in sombra:
            if usuario in halladas:
                print(f"  ✓ {usuario}: {halladas[usuario]}")
            else:
                print(f"  ✗ {usuario}: no cayó (¿falta una regla? ¿es pbkdf2?)")
        print(f"\n{len(halladas)}/{len(sombra)} contraseñas recuperadas")
    else:
        with open(args.loot) as fh:
            print(descifrar_loot(fh.read(), args.password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
