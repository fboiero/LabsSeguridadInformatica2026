#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""cracker.py — Lab Extra 4 (resuelto, grupo 14). Solo biblioteca estándar."""
import argparse
import hashlib
import sys
import time

ITER_PBKDF2 = 200_000   # tiene que coincidir con sombra.txt


def descifrar_loot(hex_cifrado: str, password: str) -> str:
    """El loot se cifró con XOR contra sha256(password) repetido (involutivo)."""
    clave = hashlib.sha256(password.encode()).digest()
    datos = bytes.fromhex(hex_cifrado.strip())
    return bytes(b ^ clave[i % len(clave)] for i, b in enumerate(datos)).decode("utf-8", "ignore")


def hash_de(algo: str, salt_hex: str, password: str) -> str:
    """Calcula el hash de un candidato igual que el servidor."""
    salt = bytes.fromhex(salt_hex)
    pw = password.encode()
    if algo == "md5":
        return hashlib.md5(salt + pw).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(salt + pw).hexdigest()
    if algo == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", pw, salt, ITER_PBKDF2).hex()
    raise ValueError(f"algoritmo desconocido: {algo}")


def cargar_sombra(ruta: str) -> list:
    """Parsea sombra.txt -> [(usuario, algo, salt_hex, hash_hex)]."""
    filas = []
    with open(ruta) as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            usuario, algo, salt_hex, hash_hex = linea.split(":")
            filas.append((usuario, algo, salt_hex, hash_hex))
    return filas


def aplicar_reglas(palabra: str) -> list:
    """Variantes de mangling tipo john --rules / hashcat -r."""
    variantes = [palabra, palabra.capitalize(), palabra.upper()]
    bases = [palabra, palabra.capitalize()]
    for base in bases:
        for anio in ("2024", "2025", "2026"):
            variantes.append(base + anio)
        for n in ("1", "12", "123", "1234", "!", "123!"):
            variantes.append(base + n)
    # dedup conservando orden
    vistos, out = set(), []
    for v in variantes:
        if v not in vistos:
            vistos.add(v)
            out.append(v)
    return out


def crackear(sombra: list, diccionario: str, con_reglas: bool = False) -> dict:
    with open(diccionario) as fh:
        lemmas = [l.strip() for l in fh if l.strip()]
    halladas = {}
    for usuario, algo, salt_hex, hash_hex in sombra:
        candidatos = []
        for lemma in lemmas:
            candidatos.extend(aplicar_reglas(lemma) if con_reglas else [lemma])
        encontrada = None
        for cand in candidatos:
            if hash_de(algo, salt_hex, cand) == hash_hex:
                encontrada = cand
                break
        if encontrada is not None:
            halladas[usuario] = encontrada
            print(f"  [+] {usuario} ({algo}) -> {encontrada}")
        else:
            print(f"  [-] {usuario} ({algo}) no cayó")
    return halladas


def medir_velocidad(algo: str, salt_hex: str, n: int = 50) -> float:
    """Intentos/segundo estimados para un algoritmo (P1)."""
    t0 = time.perf_counter()
    for i in range(n):
        hash_de(algo, salt_hex, f"prueba{i}")
    dt = time.perf_counter() - t0
    return n / dt if dt else float("inf")


def main() -> int:
    ap = argparse.ArgumentParser(description="Cracker de contraseñas (Lab Extra 4)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("crackear")
    c.add_argument("sombra")
    c.add_argument("diccionario")
    c.add_argument("--reglas", action="store_true")
    d = sub.add_parser("descifrar")
    d.add_argument("loot")
    d.add_argument("--password", required=True)
    m = sub.add_parser("velocidad")
    m.add_argument("sombra")
    args = ap.parse_args()

    if args.cmd == "crackear":
        sombra = cargar_sombra(args.sombra)
        halladas = crackear(sombra, args.diccionario, args.reglas)
        print(f"\n{len(halladas)}/{len(sombra)} contraseñas recuperadas")
    elif args.cmd == "velocidad":
        for usuario, algo, salt_hex, _h in cargar_sombra(args.sombra):
            vps = medir_velocidad(algo, salt_hex)
            print(f"  {algo:8} ~ {vps:,.0f} intentos/segundo")
    else:
        with open(args.loot) as fh:
            print(descifrar_loot(fh.read(), args.password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
