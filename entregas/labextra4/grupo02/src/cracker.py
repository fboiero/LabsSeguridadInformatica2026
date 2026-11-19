#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
cracker.py — Lab Extra 4. Tu cracker de contraseñas. Solo biblioteca estándar.

Looteaste `caso/sombra.txt` de phantomcorp-web: un volcado de hashes con sus
algoritmos y salts. Tu trabajo: recuperar las contraseñas y con ellas abrir el
loot cifrado de cada usuario (`caso/loot/<usuario>.enc`).

`descifrar_loot()` ya viene implementada como referencia: leela.

Uso:
  python3 cracker.py crackear caso/sombra.txt caso/diccionario.txt
  python3 cracker.py descifrar caso/loot/operador.enc --password riverplate
"""
import argparse
import hashlib
import sys
import time

ITER_PBKDF2 = 200_000   # tiene que coincidir con sombra.txt


# ---------------------------------------------------------------------------
# REFERENCIA (ya implementada). Leela: es la mitad del lab.
# ---------------------------------------------------------------------------
def descifrar_loot(hex_cifrado: str, password: str) -> str:
    """El loot se cifró con XOR contra sha256(password) repetido.
    XOR es involutivo: con la contraseña correcta, esto devuelve el texto."""
    clave = hashlib.sha256(password.encode()).digest()
    datos = bytes.fromhex(hex_cifrado.strip())
    return bytes(b ^ clave[i % len(clave)] for i, b in enumerate(datos)).decode("utf-8", "ignore")


def hash_de(algo: str, salt_hex: str, password: str) -> str:
    """Calcula el hash de un candidato EXACTAMENTE como lo hizo el servidor."""
    salt = bytes.fromhex(salt_hex)
    if algo == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITER_PBKDF2).hex()
    h = hashlib.new(algo)
    h.update(salt + password.encode())
    return h.hexdigest()


def cargar_sombra(ruta: str) -> list:
    """Devuelve una lista de tuplas (usuario, algo, salt_hex, hash_hex)
    parseando sombra.txt (ignorá líneas de comentario que empiezan con #)."""
    resultado = []
    with open(ruta, encoding="utf-8") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            usuario, algo, salt_hex, hash_hex = linea.split(":")
            resultado.append((usuario, algo, salt_hex, hash_hex))
    return resultado


def aplicar_reglas(palabra: str) -> list:
    """Dado un lemma del diccionario, devolvé variantes probables:
    la palabra sola, palabra+año, palabra+números comunes, mayúscula inicial,
    y combinaciones de esas. Esto es lo que john hace con --rules."""
    anios = ["2023", "2024", "2025", "2026"]
    numeros = ["1", "12", "123", "1234"]
    capitalizada = palabra.capitalize()

    variantes = {palabra, capitalizada}
    for sufijo in anios + numeros:
        variantes.add(palabra + sufijo)
        variantes.add(capitalizada + sufijo)
    variantes.add(palabra + "!")
    variantes.add(capitalizada + "!")

    return list(variantes)


def crackear(sombra: list, diccionario: str, con_reglas: bool = False) -> dict:
    """Para cada usuario, probá cada candidato del diccionario (y sus variantes
    si con_reglas=True) hasta que hash_de() coincida con el hash looteado."""
    with open(diccionario, encoding="utf-8") as fh:
        palabras = [p.strip() for p in fh if p.strip() and not p.startswith("#")]

    halladas = {}
    for usuario, algo, salt_hex, hash_hex in sombra:
        print(f"[*] atacando {usuario} ({algo})...")
        inicio = time.time()
        intentos = 0
        encontrada = None

        for palabra in palabras:
            candidatos = aplicar_reglas(palabra) if con_reglas else [palabra]
            for candidato in candidatos:
                intentos += 1
                if hash_de(algo, salt_hex, candidato) == hash_hex:
                    encontrada = candidato
                    break
            if encontrada:
                break

        transcurrido = time.time() - inicio
        velocidad = intentos / transcurrido if transcurrido > 0 else intentos
        if encontrada:
            halladas[usuario] = encontrada
            print(f"    cayó en {intentos} intentos, {transcurrido:.3f}s "
                  f"({velocidad:.0f} intentos/s)")
        else:
            print(f"    no cayó tras {intentos} intentos, {transcurrido:.3f}s "
                  f"({velocidad:.0f} intentos/s)")

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