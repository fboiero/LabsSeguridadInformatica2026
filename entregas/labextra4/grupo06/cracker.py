#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
cracker.py — Lab Extra 4. Tu cracker de contraseñas. Solo biblioteca estándar.

Looteaste `caso/sombra.txt` de phantomcorp-web: un volcado de hashes con sus
algoritmos y salts. Tu trabajo: recuperar las contraseñas y con ellas abrir el
loot cifrado de cada usuario (`caso/loot/<usuario>.enc`).

Completá los TODO. NO cambies las firmas ni la CLI.
`descifrar_loot()` ya viene implementada como referencia: leela.

Uso:
  python3 cracker.py crackear caso/sombra.txt caso/diccionario.txt
  python3 cracker.py descifrar caso/loot/operador.enc --password riverplate

Extra (R3): la contraseña del admin NO está literal en el diccionario.
Implementá reglas de "mangling" en `aplicar_reglas()`: sufijos de año, de
números, mayúscula inicial, etc.
"""
import argparse
import hashlib
import sys

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
    """Calcula el hash de un candidato EXACTAMENTE como lo hizo el servidor.
    Pista: md5/sha256 son hash(salt_bytes + password); pbkdf2 usa
    hashlib.pbkdf2_hmac('sha256', password, salt, ITER_PBKDF2)."""
    salt = bytes.fromhex(salt_hex)
    password_bytes = password.encode("utf-8")
    algoritmo = algo.lower()

    if algoritmo == "md5":
        return hashlib.md5(salt + password_bytes).hexdigest()
    if algoritmo == "sha256":
        return hashlib.sha256(salt + password_bytes).hexdigest()
    if algoritmo == "pbkdf2":
        return hashlib.pbkdf2_hmac(
            "sha256", password_bytes, salt, ITER_PBKDF2
        ).hex()
    raise ValueError(f"Algoritmo no soportado: {algo}")



def cargar_sombra(ruta: str) -> list:
    """Lee el volcado y devuelve (usuario, algoritmo, salt, hash)."""
    registros = []

    with open(ruta, "r", encoding="utf-8-sig") as archivo:
        for numero, linea in enumerate(archivo, start=1):
            linea = linea.strip()

            if not linea or linea.startswith("#"):
                continue

            partes = linea.split(":")
            if len(partes) != 4:
                raise ValueError(
                    f"Formato invalido en linea {numero}: se esperan 4 campos"
                )

            usuario, algo, salt_hex, hash_hex = partes
            registros.append((usuario, algo, salt_hex, hash_hex))

    return registros



def aplicar_reglas(palabra: str) -> list:
    """Dado un lemma del diccionario, devolvé variantes probables:
    la palabra sola, palabra+año (2024..2026), palabra+números comunes
    (1, 12, 123), palabra con mayúscula inicial... Agregá las que se te ocurran.
    Esto es lo que john hace con --rules y hashcat con -r."""
    # Orden estable y cantidad acotada; sin candidatos de cuentas concretas.
    sufijos = ("", "2024", "2025", "2026", "1", "12", "123")
    bases = (palabra, palabra.capitalize(), palabra.lower(), palabra.upper())
    variantes = []
    vistas = set()
    for base in bases:
        for sufijo in sufijos:
            candidato = base + sufijo
            if candidato not in vistas:
                vistas.add(candidato)
                variantes.append(candidato)
    return variantes



def crackear(sombra: list, diccionario: str, con_reglas: bool = False) -> dict:
    """Prueba candidatos del diccionario contra el volcado ficticio."""
    halladas = {}
    pendientes = []

    for usuario, algo, salt_hex, hash_hex in sombra:
        if algo.lower().startswith("pbkdf2"):
            print(f"[INFO] {usuario}: PBKDF2 omitido en corrida general")
            continue

        pendientes.append((usuario, algo, salt_hex, hash_hex))

    with open(diccionario, "r", encoding="utf-8-sig") as archivo:
        for linea in archivo:
            palabra = linea.strip()

            if not palabra or palabra.startswith("#"):
                continue

            candidatos = (
                aplicar_reglas(palabra) if con_reglas else [palabra]
            )

            for candidato in candidatos:
                for usuario, algo, salt_hex, hash_hex in pendientes[:]:
                    calculado = hash_de(algo, salt_hex, candidato)

                    if calculado.lower() == hash_hex.lower():
                        halladas[usuario] = candidato
                        pendientes.remove(
                            (usuario, algo, salt_hex, hash_hex)
                        )
                        print(f"[OK] {usuario}: coincidencia encontrada")

                if not pendientes:
                    break

            if not pendientes:
                break

    print(f"[INFO] Recuperadas: {len(halladas)} de {len(sombra)}")
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
