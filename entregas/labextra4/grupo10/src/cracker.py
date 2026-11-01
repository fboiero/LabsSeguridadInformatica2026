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
    salt_bytes = bytes.fromhex(salt_hex.strip())
    pwd_bytes = password.encode("utf-8")
    algo_norm = algo.strip().lower()

    if algo_norm == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, ITER_PBKDF2).hex()
    elif algo_norm in ("md5", "sha256"):
        h = hashlib.new(algo_norm)
        h.update(salt_bytes + pwd_bytes)
        return h.hexdigest()
    else:
        raise ValueError(f"Algoritmo no soportado: {algo}")


def cargar_sombra(ruta: str) -> list:
    """Devuelve una lista de tuplas (usuario, algo, salt_hex, hash_hex)
    parseando sombra.txt (ignorá líneas de comentario que empiezan con #)."""
    registros = []
    with open(ruta, "r", encoding="utf-8") as fh:
        for num_linea, linea in enumerate(fh, 1):
            linea_limpia = linea.strip()
            if not linea_limpia or linea_limpia.startswith("#"):
                continue
            partes = [p.strip() for p in linea_limpia.split(":")]
            if len(partes) != 4 or not all(partes):
                raise ValueError(f"Registro inválido en {ruta}:{num_linea}: '{linea_limpia}'")
            usuario, algo, salt_hex, hash_hex = partes
            registros.append((usuario, algo.lower(), salt_hex.lower(), hash_hex.lower()))
    return registros


def aplicar_reglas(palabra: str) -> list:
    """Dado un lemma del diccionario, devolvé variantes probables:
    la palabra sola, palabra+año (2024..2026), palabra+números comunes
    (1, 12, 123), palabra con mayúscula inicial... Agregá las que se te ocurran.
    Esto es lo que john hace con --rules y hashcat con -r."""
    variantes = []

    # 1. Palabra base original (al inicio)
    variantes.append(palabra)

    # 2. Mayúscula inicial
    cap = palabra.capitalize()
    variantes.append(cap)

    # 3. Sufijos de año (2024..2026)
    anios = ["2024", "2025", "2026"]
    for anio in anios:
        variantes.append(palabra + anio)
        variantes.append(cap + anio)

    # 4. Sufijos numéricos comunes (1, 12, 123)
    numeros = ["1", "12", "123"]
    for num in numeros:
        variantes.append(palabra + num)
        variantes.append(cap + num)

    # Deduplicación determinista preservando orden de inserción
    return list(dict.fromkeys(variantes))


def crackear(sombra: list, diccionario: str, con_reglas: bool = False) -> dict:
    """Para cada usuario, probá cada candidato del diccionario (y sus variantes
    si con_reglas=True) hasta que hash_de() coincida con el hash looteado.
    Devolvé {usuario: password} de los que cayeron. Imprimí el progreso.

    OJO con pbkdf2: 200.000 iteraciones por intento. ¿Conviene probarlo con el
    diccionario entero? ¿Qué te dice eso del algoritmo? (Pista: es la P4.)"""
    with open(diccionario, "r", encoding="utf-8") as fh:
        palabras_base = [linea.strip() for linea in fh if linea.strip()]

    if con_reglas:
        candidatos = []
        for p in palabras_base:
            candidatos.extend(aplicar_reglas(p))
        candidatos = list(dict.fromkeys(candidatos))
    else:
        candidatos = palabras_base

    halladas = {}
    total_candidatos = len(candidatos)

    for usuario, algo, salt_hex, hash_esperado in sombra:
        intentos_completados = 0
        es_lento = (algo.lower() == "pbkdf2")

        if es_lento:
            print(f"[*] Evaluando cuenta '{usuario}' ({algo}, {ITER_PBKDF2:,} iteraciones, {total_candidatos} candidatos)...")

        try:
            for idx, cand in enumerate(candidatos, 1):
                if es_lento and (idx % 10 == 0 or idx == 1):
                    print(f"    [pbkdf2] Probando candidato {idx}/{total_candidatos}...", flush=True)

                coincide = (hash_de(algo, salt_hex, cand) == hash_esperado)
                intentos_completados += 1  # Se contabiliza EXCLUSIVAMENTE tras finalizar el cálculo del hash

                if coincide:
                    halladas[usuario] = cand
                    break
        except KeyboardInterrupt:
            candidatos_restantes = total_candidatos - intentos_completados
            print(f"\n[!] BÚSQUEDA INTERRUMPIDA MANUALMENTE EN '{usuario}' ({algo}):")
            print(f"    - Intentos efectivamente completados: {intentos_completados} de {total_candidatos}")
            print(f"    - Candidatos pendientes sin evaluar: {candidatos_restantes}")
            print(f"    - ESTADO: BÚSQUEDA PARCIAL E INCOMPLETA.")
            raise

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
        try:
            sombra = cargar_sombra(args.sombra)
            halladas = crackear(sombra, args.diccionario, args.reglas)
            for usuario, _algo, _salt, _h in sombra:
                if usuario in halladas:
                    print(f"  ✓ {usuario}: {halladas[usuario]}")
                else:
                    print(f"  ✗ {usuario}: no cayó (¿falta una regla? ¿es pbkdf2?)")
            print(f"\n{len(halladas)}/{len(sombra)} contraseñas recuperadas")
        except KeyboardInterrupt:
            print(f"\n[!] PROCESO CANCELADO POR EL USUARIO (Ctrl+C)")
            print(f"    La búsqueda se detuvo antes de completar la evaluación.")
            print(f"    Las cuentas pendientes NO deben considerarse como 'no cayeron'.")
            return 130
    else:
        with open(args.loot) as fh:
            print(descifrar_loot(fh.read(), args.password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
