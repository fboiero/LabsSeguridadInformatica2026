#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
cripto.py — Laboratorio 02. CLI con cuatro subcomandos. Solo biblioteca estándar.

Cada subcomando tiene un bloque TODO que hoy lanza NotImplementedError. Tu trabajo
es completarlos. NO modifiques la firma de las funciones ni la interfaz de la CLI.
La función xor_cifrar() ya está implementada como referencia: leela, es la base de
casi todo el lab.
"""
import argparse
import hashlib
import hmac
import sys

# ---------------------------------------------------------------------------
# REFERENCIA (ya implementada). Leela antes de empezar.
# ---------------------------------------------------------------------------
def xor_cifrar(datos: bytes, clave: bytes) -> bytes:
    """Cifra (y descifra) por XOR de clave repetida. XOR es involutivo:
    aplicar la misma clave dos veces devuelve el original."""
    return bytes(b ^ clave[i % len(clave)] for i, b in enumerate(datos))


# ---------------------------------------------------------------------------
# B.1 — romper XOR de clave de 1 byte por análisis de frecuencia. TODO
# ---------------------------------------------------------------------------
def romper_xor_1byte(cifrado: bytes) -> tuple[int, bytes]:
    """Prueba las 256 claves posibles de 1 byte y devuelve (clave, texto_claro)
    de la más probable de ser lenguaje natural.

    Pista: el texto plano en español/inglés tiene muchísimos espacios y vocales.
    Puntuá cada candidato por cuántos de sus bytes caen en un conjunto de
    caracteres frecuentes (letras comunes + espacio) y quedate con el mejor.
    Esto demuestra por qué un cifrado clásico de clave corta NO protege nada.
    """
    def puntuar_candidato(datos: bytes) -> float:
        score = 0.0
        for b in datos:
            if b == 32:  # espacio (máxima frecuencia en prosa)
                score += 5.0
            elif b in b'eaosrnidltcupEAOSRNIDLTCUP':  # letras más frecuentes en español/inglés
                score += 3.0
            elif (65 <= b <= 90) or (97 <= b <= 122):  # resto de letras ASCII
                score += 2.0
            elif (48 <= b <= 57) or b in b'.,;:!?-_\'\"()':  # dígitos y puntuación común
                score += 1.0
            elif b in (9, 10, 13):  # saltos de línea y tabuladores
                score += 1.0
            else:  # penalización severa para caracteres de control y bytes anómalos
                score -= 15.0
        return score

    mejor_clave = -1
    mejor_score = float('-inf')
    mejor_texto = b''

    for k in range(256):
        candidato = xor_cifrar(cifrado, bytes([k]))
        score = puntuar_candidato(candidato)
        if score > mejor_score:
            mejor_score = score
            mejor_clave = k
            mejor_texto = candidato

    return mejor_clave, mejor_texto


# ---------------------------------------------------------------------------
# B.2 — MAC ingenuo vs HMAC. TODO
# ---------------------------------------------------------------------------
def mac_ingenuo(clave: bytes, msg: bytes) -> str:
    """Devuelve sha256(clave || msg) en hex. Es lo que MUCHA gente hace...
    y es vulnerable a length-extension. Lo implementás para después romperlo
    conceptualmente en el informe."""
    return hashlib.sha256(clave + msg).hexdigest()

def mac_hmac(clave: bytes, msg: bytes) -> str:
    """Devuelve el HMAC-SHA256 en hex. Esta es la forma CORRECTA."""
    return hmac.new(clave, msg, hashlib.sha256).hexdigest()

def verificar_mac(esperado: str, recibido: str) -> bool:
    """Compara dos MAC en hex. DEBE ser en tiempo constante para no filtrar
    información por el tiempo de comparación.
    Pista: hmac.compare_digest."""
    return hmac.compare_digest(esperado, recibido)


def main() -> int:
    ap = argparse.ArgumentParser(description="Herramientas de cripto (Lab 02).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("xor", help="cifrar/descifrar por XOR (hex de salida)")
    p.add_argument("--texto", required=True)
    p.add_argument("--clave", required=True)

    p = sub.add_parser("romper", help="romper un cifrado XOR de 1 byte (hex de entrada)")
    p.add_argument("--hex", required=True, help="cifrado en hexadecimal")

    p = sub.add_parser("mac", help="calcular MAC de un mensaje")
    p.add_argument("--clave", required=True)
    p.add_argument("--msg", required=True)
    p.add_argument("--modo", choices=["ingenuo", "hmac"], default="hmac")

    a = ap.parse_args()
    if a.cmd == "xor":
        print(xor_cifrar(a.texto.encode(), a.clave.encode()).hex())
    elif a.cmd == "romper":
        k, claro = romper_xor_1byte(bytes.fromhex(a.hex))
        print(f"clave=0x{k:02x}")
        print(claro.decode(errors="replace"))
    elif a.cmd == "mac":
        fn = mac_ingenuo if a.modo == "ingenuo" else mac_hmac
        print(fn(a.clave.encode(), a.msg.encode()))
    return 0

if __name__ == "__main__":
    sys.exit(main())
