#!/usr/bin/env python3
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
    mejor_clave, mejor_texto, mejor_puntaje = 0, b"", float("-inf")
    for clave in range(256):  # 0x00 a 0xFF
        candidato = bytes(b ^ clave for b in cifrado)
        puntaje = 0
        for c in candidato:
            if c == 0x20 or chr(c) in "aeiouAEIOU":
                puntaje += 2  # espacios y vocales: frecuentes en lenguaje natural
            elif c < 0x80 and chr(c).isalpha():
                puntaje += 1
            elif c in (0x09, 0x0A, 0x0D) or 0x20 < c < 0x7F:
                pass  # puntuación, dígitos y saltos de línea: neutros
            else:
                puntaje -= 5  # control o no ASCII: muy improbable en texto natural
        if puntaje > mejor_puntaje:
            mejor_clave, mejor_texto, mejor_puntaje = clave, candidato, puntaje
    return mejor_clave, mejor_texto


# ---------------------------------------------------------------------------
# B.2 — MAC ingenuo vs HMAC. TODO
# ---------------------------------------------------------------------------
def mac_ingenuo(clave: bytes, msg: bytes) -> str:
    """Devuelve sha256(clave || msg) en hex. Es lo que MUCHA gente hace...
    y es vulnerable a length-extension. Lo implementás para después romperlo
    conceptualmente en el informe."""
    # Intencionalmente inseguro (vulnerable a length-extension): sha256(clave || msg)
    return hashlib.sha256(clave + msg).hexdigest()

def mac_hmac(clave: bytes, msg: bytes) -> str:
    """Devuelve el HMAC-SHA256 en hex. Esta es la forma CORRECTA."""
    return hmac.new(clave, msg, hashlib.sha256).hexdigest()

def verificar_mac(esperado: str, recibido: str) -> bool:
    """Compara dos MAC en hex. DEBE ser en tiempo constante para no filtrar
    información por el tiempo de comparación.
    Pista: hmac.compare_digest."""
    # Comparación en tiempo constante; no usar ==
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
