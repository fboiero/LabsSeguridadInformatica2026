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


def puntuar_texto(texto_bytes):
    # Asigna mayor puntaje a caracteres imprimibles y comunes (letras y espacios)
    puntaje = 0
    frecuentes = b" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for byte in texto_bytes:
        if byte in frecuentes:
            puntaje += 1
    return puntaje

def romper_xor_1byte(datos_cifrados):
    mejor_clave = None
    mejor_puntaje = -1
    mejor_texto = b""

    # 1. Probar todas las claves posibles (0 a 255)
    for clave in range(256):
        # 2. Hacer XOR de cada byte con la clave actual
        descifrado = bytes([byte ^ clave for byte in datos_cifrados])
        
        # 3. Calcular qué tan "humano" suena el texto
        puntaje = puntuar_texto(descifrado)
        
        # 4. Guardar si es el mejor resultado hasta ahora
        if puntaje > mejor_puntaje:
            mejor_puntaje = puntaje
            mejor_clave = clave
            mejor_texto = descifrado

    return mejor_clave, mejor_texto


# ---------------------------------------------------------------------------
# B.2 — MAC ingenuo vs HMAC. TODO
# ---------------------------------------------------------------------------
def mac_ingenuo(clave: bytes, msg: bytes) -> str:
    """Devuelve sha256(clave || msg) en hex."""
    return hashlib.sha256(clave + msg).hexdigest()
def mac_hmac(clave: bytes, msg: bytes) -> str:
    """Devuelve el HMAC-SHA256 en hex."""
    return hmac.new(clave, msg, hashlib.sha256).hexdigest()

def verificar_mac(esperado: str, recibido: str) -> bool:
    """Compara dos MAC en hex en tiempo constante."""
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
