#!/usr/bin/env python3
"""
Genera los datos del reto XOR para el lab02.
Crea data/muestra/reto_xor.hex con un mensaje cifrado con una clave de 1 byte.
"""
import secrets
import pathlib

MENSAJE = (
    "PhantomCorp confidential: operacion AURORA autorizada para el 2024-03-15. "
    "Coordinar con agentes en nodos 7, 12 y 19. Clave de sesion: DELTA-BRAVO-9."
)


def xor_1byte(texto: bytes, clave: int) -> bytes:
    return bytes(b ^ clave for b in texto)


def main():
    # Se excluye 0x00 para evitar generar accidentalmente texto sin cifrar.
    clave = secrets.randbelow(255) + 1
    cifrado = xor_1byte(MENSAJE.encode(), clave)
    out = pathlib.Path(__file__).parent / "muestra" / "reto_xor.hex"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(cifrado.hex())
    print(f"[+] reto_xor.hex generado (clave usada internamente: 0x{clave:02x})")
    print(f"[+] Archivo: {out}")


if __name__ == "__main__":
    main()

