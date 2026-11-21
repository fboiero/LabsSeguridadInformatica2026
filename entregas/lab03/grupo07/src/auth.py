#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
auth.py — Laboratorio 03. Autenticación hecha bien. Solo biblioteca estándar.

Completá los TODO. NO cambies las firmas ni la CLI. `hotp()` viene implementada
como referencia (es la base del TOTP): leela.
"""
import argparse, hashlib, hmac, secrets, struct, sys, time

# --- B.1: almacenamiento de contraseñas ---
def hash_password(password: str, salt: bytes = None, iters: int = 200_000) -> str:
    """Devuelve una cadena 'pbkdf2_sha256$iters$salt_hex$dk_hex'.
    Pista: secrets.token_bytes para el salt; hashlib.pbkdf2_hmac('sha256', ...).
    ¿Por qué salt por usuario? ¿Por qué 200.000 iteraciones y no una?"""
    # Salt aleatorio por usuario: si no viene uno dado (verify lo reinyecta),
    # generamos 16 bytes criptográficamente aleatorios.
    if salt is None:
        salt = secrets.token_bytes(16)
    # Derivación lenta de clave: PBKDF2-HMAC-SHA256 con muchas iteraciones.
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    # Guardamos algoritmo, iteraciones y salt junto al hash para poder re-verificar.
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"

def verify_password(password: str, almacenado: str) -> bool:
    """Verifica una contraseña contra el registro de hash_password().
    DEBE comparar en tiempo constante (hmac.compare_digest)."""
    try:
        algo, iters_s, salt_hex, dk_hex = almacenado.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        esperado = bytes.fromhex(dk_hex)
    except (ValueError, AttributeError):
        # Registro mal formado: no autenticamos.
        return False
    # Recalculamos con el MISMO salt e iteraciones que se guardaron.
    calculado = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    # Comparación en tiempo constante: no corta en el primer byte distinto,
    # así no se filtra información por tiempo (ataque de timing, Parte A).
    return hmac.compare_digest(calculado, esperado)

# --- B.2: segundo factor (TOTP / RFC 6238) ---
def hotp(secret: bytes, contador: int, digitos: int = 6, algo: str = "sha1") -> str:
    """HOTP (RFC 4226): HMAC del contador + truncamiento dinámico. YA IMPLEMENTADA."""
    h = hmac.new(secret, struct.pack(">Q", contador), algo).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digitos)
    return str(code).zfill(digitos)

def totp(secret: bytes, t: int = None, paso: int = 30, digitos: int = 6) -> str:
    """TOTP (RFC 6238): HOTP usando como contador el tiempo dividido en pasos.
    Pista: contador = t // paso. Si t es None, usá time.time()."""
    # El "contador" del HOTP pasa a ser la cantidad de intervalos de `paso`
    # segundos transcurridos desde la época Unix. Por eso el código cambia
    # solo/cada 30 s y es igual en ambos extremos si los relojes coinciden.
    if t is None:
        t = int(time.time())
    contador = int(t) // paso
    return hotp(secret, contador, digitos)

def main() -> int:
    ap = argparse.ArgumentParser(description="Autenticación (Lab 03).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hash"); p.add_argument("--password", required=True)
    p = sub.add_parser("verify"); p.add_argument("--password", required=True); p.add_argument("--registro", required=True)
    p = sub.add_parser("totp"); p.add_argument("--secret", required=True, help="secreto ASCII"); p.add_argument("--t", type=int, default=None)
    a = ap.parse_args()
    if a.cmd == "hash": print(hash_password(a.password))
    elif a.cmd == "verify": print("OK" if verify_password(a.password, a.registro) else "FALLO"); return 0 if verify_password(a.password, a.registro) else 1
    elif a.cmd == "totp": print(totp(a.secret.encode(), a.t))
    return 0

if __name__ == "__main__":
    sys.exit(main())
