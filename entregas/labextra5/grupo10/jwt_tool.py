#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
# Adaptación del esqueleto de la cátedra — Grupo 10.
"""Herramienta educativa HS256, exclusivamente para el laboratorio local.

Conserva las firmas y la CLI del esqueleto. No es un validador de sesiones
para producción: verificar la firma NO valida expiración, emisor o audiencia.
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time


def b64url_dec(texto: str) -> bytes:
    """Decodifica base64url sin padding (función provista por la cátedra)."""
    pad = "=" * (-len(texto) % 4)
    return base64.urlsafe_b64decode(texto + pad)


def b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def decodificar(token: str) -> tuple:
    """Devuelve header, payload y firma hexadecimal, SIN verificar confianza."""
    cab, pay, fir = token.split(".")
    header = json.loads(b64url_dec(cab))
    payload = json.loads(b64url_dec(pay))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Header y payload deben ser objetos JSON")
    return header, payload, b64url_dec(fir).hex()


def firma_es_valida(token: str, secreto: bytes) -> bool:
    """Verifica solo la firma HS256, con comparación en tiempo constante."""
    try:
        cab, pay, fir = token.split(".")
        header = json.loads(b64url_dec(cab))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return False
        mensaje = f"{cab}.{pay}".encode("ascii")
        esperada = b64url(hmac.new(secreto, mensaje, hashlib.sha256).digest())
        return hmac.compare_digest(fir.encode("ascii"), esperada.encode("ascii"))
    except (ValueError, UnicodeError, binascii.Error):
        return False


def crackear_secreto(token: str, diccionario: str) -> str:
    """Prueba cada línea no vacía en orden, sin efectuar peticiones de red.

    Devuelve cadena vacía si no encuentra coincidencia. Las estadísticas se
    imprimen en stderr para mantener SECRETO y los tokens limpios en stdout.
    Solo quita saltos de línea: los espacios pueden ser parte de una clave.
    """
    decodificar(token)
    inicio = time.perf_counter()
    intentos = 0
    encontrado = ""
    with open(diccionario, encoding="utf-8") as archivo:
        for linea in archivo:
            candidato = linea.rstrip("\r\n")
            if not candidato:
                continue
            intentos += 1
            if firma_es_valida(token, candidato.encode("utf-8")):
                encontrado = candidato
                break
    segundos = time.perf_counter() - inicio
    print(f"CANDIDATOS: {intentos}\nSEGUNDOS: {segundos:.9f}", file=sys.stderr)
    return encontrado


def forjar(secreto: bytes, sub: str, role: str) -> str:
    """Genera un token HS256 del caso didáctico, con vigencia de una hora."""
    ahora = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "role": role, "iat": ahora, "exp": ahora + 3600}
    cab = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pay = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    mensaje = f"{cab}.{pay}"
    firma = hmac.new(secreto, mensaje.encode("ascii"), hashlib.sha256).digest()
    return f"{mensaje}.{b64url(firma)}"


def main() -> int:
    ap = argparse.ArgumentParser(description="jwt_tool — Lab Extra 5")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decodificar", help="leer header/payload (sin verificar)")
    d.add_argument("token")
    c = sub.add_parser("crackear", help="crackear el secreto con diccionario")
    c.add_argument("token")
    c.add_argument("diccionario")
    f = sub.add_parser("forjar", help="firmar un token propio con el secreto")
    f.add_argument("secreto")
    f.add_argument("--sub", default="diego")
    f.add_argument("--role", default="admin")
    args = ap.parse_args()
    try:
        if args.cmd == "decodificar":
            header, payload, firma = decodificar(args.token)
            print("HEADER: ", json.dumps(header, indent=2))
            print("PAYLOAD:", json.dumps(payload, indent=2))
            print("FIRMA:  ", firma[:32] + "…")
        elif args.cmd == "crackear":
            secreto = crackear_secreto(args.token, args.diccionario)
            print(f"SECRETO: {secreto}" if secreto else "No cayó con ese diccionario.")
        else:
            print(forjar(args.secreto.encode(), args.sub, args.role))
    except (ValueError, UnicodeError, binascii.Error, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
