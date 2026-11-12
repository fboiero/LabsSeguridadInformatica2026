#!/usr/bin/env python3
"""Part 2 evidence for P4: forge an alg:none token and show the server rejects it.

Pure stdlib. Starts nothing: it expects the target already running on $PORT
(default 8080). Builds three tokens by hand and reports what /admin answers:

  1. alg:none with an EMPTY signature  (the classic alg:none attack)
  2. alg:none with a bogus signature
  3. a well-formed HS256 token signed with the WRONG secret

All three must get 401: this server recomputes HMAC-SHA256 and never trusts the
header's "alg", so a missing or wrong signature never matches.
"""
import base64
import hashlib
import hmac
import json
import os
import urllib.request
import urllib.error

PORT = os.environ.get("PORT", "8080")
BASE = f"http://127.0.0.1:{PORT}"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def armar(header: dict, payload: dict, firma_b64url: str) -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{firma_b64url}"


def admin(token: str):
    req = urllib.request.Request(BASE + "/admin",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=4) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


payload = {"sub": "diego", "role": "admin", "iat": 0, "exp": 9999999999}

casos = [
    ("alg:none, firma vacia",
     armar({"alg": "none", "typ": "JWT"}, payload, "")),
    ("alg:none, firma basura",
     armar({"alg": "none", "typ": "JWT"}, payload, b64url(b"loquesea"))),
    ("HS256 firmado con secreto EQUIVOCADO ('secret')",
     None),  # built below with a real HMAC over the wrong key
]

# third case: a structurally valid HS256 token, signed with the wrong secret
h = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())
firma_mala = b64url(hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest())
casos[2] = (casos[2][0], f"{h}.{p}.{firma_mala}")

print("### P4 - el servidor ignora el header alg y recalcula HMAC-SHA256")
print(f"### objetivo: {BASE}/admin  (se espera 401 en los tres)\n")
for nombre, token in casos:
    code, body = admin(token)
    print(f"[{nombre}]")
    print(f"  token : {token[:60]}{'...' if len(token) > 60 else ''}")
    print(f"  /admin: HTTP {code} {body}\n")
