#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
objetivo/server.py — PhantomCorp "vulnerable", Lab Extra 3 (hardening).

Esta app tiene CINCO problemas que ya conocés de los labs 05-07:

  D1  El header Server canta producto y versión          (banner/info leak)
  D2  /api/status expone debug:true y datos internos     (servicio dev en prod)
  D3  /robots.txt lista rutas sensibles y /backup responde 200
  D4  /login es vulnerable a SQLi (bypass con ' OR 1=1 --)
  D5  /descargar?archivo= permite path traversal (../../etc)

TU TRABAJO: copiá esta carpeta a tu entrega y PARCHÁLA ahí. No modifiques este
original: es la referencia "rota". Cuando tu copia esté endurecida, corré:

  python3 labs/labextra3-hardening/verificar-defensa.py --dir entregas/labextra3/grupoXX/objetivo

El verificador ATACA tu copia. Por cada ataque que YA NO FUNCIONA, te muestra
la flag defensiva para entregar con ./ctf submit extra3.
"""
import base64
import binascii
import hmac
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# D1 (parche grupo08): banner genérico. No identifica producto, versión, build
# ("-debug") ni el runtime de Python. Se aplica también a las páginas de error
# que genera BaseHTTPRequestHandler (501, 400...), porque todas usan
# version_string().
VERSION = "webserver"

# D3 (parche grupo08): /backup solo con credenciales de operador, inyectadas por
# entorno (nunca en el código). Si no están configuradas, el endpoint queda
# APAGADO (fail-closed): responde 404 como cualquier ruta inexistente.
BACKUP_USER = os.environ.get("PHANTOM_BACKUP_USER", "")
BACKUP_PASS = os.environ.get("PHANTOM_BACKUP_PASS", "")

DB = "/tmp/phantom_hardening.db"
DESCARGAS = "/tmp/phantom_descargas"    # raíz "pública" de /descargar


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    db = sqlite3.connect(DB)
    db.execute("CREATE TABLE usuarios (user TEXT, password TEXT)")
    db.execute("INSERT INTO usuarios VALUES ('admin', 'sup3r-s3cr3t0')")
    db.commit()
    db.close()
    os.makedirs(DESCARGAS, exist_ok=True)
    with open(os.path.join(DESCARGAS, "manual.txt"), "w") as fh:
        fh.write("Manual de la intranet PhantomCorp.\n")


class Handler(BaseHTTPRequestHandler):
    server_version = VERSION            # D1
    sys_version = ""

    def version_string(self):
        # D1: el default arma "server_version + ' ' + sys_version" (dejaba
        # "PhantomServer/2.4.1-debug " con espacio colgando). Devolvemos un
        # valor fijo para que ninguna respuesta, ni las de error, filtre nada.
        return VERSION

    def _backup_autorizado(self):
        """D3: HTTP Basic contra credenciales de entorno, comparación en
        tiempo constante. Sin credenciales configuradas -> nunca autoriza."""
        if not (BACKUP_USER and BACKUP_PASS):
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            user, _, pwd = base64.b64decode(auth[6:], validate=True) \
                .decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        ok_user = hmac.compare_digest(user.encode(), BACKUP_USER.encode())
        ok_pass = hmac.compare_digest(pwd.encode(), BACKUP_PASS.encode())
        return ok_user and ok_pass

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        params = parse_qs(qs)

        if path == "/":
            self._html(200, "<h1>PhantomCorp</h1><p>Portal de empleados.</p>")
        elif path == "/robots.txt":
            # D3 (parche): robots.txt es PÚBLICO y lo lee primero el atacante.
            # Solo sirve para guiar crawlers legítimos, nunca como control de
            # acceso: no se listan rutas sensibles.
            self._txt(200, "User-agent: *\nDisallow:\n")
        elif path == "/backup":
            # D3 (parche): la protección real está en la ruta, no en el robots.
            if not (BACKUP_USER and BACKUP_PASS):
                # Fail-closed: sin credenciales de operador, no existe.
                self._txt(404, "404 - no existe")
            elif not self._backup_autorizado():
                self._send(401, b"401 - autenticacion requerida",
                           "text/plain; charset=utf-8",
                           {"WWW-Authenticate": 'Basic realm="phantom-ops"'})
            else:
                self._txt(200, "dump_pre_migracion: usuarios=1 OK")
        # D2 (parche): /api/status se ELIMINÓ. Era un endpoint de debug
        # (debug:true, ruta de la DB, PID) y no tiene lugar en producción. No
        # tiene rama propia: cae en el 404 genérico, indistinguible de cualquier
        # ruta que nunca existió.
        elif path == "/login":
            # D4: SQLi clásico — consulta por interpolación de strings
            user = params.get("user", [""])[0]
            pwd = params.get("pass", [""])[0]
            db = sqlite3.connect(DB)
            cur = db.execute(
                "SELECT user FROM usuarios WHERE user = '" + user
                + "' AND password = '" + pwd + "'")     # ¡NUNCA así!
            if cur.fetchone():
                self._html(200, "<h1>Bienvenido, " + user + "</h1>")
            else:
                self._html(401, "<h1>Credenciales inválidas</h1>")
            db.close()
        elif path == "/descargar":
            # D5: path traversal — concatena y lee sin validar
            nombre = params.get("archivo", [""])[0]
            ruta = DESCARGAS + "/" + nombre
            try:
                with open(ruta, "rb") as fh:
                    self._txt(200, fh.read(8192).decode("utf-8", "ignore"))
            except Exception:
                self._txt(404, "no encontrado")
        else:
            self._txt(404, "404 - no existe")

    # --- helpers de respuesta ---
    def _html(self, code, body):
        self._send(code, body.encode(), "text/html; charset=utf-8")

    def _txt(self, code, body):
        self._send(code, body.encode(), "text/plain; charset=utf-8")

    def _json(self, code, body):
        self._send(code, body.encode(), "application/json")

    def _send(self, code, body, ctype, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    init_db()
    puerto = int(os.environ.get("PORT", "8080"))
    print(f"PhantomCorp (VULNERABLE) en 0.0.0.0:{puerto}")
    ThreadingHTTPServer(("0.0.0.0", puerto), Handler).serve_forever()
