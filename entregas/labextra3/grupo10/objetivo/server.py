#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
objetivo/server.py — copia endurecida de PhantomCorp para el Grupo 10.

La versión original tenía CINCO problemas que se abordan en esta copia:

  D1  El header Server canta producto y versión          (banner/info leak)
  D2  /api/status expone debug:true y datos internos     (servicio dev en prod)
  D3  /robots.txt lista rutas sensibles y /backup responde 200
  D4  /login es vulnerable a SQLi (bypass con ' OR 1=1 --)
  D5  /descargar?archivo= permite path traversal (../../etc)

Esta copia fue parchada dentro de la entrega del Grupo 10. El original bajo
labs/labextra3-hardening/objetivo permanece sin cambios como referencia. Para
repetir la verificación contra esta copia, corré:

  python3 labs/labextra3-hardening/verificar-defensa.py --dir entregas/labextra3/grupo10/objetivo

El verificador intenta reproducir los ataques contra esta copia endurecida.
"""
import html
import os
import sqlite3
import tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

VERSION = ""                             # D1: no divulgar producto ni versión

ESTADO = os.environ.get(
    "PHANTOM_HARDENING_STATE",
    os.path.join(tempfile.gettempdir(), "phantom_hardening"),
)
DB = os.path.join(ESTADO, "phantom_hardening.db")
DESCARGAS = os.path.join(ESTADO, "descargas")


def init_db():
    os.makedirs(ESTADO, exist_ok=True)
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
    server_version = VERSION
    sys_version = ""

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        params = parse_qs(qs)

        if path == "/":
            self._html(200, "<h1>PhantomCorp</h1><p>Portal de empleados.</p>")
        elif path == "/robots.txt":
            # D3: robots no publica rutas sensibles.
            self._txt(200, "User-agent: *\nDisallow:\n")
        elif path == "/backup":
            # D3: el recurso sensible no está disponible sin autorización.
            self._txt(404, "404 - no existe")
        elif path == "/api/status":
            # D2: el endpoint de debug no se publica en producción.
            self._txt(404, "404 - no existe")
        elif path == "/login":
            # D4: los datos del usuario se envían como parámetros SQL.
            user = params.get("user", [""])[0]
            pwd = params.get("pass", [""])[0]
            db = sqlite3.connect(DB)
            try:
                cur = db.execute(
                    "SELECT user FROM usuarios WHERE user = ? AND password = ?",
                    (user, pwd),
                )
                autenticado = cur.fetchone() is not None
            finally:
                db.close()
            if autenticado:
                self._html(200, "<h1>Bienvenido, " + html.escape(user) + "</h1>")
            else:
                self._html(401, "<h1>Credenciales inválidas</h1>")
        elif path == "/descargar":
            # D5: canonicalizar la ruta y confinarla a la raíz de descargas.
            nombre = params.get("archivo", [""])[0]
            try:
                raiz = Path(DESCARGAS).resolve()
                ruta = (raiz / nombre).resolve()
                if not ruta.is_relative_to(raiz) or not ruta.is_file():
                    raise FileNotFoundError
                self._txt(200, ruta.read_bytes()[:8192].decode("utf-8", "ignore"))
            except (OSError, RuntimeError, ValueError):
                self._txt(404, "no encontrado")
        else:
            self._txt(404, "404 - no existe")

    # --- helpers de respuesta ---
    def _html(self, code, body):
        self._send(code, body.encode(), "text/html; charset=utf-8")

    def _txt(self, code, body):
        self._send(code, body.encode(), "text/plain; charset=utf-8")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    init_db()
    puerto = int(os.environ.get("PORT", "8080"))
    print(f"PhantomCorp (HARDENED) en 0.0.0.0:{puerto}")
    ThreadingHTTPServer(("0.0.0.0", puerto), Handler).serve_forever()
