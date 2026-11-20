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
import os
import sqlite3
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# D1: nombre genérico; no expone el producto ni la versión desplegada.
VERSION = "Servidor"

RUNTIME_DIR = tempfile.gettempdir()
DB = os.path.join(RUNTIME_DIR, "phantom_hardening.db")
DESCARGAS = os.path.join(RUNTIME_DIR, "phantom_descargas")


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

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        params = parse_qs(qs)

        if path == "/":
            self._html(200, "<h1>PhantomCorp</h1><p>Portal de empleados.</p>")
        elif path == "/robots.txt":
            # D3: no publicar rutas sensibles en robots.txt
            self._txt(200, "User-agent: *\n")
        elif path == "/backup":
            # D3: impedir el acceso publico al backup
            self._txt(404, "404 - no existe")
        elif path == "/api/status":
            # D2: el endpoint de diagnóstico no se publica en producción.
            self._txt(404, "404 - no existe")
        elif path == "/login":
            # D4: parámetros enlazados; las credenciales son datos, no SQL
            user = params.get("user", [""])[0]
            pwd = params.get("pass", [""])[0]
            db = sqlite3.connect(DB)
            cur = db.execute(
                "SELECT user FROM usuarios WHERE user = ? AND password = ?",
                (user, pwd))
            if cur.fetchone():
                self._html(200, "<h1>Bienvenido, " + user + "</h1>")
            else:
                self._html(401, "<h1>Credenciales inválidas</h1>")
            db.close()
        elif path == "/descargar":
            # D5: confinar la ruta RESUELTA al directorio de descargas, no
            # filtrar la cadena ".." (eso no cubre absolutas ni symlinks, y
            # un 404 por archivo inexistente no equivale a estar bloqueado).
            nombre = params.get("archivo", [""])[0]
            base = os.path.realpath(DESCARGAS)
            if os.path.isabs(nombre):
                # os.path.join descarta DESCARGAS si nombre es absoluto;
                # tratamos cualquier ruta absoluta como fuera de alcance.
                self._txt(404, "no encontrado")
            else:
                ruta = os.path.realpath(os.path.join(base, nombre))
                dentro = ruta == base or ruta.startswith(base + os.sep)
                if not dentro:
                    self._txt(404, "no encontrado")
                else:
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
    print(f"PhantomCorp (VULNERABLE) en 0.0.0.0:{puerto}")
    ThreadingHTTPServer(("0.0.0.0", puerto), Handler).serve_forever()
