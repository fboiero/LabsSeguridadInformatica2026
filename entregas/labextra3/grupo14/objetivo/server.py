#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
objetivo/server.py — PhantomCorp ENDURECIDO, Lab Extra 3 (grupo 14).

Copia parchada del objetivo vulnerable. Las 5 defensas (ver comentarios D1-D5):
  D1  header Server neutro (no filtra producto ni versión)
  D2  /api/status apagado en producción (404)
  D3  /backup protegido (404) y robots.txt sin rutas sensibles
  D4  /login con consulta parametrizada (SQLi bloqueado)
  D5  /descargar con validación de ruta (path traversal bloqueado)
"""
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

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
    # D1: banner neutro. No revela producto ni versión del servidor.
    server_version = "web"
    sys_version = ""

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        params = parse_qs(qs)

        if path == "/":
            self._html(200, "<h1>PhantomCorp</h1><p>Portal de empleados.</p>")
        elif path == "/robots.txt":
            # D3: robots sin pistas de rutas sensibles.
            self._txt(200, "User-agent: *\nDisallow:\n")
        elif path == "/backup":
            # D3: endpoint sensible apagado (no existe para el cliente).
            self._txt(404, "404 - no existe")
        elif path == "/api/status":
            # D2: servicio de debug apagado en producción.
            self._txt(404, "404 - no existe")
        elif path == "/login":
            # D4: consulta PARAMETRIZADA — los valores nunca se interpolan.
            user = params.get("user", [""])[0]
            pwd = params.get("pass", [""])[0]
            db = sqlite3.connect(DB)
            cur = db.execute(
                "SELECT user FROM usuarios WHERE user = ? AND password = ?",
                (user, pwd))
            fila = cur.fetchone()
            db.close()
            if fila:
                # Además, no reflejar el input crudo en la respuesta.
                self._html(200, "<h1>Bienvenido, " + self._esc(fila[0]) + "</h1>")
            else:
                self._html(401, "<h1>Credenciales inválidas</h1>")
        elif path == "/descargar":
            # D5: solo nombre de archivo, dentro de DESCARGAS. Sin traversal.
            nombre = params.get("archivo", [""])[0]
            base = os.path.basename(nombre)          # descarta cualquier ../
            ruta = os.path.realpath(os.path.join(DESCARGAS, base))
            raiz = os.path.realpath(DESCARGAS)
            if not base or os.path.commonpath([raiz, ruta]) != raiz:
                self._txt(403, "ruta no permitida")
                return
            try:
                with open(ruta, "rb") as fh:
                    self._txt(200, fh.read(8192).decode("utf-8", "ignore"))
            except Exception:
                self._txt(404, "no encontrado")
        else:
            self._txt(404, "404 - no existe")

    @staticmethod
    def _esc(s):
        return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

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
    print(f"PhantomCorp (ENDURECIDO) en 0.0.0.0:{puerto}")
    ThreadingHTTPServer(("0.0.0.0", puerto), Handler).serve_forever()
