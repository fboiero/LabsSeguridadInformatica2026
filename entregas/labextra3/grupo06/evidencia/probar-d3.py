import importlib.util
import threading
import tempfile
import os
from http.server import ThreadingHTTPServer
from urllib.request import urlopen
from urllib.error import HTTPError

ruta = "entregas/labextra3/grupo06/objetivo/server.py"
spec = importlib.util.spec_from_file_location("phantom_d3", ruta)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as temporal:
    mod.DB = os.path.join(temporal, "phantom.db")
    mod.DESCARGAS = os.path.join(temporal, "descargas")
    mod.init_db()

    servidor = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()

    try:
        for endpoint in ("/", "/robots.txt", "/backup", "/descargar?archivo=manual.txt"):
            try:
                with urlopen(f"http://127.0.0.1:{servidor.server_port}{endpoint}", timeout=5) as respuesta:
                    codigo = respuesta.status
                    contenido = respuesta.read().decode("utf-8", "replace")
            except HTTPError as error:
                codigo = error.code
                contenido = error.read().decode("utf-8", "replace")

            print(f"{endpoint}: HTTP {codigo} | {contenido!r}")
    finally:
        servidor.shutdown()
        servidor.server_close()
