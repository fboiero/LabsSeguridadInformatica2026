"""Prueba HTTP aislada para D1 y D2 sobre la copia parcheada."""
import importlib.util
import os
import tempfile
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen


RUTA = "entregas/labextra3/grupo06/objetivo/server.py"
spec = importlib.util.spec_from_file_location("phantom_d1_d2", RUTA)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

with tempfile.TemporaryDirectory(prefix="extra3-p1-") as temporal:
    app.DB = os.path.join(temporal, "phantom.db")
    app.DESCARGAS = os.path.join(temporal, "descargas")
    app.init_db()
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    base = f"http://127.0.0.1:{servidor.server_port}"
    try:
        with urlopen(base + "/", timeout=5) as respuesta:
            banner = respuesta.headers.get("Server", "")
            print(f"GET /: HTTP {respuesta.status}; Server: {banner!r}")
            assert "PhantomServer" not in banner and "2.4.1" not in banner
        try:
            urlopen(base + "/api/status", timeout=5)
            raise AssertionError("/api/status no debe responder exitosamente")
        except HTTPError as error:
            cuerpo = error.read().decode("utf-8", "replace")
            print(f"GET /api/status: HTTP {error.code}; cuerpo: {cuerpo!r}")
            assert error.code == 404
            assert '"debug"' not in cuerpo and '"pid"' not in cuerpo
        print("Pruebas D1 y D2: OK.")
    finally:
        servidor.shutdown()
        servidor.server_close()
        hilo.join()
