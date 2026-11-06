#!/usr/bin/env python3
"""Comprueba regresiones funcionales de la copia endurecida del laboratorio."""
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SERVER = Path(__file__).resolve().parents[1] / "objetivo" / "server.py"
STATE = ROOT / ".progreso" / "labextra3-runtime" / "a" / "b" / "c"
DOWNLOADS = STATE / "descargas"
PORT = 18342
BASE = f"http://127.0.0.1:{PORT}"


def request(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=2) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def main():
    # El marcador está fuera de descargas; el caso permite probar traversal en Windows.
    escape_target = (DOWNLOADS / "../../../../etc/passwd").resolve()
    escape_target.parent.mkdir(parents=True, exist_ok=True)
    escape_target.write_text("root:lab-extra-fixture\n", encoding="utf-8")

    env = os.environ.copy()
    env["PORT"] = str(PORT)
    env["PHANTOM_HARDENING_STATE"] = str(STATE)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen(
        [sys.executable, str(SERVER)], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(30):
            try:
                status, body = request("/")
                break
            except (OSError, TimeoutError):
                time.sleep(0.1)
        else:
            raise RuntimeError("El servidor no respondió en el puerto local de prueba.")

        checks = [
            ("GET /", status == 200 and "PhantomCorp" in body, status),
        ]
        query = urllib.parse.urlencode({"user": "admin", "pass": "sup3r-s3cr3t0"})
        login_status, login_body = request("/login?" + query)
        checks.append(("login legítimo", login_status == 200 and "Bienvenido" in login_body, login_status))

        bad_query = urllib.parse.urlencode({"user": "admin", "pass": "incorrecta"})
        bad_status, _ = request("/login?" + bad_query)
        checks.append(("login inválido", bad_status == 401, bad_status))

        manual_status, manual_body = request("/descargar?archivo=manual.txt")
        checks.append(("descarga manual.txt", manual_status == 200 and "Manual de la intranet" in manual_body, manual_status))

        traversal = urllib.parse.urlencode({"archivo": "../../../../etc/passwd"})
        traversal_status, traversal_body = request("/descargar?" + traversal)
        checks.append(("traversal a fixture fuera de descargas", traversal_status == 404 and "root:lab-extra-fixture" not in traversal_body, traversal_status))

        for label, ok, status in checks:
            print(f"{'OK' if ok else 'FALLO'} | {label} | HTTP {status}")
        failures = [label for label, ok, _ in checks if not ok]
        print(f"{len(checks) - len(failures)}/{len(checks)} comprobaciones funcionales correctas.")
        return 1 if failures else 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


if __name__ == "__main__":
    sys.exit(main())
