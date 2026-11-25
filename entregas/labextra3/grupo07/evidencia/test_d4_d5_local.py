"""Pruebas locales de D4/D5 con datos temporales; no toca el servidor original."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import urlopen


REPO = Path(__file__).resolve().parents[4]
VERIFY = REPO / "labs" / "labextra3-hardening" / "verificar-defensa.py"
DELIVERY_SERVER = Path(__file__).resolve().parents[1] / "objetivo" / "server.py"


def request(url):
    try:
        with urlopen(url, timeout=3) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    with tempfile.TemporaryDirectory(prefix="labextra3-") as temp:
        data = Path(temp) / "data"
        data.mkdir()
        sibling = Path(temp) / "phantom_descargas_backup"
        sibling.mkdir()
        (sibling / "secreto.txt").write_text("FUERA_DEL_LIMITE", encoding="utf-8")

        # En Windows, redirigir los paths Linux /tmp de la plantilla a temp.
        text = DELIVERY_SERVER.read_text(encoding="utf-8")
        text = text.replace('DB = "/tmp/phantom_hardening.db"', f'DB = r"{data / "phantom_hardening.db"}"')
        text = text.replace('DESCARGAS = "/tmp/phantom_descargas"', f'DESCARGAS = r"{data / "phantom_descargas"}"')
        target = Path(temp) / "objetivo"
        target.mkdir()
        (target / "server.py").write_text(text, encoding="utf-8")

        port = free_port()
        env = os.environ.copy()
        env["PORT"] = str(port)
        proc = subprocess.Popen([sys.executable, str(target / "server.py")], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base = f"http://127.0.0.1:{port}"
        try:
            for _ in range(30):
                try:
                    request(base + "/")
                    break
                except Exception:
                    time.sleep(0.1)

            status, _ = request(base + "/")
            assert status == 200, f"GET / devolvió {status}"
            print("OK GET / -> 200")

            status, _ = request(base + "/login?user=admin&pass=sup3r-s3cr3t0")
            assert status == 200, f"login válido devolvió {status}"
            print("OK login legítimo -> 200")

            for user, password in (("admin'--", "x"), ("x", "' OR 1=1 --")):
                url = f"{base}/login?user={quote(user, safe='')}&pass={quote(password, safe='')}"
                status, _ = request(url)
                assert status == 401, f"bypass SQL devolvió {status}"
            print("OK bypasses SQL clásicos -> 401")

            status, body = request(base + "/descargar?archivo=manual.txt")
            assert status == 200 and "Manual de la intranet" in body
            print("OK descarga manual legítima -> 200")

            attacks = (
                "../../../../etc/passwd",
                "../../../../phantom_descargas_backup/secreto.txt",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//etc/passwd",
            )
            for payload in attacks:
                status, body = request(f"{base}/descargar?archivo={quote(payload, safe='')}")
                assert status != 200 or ("root:" not in body and "FUERA_DEL_LIMITE" not in body), payload
            print("OK traversales, encoding y límite estructural bloqueados")
        finally:
            proc.terminate()
            proc.wait(timeout=5)

        # El verificador completo debe aprobar nuestras D4/D5; D1-D3 quedan
        # para los otros responsables del reparto.
        verify_port = free_port()
        verify_env = os.environ.copy()
        verify_env["PYTHONIOENCODING"] = "utf-8"
        checked = subprocess.run(
            [sys.executable, str(VERIFY), "--dir", str(target), "--port", str(verify_port)],
            capture_output=True, text=True, encoding="utf-8", timeout=15, env=verify_env,
        )
        print("\n=== Verificador del laboratorio (D4/D5 son este bloque) ===")
        print(checked.stdout, end="")
        plain = re.sub(r"\x1b\[[0-9;]*m", "", checked.stdout)
        assert "✓ D4" in plain and "✓ D5" in plain
        assert checked.returncode == 1  # D1-D3 aún no integradas.


if __name__ == "__main__":
    main()
