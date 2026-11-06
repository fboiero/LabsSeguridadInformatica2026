import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("timeline.py")
SPEC = importlib.util.spec_from_file_location("lab11_timeline", MODULE_PATH)
timeline = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(timeline)


class TimelineTests(unittest.TestCase):
    def test_parsea_y_filtra_access_log(self):
        repo_root = Path(__file__).resolve().parents[4]
        log = repo_root / "labs/lab11-forensia/caso/logs/access.log"
        events = timeline.construir_timeline(str(log), "185.220.101.42")
        self.assertEqual(len(events), 16)
        self.assertTrue(all(e["ip"] == "185.220.101.42" for e in events))
        self.assertEqual(events[0]["ts"], "05/Sep/2026:02:14:03 +0000")
        self.assertEqual(events[-1]["ts"], "05/Sep/2026:02:23:15 +0000")
        self.assertEqual(events[-1]["status"], 200)
        self.assertEqual(events[-1]["ruta"], "/uploads/shell.php?c=cat%20/app/priv/clientes.db.txt")

    def test_descarta_lineas_invalidas(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "access.log"
            log.write_text("comentario\n10.0.0.1 - - [time] \"GET / HTTP/1.1\" 200 1\n", encoding="utf-8")
            self.assertEqual(len(timeline.construir_timeline(str(log))), 1)

    def test_clasificacion_de_fases(self):
        cases = {
            "/": "RECON",
            "/portal-rrhh/login": "EXPLOIT",
            "/backup/rrhh.conf": "ENUM",
            "/api/reporte?cmd=id": "RCE",
            "/api/reporte?cmd=wget%20shell.php": "WEBSHELL",
            "/uploads/shell.php?c=cat%20clientes.db.txt": "ACCESO/EXFIL",
        }
        for route, expected in cases.items():
            with self.subTest(route=route):
                self.assertEqual(timeline.clasificar_fase(route), expected)


if __name__ == "__main__":
    unittest.main()
