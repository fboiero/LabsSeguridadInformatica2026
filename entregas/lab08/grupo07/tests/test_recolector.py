import contextlib
import importlib.util
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "src" / "recolector.py"
SPEC = importlib.util.spec_from_file_location("recolector", SOURCE)
recolector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recolector)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith("id=404"):
            self.send_response(404)
            self.end_headers()
            return
        if self.path.endswith("id=slow"):
            time.sleep(0.08)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"nombre":"Prueba","area":"QA"}')

    def log_message(self, *_args):
        pass


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, _request, _client_address):
        # El cliente cancela a propósito la solicitud de timeout.
        pass


class RecolectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _QuietServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=1)

    def test_inclusive_range_and_stops_at_first_flag(self):
        responses = [
            {"nombre": "A", "area": "QA"},
            {"nombre": "B", "area": "IT", "nota_interna": "FLAG{controlado}"},
            {"nombre": "C", "area": "QA", "flag": "FLAG{no_debe_leerse}"},
        ]
        with mock.patch.object(recolector, "consultar_legajo", side_effect=responses) as consulta:
            self.assertEqual(
                recolector.buscar_flag("http://test", 10, 12),
                (11, "FLAG{controlado}"),
            )
        self.assertEqual([call.args[1] for call in consulta.call_args_list], [10, 11])

    def test_no_flag_scans_both_inclusive_endpoints(self):
        with mock.patch.object(recolector, "consultar_legajo", return_value={"nombre": "X", "area": "Y"}) as consulta:
            self.assertIsNone(recolector.buscar_flag("http://test", 2, 4))
        self.assertEqual([call.args[1] for call in consulta.call_args_list], [2, 3, 4])

    def test_missing_and_error_results_are_skipped(self):
        responses = [None, None, {"nombre": "Z", "area": "QA", "secreto": "FLAG{tras_error}"}]
        with mock.patch.object(recolector, "consultar_legajo", side_effect=responses):
            self.assertEqual(recolector.buscar_flag("http://test", 1, 3), (3, "FLAG{tras_error}"))

    def test_reversed_range_makes_no_requests(self):
        with mock.patch.object(recolector, "consultar_legajo") as consulta:
            self.assertIsNone(recolector.buscar_flag("http://test", 3, 2))
        consulta.assert_not_called()

    def test_http_404_returns_none(self):
        self.assertIsNone(recolector.consultar_legajo(self.base, "404"))

    def test_timeout_returns_none_and_reports_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = recolector.consultar_legajo(self.base, "slow", timeout=0.001)
        self.assertIsNone(result)
        self.assertIn("error en id=slow", stderr.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
