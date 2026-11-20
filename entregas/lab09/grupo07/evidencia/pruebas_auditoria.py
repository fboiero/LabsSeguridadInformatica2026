"""Verificaciones de C sobre módulos oficiales; fixtures sin procesos ni red.

No implementa ni prueba el esqueleto de A. No cambia el alcance ni las tools.
"""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.request

RAIZ = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(RAIZ / "labs/lab09-agentes/src"))
import herramientas as h
from llm import ClienteMock


class Auditoria(unittest.TestCase):
    def setUp(self):
        self.proceso = patch.object(h.subprocess, "run", side_effect=AssertionError("proceso prohibido"))
        self.red = patch.object(h.urllib.request, "urlopen", side_effect=AssertionError("red prohibida"))
        self.run = self.proceso.start()
        self.urlopen = self.red.start()
        self.addCleanup(self.proceso.stop)
        self.addCleanup(self.red.stop)

    def tearDown(self):
        self.run.assert_not_called()
        self.urlopen.assert_not_called()

    def test_r4_bloquea_las_tres_tools_antes_de_efectos(self):
        for nombre, args in [
            ("nmap_scan", {"host": "8.8.8.8"}),
            ("http_get", {"url": "http://8.8.8.8/"}),
            ("http_post", {"url": "http://8.8.8.8/", "data": {}}),
        ]:
            with self.subTest(tool=nombre):
                self.assertIn("BLOQUEADO POR GUARDRAIL", h.ejecutar_tool(nombre, args))

    def test_tool_desconocida_no_ejecuta(self):
        self.assertIn("tool desconocida", h.ejecutar_tool("shell", {}))

    def test_argumentos_invalidos_no_tienen_error_normalizado(self):
        with self.assertRaises(TypeError):
            h.ejecutar_tool("http_get", {})
        with self.assertRaises(AttributeError):
            h.ejecutar_tool("http_get", {"url": 123})

    def test_scope_no_restringe_puerto_y_parser_no_es_urlparse(self):
        self.assertIsNone(h._verificar_alcance("http://phantomcorp:9999/"))
        # Fixture puramente textual: el host real es externo.invalid, pero el
        # parser casero corta primero por ':' y devuelve phantomcorp.
        fixture = "http://phantomcorp:80@externo.invalid/"
        self.assertEqual(urllib.request.urlparse(fixture).hostname, "externo.invalid")
        self.assertIsNone(h._verificar_alcance(fixture))
        # No se pasa esta URL a ninguna tool ni se intenta resolverla.

    def test_redirect_estandar_construye_destino_sin_revalidar_scope(self):
        inicial = urllib.request.Request("http://phantomcorp/")
        # redirect_request SOLO construye un Request: nunca hace I/O.
        siguiente = urllib.request.HTTPRedirectHandler().redirect_request(
            inicial, None, 302, "fixture", {}, "http://externo.invalid/fin")
        self.assertEqual(siguiente.host, "externo.invalid")
        self.assertIn("BLOQUEADO", h._verificar_alcance(siguiente.full_url))
        # Las tools usan urlopen predeterminado y no revalidan este Request.

    def test_mock_ignora_resultados_y_no_extrae_token(self):
        cliente = ClienteMock("fixture", {})
        acciones = [cliente.paso([{"id": "fixture", "output": "HTTP 500 sin token"}])
                    for _ in range(8)]
        self.assertEqual(acciones[6]["nombre"], "http_post")
        self.assertEqual(acciones[6]["argumentos"], ClienteMock.PLAN[6]["argumentos"])
        self.assertEqual(cliente.paso([])["tipo"], "final")


if __name__ == "__main__":
    unittest.main(verbosity=2)
