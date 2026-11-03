"""Pruebas stdlib de la implementación, sin dependencias ni red externa."""
import contextlib
import hashlib
import hmac
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import jwt_tool as jwt


class JWTTests(unittest.TestCase):
    def setUp(self):
        self.clave = b"clave-ficticia-de-prueba"
        with patch.object(jwt.time, "time", return_value=1700000000):
            self.token = jwt.forjar(self.clave, "diego", "user")

    def test_decodificar(self):
        header, payload, firma = jwt.decodificar(self.token)
        self.assertEqual(header, {"alg": "HS256", "typ": "JWT"})
        self.assertEqual(payload, {"sub": "diego", "role": "user",
                                   "iat": 1700000000, "exp": 1700003600})
        self.assertEqual(len(firma), 64)

    def test_hmac_independiente(self):
        cab, pay, fir = self.token.split(".")
        esperado = hmac.new(self.clave, f"{cab}.{pay}".encode(), hashlib.sha256)
        self.assertEqual(jwt.b64url_dec(fir), esperado.digest())
        self.assertTrue(jwt.firma_es_valida(self.token, self.clave))

    def test_clave_incorrecta(self):
        self.assertFalse(jwt.firma_es_valida(self.token, b"otra"))

    def test_firma_alterada(self):
        cab, pay, fir = self.token.split(".")
        cambio = ("A" if fir[0] != "A" else "B") + fir[1:]
        self.assertFalse(jwt.firma_es_valida(f"{cab}.{pay}.{cambio}", self.clave))

    def test_payload_alterado_se_lee_pero_no_valida(self):
        cab, _, fir = self.token.split(".")
        pay = jwt.b64url(json.dumps({"sub": "maria"}).encode())
        alterado = f"{cab}.{pay}.{fir}"
        self.assertEqual(jwt.decodificar(alterado)[1]["sub"], "maria")
        self.assertFalse(jwt.firma_es_valida(alterado, self.clave))

    def test_none_y_malformados(self):
        _, pay, _ = self.token.split(".")
        cab = jwt.b64url(b'{"alg":"none"}')
        for token in ("", "a.b", "a.b.c.d", "@.@.@", f"{cab}.{pay}.",
                      f"{jwt.b64url(b'[]')}.{pay}.abc", self.token + "é"):
            with self.subTest(token=token):
                self.assertFalse(jwt.firma_es_valida(token, self.clave))

    def test_firma_no_equivale_a_validar_expiracion(self):
        self.assertTrue(jwt.firma_es_valida(self.token, self.clave))
        self.assertLess(jwt.decodificar(self.token)[1]["exp"], jwt.time.time())

    def test_diccionario_y_estadisticas(self):
        with tempfile.TemporaryDirectory() as tmp:
            archivo = Path(tmp) / "diccionario.txt"
            archivo.write_text("\nincorrecta\nclave-ficticia-de-prueba\notra\n", encoding="utf-8")
            salida = io.StringIO()
            with contextlib.redirect_stderr(salida):
                self.assertEqual(jwt.crackear_secreto(self.token, str(archivo)),
                                 self.clave.decode())
            self.assertIn("CANDIDATOS: 2", salida.getvalue())

    def test_no_encontrado_y_diccionario_vacio(self):
        with tempfile.TemporaryDirectory() as tmp:
            archivo = Path(tmp) / "diccionario.txt"
            for contenido in ("incorrecta\n", ""):
                archivo.write_text(contenido, encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(jwt.crackear_secreto(self.token, str(archivo)), "")

    def test_espacios_y_unicode_en_clave(self):
        clave = " contraseña de prueba "
        token = jwt.forjar(clave.encode(), "diego", "user")
        with tempfile.TemporaryDirectory() as tmp:
            archivo = Path(tmp) / "diccionario.txt"
            archivo.write_text(clave + "\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(jwt.crackear_secreto(token, str(archivo)), clave)


if __name__ == "__main__":
    unittest.main(verbosity=2)
