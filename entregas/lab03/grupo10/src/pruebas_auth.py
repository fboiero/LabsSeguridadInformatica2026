#!/usr/bin/env python3
"""Pruebas del Lab 03. Ejecutar: python src/pruebas_auth.py.

Solo biblioteca estándar. Los resultados esperados de TOTP provienen de
RFC 6238, apéndice B (SHA-1); los de seis dígitos son sus últimos seis
dígitos, conservando los ceros iniciales. No se reemplaza ni simula auth.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auth


class PruebasTOTP(unittest.TestCase):
    SECRETO = b"12345678901234567890"

    def test_vector_59(self):
        self.assertEqual(auth.totp(self.SECRETO, 59), "287082")

    def test_vector_1111111109(self):
        self.assertEqual(auth.totp(self.SECRETO, 1111111109), "081804")

    def test_vector_1111111111(self):
        self.assertEqual(auth.totp(self.SECRETO, 1111111111), "050471")

    def test_vector_1234567890(self):
        self.assertEqual(auth.totp(self.SECRETO, 1234567890), "005924")

    def test_vector_2000000000(self):
        self.assertEqual(auth.totp(self.SECRETO, 2000000000), "279037")

    def test_vector_59_ocho_digitos(self):
        self.assertEqual(auth.totp(self.SECRETO, 59, digitos=8), "94287082")

    def test_misma_ventana(self):
        self.assertEqual(
            auth.totp(self.SECRETO, 30), auth.totp(self.SECRETO, 59)
        )

    def test_cambio_de_ventana(self):
        # Esta desigualdad corresponde a este secreto y estos tiempos;
        # no afirma que nunca pueda repetirse un código entre ventanas.
        self.assertNotEqual(
            auth.totp(self.SECRETO, 59), auth.totp(self.SECRETO, 60)
        )


class PruebasContrasenas(unittest.TestCase):
    PASSWORD = "Phantom-2026!"
    SALT_FIJO = bytes.fromhex("00112233445566778899aabbccddeeff")

    def test_salt_aleatorio_por_registro(self):
        primero = auth.hash_password(self.PASSWORD)
        segundo = auth.hash_password(self.PASSWORD)
        self.assertNotEqual(primero, segundo)
        self.assertNotEqual(primero.split("$")[2], segundo.split("$")[2])

    def test_formato_y_derivacion_del_registro(self):
        registro = auth.hash_password(self.PASSWORD)
        partes = registro.split("$")
        self.assertEqual(len(partes), 4)
        algoritmo, iteraciones, salt_hex, dk_hex = partes
        self.assertEqual(algoritmo, "pbkdf2_sha256")
        self.assertEqual(int(iteraciones), 200_000)
        salt = bytes.fromhex(salt_hex)
        derivada = bytes.fromhex(dk_hex)
        self.assertEqual(len(salt), 16)
        self.assertEqual(len(derivada), 32)
        esperada = hashlib.pbkdf2_hmac(
            "sha256", self.PASSWORD.encode("utf-8"), salt, int(iteraciones)
        )
        self.assertEqual(derivada, esperada)

    def test_salt_fijo_reproduce_registro(self):
        primero = auth.hash_password(self.PASSWORD, salt=self.SALT_FIJO)
        segundo = auth.hash_password(self.PASSWORD, salt=self.SALT_FIJO)
        self.assertEqual(primero, segundo)
        self.assertEqual(primero.split("$")[2], self.SALT_FIJO.hex())

    def test_password_correcta(self):
        registro = auth.hash_password(self.PASSWORD)
        self.assertIs(auth.verify_password(self.PASSWORD, registro), True)

    def test_password_incorrecta(self):
        registro = auth.hash_password(self.PASSWORD)
        self.assertIs(auth.verify_password("otra", registro), False)

    def test_registro_alterado_en_un_caracter(self):
        registro = auth.hash_password(self.PASSWORD)
        # Se cambia un dígito hexadecimal del hash, sin romper el formato.
        reemplazo = "0" if registro[-1] != "0" else "1"
        alterado = registro[:-1] + reemplazo
        self.assertIs(auth.verify_password(self.PASSWORD, alterado), False)

    def test_registros_mal_formados(self):
        # Construcción independiente: no depende de hash_password.
        prefijo = "pbkdf2_sha256"
        salt = self.SALT_FIJO.hex()
        dk = hashlib.pbkdf2_hmac(
            "sha256", self.PASSWORD.encode("utf-8"), self.SALT_FIJO, 1_000
        ).hex()
        registros = (
            "",
            "registro_incompleto",
            f"{prefijo}$1000${salt}",
            f"otro_algoritmo$1000${salt}${dk}",
            f"{prefijo}$no_es_numero${salt}${dk}",
            f"{prefijo}$1000$zz${dk}",
            f"{prefijo}$1000${salt}$zz",
            f"{prefijo}$1000${salt}${dk}$extra",
        )
        for registro in registros:
            with self.subTest(registro=registro):
                self.assertIs(auth.verify_password(self.PASSWORD, registro), False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
