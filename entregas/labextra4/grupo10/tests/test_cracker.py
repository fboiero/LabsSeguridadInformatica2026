#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
test_cracker.py — Pruebas unitarias de src/cracker.py (Lab Extra 4, Grupo 10).

Responsable: Belén. No se modifica src/cracker.py; estas pruebas se adaptan a
sus firmas reales (hash_de, cargar_sombra, aplicar_reglas, crackear).

Datos exclusivamente sintéticos: ningún hash, salt, contraseña ni usuario de
este archivo proviene de labs/labextra4-cracking/caso/. Los hashes esperados
se calculan en el propio test con hashlib, de forma independiente.

Uso:
    python -m unittest entregas.labextra4.grupo10.tests.test_cracker -v
    # o, parado en entregas/labextra4/grupo10/:
    python tests/test_cracker.py
"""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import cracker  # noqa: E402


def _escribir_temp(contenido: str) -> str:
    """Crea un archivo temporal de texto y devuelve su ruta."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8")
    f.write(contenido)
    f.close()
    return f.name


class TestHashDe(unittest.TestCase):
    """hash_de(algo, salt_hex, password) -> str"""

    def test_md5(self):
        salt, pwd = "deadbeef", "clave-sintetica-1"
        esperado = hashlib.md5(bytes.fromhex(salt) + pwd.encode()).hexdigest()
        self.assertEqual(cracker.hash_de("md5", salt, pwd), esperado)

    def test_sha256(self):
        salt, pwd = "cafebabe", "clave-sintetica-2"
        esperado = hashlib.sha256(bytes.fromhex(salt) + pwd.encode()).hexdigest()
        self.assertEqual(cracker.hash_de("sha256", salt, pwd), esperado)

    def test_pbkdf2(self):
        salt, pwd = "0102030405060708", "clave-sintetica-3"
        esperado = hashlib.pbkdf2_hmac(
            "sha256", pwd.encode(), bytes.fromhex(salt), cracker.ITER_PBKDF2
        ).hex()
        self.assertEqual(cracker.hash_de("pbkdf2", salt, pwd), esperado)

    def test_algoritmo_no_soportado_levanta_valueerror(self):
        with self.assertRaises(ValueError):
            cracker.hash_de("bcrypt", "aa", "x")

    def test_normaliza_mayusculas_y_espacios_en_el_algoritmo(self):
        salt, pwd = "aabbccdd", "clave-sintetica-4"
        self.assertEqual(cracker.hash_de("MD5", salt, pwd), cracker.hash_de("md5", salt, pwd))
        self.assertEqual(cracker.hash_de(" sha256 ", salt, pwd), cracker.hash_de("sha256", salt, pwd))


class TestCargarSombra(unittest.TestCase):
    """cargar_sombra(ruta) -> list[tuple(usuario, algo, salt_hex, hash_hex)]"""

    def test_parseo_correcto_ignora_comentarios_y_lineas_vacias(self):
        contenido = (
            "# comentario de cabecera, formato usuario:algo:salt:hash\n"
            "\n"
            "usuario_sintetico_a:MD5:AABBCC:112233\n"
            "   \n"
            "usuario_sintetico_b:SHA256:ddeeff:445566\n"
        )
        ruta = _escribir_temp(contenido)
        try:
            registros = cracker.cargar_sombra(ruta)
        finally:
            Path(ruta).unlink()
        self.assertEqual(
            registros,
            [
                ("usuario_sintetico_a", "md5", "aabbcc", "112233"),
                ("usuario_sintetico_b", "sha256", "ddeeff", "445566"),
            ],
        )

    def test_registro_con_menos_campos_levanta_valueerror(self):
        ruta = _escribir_temp("usuario_incompleto:md5:aabbcc\n")
        try:
            with self.assertRaises(ValueError):
                cracker.cargar_sombra(ruta)
        finally:
            Path(ruta).unlink()

    def test_registro_con_campo_vacio_levanta_valueerror(self):
        ruta = _escribir_temp("usuario_x::aabbcc:112233\n")
        try:
            with self.assertRaises(ValueError):
                cracker.cargar_sombra(ruta)
        finally:
            Path(ruta).unlink()


class TestAplicarReglas(unittest.TestCase):
    """aplicar_reglas(palabra) -> list[str]"""

    def test_incluye_la_palabra_base_y_la_mayuscula_inicial(self):
        variantes = cracker.aplicar_reglas("fantasma")
        self.assertIn("fantasma", variantes)
        self.assertIn("Fantasma", variantes)

    def test_incluye_sufijos_de_anio_2024_a_2026(self):
        variantes = cracker.aplicar_reglas("fantasma")
        for anio in ("2024", "2025", "2026"):
            self.assertIn("fantasma" + anio, variantes)
            self.assertIn("Fantasma" + anio, variantes)

    def test_incluye_sufijos_numericos_comunes(self):
        variantes = cracker.aplicar_reglas("fantasma")
        for num in ("1", "12", "123"):
            self.assertIn("fantasma" + num, variantes)
            self.assertIn("Fantasma" + num, variantes)

    def test_sin_candidatos_duplicados(self):
        # "Operador" y "ABC" ya empiezan en mayúscula: palabra.capitalize()
        # puede coincidir con la palabra original (o con otra variante), que
        # es exactamente el caso donde aparecería un duplicado si no se
        # dedupicara.
        for lemma in ("fantasma", "Operador", "x", "ABC", "a1"):
            variantes = cracker.aplicar_reglas(lemma)
            self.assertEqual(
                len(variantes),
                len(set(variantes)),
                f"aplicar_reglas({lemma!r}) devolvió candidatos duplicados: {variantes!r}",
            )

    def test_preserva_orden_de_insercion(self):
        variantes = cracker.aplicar_reglas("fantasma")
        self.assertEqual(variantes[0], "fantasma")
        self.assertEqual(variantes[1], "Fantasma")


class TestCrackear(unittest.TestCase):
    """crackear(sombra, diccionario, con_reglas=False) -> dict[usuario, password]"""

    def _registro_md5(self, usuario: str, salt_hex: str, password: str):
        hash_hex = cracker.hash_de("md5", salt_hex, password)
        return (usuario, "md5", salt_hex, hash_hex)

    def test_caso_correcto_sin_reglas(self):
        reg = self._registro_md5("operador_sintetico", "11223344", "clave1")
        dic = _escribir_temp("clave0\nclave1\nclave2\n")
        try:
            halladas = cracker.crackear([reg], dic, con_reglas=False)
        finally:
            Path(dic).unlink()
        self.assertEqual(halladas, {"operador_sintetico": "clave1"})

    def test_caso_invalido_password_fuera_del_diccionario(self):
        reg = self._registro_md5("analista_sintetico", "55667788", "no-esta-en-el-diccionario")
        dic = _escribir_temp("clave0\nclave1\nclave2\n")
        try:
            halladas = cracker.crackear([reg], dic, con_reglas=False)
        finally:
            Path(dic).unlink()
        self.assertNotIn("analista_sintetico", halladas)
        self.assertEqual(halladas, {})

    def test_cae_con_reglas_pero_no_sin_reglas(self):
        # La contraseña real es un lemma del diccionario con una variante de
        # mangling (año): sin --reglas no debería caer; con --reglas, sí.
        reg = self._registro_md5("admin_sintetico", "99aabbcc", "fantasma2025")
        dic = _escribir_temp("fantasma\notrapalabra\n")
        try:
            sin_reglas = cracker.crackear([reg], dic, con_reglas=False)
            con_reglas = cracker.crackear([reg], dic, con_reglas=True)
        finally:
            Path(dic).unlink()
        self.assertEqual(sin_reglas, {})
        self.assertEqual(con_reglas, {"admin_sintetico": "fantasma2025"})

    def test_varios_usuarios_mezcla_de_hallados_y_no_hallados(self):
        reg_a = self._registro_md5("usuario_a", "aaaaaaaa", "clave1")
        reg_b = self._registro_md5("usuario_b", "bbbbbbbb", "no-cae")
        dic = _escribir_temp("clave0\nclave1\nclave2\n")
        try:
            halladas = cracker.crackear([reg_a, reg_b], dic, con_reglas=False)
        finally:
            Path(dic).unlink()
        self.assertEqual(halladas, {"usuario_a": "clave1"})
        self.assertNotIn("usuario_b", halladas)

    def test_pbkdf2_sin_limite_arbitrario_de_candidatos(self):
        # El diccionario sintético tiene 12 candidatos y la contraseña real
        # es EL ÚLTIMO. Si crackear() tuviera un límite arbitrario (por
        # ejemplo, evaluar solo los primeros N candidatos de pbkdf2 "porque
        # es lento"), esta contraseña nunca se encontraría. Confirma que
        # recorre el diccionario completo también para pbkdf2.
        salt = "0102030405060708"
        candidatos = [f"candidato_sintetico_{i}" for i in range(11)]
        candidatos.append("clave_real_al_final")
        dic = _escribir_temp("\n".join(candidatos) + "\n")
        hash_hex = cracker.hash_de("pbkdf2", salt, "clave_real_al_final")
        reg = ("root_sintetico", "pbkdf2", salt, hash_hex)
        try:
            halladas = cracker.crackear([reg], dic, con_reglas=False)
        finally:
            Path(dic).unlink()
        self.assertEqual(halladas, {"root_sintetico": "clave_real_al_final"})

    def test_busqueda_interrumpida_no_se_informa_como_completada_sin_resultados(self):
        # Simula un Ctrl+C a mitad de la evaluación de un usuario. crackear()
        # tiene que PROPAGAR KeyboardInterrupt, no devolver un dict vacío o
        # parcial como si fuera un resultado ya completo y sin coincidencias:
        # quien llama tiene que enterarse de que la búsqueda quedó
        # incompleta, no asumir que ya se evaluó todo el diccionario.
        salt = "aabbccdd11223344"
        candidatos = [f"candidato_{i}" for i in range(10)]
        dic = _escribir_temp("\n".join(candidatos) + "\n")
        # Hash que no coincide con ningún candidato real: si la interrupción
        # simulada no cortara el proceso, crackear() recorrería la lista
        # entera sin encontrar nada.
        hash_hex = cracker.hash_de("md5", salt, "contraseña-fuera-de-la-lista")
        reg = ("victima_sintetica", "md5", salt, hash_hex)

        llamadas = {"n": 0}
        original_hash_de = cracker.hash_de

        def hash_de_con_interrupcion(algo, salt_hex, password):
            llamadas["n"] += 1
            if llamadas["n"] == 3:
                raise KeyboardInterrupt
            return original_hash_de(algo, salt_hex, password)

        cracker.hash_de = hash_de_con_interrupcion
        try:
            with self.assertRaises(KeyboardInterrupt):
                cracker.crackear([reg], dic, con_reglas=False)
        finally:
            cracker.hash_de = original_hash_de
            Path(dic).unlink()
        # Se interrumpió antes de recorrer todos los candidatos: la llamada
        # número 3 de 10 confirma que no se "completó" silenciosamente.
        self.assertEqual(llamadas["n"], 3)
        self.assertLess(llamadas["n"], len(candidatos))


if __name__ == "__main__":
    unittest.main(verbosity=2)
