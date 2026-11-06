"""Propuesta didáctica local; no modifica el IDS de la cátedra."""
import re
import unittest
from urllib.parse import parse_qs

PATRON = re.compile(r"\bunion(?:\s|/\*.*?\*/)+select\b", re.I | re.S)


def detectar(query):
    # Una decodificación, igual que el procesamiento habitual de formularios.
    return any(PATRON.search(valor) for valores in
               parse_qs(query, keep_blank_values=True).values() for valor in valores)


class FirmaTests(unittest.TestCase):
    def test_variantes_detectadas(self):
        for query in ("q=UNION+SELECT", "q=UNION%20SELECT", "q=UNION/**/SELECT",
                      "q=uNiOn%09sElEcT", "q=UNION/*comentario*/SELECT",
                      "q=UNION%2F%2A%2A%2FSELECT", "q=UNION/**/%0ASELECT"):
            with self.subTest(query=query):
                self.assertTrue(detectar(query))

    def test_controles_negativos(self):
        for query in ("q=catalogo", "item=73", "q=reunion+selectiva", "q=select"):
            with self.subTest(query=query):
                self.assertFalse(detectar(query))


if __name__ == "__main__":
    unittest.main(verbosity=2)
