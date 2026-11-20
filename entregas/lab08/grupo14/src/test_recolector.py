#!/usr/bin/env python3
"""Self-check de buscar_flag() sin red: mockea consultar_legajo().

Corré: python3 test_recolector.py
"""
from unittest.mock import patch

import recolector


LEGAJOS = {
    1: {"nombre": "Ana", "area": "RRHH"},
    2: {"nombre": "Beto", "area": "IT"},
    3: {"nombre": "Cris", "area": "IT", "flag": "FLAG{test_123}"},
    4: {"nombre": "Dana", "area": "RRHH"},
}


def _fake_consultar(base, id_, timeout=3.0):
    return LEGAJOS.get(id_)


def test_encuentra_y_corta():
    llamadas = []

    def espia(base, id_, timeout=3.0):
        llamadas.append(id_)
        return _fake_consultar(base, id_, timeout)

    with patch("recolector.consultar_legajo", side_effect=espia):
        resultado = recolector.buscar_flag("http://fake", 1, 4)

    assert resultado == (3, "FLAG{test_123}"), resultado
    assert llamadas == [1, 2, 3], f"no cortó al encontrar el flag: {llamadas}"


def test_sin_flag_devuelve_none():
    with patch("recolector.consultar_legajo", side_effect=_fake_consultar):
        resultado = recolector.buscar_flag("http://fake", 1, 2)
    assert resultado is None, resultado


def test_ids_inexistentes_no_rompen():
    with patch("recolector.consultar_legajo", return_value=None):
        resultado = recolector.buscar_flag("http://fake", 100, 105)
    assert resultado is None, resultado


if __name__ == "__main__":
    test_encuentra_y_corta()
    test_sin_flag_devuelve_none()
    test_ids_inexistentes_no_rompen()
    print("OK: todos los self-checks pasaron")
