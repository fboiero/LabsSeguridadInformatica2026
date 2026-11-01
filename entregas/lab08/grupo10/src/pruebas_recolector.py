#!/usr/bin/env python3
"""Pruebas unitarias del recolector, sin dependencias ni conexiones de red.

Dentro de Docker local, desde la raíz del repositorio:
    python3 -B -m unittest discover -s entregas/lab08/grupo10/src \
        -p 'pruebas_recolector.py' -v

urlopen se reemplaza por respuestas JSON en memoria o un HTTPError 404.
Los datos son ficticios: no se lee .env ni se usan credenciales o flags reales.
"""

import io
import json
import unittest
from unittest.mock import call, patch
from urllib.error import HTTPError

import recolector


def respuesta_json(datos):
    """BytesIO implementa read() y el contexto with usado por urlopen."""
    return io.BytesIO(json.dumps(datos).encode("utf-8"))


class PruebasRecolector(unittest.TestCase):
    BASE = "http://phantomcorp-db"
    HALLAZGO = "hallazgo_ficticio_para_pruebas"

    def test_devuelve_hallazgo_y_detiene_recorrido(self):
        respuestas = [
            respuesta_json({"id": 11, "nombre": "Prueba", "area": "Lab"}),
            respuesta_json({
                "id": 12,
                "nombre": "Prueba",
                "area": "Lab",
                "dato_especial": self.HALLAZGO,
            }),
        ]
        with patch(
            "recolector.urllib.request.urlopen", side_effect=respuestas
        ) as urlopen:
            resultado = recolector.buscar_flag(self.BASE, 11, 14)

        self.assertEqual(resultado, (12, self.HALLAZGO))
        # La lista exacta demuestra que no consultó los legajos 13 y 14.
        self.assertEqual(urlopen.call_args_list, [
            call(f"{self.BASE}/empleado?id=11", timeout=3.0),
            call(f"{self.BASE}/empleado?id=12", timeout=3.0),
        ])

    def test_continua_tras_404_hasta_encontrar_hallazgo(self):
        respuestas = [
            HTTPError(
                f"{self.BASE}/empleado?id=31", 404, "Not Found", None, None
            ),
            respuesta_json({"id": 32, "nombre": "Prueba", "area": "Lab"}),
            respuesta_json({
                "id": 33,
                "nombre": "Prueba",
                "area": "Lab",
                "dato_especial": self.HALLAZGO,
            }),
        ]
        with patch(
            "recolector.urllib.request.urlopen", side_effect=respuestas
        ) as urlopen:
            resultado = recolector.buscar_flag(self.BASE, 31, 34)

        self.assertEqual(resultado, (33, self.HALLAZGO))
        # El 404 no corta la búsqueda y tampoco se consulta después de hallar.
        self.assertEqual(urlopen.call_args_list, [
            call(f"{self.BASE}/empleado?id=31", timeout=3.0),
            call(f"{self.BASE}/empleado?id=32", timeout=3.0),
            call(f"{self.BASE}/empleado?id=33", timeout=3.0),
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
