import importlib.util
import hashlib
import tempfile
from pathlib import Path

ruta = "entregas/labextra4/grupo06/cracker.py"
spec = importlib.util.spec_from_file_location("cracker_p2", ruta)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Hash de prueba independiente: no cambia la función de Persona 1.
mod.hash_de = lambda algo, salt, password: hashlib.sha256(
    bytes.fromhex(salt) + password.encode("utf-8")
).hexdigest()

salt = "a1b2c3d4"
password = "claveprueba"
hash_esperado = mod.hash_de("sha256", salt, password)

sombra = [
    ("usuario_prueba", "sha256", salt, hash_esperado)
]

with tempfile.TemporaryDirectory() as carpeta:
    diccionario = Path(carpeta) / "diccionario.txt"
    diccionario.write_text(
        "incorrecta\nclaveprueba\notra\n",
        encoding="utf-8"
    )

    resultado = mod.crackear(sombra, str(diccionario))
    print("Resultado:", resultado)

    assert resultado == {"usuario_prueba": "claveprueba"}
    print("PRUEBA P2 SUPERADA")
