#!/usr/bin/env python3
"""Entrega al motor oficial solo las flags recuperadas por reproducir.py."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", required=True, help="Ruta de Git Bash o bash de Linux")
    parser.add_argument("--sesion", type=Path, required=True)
    parser.add_argument("--registro", type=Path, required=True)
    args = parser.parse_args()
    raiz = Path(__file__).resolve().parents[4]
    sesion = args.sesion.resolve()
    registro = args.registro.resolve()
    registro.mkdir(parents=True, exist_ok=False)
    resumen = json.loads((sesion / "16-resumen.json").read_text(encoding="utf-8"))
    registro_comandos = registro / "ctf-comandos.txt"
    with registro_comandos.open("x", encoding="utf-8") as log:
        for reto in ("R1", "R2", "R3"):
            # El motor oficial acepta también el contenido sin FLAG{...} y
            # agrega ese envoltorio al verificar. Evita la transformación de
            # llaves observada al pasar argv al bash.exe de este entorno.
            valor = resumen[reto].removeprefix("FLAG{").removesuffix("}")
            # `ctf` invoca utilidades Bash/GNU y se espera CWD con git LF.
            # En Windows ejecutar desde Git Bash evita la pérdida de llaves
            # observada al pasar FLAG{...} como argv desde PowerShell.
            import shlex
            comando_shell = "./ctf submit extra5 " + reto + " " + shlex.quote(valor)
            comando = [args.bash, "-lc", comando_shell]
            log.write(subprocess.list2cmdline(comando) + "\n")
            log.flush()
            with (registro / f"ctf-submit-{reto}.txt").open("xb") as salida:
                subprocess.run(comando, cwd=raiz, stdout=salida,
                               stderr=subprocess.STDOUT, check=True)
        comando = [args.bash, "-lc", "./ctf status extra5"]
        log.write(subprocess.list2cmdline(comando) + "\n")
        with (registro / "ctf-status-extra5.txt").open("xb") as salida:
            subprocess.run(comando, cwd=raiz, stdout=salida,
                           stderr=subprocess.STDOUT, check=True)
    print("Submit y status oficiales guardados en", registro)


if __name__ == "__main__":
    main()
