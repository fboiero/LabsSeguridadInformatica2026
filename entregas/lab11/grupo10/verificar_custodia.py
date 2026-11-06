"""Verifica evidencia del Lab 11 sin modificar los archivos originales.

En Windows, Git puede convertir los finales LF a CRLF. Para comparar el
contenido lógico registrado en evidencia.sha256, normalizamos CRLF a LF solo
en memoria antes de calcular SHA-256.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CASE = ROOT / "labs" / "lab11-forensia" / "caso"
MANIFEST = CASE / "evidencia.sha256"
REPORT = Path(__file__).with_name("verificacion-custodia.txt")


def main() -> int:
    results: list[tuple[str, str, str, str]] = []

    for number, raw_line in enumerate(
        MANIFEST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            expected, relative_path = line.split(maxsplit=1)
        except ValueError as exc:
            raise ValueError(f"Línea inválida en manifiesto ({number}): {raw_line!r}") from exc

        relative_path = relative_path.strip().lstrip("* ")
        path = (CASE / relative_path).resolve()
        if not path.is_relative_to(CASE.resolve()):
            raise ValueError(f"Ruta fuera del caso en manifiesto: {relative_path}")
        if not path.is_file():
            results.append(("MISSING", relative_path, expected, "-"))
            continue

        # Normaliza CRLF -> LF solo en memoria. No escribe sobre el caso.
        # Git puede materializar CRLF en Windows. La conversión es solo
        # CRLF -> LF y ocurre en memoria; si no hay CRLF se hashean los bytes
        # originales directamente.
        content = path.read_bytes()
        normalized = content.replace(b"\r\n", b"\n")
        actual = hashlib.sha256(normalized).hexdigest()
        status = "OK" if actual == expected.lower() else "MISMATCH"
        results.append((status, relative_path, expected.lower(), actual))

    lines = [
        "Verificacion de cadena de custodia - Lab 11",
        f"Manifiesto: {MANIFEST.relative_to(ROOT)}",
        "Metodo: SHA-256 de bytes; CRLF->LF solo en memoria si aparece. Originales sin modificar.",
        "",
        "ESTADO    ARCHIVO                                      HASH ESPERADO                                                       HASH CALCULADO",
    ]
    for status, relative_path, expected, actual in results:
        lines.append(f"{status:<9} {relative_path:<45} {expected}  {actual}")

    ok_count = sum(result[0] == "OK" for result in results)
    mismatch_count = sum(result[0] == "MISMATCH" for result in results)
    missing_count = sum(result[0] == "MISSING" for result in results)
    lines.extend(
        [
            "",
            f"Resumen: {ok_count} OK; {mismatch_count} discrepancia(s); {missing_count} faltante(s).",
            "MISMATCH: el hash calculado no coincide con el manifiesto; documentar e investigar, no corregir el original.",
        ]
    )

    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(lines))
    return 1 if mismatch_count or missing_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
