"""Lectura reproducible de fuentes de R3 y control de custodia; no ejecuta artefactos."""
from pathlib import Path
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[4]
CASE = ROOT / 'labs/lab11-forensia/caso'
OUT = Path(__file__).resolve().parents[1] / 'evidencia/salidas'
selected = ['memoria/bash_history.txt', 'memoria/pslist.txt', 'memoria/lsof.txt', 'disco/listado.txt', 'logs/access.log']
expected = {}
for line in (CASE / 'evidencia.sha256').read_text().splitlines():
    parts = line.split(maxsplit=1)
    if len(parts) == 2 and len(parts[0]) == 64:
        expected[parts[1].lstrip('*')] = parts[0]
sha = lambda b: hashlib.sha256(b).hexdigest()
checks = []
for rel in selected:
    raw = (CASE / rel).read_bytes()
    blob = subprocess.check_output(['git', 'show', f'HEAD:labs/lab11-forensia/caso/{rel}'], cwd=ROOT)
    checks += [rel, f'esperado={expected[rel]}', f'checkout={sha(raw)}', f'blob_HEAD={sha(blob)}',
               f'blob_coincide_manifiesto={sha(blob) == expected[rel]}',
               f'checkout_CRLF_a_LF_igual_blob={raw.replace(bytes([13,10]), bytes([10])) == blob}', '']
(OUT / 'p3-custodia-fuentes.txt').write_text('\n'.join(checks), encoding='utf-8')
lines = []
for rel in selected:
    lines.append(f'=== {rel} (checkout; numeracion de lineas original) ===')
    for n, line in enumerate((CASE / rel).read_text(encoding='utf-8').splitlines(), 1):
        if rel != 'logs/access.log' or 18 <= n <= 21:
            lines.append(f'{rel}:{n}: {line}')
(OUT / 'r3-escalada-memoria.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('Guardados p3-custodia-fuentes.txt y r3-escalada-memoria.txt. Originales sin escritura.')
