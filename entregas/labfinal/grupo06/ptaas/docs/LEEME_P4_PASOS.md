# Cierre acelerado del Change 005 — Persona 4

Colocá cada archivo en `ptaas/` respetando las carpetas `tools/`, `tests/` y `docs/`. Ningún archivo existente debería sobrescribirse.

## Paso único: revisión estática + tests (NO ejecuta escaneos)

Desde PowerShell, estando en `ptaas`:

```powershell
.\.venv\Scripts\python.exe -m tools.p4_preflight_005
.\.venv\Scripts\python.exe -m pytest tests/test_p4_preflight_005.py -q
.\.venv\Scripts\ruff.exe check tools/p4_preflight_005.py tests/test_p4_preflight_005.py
.\.venv\Scripts\mypy.exe --strict --follow-imports=silent tools/p4_preflight_005.py
.\.venv\Scripts\python.exe -m pytest -q
```

Si todos pasan, revisar diff ANTES de cualquier commit:

```powershell
git add tools/p4_preflight_005.py tests/test_p4_preflight_005.py docs/P4_REVISION_PENDIENTE_005.md docs/LEEME_P4_PASOS.md entrega/evidencia/salidas/p4-template-preflight.json
git diff --cached --check
git diff --cached --stat
git commit -m "005: evidencia de preflight Nuclei y solicitud de revision"
git push origin labfinal-ptaas-p4-grupo06
```

No agregar `evidencia/zap/prueba-escritura.txt`, `INSTRUCCIONES_P4.md` ni `tools/run_zap_lab_p4.py` automáticamente. No copiar templates a allowlist ni ejecutar ZAP/Nuclei sin los gates y revisión documentados.

## Revisiones que requieren otras personas

1. Enviar a **P3** la revisión de `design.md` y los deltas `correlation`/`vuln-analysis`; P3 revisa P4.
2. Solicitar al revisor designado los cinco templates YAML y su firma por archivo, fecha y versión.
3. Pedir al responsable de RoE/P2 confirmación de autorización/HITL para el laboratorio.
4. Recién entonces planificar corridas de ZAP/Nuclei y archivar deltas OpenSpec.

## Nota sobre evaluaciones live

El runner actual utiliza Anthropic y requiere una credencial local válida. Si no existe acceso configurado, informar “live pendiente” en la entrega. Nunca registrar un golden como live.
