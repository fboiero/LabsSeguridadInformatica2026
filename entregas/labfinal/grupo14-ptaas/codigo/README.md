# Código del grupo 14 — copia para revisión

Esta carpeta es una **copia-fotografía** del aporte de código del grupo, para que la
entrega sea autocontenida. **No se ejecuta desde acá** (sus imports apuntan al kit):
es una copia de lectura para el corrector. El código **vivo y ejecutable** está en el
kit del proyecto, porque ahí es donde corre (imports `from harness...`, descubrimiento
de `pytest`, y el workflow spec-driven de OpenSpec).

> Por qué en el kit: el enunciado indica "este kit trae una base de referencia; deben
> revisarla y ampliarla". Extender el kit es el flujo esperado. Igual dejamos esta copia
> acá para que se vea con claridad qué agregó el grupo.

## Mapa: archivo → ubicación ejecutable en el kit

Base del kit: `labs/labfinal-practico-integrador/ptaas-kit/`

| Copia en esta carpeta | Archivo vivo en el kit | Qué es |
|---|---|---|
| `harness/limits.py` | `harness/limits.py` | **Nuevo.** `GuardedHarness`: topes de iteración de loop y por objetivo. |
| `tests/test_grupo14_redteam.py` | `tests/test_grupo14_redteam.py` | **Nuevo.** Red-team del guard: hallazgo + corrección. |
| `tests/test_grupo14_audit_sensibles.py` | `tests/test_grupo14_audit_sensibles.py` | **Nuevo.** Scenario "sin datos sensibles" de audit-log. |
| `demo/recorrido_grupo14.py` | `demo/recorrido_grupo14.py` | **Nuevo.** Demo de recorrido completo con un comando. |
| `openspec/changes/008-grupo14-limits-enforcement/` | igual ruta | **Nuevo.** Change OpenSpec: proposal, tasks y delta de spec. |
| `contracts.py.patch` | `harness/contracts.py` | **Modificación** (2 agregados): `evidence_ref()` + su cableado en `record()` e `invoke()`. El `.patch` muestra exactamente las líneas agregadas. |

Todo lo demás del kit es base provista por la cátedra; no lo tocamos.

## Cómo correrlo (desde el kit, no desde acá)

```bash
cd labs/labfinal-practico-integrador/ptaas-kit
pip install pyyaml pytest
python -X utf8 -m pytest -q                # 88 tests
python -X utf8 evals/run_evals.py --mode golden   # 10/10
python -X utf8 demo/recorrido_grupo14.py   # recorrido completo
```

La salida registrada de estos comandos está en `../evidencia/`.
