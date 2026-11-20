# PTaaS — Entrega grupo 14 (variante capstone con swarm de agentes)

**Grupo:** 14 · ver `INTEGRANTES.md` · **Fecha:** 2026-11-20
**Base:** `labs/labfinal-practico-integrador/ptaas-kit/` (kit de referencia de la cátedra)

> **Honestidad sobre el alcance.** Esta variante está pensada como un proyecto de
> equipo de ~15 días. El kit de la cátedra ya trae una base de referencia (specs,
> harness, 77 tests, evals, demo). **Lo que entregamos acá es el *delta* propio del
> grupo**, construido y entendido por nosotros sobre esa base, no el kit completo
> presentado como obra nuestra. Más abajo delimitamos con precisión qué es base
> provista y qué es aporte del grupo, y qué quedó pendiente.

---

## 1. Qué es la plataforma (en una página)

PTaaS automatiza un pentest **autorizado** con un swarm de agentes de IA que
recorren las fases **recon → correlación → análisis → validación → reporte**. La
tesis del proyecto no es "romper", sino **construir el control** que hace ese
pentest seguro y auditable:

- **Guard determinista** (sin LLM): toda acción pasa por `Harness.invoke` y se
  autoriza contra un **scope token** (alcance + ventana + fase). Lo no autorizado
  se bloquea y **queda en bitácora**.
- **Bitácora append-only con hash encadenado**: detecta alteración y borrado.
- **Gates HITL** (humano en el loop) antes de la primera acción activa, de la
  validación y de la entrega.
- **Validación** solo parametrizando PoCs de un **catálogo versionado** en sandbox;
  nunca se generan exploits nuevos.
- **Loops acotados**: cada loop tiene condición de parada y tope de iteraciones.

Marco de referencia: PTES, NIST SP 800-115, OWASP WSTG, CVSS v4, CWE,
ISO/IEC 29147 y 30111.

## 2. Estado de la base (verificado por nosotros)

Lo corrimos y verificamos (evidencia en `evidencia/`):

| Comando | Resultado |
|---|---|
| `python -m pytest -q` | **88 pasan** (77 del kit + 11 nuestros) — `evidencia/pytest.txt` |
| `python evals/run_evals.py --mode golden` | **10/10** — `evidencia/evals-golden.txt` |
| `python tools/progress.py` | MVP 001 al 64%; changes 002–007 al 0% — `evidencia/progress.txt` |
| `python demo/recorrido_grupo14.py` | **OK — recorrido completo** — `evidencia/demo-recorrido.txt` |

## 3. Aporte propio del grupo (el delta)

Todo lo siguiente lo escribimos y lo entendemos nosotros:

### 3.1 Hallazgo de red-team + corrección (criterio 1)
El guard aplica alcance, fase, allow-list, token y kill-switch, pero las decisiones
de parada de los loops (`harness/loops.py`, `decide_recon`, etc.) son **solo
consultivas**: el agente puede ignorarlas y `Harness.invoke` no impone ningún tope.
La spec (delta de `asset-discovery`, Scenario "tope alcanzado") exige que **el
harness** rechace la iteración, no solo que el agente decida parar. Ese enforcement
no existía.

- **Hallazgo caracterizado** en test: `tests/test_grupo14_redteam.py`
  (`test_caracterizacion_sin_enforcement_a_nivel_harness`).
- **Corrección**: `harness/limits.py` → `GuardedHarness` (determinista, aditivo, no
  cambia el contrato del harness) con dos controles: (1) **tope de iteraciones de
  loop por fase** (`begin_iteration`, leído de `policy.yaml`) — cumple literalmente
  la spec; (2) **tope de invocaciones por `(acción, objetivo)`** como defensa en
  profundidad, con el bloqueo registrado en bitácora.
- **Change OpenSpec** con delta de spec, proposal y tasks:
  `openspec/changes/008-grupo14-limits-enforcement/`.
- `begin_iteration` se usa de verdad en el loop de recon de la demo.

### 3.2 Scenario faltante de `audit-log`: "sin datos sensibles" (criterios 1 y 3)
La spec exige que la bitácora **no** guarde credenciales ni datos del cliente, solo
referencias. Implementamos el control y su test:

- `harness/contracts.py` → `evidence_ref(content)`: cita la evidencia por digest
  SHA-256 + tamaño, nunca el contenido. **Cableado al camino real**: `AuditLog.record`
  acepta `evidence` y guarda solo la referencia, y `Harness.invoke` adjunta la
  referencia de la salida del adaptador en cada registro OK.
- `tests/test_grupo14_audit_sensibles.py`: verifica que la referencia no filtra el
  token ni los datos, y que `record(evidence=...)` guarda el digest, no el contenido.

### 3.3 Demo de recorrido de punta a punta (criterios 2 y 5)
`demo/recorrido_grupo14.py`: **un comando** ejecuta CREATED → DELIVERED con guard,
tokens por fase, gates HITL, `GuardedHarness`, loop con parada, reporte con
CWE+CVSS v4 y verificación de la cadena de hashes. Usa adaptadores **inertes
simulados** (sin escaneo real, por las reglas del proyecto).

### 3.4 Retrospectiva de ética y trabajo con IA (criterio 6)
Ver `retrospectiva-ia.md`: cómo usamos la IA, errores concretos que detectamos y
corregimos, y controles propuestos con estándares.

## 4. Cómo reproducir

```bash
cd labs/labfinal-practico-integrador/ptaas-kit
pip install pyyaml pytest
python -m pytest -q                      # 88 tests
python evals/run_evals.py --mode golden  # 10 casos
python demo/recorrido_grupo14.py         # recorrido completo
```
(En Windows, anteponer `PYTHONUTF8=1` por el encoding de la consola.)

## 5. Autoevaluación honesta contra la rúbrica

| Criterio | Dónde estamos | Por qué |
|---|---|---|
| 1. Harness e invariantes (25) | Logrado / tramo alto | Invariantes con tests; red-team propio con bypass hallado **y corregido** |
| 2. Swarm y loops (20) | En desarrollo | Loops con parada y tope demostrados en demo; falta corrida con agentes LLM reales |
| 3. Specs y tests (15) | En desarrollo / Logrado parcial | Llenamos un scenario faltante + delta de spec propio (change 008); no llegamos a `progress.py` 100% (changes 002–007 sin tocar) |
| 4. Herramientas y adaptadores (15) | En desarrollo (declarado) | Adaptadores inertes/simulados; subir a "Logrado" exige una corrida real (nmap/httpx/ZAP) contra DVWA/Juice Shop, que no hicimos hoy |
| 5. Informe, evals y demo (15) | Logrado parcial | Demo de un comando + evals 10/10; evals no llegan a 20 casos |
| 6. Ética y trabajo con IA (10) | Logrado | Retrospectiva con errores reales de IA detectados y corregidos |

## 6. Qué quedó pendiente (honestidad)

Lo que **no** hicimos, por ser trabajo de las ~2 semanas y no de un día:
- Changes 002–007 (persistencia SQLite, loops B/C completos con LLM, sandbox real,
  reporting a DefectDojo).
- Adaptadores reales (nmap/httpx/ZAP/Nuclei) corriendo contra DVWA/Juice Shop.
- Rate limit por segundo con ventana temporal (anotado en el change 008).
- Evals en vivo comparando modelos/prompts.
