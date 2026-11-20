# Tasks — Change 001

Estado real: el **núcleo determinista** está implementado y testeado (77 tests). Falta la integración con el runtime de orquestación (LangGraph), las herramientas reales y el sandbox.

## 1. Harness (control plane)
- [x] 1.1 Máquina de estados del engagement (`harness/engagement.py`)
- [x] 1.2 `ScopeToken`, `Guard`, `is_live()` cargando `policy.yaml` (`contracts.py`, `policy_loader.py`)
- [x] 1.3 `Harness.invoke()` con kill switch y gates HITL
- [x] 1.4 Bitácora append-only con hash encadenado (verificación en `tests/test_audit_and_policy.py`)
- [x] 1.5 Persistir la bitácora (SQLite) y exponer verificador de integridad como comando — change 002 (`harness/audit.py`, `python -m harness.audit verify`)

## 2. Capabilities mínimas
- [x] 2.0 Reglas deterministas: schemas, dedupe, priorización, loops (`schemas.py`, `loops.py`)
- [x] 2.0b Adaptadores acotados nmap y Nuclei (argv builders + perfiles)
- [x] 2.0c Catálogo de verificaciones inertes y evaluadores (`harness/poc/`)
- [x] 2.0d Reporte con CWE + CVSS v4 + remediación y gate de entrega (`reporting.py`)
- [x] 2.1 authorization: cargar RoE firmado → emitir token (`harness/roe.py`, `harness/tokens.py`; ver change 003)
- [x] 2.2 asset-discovery: adaptadores subfinder/httpx + loop A conectado a LangGraph — adaptadores y loop A hechos y corridos contra el lab (change 004, recorrido del 007/008). **LangGraph no se adoptó:** orquestación determinista propia, decisión registrada en el change 009 (alternativa, costo y tests de control)
- [x] 2.3 correlation: clientes NVD/EPSS/CWE reales — change 005 (clientes de snapshot offline con verificación de hash y antigüedad, mapeo CWE). No hay snapshot de datos NVD en el repositorio (observación 4 del archivo del 005)
- [x] 2.4 vuln-analysis: adaptador ZAP baseline + loop B conectado — change 005 (adaptador, loop B) y change 008 (loop B con ZAP en el recorrido, corrida real)
- [x] 2.5 validation: sandbox efímero (contenedor, red aislada) que implemente `Sender` — change 006 (`harness/sandbox.py`, prueba de aislamiento real)
- [x] 2.6 reporting: exportación a DefectDojo — change 007 (`harness/defectdojo_export.py`), exportación real en `P5-recorrido-04` e importación de prueba en DefectDojo local

## 3. Verificación
- [x] 3.1 Fuera de scope → BLOCKED + bitácora
- [x] 3.2 Toda acción activa exige token vivo
- [x] 3.3 Token vencido → BLOCKED
- [x] 3.4 Kill switch → ABORTED
- [x] 3.5 Informe exige CWE + CVSS v4
- [x] 3.6 Evals golden por agente (`evals/`); modo `live` pendiente de probar
- [x] 3.7 Test end-to-end contra el laboratorio aislado (DVWA/Juice Shop) — tests del recorrido (`tests/test_reporting_e2e.py`, `tests/test_analisis_real.py`) y corrida real `P5-recorrido-04` (entregada)
