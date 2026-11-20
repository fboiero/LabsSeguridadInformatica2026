# Lautaro — Change 002: bitácora persistente

Corte del 20/11/2026. Trabajo sobre `final-grupo07`, solo dentro de la entrega.

## Qué quedó implementado
- **`harness/audit.py` · `SqliteAuditLog`**: bitácora append-only persistida en
  SQLite, un archivo por engagement, con la **misma cadena de hashes** que
  `contracts.AuditLog` (sha256 del cuerpo con `prev`). Hereda de `AuditLog`, así
  que es un drop-in del Harness **sin tocar `contracts.py`**.
- **Append-only por motor:** triggers `BEFORE UPDATE`/`BEFORE DELETE` que hacen
  `RAISE(ABORT, …)`; no hay API de modificación/borrado.
- **Verificación al abrir:** si la cadena está corrupta, el constructor lanza
  `AuditChainCorrupted` y el engagement no continúa. Verificación bajo demanda
  con `verify()` y con la CLI `python -m harness.audit verify <archivo>`.
- **Concurrencia:** `threading.Lock` serializa leer-último-hash + insertar, y WAL
  en SQLite; dos escritores no comparten `prev`.
- **Delta de spec** `audit-log`: 4 Requirements nuevos (persistencia por
  engagement, verificación al abrir, almacenamiento inmutable, escrituras
  concurrentes) con Scenarios negativos; archivado en `openspec/specs/audit-log/spec.md`.
- **Tests** (`tests/test_audit_persistence.py`, 10): persistencia tras reinicio,
  aislamiento entre engagements, UPDATE/DELETE bloqueados, detección de
  alteración y de borrado intermedio, verificación al abrir, escrituras
  concurrentes, CLI, "sin datos sensibles" e integración con `Harness`.

## Estado
- `python -m pytest -q` → **162 passed** (152 base + 10 de 002).
- `ruff check harness/audit.py tests/test_audit_persistence.py` → all checks passed.
- `mypy harness` → `harness/audit.py` sin errores (los 39 restantes son
  preexistentes en otros módulos, no introducidos por 002).
- `python tools/progress.py` → exit 0 (verde). 002 en 13/14 tareas.
- Mutation check del verificador: romper la comparación de hash hace **fallar 2
  tests** (la mutación queda matada). Ver `evidencia/lautaro/mutation-002.txt`.

## Pendiente (honesto)
- Tarea **1.3 — revisión del delta por otro integrante**: queda sin marcar; es
  coordinación con el grupo, no código.
- Integración en `harness/run.py`: se demostró el enganche con `Harness` en un
  test; cablear la ruta de archivo por engagement en el `run` de punta a punta se
  coordina con Fernando (dueño de 006/007) para no pisar su integración.

## Declaración de uso de IA (Lautaro Mariño, @lautaromarino0)
Se utilizó **Claude (Anthropic)** como asistente. **Qué:** ayudó a diseñar el
esquema SQLite y la política de integridad (`design.md`), a redactar el delta de
`audit-log`, los tests y `harness/audit.py`, a partir de mi análisis; revisé y
ajusté cada archivo antes de commitearlo. **Cómo se verificó:** corrí la suite
completa, `ruff`, `mypy`, `progress.py` y un mutation check del verificador en el
entorno virtual del kit; las salidas crudas están en `evidencia/lautaro/`. No se
inventaron resultados ni se marcó 1.3 como hecha. No se cambió la interfaz pública
de `contracts.py`. El esqueleto/arquitectura es del kit del curso; lo nuevo es la
persistencia (002).

## Reproducir
```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
python -m pytest -q
python -m pytest tests/test_audit_persistence.py -v
python tools/progress.py
python -m harness.audit verify <archivo.db>   # OK -> 0 ; corrupta -> 1
```
