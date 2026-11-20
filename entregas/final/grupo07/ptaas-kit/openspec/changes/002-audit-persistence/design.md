# Design — Change 002: persistencia de la bitácora

## Objetivo
Pasar la bitácora de memoria a un almacenamiento **append-only en SQLite**, un
archivo por engagement, con la **misma cadena de hashes** que `AuditLog`
(contracts.py), de modo que sobreviva a reinicios y detecte alteración o borrado.
Sin tocar la interfaz pública de `harness/contracts.py`.

## Esquema SQLite
Una tabla por archivo; un archivo por engagement.

```sql
CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,  -- orden de inserción
    ts         REAL NOT NULL,
    engagement TEXT NOT NULL,
    agent      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    phase      TEXT NOT NULL,
    result     TEXT NOT NULL,
    prev       TEXT NOT NULL,                       -- hash del registro anterior
    hash       TEXT NOT NULL UNIQUE                 -- sha256(body sin 'hash')
);
```

El `hash` reproduce exactamente el de `AuditLog.record`:
`sha256(json.dumps(body, sort_keys=True))` sobre
`{ts, engagement, agent, action, target, phase, result, prev}`. Así las dos
implementaciones son intercambiables y el verificador sirve para ambas.

## Política de integridad (decisiones)

- **UPDATE/DELETE prohibidos por trigger** (defensa en profundidad, no solo
  convención): `BEFORE UPDATE` y `BEFORE DELETE` hacen `RAISE(ABORT, …)`. Además
  la clase no expone ningún método de modificación/borrado (criterio de
  aceptación 3). Un atacante que use otra herramienta y borre/edite una fila
  **rompe la cadena** y el verificador lo detecta igual.
- **GENESIS por engagement:** el primer registro de cada archivo lleva
  `prev="GENESIS"`. Como hay un archivo por engagement, cada cadena arranca
  limpia y los engagements quedan aislados por construcción.
- **Verificación al abrir:** al instanciar se recorre la cadena; si está corrupta
  se lanza `AuditChainCorrupted` y el engagement **no continúa** (invariante del
  proposal). También hay verificación bajo demanda (`verify()` y la CLI).
- **Evidencia = referencia, no contenido:** el registro guarda solo metadatos
  (acción, objetivo, fase, resultado). No se almacenan credenciales ni contenido
  de datos del cliente (Requirement "sin datos sensibles").

## Concurrencia
Las escrituras pasan por un `threading.Lock` de proceso: leer el último hash e
insertar la fila nueva es una sección crítica atómica, así dos hilos no calculan
el mismo `prev`. SQLite se abre en modo **WAL** con `check_same_thread=False`.
Para el MVP el alcance es multi-hilo en un proceso; multi-proceso agregaría el
lock de archivo de SQLite leyendo el último hash dentro de la transacción.

## Integración con el Harness
`SqliteAuditLog` **hereda** de `AuditLog` y re-define `record()`; mantiene además
un espejo en memoria `entries` (cargado desde el archivo al abrir) para no cambiar
el contrato que leen el Harness y los tests. Se le pasa a `Harness(audit=...)` tal
cual, sin modificar `contracts.py`.

## CLI
`python -m harness.audit verify <archivo.db>` → imprime OK/CORRUPTA y retorna
código 0/1, para el criterio de aceptación 2.
