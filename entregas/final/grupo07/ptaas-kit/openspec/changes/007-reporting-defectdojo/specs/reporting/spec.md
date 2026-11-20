# Delta — reporting
## Requirement: Herramientas reales en el recorrido
El modo --tools-mode docker DEBE ejecutar los adaptadores de A/B con Docker en
red internal 10.99.0.0/28, sin shell y con cleanup incluso ante timeout. Sin fallback
a fixtures. La correlación sigue offline y el candidato CSP sigue manual hasta
validación explícita. La procedencia DEBE acompañar el reporte y los gates se mantienen.

### Scenario: Modo Docker sin aprobación
- GIVEN un laboratorio interno y RoE vigente
- WHEN se pide el modo docker
- THEN los loops usan Docker y la entrega queda PENDING_HITL sin aprobación

### Scenario: Red pública o error de herramienta
- GIVEN red no interna o herramienta con error
- WHEN se intenta el recorrido
- THEN falla sin usar fixtures y elimina su worker
# Extensión 20/11: ejecución Docker de 004/005 integrada al reporte.

Tests: tests/test_report_bundle.py, tests/test_run_integration.py

## Requirement: Evidencia trazable
Cada referencia DEBE resolver a un registro de la bitácora del engagement y activo del hallazgo.

### Scenario: Referencia ajena o inexistente
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN la generación falla

## Requirement: Resumen PTES y procedencia
El informe DEBE incluir resumen ejecutivo, alcance, metodología, hallazgos, límites y remediación; distinguir fixtures, Sender restringido y sandbox.

### Scenario: Hallazgo observado con fixture
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN no se declara validado en sandbox real

## Requirement: Métricas y estados
El informe DEBE validar el vector base CVSS v4 estricto, EPSS opcional entre 0 y 1 y estado de validación. No calcula score numérico.

### Scenario: Vector con métricas extra inválidas o EPSS fuera de rango
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN se rechaza indicando el campo

## Requirement: Exportación y privacidad
La exportación DEBE usar Generic Findings Import JSON con campos permitidos y omitir datos crudos, cookies y secretos.

### Scenario: Texto con password, token o clave privada
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN se rechaza antes de exportar

## Requirement: Entrega versionada con HITL
La aprobación DEBE estar ligada al hash del informe completo y vencer; cambiar el informe invalida la aprobación.

### Scenario: Se modifica un informe ya aprobado
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN la entrega queda pendiente sin archivos publicados

## Requirement: Integración explícita de 004/005
El comando DEBE llamar ReconLoop, Correlator y DetectionLoop del equipo mediante
sus adaptadores y Harness.invoke. La demo offline DEBE identificar fixtures sintéticas,
correlación sin coincidencias y el candidato manual para validación, sin inventar CVE.
La procedencia de cada fase DEBE acompañar al informe y su versión aprobada.

### Scenario: HTTPX no ofrece versión exacta
- GIVEN las fixtures de 004 con PHP y Apache sin versión
- WHEN se correlaciona con los snapshots de 005
- THEN la lista CVE es vacía y el candidato CSP se identifica como semilla manual

### Scenario: análisis sin vínculo explícito al candidato
- GIVEN las alertas genéricas de las fixtures de 005
- WHEN DetectionLoop las analiza
- THEN el candidato queda inconcluso hasta su validación separada con aprobación

## Requirement: Bitácora durable del recorrido integrado
El comando DEBE utilizar SqliteAuditLog del change 002, con archivo determinado
por engagement dentro de la salida. DEBE conservar y verificar registros previos
al reabrir, rechazar cadenas corruptas o de otro engagement antes de actuar,
exportar audit.json compatible y cerrar la conexión aun si falla el recorrido.
Los gates de validación y entrega se mantienen independientes y no se aprueban
automáticamente. La CLI DEBE informar la ruta que acepta `harness.audit verify`.

### Scenario: Reinicio con bitácora sana
- GIVEN un recorrido guardado y cerrado en SQLite
- WHEN se ejecuta de nuevo para el mismo engagement y salida
- THEN los registros anteriores se conservan y la nueva cadena verifica

### Scenario: Bitácora alterada
- GIVEN una fila modificada fuera de los triggers
- WHEN se intenta reabrir el recorrido
- THEN no se llama al pipeline y se informa el fallo de integridad

### Scenario: Engagements diferentes
- GIVEN dos RoE con distintos engagement_id y la misma carpeta de salida
- WHEN se ejecutan sus recorridos
- THEN usan archivos SQLite diferentes sin mezclar sus registros

### Scenario: Fallo durante el recorrido
- GIVEN una bitácora SQLite abierta
- WHEN el pipeline falla
- THEN la conexión se cierra y el error se propaga
