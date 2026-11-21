# Delta — correlation (Change 005, propuesta P4)

Tests: tests/test_schemas.py, tests/test_correlation_loop_b.py

## ADDED Requirements

### Requirement: Snapshots offline íntegros y trazables
La correlación DEBE leer NVD y EPSS desde snapshots locales, sin conexiones a Internet durante la consulta. Cada snapshot DEBE conservar procedencia, fecha, versión de esquema y un hash verificable. Los fixtures sintéticos de prueba DEBEN identificarse como tales y NO DEBEN presentarse como datos oficiales.

#### Scenario: snapshot válido
- GIVEN un snapshot local de prueba con esquema, fecha y hash consistentes
- WHEN se solicita la consulta de un registro existente
- THEN se devuelve el dato junto con la referencia de procedencia, sin realizar conexiones de red

#### Scenario: snapshot alterado
- GIVEN un snapshot cuyo contenido no coincide con el hash registrado
- WHEN el cliente intenta cargarlo
- THEN rechaza el snapshot y produce un error auditable, sin usar sus registros

#### Scenario: snapshot ausente o desactualizado
- GIVEN un snapshot inexistente o que excede el umbral de vigencia configurado
- WHEN se intenta correlacionar un activo
- THEN se declara explícitamente `missing` o `stale`, sin atribuir actualidad a datos no vigentes ni reemplazar la consulta offline con sondeos

### Requirement: Enriquecimiento sin datos inventados
La correlación DEBE vincular CVE, CWE y EPSS solo con registros comprobables del snapshot y con identificación de producto/versión sustentada en evidencia. La ausencia de datos DEBE conservarse como `None` o `unknown` según el contrato de `CandidateFinding`.

#### Scenario: CVE inexistente en el snapshot
- GIVEN un activo cuya tecnología no tiene coincidencia verificable en NVD
- WHEN se solicita correlacionar posibles CVE
- THEN no se crea un candidato por CVE y no se inventa un identificador

#### Scenario: EPSS ausente
- GIVEN un CVE válido que no aparece en el snapshot EPSS
- WHEN se enriquece el candidato
- THEN `epss` permanece `None` y la ausencia queda trazada

#### Scenario: versión ambigua
- GIVEN un producto detectado sin versión suficiente para comprobar afectación
- WHEN se busca una coincidencia NVD dependiente de versión
- THEN no se afirma una coincidencia confirmada y la incertidumbre queda reflejada en la confianza o en la ausencia de candidato

### Requirement: Evidencia y confianza reproducibles
Todo candidato generado DEBE tener `evidence_refs` resolubles y justificar la relación entre activo, tecnología y fuente. La confianza DEBE depender de reglas deterministas documentadas, nunca de una conjetura del agente.

#### Scenario: evidencia no disponible
- GIVEN una coincidencia propuesta sin referencias de evidencia resolubles
- WHEN se intenta producir un `CandidateFinding`
- THEN el candidato se rechaza y no se persiste

#### Scenario: evidencia independiente y coincidente
- GIVEN evidencia del activo y una coincidencia de producto y versión verificable en el snapshot
- WHEN se evalúa la confianza usando los mismos insumos
- THEN se obtiene la misma clasificación y se conservan las referencias originales

### Requirement: Correlación exclusivamente sobre datos
En fase `CORRELATE` NO DEBE ejecutarse ninguna acción que contacte activos. Cualquier propuesta de sondeo DEBE bloquearse mediante el harness y registrarse en la bitácora.

#### Scenario: intento de acción activa durante correlación
- GIVEN un token válido para fase `CORRELATE`
- WHEN se solicita a `Harness.invoke` una capacidad que contacte un activo
- THEN el harness la bloquea y registra el intento sin invocar el adaptador

### Requirement: Deduplicación y normalización justificadas
Los candidatos equivalentes por activo y CVE/CWE DEBEN consolidar sus evidencias. CWE y técnicas ATT&CK solo DEBEN asignarse si existe mapeo con fuente explícita; de lo contrario DEBEN mantenerse como `unknown` y `None`, respectivamente.

#### Scenario: candidato duplicado
- GIVEN dos candidatos del mismo activo y CVE con referencias distintas
- WHEN se deduplican
- THEN queda un candidato con ambas referencias de evidencia

#### Scenario: taxonomía no mapeable
- GIVEN un hallazgo sin equivalencia CWE o ATT&CK verificable
- WHEN se normalizan sus taxonomías
- THEN `cwe` es `unknown` y `attack_technique` es `None`, sin equivalencias inventadas

#### Scenario: hallazgos sin CVE y CWE desconocido
- GIVEN dos observaciones diferentes del mismo activo sin CVE ni CWE conocido
- WHEN se considera consolidarlas
- THEN no se debe perder evidencia ni convertir observaciones independientes en un solo hallazgo sin identidad compartida demostrada

> Nota para revisión: la última situación puede requerir ampliar la clave de deduplicación de `harness/schemas.py`, que actualmente usa `(asset_id, cve or cwe)`; no modificar ese archivo sin coordinar con su dueño.
