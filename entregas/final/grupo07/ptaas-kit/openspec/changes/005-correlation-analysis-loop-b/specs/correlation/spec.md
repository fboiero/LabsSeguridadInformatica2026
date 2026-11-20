# Delta — correlation

Tests: `tests/test_correlation.py`, `tests/test_adapters_004_005.py`

## Requirement: Snapshots offline versionados
La correlación DEBE leer snapshots locales de NVD y EPSS con fecha y origen, sin consultas de red durante pruebas o lookup.

### Scenario: lookup offline
- GIVEN un snapshot que contiene un producto/version
- WHEN se consulta con un token CORRELATE
- THEN el adaptador devuelve el registro guardado sin invocar un cliente de red

### Scenario: snapshot ausente o desactualizado
- GIVEN un snapshot inexistente o cuyo `as_of` supera la política de frescura
- WHEN se intenta correlacionar
- THEN se informa `unknown`/error de snapshot y no se usan datos inventados

## Requirement: Coincidencia exacta y evidencia
Un candidato DEBE relacionar un activo y versión observados con un registro NVD que coincida exactamente con un alias del snapshot, y citar ambas fuentes.

### Scenario: candidato con evidencia
- GIVEN un activo con una versión que coincide con un registro local
- WHEN se correlaciona
- THEN `CandidateFinding` incluye CVE, activo, tecnología y fuente NVD en `evidence_refs`

### Scenario: tecnología sin coincidencia
- GIVEN una tecnología que no aparece en los snapshots
- WHEN se correlaciona
- THEN no se inventa CVE ni se crea candidato

## Requirement: Datos ausentes y deduplicación
Los campos que falten DEBEN quedar como `null`/`unknown`; duplicados por activo y CVE/CWE DEBEN fusionar sus evidencias.

### Scenario: EPSS ausente
- GIVEN un CVE del snapshot NVD que no aparece en EPSS
- WHEN se correlaciona
- THEN `epss` queda `null` y no se transforma en cero

### Scenario: duplicado entre fuentes
- GIVEN el mismo CVE/activo desde dos evidencias
- WHEN termina la correlación
- THEN queda un candidato y conserva ambas referencias

## Requirement: Mapeo CWE y ATT&CK contextual
El sistema DEBE mapear CWE y SOLO asignar ATT&CK si existe una relación explícita y aplicable en el mapa versionado.

### Scenario: mapeo sin contexto suficiente
- GIVEN un CWE conocido pero contexto que no satisface el mapa
- WHEN se normaliza
- THEN `attack_technique` queda `null` y el CWE se preserva
