# Delta — correlation

Tests: tests/test_schemas.py, tests/test_correlation.py, tests/test_adapters_004_005.py

## Requirement: Correlación sobre datos, sin tocar activos
La correlación DEBE operar solo sobre el `AssetGraph` y feeds de datos (CVE/NVD, EPSS, CWE); NO DEBE iniciar conexiones hacia los activos.

### Scenario: intento de sondeo en fase CORRELATE
- GIVEN un token de fase CORRELATE
- WHEN el agente intenta una acción que contacta un activo
- THEN el harness la bloquea y la registra

## Requirement: Candidato con evidencia
Todo `CandidateFinding` DEBE citar evidencia (activo, versión/tecnología detectada y fuente del dato).

### Scenario: candidato sin evidencia
- GIVEN un candidato sin `evidence_refs`
- WHEN se intenta persistir
- THEN se rechaza por schema inválido

## Requirement: Sin datos inventados
El sistema NO DEBE completar CVE, EPSS ni CWE inexistentes; los datos ausentes DEBEN marcarse como `unknown`/`null`.

### Scenario: tecnología sin CVE conocido
- GIVEN una tecnología sin entradas en el feed
- WHEN se enriquece el activo
- THEN `cve` es `null` y no se genera candidato por CVE

## Requirement: Deduplicación
El sistema DEBE deduplicar candidatos por (activo, CWE/CVE).

### Scenario: mismo hallazgo por dos fuentes
- GIVEN dos candidatos con igual activo y CVE
- WHEN termina la correlación
- THEN queda un único candidato con ambas evidencias

## Requirement: Normalización de taxonomías
Cada candidato DEBERÍA mapearse a CWE y, cuando aplique, a una técnica MITRE ATT&CK.

### Scenario: candidato sin CWE mapeable
- GIVEN un candidato sin CWE derivable
- WHEN se normaliza
- THEN se marca `cwe: unknown` y pasa a análisis con baja confianza

## Change 005 — snapshots NVD/EPSS y coincidencia exacta

### Requirement: Snapshots offline con fecha y frescura
Los lookups DEBEN consultar archivos locales versionados con fecha y origen; snapshots fuera de `max_age_days` DEBEN rechazarse.

### Scenario: lookup de snapshot vigente
- GIVEN un alias exacto presente en NVD y token CORRELATE vigente
- WHEN se consulta
- THEN se devuelve el registro guardado sin solicitudes de red

### Scenario: snapshot vencido
- GIVEN un snapshot anterior a la ventana de frescura
- WHEN se correlaciona
- THEN se devuelve error explícito y no se usa el dato viejo

### Requirement: Alias exacto y evidencia
Un candidato DEBE coincidir exactamente con un alias de producto y versión, y conservar refs al activo y al registro NVD.

### Scenario: producto parecido sin versión exacta
- GIVEN un activo con versión distinta de las aliases del feed
- WHEN se correlaciona
- THEN no se crea candidato ni se inventa CVE

### Requirement: Datos faltantes y mapeo contextual
EPSS, CVSS v4 y técnica ATT&CK ausentes DEBEN quedar `null`; ATT&CK solo se asigna si se satisface el contexto local explícito.
