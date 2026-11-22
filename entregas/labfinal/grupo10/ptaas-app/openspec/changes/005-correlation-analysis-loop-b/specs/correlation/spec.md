Tests: `tests/test_recon_correlation_reporting.py`

## Requirements

### Scenario: Candidato con evidencia
- GIVEN una observación con referencias de evidencia
- WHEN se correlaciona
- THEN se produce un candidato y los datos ausentes quedan `null`

### Scenario: Candidato sin evidencia
- GIVEN una observación sin referencias
- WHEN se correlaciona
- THEN se rechaza

### Scenario: Template fuera de allowlist
- GIVEN un template no registrado
- WHEN se construye el scan
- THEN no se ejecuta

### Scenario: Loop B sin progreso
- GIVEN dos batches idénticos
- WHEN se analiza
- THEN termina como `inconclusive`
