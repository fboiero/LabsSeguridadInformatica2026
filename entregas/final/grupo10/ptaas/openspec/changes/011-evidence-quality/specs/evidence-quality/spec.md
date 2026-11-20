## ADDED Requirements

Tests: `tests/test_evidence_quality.py`.

### Requirement: Revisión defensiva sin datos crudos ni acciones
### Scenario: Evidencia histórica de la rama del grupo
- GIVEN el commit local del grupo con sus artefactos archivados
- WHEN se genera el paquete
- THEN se inventarían sus referencias Git, se extraen solo estados del registro y el modelo no recibe rutas ni texto original

### Scenario: Estado incompleto o inventado
- GIVEN una salida del modelo con referencias cruzadas, duplicadas o estados incompatibles
- WHEN se valida el análisis
- THEN se descarta sin copiar la salida cruda; el informe sigue pendiente de revisión humana

### Scenario: Contexto Bandit acotado y ligado al informe
- GIVEN metadatos de Bandit y etiquetas contextuales aprobadas para ese hash
- WHEN se prepara el análisis
- THEN solo se admiten etiquetas enumeradas de alertas conocidas, sin código, comandos ni rutas

### Scenario: Comparación reproducible
- GIVEN el mismo lote de casos de evidencia sintética
- WHEN se comparan Astra, Terra y Sol
- THEN se registra calidad por caso y latencia por modelo sin inventar costos ni afirmar una aprobación
