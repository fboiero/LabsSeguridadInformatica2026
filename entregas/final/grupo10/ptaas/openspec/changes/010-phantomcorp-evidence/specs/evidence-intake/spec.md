## ADDED Requirements

Tests: `tests/test_phantomcorp_evidence.py`.

### Requirement: Recolección local sin acceso al activo
### Scenario: Carpeta explícita con exportaciones autorizadas
- GIVEN una carpeta local de staging aprobada por el operador
- WHEN se ejecuta el recolector
- THEN busca solo los cuatro nombres fijos, valida los metadatos y calcula sus hashes

### Scenario: Archivo inesperado o no conforme
- GIVEN un nombre extra o un archivo previsto que es enlace, demasiado grande o inválido
- WHEN se importa
- THEN el extra se ignora y el archivo previsto no conforme se marca rechazado sin propagar sus datos

### Scenario: Hito no acreditado automáticamente
- GIVEN metadatos válidos, inválidos o ausentes
- WHEN se genera el borrador
- THEN todos los hitos quedan sin acreditar, con su estado de importación y revisión humana pendiente
