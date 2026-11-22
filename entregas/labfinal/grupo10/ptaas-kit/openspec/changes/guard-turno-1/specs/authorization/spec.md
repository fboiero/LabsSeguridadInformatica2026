# Delta — validación de targets DNS

Tests: tests/authorization/test_guard_boundaries.py

## Requirement: rechazar nombres DNS malformados
Un target de dominio con espacios internos no puede autorizarse por coincidencia de sufijo.

### Scenario: etiqueta con espacio interno
- GIVEN un token válido para el dominio del laboratorio
- WHEN el target incluye un espacio dentro de una etiqueta de subdominio
- THEN se registra BLOCKED sin invocar el adaptador
