## ADDED Requirements

### Consulta humana opcional de Correlación

Correlación PUEDE pedir contexto humano cuando lo considere útil para interpretar
la evidencia, sin requerir una intervención en cada turno. La pregunta pendiente
DEBE persistir; la persona puede responder o indicar que no tiene más contexto.
La respuesta es contexto no verificado, no autoriza ni repite consultas, y no
convierte una observación en hallazgo confirmado. Redacción no requiere una pausa.

#### Scenario: Contexto solicitado y sesión recuperada
- GIVEN Correlación solicita contexto sobre la evidencia disponible
- WHEN se reabre la sesión y la persona responde o indica que no tiene contexto
- THEN Correlación continúa sin repetir consultas y conserva los límites de la evidencia

#### Scenario: Correlación no necesita contexto
- GIVEN Correlación devuelve una interpretación sin pregunta humana
- WHEN se procesa su respuesta
- THEN el flujo continúa a Redacción sin intervención humana

Tests: `tests/test_relevo.py`.
