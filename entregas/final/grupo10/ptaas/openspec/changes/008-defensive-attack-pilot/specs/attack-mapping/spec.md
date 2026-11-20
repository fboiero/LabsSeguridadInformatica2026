## ADDED Requirements

Tests: `tests/test_attack_pilot.py`, `tests/test_runtime.py`.

### Requirement: Asociación preliminar sustentada
El piloto DEBE devolver una decisión por caso, con referencias exactas al caso
y técnica permitida por el extracto versionado; nunca confirma un incidente.

### Scenario: Serie de fallos compatible
- GIVEN una serie sintética de fallos de inicio de sesión del mismo contexto
- WHEN el agente referencia la evidencia de la serie y propone T1110
- THEN se guarda como candidato pendiente de revisión humana

### Scenario: Falta de evidencia conductual
- GIVEN un evento aislado o una alerta estática sin logs
- WHEN se procesan los casos
- THEN solo se permite evidencia insuficiente, sin técnica

### Scenario: Referencias inventadas o cruzadas
- GIVEN una técnica fuera del catálogo, evidencia de otro caso o casos omitidos
- WHEN se valida la salida
- THEN no se guarda ninguna decisión y se pide revisión humana

### Requirement: Ruteo y presupuesto explícitos

### Scenario: Ruteo por rol y tope separado
- GIVEN el piloto opcional o la demo original
- WHEN se pide generación a OpenCode
- THEN MITRE y Bandit usan Astra, coordinación e informe Sol, inventario y
  correlación Terra; el piloto intenta como máximo una generación sin fallback.
