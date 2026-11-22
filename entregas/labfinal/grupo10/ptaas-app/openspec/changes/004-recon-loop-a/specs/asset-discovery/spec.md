Tests: `tests/test_recon_correlation_reporting.py`

## Requirements

### Scenario: Loop A estabilizado
- GIVEN un objetivo Juice Shop autorizado
- WHEN el grafo no cambia en una ronda posterior
- THEN el loop termina con `graph_stabilized`

### Scenario: Descubrimiento fuera de alcance
- GIVEN un resultado de subfinder externo
- WHEN se normaliza el grafo
- THEN se registra como fuera de alcance y no se sondea

### Scenario: Salida de herramienta fija
- GIVEN el dominio autorizado
- WHEN se construye argv
- THEN solo se usa `subfinder -d <lab> -silent`
