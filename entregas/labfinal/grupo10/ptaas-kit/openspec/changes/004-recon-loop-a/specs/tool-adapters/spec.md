# Delta — tool-adapters (Change 004: Adaptadores de recon)

Tests: `tests/test_subfinder_httpx_adapters.py`

## Requirement: Adaptadores tipados de recon (`subfinder.enum` y `httpx.probe`)
Los adaptadores `subfinder.enum` y `httpx.probe` DEBEN declarar fase `RECON`, modo no destructivo, validar targets y salidas JSON/JSONL, construir argv fijo sin shell y aplicar `RateLimiter`.

### Scenario: rechazo de salida inválida o error de ejecución en adaptador
- GIVEN un runner que devuelve JSON malformado o falla por timeout/binario ausente
- WHEN se invoca el adaptador `subfinder.enum` o `httpx.probe`
- THEN el adaptador rechaza la salida o reporta `ToolExecutionError` controlado sin ejecutar shell

### Scenario: bloqueo por exceso de rate limit en `httpx.probe`
- GIVEN un `RateLimiter` configurado según `policy.yaml` (5 rps por target)
- WHEN se excede el umbral sobre el mismo objetivo dentro de la ventana de 1 segundo
- THEN `httpx.probe` rechaza la solicitud excedente antes de invocar el runner
