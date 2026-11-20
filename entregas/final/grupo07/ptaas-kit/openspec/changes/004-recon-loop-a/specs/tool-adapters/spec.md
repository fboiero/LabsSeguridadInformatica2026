# Delta — tool-adapters

Tests: `tests/test_adapters_004_005.py`, `tests/test_recon_loop.py`

## Requirement: Subfinder pasivo y acotado
El adaptador `subfinder.enum` DEBE usar argv fijo sin shell, JSONL validado, timeout y límite de solicitudes/resultados; NO DEBE usar fuentes activas ni iniciar actualizaciones automáticas.

### Scenario: argumentos de subfinder
- GIVEN un dominio FQDN válido
- WHEN se construye el argv
- THEN se usa `-d`, JSONL, rate limit y timeout, sin `-all`, `-active`, proxy ni shell

### Scenario: línea JSON inválida
- GIVEN salida JSONL malformada o sin hostname
- WHEN se procesa
- THEN se rechaza como error de salida y no produce activos parciales

## Requirement: HTTPX con límites deterministas
El adaptador `httpx.probe` DEBE aceptar un único hostname validado y usar JSONL, límite de tasa, timeout corto, reintentos cero y sin salida a servicios cloud.

### Scenario: argumentos de httpx
- GIVEN un hostname permitido
- WHEN se construye el argv
- THEN los argumentos incluyen el límite configurado, timeout y reintentos cero, y excluyen dashboard, paths arbitrarios, requests crudos y archivos de entrada

### Scenario: entrada con metacaracteres
- GIVEN un target que contiene flags, espacios, URL o metacaracteres
- WHEN el adaptador valida el target
- THEN lo rechaza antes de ejecutar el runner

## Requirement: Salida de herramientas validada
Los adaptadores DEBEN convertir su salida a objetos estructurados; una línea inválida no debe incorporarse como evidencia.

### Scenario: jsonl de httpx inválido
- GIVEN una línea JSON inválida
- WHEN se procesa
- THEN se devuelve un error de schema en vez de un objeto parcial
