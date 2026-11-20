# Spec — tool-adapters

Tests: `tests/test_adapters.py`, `tests/test_audit_and_policy.py`, `tests/test_adapters_004_005.py`, `tests/test_recon_loop.py`
Configuración: `harness/profiles.yaml`, `harness/tools.yaml`, `harness/policy.yaml`

## Requirement: Declaración de capability
Todo adaptador DEBE declarar nombre, fases permitidas y si es destructivo; el harness NO DEBE ejecutar capabilities sin adaptador registrado.

### Scenario: capability sin adaptador
- GIVEN una capability habilitada en la fase pero sin adaptador
- WHEN se invoca
- THEN la acción es bloqueada y registrada

### Scenario: adaptador fuera de su fase
- GIVEN un adaptador declarado solo para ANALYZE
- WHEN se invoca con un token de RECON
- THEN la acción es bloqueada

## Requirement: Ejecución sin shell
Los adaptadores DEBEN construir argv fijo y ejecutar sin shell, con timeout; NO DEBEN interpolar entrada sin validar.

### Scenario: target con metacaracteres
- GIVEN un target como `; rm -rf /` o `10.0.0.5 -A`
- WHEN el adaptador valida el target
- THEN lo rechaza antes de construir el comando

## Requirement: Argumentos prohibidos
El perfil de cada herramienta DEBE listar argumentos prohibidos y el adaptador DEBE rechazarlos.

### Scenario: nmap con scripts
- GIVEN un perfil de nmap que agrega `--script=vuln`
- WHEN se construye el comando
- THEN se rechaza por argumento prohibido

## Requirement: Nuclei acotado
El adaptador de Nuclei DEBE usar solo el directorio de templates curado, excluir etiquetas intrusivas y desactivar OAST.

### Scenario: perfil de Nuclei
- GIVEN el perfil vigente
- WHEN se construye el comando
- THEN incluye el directorio curado, excluye `intrusive`, `dos`, `fuzz`, `bruteforce` y desactiva OAST

## Requirement: Coherencia de configuración
Toda capability habilitada en `policy.yaml` DEBE existir en `tools.yaml` y viceversa.

### Scenario: capability huérfana
- GIVEN una capability presente en un solo archivo
- WHEN corre la verificación de coherencia
- THEN el test falla

## Change 004 — adaptadores de recon

### Requirement: Subfinder pasivo y acotado
`subfinder.enum` DEBE emitir JSONL con argv fijo, rate limit y timeout, sin fuentes activas ni actualizaciones automáticas.

### Scenario: argv de subfinder
- GIVEN un dominio validado
- WHEN se construye el comando
- THEN se activa JSONL pasivo y el rate limit del perfil sin `-all` ni `-active`

### Requirement: HTTPX acotado a un host
`httpx.probe` DEBE recibir un único hostname, producir JSONL y usar timeout, tasa y cero reintentos.

### Scenario: target con flag o URL
- GIVEN una entrada con espacios, esquema o flag
- WHEN se valida el target
- THEN se rechaza antes de ejecutar el runner

## Change 005 — ZAP baseline y Nuclei curado

### Requirement: Nuclei solo ejecuta allow-list intacta
El adaptador DEBE verificar SHA-256 de cada archivo declarado y DEBE rechazar rutas fuera del directorio, hashes alterados o requests distintos de GET.

### Scenario: template fuera de la allow-list
- GIVEN un archivo que no figura en `manifest.json`
- WHEN se construye argv
- THEN no se incluye ese template en la ejecución

### Requirement: ZAP entrega reporte baseline
El adaptador DEBE limitar el tiempo, generar JSON en una ruta temporal y eliminarlo al finalizar.

### Scenario: reporte de fixture
- GIVEN un reporte JSON de ZAP baseline
- WHEN se procesa
- THEN se devuelven alertas estructuradas sin red durante el test
