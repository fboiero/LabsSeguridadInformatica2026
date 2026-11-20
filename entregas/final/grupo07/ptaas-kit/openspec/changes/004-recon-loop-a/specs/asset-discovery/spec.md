# Delta — asset-discovery

Tests: `tests/test_asset_graph.py`, `tests/test_recon_loop.py`

## Requirement: Persistencia versionada del grafo
El sistema DEBE guardar el `AssetGraph` con versión de schema, IDs estables, fuentes y relaciones de descubrimiento; cargar un grafo incompatible DEBE fallar explícitamente.

### Scenario: guardar y recuperar el grafo
- GIVEN activos de más de una herramienta
- WHEN se guarda y se carga el grafo
- THEN se conservan IDs, tecnologías, alcance y fuentes sin duplicar nodos

### Scenario: schema desconocido
- GIVEN un archivo de grafo con `schema_version` no soportada
- WHEN se carga
- THEN se rechaza sin reemplazarlo ni omitir datos silenciosamente

## Requirement: Descubrimientos fuera de scope
El sistema DEBE registrar los hallazgos fuera del scope como nodos no alcanzables y NO DEBE enviarlos a un adaptador activo.

### Scenario: subdominio fuera de alcance
- GIVEN un token que autoriza `lab.example.test`
- WHEN subfinder descubre `otro.ejemplo.org`
- THEN el nodo queda marcado fuera de alcance, httpx no corre sobre él y el intento queda bloqueado en la bitácora

## Requirement: Recon pasivo antes que activo
El sistema DEBE invocar el enumerador pasivo antes de hacer probes HTTP y solo debe sondear activos nuevos que el Guard permita.

### Scenario: orden pasivo a activo
- GIVEN un dominio autorizado sin activos en el grafo
- WHEN inicia el loop A
- THEN subfinder se invoca antes de httpx y el sondeo usa el mismo token RECON vigente

## Requirement: Parada del loop A
El loop A DEBE terminar al estabilizarse el grafo o alcanzar el tope definido en `policy.yaml`.

### Scenario: grafo estabilizado
- GIVEN que una iteración no agrega activos dentro del scope
- WHEN el orquestador evalúa continuar
- THEN `decide_recon` devuelve `stop` con motivo `grafo estabilizado`

### Scenario: tope de iteraciones
- GIVEN que se alcanzó el tope de recon
- WHEN el orquestador evalúa otra iteración
- THEN el loop termina sin ejecutar otra herramienta
