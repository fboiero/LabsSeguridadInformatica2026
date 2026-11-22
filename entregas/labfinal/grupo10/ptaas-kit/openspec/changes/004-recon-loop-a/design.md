# Design — Change 004: Recon real y Loop A integrado

## 1. Decisiones de diseño

### Versionado del `AssetGraph` entre iteraciones
- `AssetGraph` mantiene un diccionario canónico indexado por `(type, address)` usando `dedupe_assets` (`harness/schemas.py`), preservando el primer descubrimiento y fusionando tecnologías detectadas sin duplicar ni re-sondear activos ya presentes.
- Cada iteración calcula `version` (entero incremental desde 1) y `digest` (`sha256` sobre la representación ordenada y serializada en JSON de los activos y hallazgos `out_of_scope`), y registra un `GraphSnapshot(iteration, total_assets, new_assets, digest)`.
- Esto permite comparar dos iteraciones de forma determinista y auditable.

### Esquemas de salida de adaptadores (`subfinder.enum` y `httpx.probe`)
- **`subfinder.enum` (`harness/adapters/subfinder_adapter.py`)**:
  - `allowed_phases = (Phase.RECON,)`, `destructive = False`.
  - Argv fijo: `["subfinder", "-d", <domain>, "-silent", "-oJ"]` (`shell=False`, timeout configurable).
  - Salida esperada: líneas JSONL (`{"host": "...", "input": "...", "source": "..."}`) o texto plano en modo fallback controlado; cada host se normaliza (`strip().lower().rstrip(".")`) y se valida con `validate_target`. Las líneas corruptas se descartan o rechazan explícitamente si toda la salida es inválida (`AdapterOutputError`).
- **`httpx.probe` (`harness/adapters/httpx_adapter.py`)**:
  - `allowed_phases = (Phase.RECON,)`, `destructive = False`.
  - Argv fijo: `["httpx", "-u", <target_url>, "-silent", "-json"]` (`shell=False`, timeout configurable).
  - Valida target (`validate_target` o `validate_url`), aplica `RateLimiter` (`rate_limit_rps_per_target` de `policy.yaml`) antes de ejecutar cada sondeo y valida que la salida sea JSON/JSONL parseable con `url`/`host` y `status_code`.

### Manejo de errores de herramientas y descubrimientos fuera de alcance
- **Binario ausente (`FileNotFoundError`) o timeout (`subprocess.TimeoutExpired`):** el adaptador captura la falla de proceso y lanza `ToolExecutionError` con detalle saneado (sin volcar secretos ni variables de entorno). `run_loop_a` registra el evento de error en la traza de iteración sin romper el estado del engagement ni saltear la bitácora.
- **Descubrimientos fuera de alcance:** cuando `subfinder.enum` devuelve un subdominio fuera del `ScopeToken` (por ejemplo, otro dominio o sufijo engañoso), el orquestador intenta igualmente respetar `Harness.invoke` o lo evalúa contra `Guard._in_scope`; todo target fuera de alcance queda registrado en `AssetGraph.out_of_scope` y con evento `BLOCKED` en `AuditLog` sin ejecutar ningún sondeo activo.
- **Integración de controles del Turno 2 (cierre de deuda H1):**
  - `ordered_recon` y `passive_before_active` (`harness/recon_order.py`) garantizan que `subfinder.enum` corra antes que `httpx.probe`.
  - `RateLimiter` (`harness/adapters/common.py`) limita las solicitudes por target según `policy.yaml`.
  - `dedupe_assets` (`harness/schemas.py`) evita incorporar o re-sondear activos repetidos.
  - `AuditLog.record(..., evidence=...)` y `AuditLog.verify_chain()` (`harness/contracts.py`) persisten solo referencias `sha256:` y permiten verificar la integridad completa de la cadena.

### Promoción de hallazgos de recon a correlación
- Solo los activos normalizados dentro de `AssetGraph.assets` (con `address`, `source_tool` y tecnologías/puertos observados) se exportan como entrada estructurada para la fase `CORRELATE`. Los registros `out_of_scope` nunca se promueven.
