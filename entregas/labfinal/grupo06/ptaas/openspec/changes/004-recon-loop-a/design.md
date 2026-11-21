# Diseño P3 — Change 004

Implementación P3 verificada mediante tests locales.

## Contratos y límites

Se conservan `Harness.invoke`, `Guard`, `ScopeToken`, `Asset` y `decide_recon` existentes. Se consumen los contratos de P1 y P2 descritos en `handoffs/`. P3 implementa sus adaptadores, un módulo `harness/asset_graph.py`, la orquestación A en `harness/loops.py` y perfiles propios. No se modifican los loops B/C, contracts, engagement, policy, reporting, Docker ni los tests existentes.

Cada acción se invoca con token RECON del engagement. La primera acción activa requiere aprobación humana mediante el mecanismo ya existente; el loop no llama a `approve`. El estado PENDING_HITL, el vencimiento y el kill switch detienen la ejecución y se preservan al reanudar. Un descubrimiento fuera de alcance se registra BLOCKED, sin invocar adaptador ni resolver su DNS. Las acciones autorizadas pasan nuevamente por el Guard antes de ejecutarse.

## Salidas y grafo

Los adaptadores devuelven un objeto con capability, target canónico, status, assets y error tipado opcional. Cada activo tiene id determinista, tipo, dirección, tecnologías y source_tool. JSONL se valida íntegramente antes de agregar un lote; una línea inválida invalida el lote, no se presenta como inventario vacío exitoso. No se almacenan cuerpos HTTP, credenciales ni banners crudos.

AssetGraph serializa JSON con schema_version=1, engagement_id, revision, iteration, status, stop_reason, assets, referencias a evidencia y descubrimientos excluidos separados. Identidad por tipo y dirección normalizada; tecnologías y referencias se fusionan sin duplicados. Una nueva observación idéntica no cuenta como activo nuevo. Escritura temporal y reemplazo atómico; lectura rechaza versión desconocida, campos inválidos y engagement distinto. El contador persistido impide reiniciar el presupuesto al reanudar.

## Plan, acción, observación y parada

La fase pasiva completa el lote de semillas antes de cualquier sondeo activo. Cada activo en alcance se sondea por Harness.invoke; las propuestas de correlación solo aportan referencias, no ejecutan herramientas ni crean candidatos sin evidencia. `decide_recon` recibe el número de activos nuevos en alcance y la iteración acumulada. Cero activos nuevos produce grafo estabilizado; el máximo es el límite configurado de RECON (actualmente 5), nunca una sexta vuelta. El tope no se amplía desde una propuesta del agente.

Un fallo de herramienta no equivale a punto fijo: se devuelve un resultado explícito de error y se preserva el último grafo válido. Dos salidas de schema inválido consecutivas escalan a PENDING_HITL. Se registran decisión, iteración y motivo sin modificar la bitácora de P1. El adaptador devuelve errores tipados capturados para que Harness registre la invocación; el loop registra además el resultado de error, sin confundir OK de invocación con éxito del reconocimiento.

## Adaptadores y límites

Un adaptador por capability, no destructivo, solo RECON. Target y parámetros se validan antes de construir argv; no se admiten flags del agente, shell, proxies, actualizaciones ni proveedores externos. El runner es inyectable para tests; la ejecución real se hace exclusivamente desde el adaptador invocado por Harness.

HTTP no sigue redirecciones automáticamente. Las Location se evalúan con RedirectPolicy; un salto autorizado vuelve a pasar por Harness y los mismos límites. DNS debe resolver exclusivamente a direcciones del laboratorio antes de actuar; no se habilita runtime real con resolver ausente.

Los perfiles deben aportar rate_limit_rps y timeout_s positivos y finitos. Se toma el mínimo entre el perfil y el límite de policy, con un limitador compartido por target entre invocaciones, además del límite de CLI. No se eligen nuevos valores de riesgo en esta propuesta. Los valores concretos y flags se verifican por P3 contra las versiones instaladas antes de una corrida real.

La enumeración pasiva no habilita consultas a terceros: el runner real debe estar aislado y usar únicamente fuentes locales compatibles. Si subfinder no admite una fuente local utilizable en ese entorno, se informa ese resultado; no se abre salida a Internet, no se sustituye con datos fabricados y no se declara corrida real exitosa. Los fixtures sintéticos se identifican como sintéticos; una captura real conserva versión, comando, fecha y procedencia.

## Verificación propuesta

Tests nuevos en `tests/test_recon_loop_a.py`, sin editar tests ajenos. Cada Scenario del delta tiene un test de comportamiento y de bloqueo. La secuencia es delta revisado, test fallido por comportamiento, commit local de prueba, implementación, test verde y mutación del control. El archivo de evidencia de P3 registra exclusivamente comandos y resultados ejecutados. Las specs estables se actualizan al archivar con revisión; no se marca revisión, corrida real ni archivo sin evidencia.

## Decisiones implementadas y verificadas

- La frontera de semillas se persiste junto al contador; una vuelta interrumpida consume su presupuesto y se repite desde su frontera, sin afirmar recuperación exacta de cada llamada.
- STOPPED, ABORTED y PENDING_HITL se preservan al recargar. La orquestación no resuelve por sí misma la revisión humana.
- Una enumeración vacía conserva la semilla de RoE para el sondeo activo autorizado.
- HTTP inspecciona Location con RedirectPolicy y devuelve referencias; no decide seguir saltos, ni siquiera locales. Cualquier consumidor que decida seguirlos debe emitir una acción nueva por Harness.
- Los perfiles aplican el límite existente de policy (5 rps) y timeout de 10 segundos. Estos valores se verificaron mediante pruebas locales.
- La ejecución HTTP fija una IP verificada del lab y el Host original; usa configuración vacía, sin proxy, con un GET sin fallback, sin reintentos ni seguimiento de redirects.
- El adaptador subfinder valida argv y JSONL con runner inyectado. Sin una fuente local inyectada retorna local_source_required, sin activar los proveedores públicos predeterminados.
