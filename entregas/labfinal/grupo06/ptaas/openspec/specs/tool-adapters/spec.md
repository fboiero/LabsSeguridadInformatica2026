# Spec — tool-adapters

Tests: `tests/test_adapters.py`, `tests/test_audit_and_policy.py`, tests/test_recon_loop_a.py
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

## Consolidación del Change 004

Origen: `openspec/changes/004-recon-loop-a/`. Deltas promovidos a esta especificación; se conserva el historial del change.

## Requirement: Adaptadores RECON acotados
subfinder.enum y httpx.probe DEBEN declarar fase RECON y destructive=False; la ejecución DEBE ocurrir vía Harness.invoke.

### Scenario: registro e invocación
- GIVEN adaptadores registrados y autorización vigente
- WHEN Harness invoca cada capability con runner de prueba
- THEN obtiene una salida validada y registra la invocación con engagement y fase

### Scenario: fase incorrecta
- GIVEN un token ANALYZE
- WHEN se solicita cualquiera de las dos capabilities
- THEN se bloquea y registra sin ejecutar runner

## Requirement: Argv fijo y ejecución limitada
Los adaptadores DEBEN revalidar target y parámetros, construir argv sin shell, imponer timeout y rechazar opciones no permitidas.

### Scenario: argv controlado
- GIVEN perfil válido y target del laboratorio
- WHEN se prepara el comando
- THEN solo contiene binario, flags fijos, target validado y límites del perfil

### Scenario: inyección o perfil prohibido
- GIVEN target con metacaracteres, parámetro que introduce flags o perfil que habilita proxy o seguimiento automático
- WHEN se construye argv
- THEN falla antes de invocar el runner

## Requirement: Parseo íntegro y errores explícitos
Los adaptadores DEBEN validar JSONL completo y distinguir ausencia de activos de errores de ejecución.

### Scenario: salida válida
- GIVEN fixture identificado de subfinder o httpx con activos del lab
- WHEN se parsea
- THEN produce activos con origen, dirección y tecnologías validados

### Scenario: salida parcial o herramienta fallida
- GIVEN línea inválida, timeout, binario ausente o retorno distinto de cero
- WHEN se procesa el resultado
- THEN retorna error tipado, descarta el lote inválido y no informa descubrimiento exitoso vacío

## Requirement: Redirecciones y red de laboratorio
HTTP NO DEBE seguir redirecciones implícitas; cada salto requiere RedirectPolicy y autorización de Harness. Ninguna herramienta DEBE contactar proveedores de Internet.

### Scenario: redirección externa
- GIVEN una respuesta Location hacia otro dominio no autorizado
- WHEN se evalúa la respuesta
- THEN se registra el bloqueo sin solicitar el destino

### Scenario: referencia local autorizada
- GIVEN Location local aceptada por RedirectPolicy
- WHEN se procesa la respuesta HTTP
- THEN se devuelve como referencia autorizada sin seguirla automáticamente; cualquier sondeo posterior requiere Harness, token vivo y limitador compartido

### Scenario: fuente pasiva externa o DNS externo
- GIVEN proveedor no local o resolución fuera de los CIDR del laboratorio
- WHEN se prepara la ejecución real
- THEN se rechaza sin emitir consultas o sondeos a terceros


## Requirement: Verificación diferenciada de resultados simulados
Los fixtures DEBEN identificarse como simulados y NO DEBEN presentarse como descubrimientos reales.

### Scenario: subdominios autorizados simulados
- GIVEN JSONL simulado con subdominios de dvwa.lab.test y duplicados
- WHEN el adaptador existente procesa la salida a través de Harness y loop A
- THEN normaliza y deduplica el inventario, sondeando solo los activos autorizados mediante un adaptador simulado

### Scenario: salida mixta simulada y exclusiones
- GIVEN JSONL simulado con activos autorizados, un subdominio excluido y nombres fuera de alcance
- WHEN el loop procesa los descubrimientos
- THEN registra los rechazados sin pasarlos al resolver ni al adaptador activo

### Scenario: enumeración simulada vacía
- GIVEN una ejecución simulada exitosa con stdout vacío
- WHEN se procesa el resultado
- THEN devuelve OK con cero descubrimientos, distinto del UNAVAILABLE real; el loop conserva la semilla autorizada y se estabiliza

### Scenario: target de enumeración fuera del token
- GIVEN un target fuera del alcance del token, incluso otro host del laboratorio
- WHEN se solicita subfinder.enum a Harness
- THEN rechaza y registra BLOCKED antes de ejecutar el runner o resolver el target


## Requirement: Ejecución real aislada y evidencia verificable
La ejecución real DEBE mantener el aislamiento, distinguir UNAVAILABLE de éxito vacío y conservar evidencia verificable.

### Scenario: enumeración nativa sin proveedores externos
- GIVEN subfinder instalado en runner aislado y todos sus proveedores excluidos explícitamente
- WHEN Harness invoca subfinder.enum
- THEN se captura su salida real (que puede ser vacía), sin fabricar subdominios; las semillas autorizadas continúan al sondeo HTTP

### Scenario: catálogo de proveedores no interpretable
- GIVEN una salida de catálogo desconocida o vacía
- WHEN se prepara el runner nativo
- THEN falla cerrado antes de enumerar

### Scenario: evidencia verificable de corrida
- GIVEN acciones reales registradas por AuditLog
- WHEN se exporta la evidencia y se ejecuta el verificador de P3 que delega en verificar_cadena de P1
- THEN se valida el hash encadenado; alterar una fila o borrar una intermedia produce fallo

### Scenario: acción real sin autorización registrada
- GIVEN ausencia de una referencia de autorización humana o ventana vencida
- WHEN se solicita la corrida real
- THEN no se inicia reconocimiento

### Scenario: captura HTTP no altera la autorización
- GIVEN un observador de salida cruda configurado
- WHEN se ejecuta httpx
- THEN conserva la resolución a IP autorizada y argv acotado; el observador recibe la salida después de ejecutar, sin sustituir el runner

La versión instalada devuelve 'No sources selected for this search' con código 1 al excluir todas las fuentes. Solo ese resultado exacto se clasifica UNAVAILABLE y queda registrado; se sondean las semillas autorizadas sin afirmar descubrimiento pasivo. Otros errores abortan. Los puertos fijos son DVWA:80 y JuiceShop:3000, también al resolver Location relativa.
