# Delta propuesto — tool-adapters — P3 / 004

Tests: tests/test_recon_loop_a.py

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

### Scenario: salto autorizado
- GIVEN Location local aceptada por RedirectPolicy
- WHEN se decide seguirla
- THEN la nueva acción pasa por Harness, token vivo y limitador compartido

### Scenario: fuente pasiva externa o DNS externo
- GIVEN proveedor no local o resolución fuera de los CIDR del laboratorio
- WHEN se prepara la ejecución real
- THEN se rechaza sin emitir consultas o sondeos a terceros


## Verificación complementaria mediante fixtures simulados

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
