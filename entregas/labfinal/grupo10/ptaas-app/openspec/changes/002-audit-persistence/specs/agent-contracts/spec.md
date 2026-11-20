# Delta de integración aprobado — primera demo de runtime

Aprobación: el usuario confirmó usar OpenCode para una demo con IA real,
herramientas simuladas y un máximo de seis llamadas al modelo.
Tests: `tests/test_runtime.py`.

## Requirement: Especialistas con modelo real y contextos separados
La demo DEBE llamar por separado a planificación, reconocimiento, correlación
y reporting, con mandatos y schemas propios. El modo fixture NO DEBE
presentarse como IA real. El proveedor OpenCode NO DEBE acceder a credenciales
almacenadas: usa la generación stateless del servicio mediante su CLI.

### Scenario: coordinación con proveedor controlado
- GIVEN un proveedor de pruebas con respuestas válidas para los cuatro roles
- WHEN corre la demo aprobada
- THEN los roles reciben entradas separadas y la salida indica qué proveedor se usó

## Requirement: Sin herramientas directas ni objetivos reales
Los modelos NO DEBEN tener herramientas de terminal, archivos o MCPs. Solo
proponen JSON. El único adaptador de esta demo DEBE devolver datos sintéticos
para `dvwa.lab.test`, pasando por Harness.invoke y su bitácora persistente.

### Scenario: propuesta fuera del objetivo
- GIVEN una respuesta de reconocimiento que propone otro dominio
- WHEN el coordinador procesa la propuesta
- THEN bloquea la acción sin ejecutar el adaptador

### Scenario: falta aprobación inicial
- GIVEN una demo sin aprobación humana inicial
- WHEN se intenta iniciar
- THEN queda PENDING_HITL sin llamadas al modelo ni al adaptador

## Requirement: Validación y procedencia
Toda respuesta DEBE validar con Pydantic estricto y sin campos extra. Los
activos, candidatos y referencias NO DEBEN inventar evidencia o CVE. Sin feeds
de vulnerabilidades, la correlación DEBE devolver una lista vacía de candidatos.

### Scenario: dos respuestas inválidas
- GIVEN un agente que devuelve dos salidas consecutivas inválidas
- WHEN se valida su segunda respuesta
- THEN se escala a PENDING_HITL sin una tercera llamada a ese agente

### Scenario: candidato inventado
- GIVEN una respuesta de correlación con candidatos sin una fuente de vulnerabilidades
- WHEN se valida la respuesta
- THEN se rechaza por falta de evidencia y no se publica como hallazgo

## Requirement: Límites y ausencia de fallback silencioso
La demo DEBE imponer un máximo global de seis llamadas, dos iteraciones de
reconocimiento y timeout por llamada. Los reintentos por schema consumen el
mismo presupuesto. Un error del proveedor NO DEBE sustituirse por respuestas fixture.

### Scenario: presupuesto agotado
- GIVEN un proveedor cuyo presupuesto de llamadas ya se consumió
- WHEN se pide otra respuesta
- THEN se escala a PENDING_HITL sin ejecutar otra generación

### Scenario: proveedor no disponible
- GIVEN un proveedor que falla
- WHEN un agente solicita una respuesta
- THEN se informa un error saneado y no se usa un proveedor simulado como reemplazo

## Requirement: Entrega humana y límites de la demo
El resultado DEBE marcarse simulado y borrador, sin hallazgos confirmados.
La demo DEBE terminar esperando aprobación de entrega; ningún modelo puede
otorgarla. Esta demo NO constituye un pentest ni completa los changes 003–007.

### Scenario: borrador terminado
- GIVEN todas las respuestas válidas y evidencia sintética
- WHEN termina reporting
- THEN se guarda un borrador marcado simulado y el estado final es PENDING_HITL antes de entregar
