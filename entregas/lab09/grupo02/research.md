# Mini-research — Laboratorio 09

**Tema elegido:** B — Riesgos de agentes autónomos ofensivos: frameworks y guardrails recomendados

## Desarrollo

### Por qué un agente ofensivo es un caso particular de riesgo

Un agente LLM con `tool-use` no es solo "un chatbot que responde texto": tiene
la capacidad de **ejecutar acciones reales** sobre sistemas externos (escanear
puertos, mandar requests HTTP, correr comandos). Cuando esas acciones son
técnicas ofensivas de pentesting, el riesgo no es solo que el LLM "se
equivoque" en una respuesta — es que ejecute una intrusión real contra un
sistema no autorizado, con las mismas consecuencias legales que si lo hiciera
una persona (en Argentina, Ley 26.388). Esto es justamente lo que vivimos en
el lab con el intento de `nmap_scan` contra `8.8.8.8`: el LLM "decidió" tocar
un host fuera del objetivo, y el único motivo por el que no se ejecutó de
verdad fue el guardrail de código.

### Qué dice OWASP sobre esto

El proyecto **OWASP Top 10 for LLM Applications** identifica varias categorías
de riesgo directamente relevantes para un agente como el de este lab:

- **Excessive Agency:** el riesgo de darle a un LLM más autonomía, permisos o
  funcionalidad de la que su tarea realmente necesita. Se mitiga limitando el
  alcance de las tools (como `ALCANCE = {"phantomcorp"}` en nuestro
  `herramientas.py`), exigiendo el mínimo privilegio posible, y — en sistemas
  más críticos — agregando confirmación humana (human-in-the-loop) antes de
  ejecutar acciones de alto impacto.
- **Prompt Injection:** si el agente procesa contenido no confiable (por
  ejemplo, la respuesta de un servidor que podría estar comprometido o ser
  adversarial), ese contenido podría intentar manipular las decisiones del
  LLM para que ejecute acciones no previstas. En nuestro lab, la respuesta de
  `phantomcorp` es controlada y benigna, pero en un escenario real cualquier
  dato externo que vuelve al LLM es una superficie de ataque potencial (tema
  relacionado al C de esta lista de research).
- **Insecure Output Handling:** confiar ciegamente en lo que el LLM decide
  ejecutar, sin validación del lado del código, es exactamente lo que el
  guardrail de `_verificar_alcance()` previene.

### Guardrails recomendados (y los que vimos en el lab)

Los frameworks de seguridad para agentes suelen recomendar una combinación de:

1. **Alcance explícito (scoping):** una allowlist concreta de qué objetivos y
   acciones están permitidas, validada en el código — nunca confiando en que
   el LLM "se va a comportar". Es exactamente el patrón de
   `_verificar_alcance()` en `herramientas.py`.
2. **Límite de pasos/recursos:** un tope duro de iteraciones (`MAX_PASOS` en
   nuestro agente) para evitar loops descontrolados o consumo excesivo.
3. **Principio de mínimo privilegio:** darle al agente solo las tools que
   necesita para su tarea — nuestro agente solo tiene `nmap_scan`,
   `http_get` y `http_post`, nada que permita, por ejemplo, modificar
   archivos del sistema.
4. **Logging y trazabilidad:** registrar cada acción ejecutada de forma
   independiente del resumen que el propio LLM genera, para poder auditar
   después qué pasó realmente (algo que en nuestro informe propusimos como
   mejora adicional al guardrail actual).
5. **Human-in-the-loop para acciones de alto impacto:** en sistemas de
   producción, antes de ejecutar algo potencialmente destructivo (no solo
   reconocimiento), se recomienda requerir aprobación explícita de una
   persona.

### Conexión con lo que vimos en el lab

El guardrail que probamos en el R4 es un ejemplo directo y simple de
"scoping": una sola función, `_verificar_alcance()`, que cualquier tool debe
consultar antes de actuar. Es mínimo pero efectivo — bloqueó exitosamente el
intento sobre `8.8.8.8`. Lo que notamos como limitación es que ese guardrail
protege el **host**, pero no limita qué se puede hacer dentro del host
autorizado (por ejemplo, no hay un límite de qué puertos puede escanear
`nmap_scan` contra `phantomcorp`, ni un control de cuántas veces puede
repetirse la misma acción) — brechas que, en un sistema con mayor
superficie de ataque, sí importarían.

## Fuentes (mín. 3, verificables)

1. OWASP — *OWASP Top 10 for Large Language Model Applications* (categorías
   de Excessive Agency, Prompt Injection e Insecure Output Handling).
2. OWASP — *LLM Applications Cybersecurity and Governance Checklist* (sección
   sobre gobernanza de agentes autónomos).
3. Documentación de Anthropic sobre *tool use* / *agentic systems* — buenas
   prácticas recomendadas para limitar el alcance y las acciones de un
   agente con herramientas.

## Reflexión (3–5 líneas)

Lo que más nos marcó de este research es que el guardrail de nuestro propio
lab, aunque simple, es exactamente el tipo de control que los frameworks
serios recomiendan como primera línea de defensa — no hace falta algo
sofisticado para tener impacto real, alcanza con una validación explícita
en el código que el LLM no pueda saltear. También nos quedó claro que ese
guardrail no es "suficiente" por sí solo: protege el host, pero no todo lo
que podría pasar dentro de ese host, lo que nos hizo pensar en capas
adicionales (rate limiting, logging independiente) que agregaríamos si este
agente fuera a producción.
