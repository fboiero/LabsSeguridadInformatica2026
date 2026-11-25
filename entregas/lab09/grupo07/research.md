# Mini-research — Laboratorio 09

**Grupo:** 07 · **Autora:** Guadalupe Gómez (@guadagomezgg8) · **Fecha:** 20/11/2026

**Tema elegido:** riesgos de agentes autónomos ofensivos y guardrails — qué dicen
los marcos de seguridad (OWASP) y cómo se contienen.

## Desarrollo

Un agente ofensivo autónomo es un LLM en un loop de tool-use con acceso a
herramientas que tocan sistemas reales. El marco de referencia más usado para
sus riesgos es el **OWASP Top 10 for LLM Applications**, cuya edición 2025 metió
de lleno el problema de la autonomía. Dos de sus categorías aplican directo a lo
que construimos en el lab:

- **LLM01:2025 — Prompt Injection.** Un atacante manipula el comportamiento del
  modelo con entradas diseñadas, de forma directa o indirecta (texto escondido en
  una respuesta o una página que el modelo lee como contexto). Entre las
  mitigaciones que lista OWASP están imponer control de privilegios sobre el
  acceso del modelo al backend y separar el contenido externo de las órdenes.
- **LLM06:2025 — Excessive Agency.** La edición 2025 amplió esta categoría por la
  aparición de agentes que corren flujos y ejecutan o escriben acciones. El riesgo
  es que el agente haga más de lo autorizado. Mitigaciones recomendadas: limitar
  las tools y sus permisos al mínimo, pedir confirmación explícita para acciones
  destructivas en lugar de dejar que el modelo las dispare solo, y registrar en
  bitácora cada llamada a tool.

En diciembre de 2025 OWASP publicó además, dentro del GenAI Security Project, una
guía específica para agentes (**Agentic AI – Threats and Mitigations**, Agentic
Security Initiative) y un Top 10 para aplicaciones agénticas. Describen amenazas
propias de los agentes —secuestro de objetivos, mal uso de tools, abuso de
identidad, envenenamiento de memoria, agentes rogue— y proponen contención por
**sandboxing, guardrails y "circuit breakers"** que limiten el radio de impacto,
más monitoreo en tiempo de ejecución para detectar comportamiento anómalo cuando
los controles preventivos fallan.

Todo esto coincide con lo que vimos en el lab: el control que importa es el
**guardrail determinista en código** (`_verificar_alcance()`), no una instrucción
en el prompt. Un modelo puede ser convencido de ignorar una instrucción; no puede
ejecutar una tool que el código no le deja ejecutar. R4 es la demostración
concreta: el agente intenta salir de alcance (`8.8.8.8`) y el código lo bloquea
antes de actuar (`evidencia/salidas/transcript-referencia.txt`, paso 8).

## Fuentes (consultadas el 20/11/2026)

1. OWASP GenAI Security Project — *OWASP Top 10 for LLM Applications* (lista 2025,
   LLM01 Prompt Injection, LLM06 Excessive Agency): Invicti, "OWASP Top 10 risks
   for LLMs (2025 update)" —
   https://invicti.com/blog/web-security/owasp-top-10-risks-llm-security-2025
2. OWASP GenAI Security Project — *Agentic AI – Threats and Mitigations* (Agentic
   Security Initiative, v1.1, diciembre 2025) —
   https://genai.owasp.org/initiatives/agentic-ai-threats-and-mitigations/
3. Fidelis Security — resumen del OWASP Top 10 for Agentic Applications
   (goal hijacking, tool misuse; sandboxing, guardrails, circuit breakers,
   monitoreo en runtime) —
   https://fidelissecurity.com/cybersecurity-101/threats-and-vulnerabilities/owasp-agentic-ai-threats/

## Reflexión (3–5 líneas)

Lo que más me ordenó el tema fue ver que el marco profesional dice lo mismo que
el lab a otra escala: el peligro de un agente no es que "piense mal", es que pueda
**actuar** fuera de lo autorizado, y la defensa no se escribe en el prompt sino en
código que el modelo no puede saltear. El guardrail de diez líneas del lab es la
versión mínima de lo que OWASP llama limitar la agencia. Me quedó claro que, con
agentes, "pedirle por favor que se porte bien" no es un control: el control es lo
que el código no le permite hacer.
