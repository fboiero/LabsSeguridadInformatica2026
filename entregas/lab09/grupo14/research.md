# Mini-research — Laboratorio 09

**Tema elegido:** B

- [ ] **A.** Tool-use / function calling: cómo lo implementan Claude y OpenAI a
  nivel de API, y en qué se parecen y diferencian.
- [x] **B.** Riesgos de agentes autónomos ofensivos: qué dicen los frameworks
  (OWASP para LLMs, etc.) y qué guardrails recomiendan.
- [ ] **C.** Prompt injection contra agentes: cómo un target podría "hablarle" al
  agente a través de sus respuestas para desviarlo (y cómo se mitiga).
- [ ] **D.** Estado del arte: herramientas reales de pentest asistido por IA y qué
  automatizan (y qué no).

## Desarrollo

El OWASP Top 10 para aplicaciones con LLM incluye la categoría **Excessive Agency**
(LLM06 en la edición 2025): un sistema basado en LLM al que se le dieron demasiadas
funciones, permisos o autonomía y que puede ejecutar acciones dañinas ante una salida
errónea, ambigua o manipulada. OWASP la descompone en tres causas: **funcionalidad
excesiva** (tools que la tarea no necesita), **permisos excesivos** (la tool tiene más
acceso del necesario) y **autonomía excesiva** (acciones de alto impacto sin
aprobación humana). Estas tres causas se corresponden con lo visto en el lab: la
allowlist `TOOLS` (solo `nmap_scan`, `http_get`, `http_post`), el alcance `ALCANCE`
validado en `_verificar_alcance()` y el límite `MAX_PASOS`.

Mitigaciones que recomienda OWASP y su relación con el lab:

- **Minimizar tools y permisos**: dar solo las tools necesarias (el agente no tiene
  shell genérica).
- **Validar en el código, no en el prompt**: el scope se impone con código
  determinístico; el prompt del sistema es una sugerencia que un LLM puede ignorar o
  que puede ser desviada por prompt injection.
- **Humano en el bucle** para acciones de alto impacto (en el lab no hay: se podría
  agregar confirmación antes de cualquier `http_post`).
- **Límites y registro**: tope de pasos, rate limiting y log de cada acción.

Para un agente *ofensivo* se suma el riesgo legal: un agente que sale de scope comete
acceso no autorizado (Ley 26.388 en Argentina), y la responsabilidad es de quien lo
dirige, no del modelo.

## Fuentes (mín. 3, verificables)

1. OWASP GenAI Security Project, *OWASP Top 10 for LLM Applications 2025*,
   LLM06:2025 Excessive Agency — https://genai.owasp.org/llm-top-10/
2. NIST, *Artificial Intelligence Risk Management Framework (AI RMF 1.0)*, NIST AI
   100-1, 2023 — https://www.nist.gov/itl/ai-risk-management-framework
3. Ley 26.388 (Delitos informáticos, modifica el Código Penal), Argentina, 2008 —
   https://www.argentina.gob.ar/normativa/nacional/ley-26388-141790
4. Anthropic, documentación de *Tool use* (loop de tool_use / tool_result) —
   https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/overview

*Nota: las fuentes se citaron de conocimiento previo del asistente de IA, sin abrirlas
en esta sesión; los integrantes deben abrir cada enlace y confirmar el contenido y la
numeración (LLM06) antes de entregar.*

## Reflexión (3–5 líneas)

El riesgo de un agente no está en el LLM sino en lo que se le permite hacer. Un
guardrail en el prompt es débil; uno en el código (alcance, allowlist, tope de pasos)
no depende de que el modelo "obedezca". Además, el agente ejecuta rápido y a escala:
si el humano no entiende lo que hace cada tool, no puede detectar que se desvió.
