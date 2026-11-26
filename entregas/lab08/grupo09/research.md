# Mini-research — Laboratorio 08

**Grupo:** 09
**Tema elegido:** **D.** De scripts a agentes: qué agrega un agente de IA
sobre un script de automatización, y qué NO debería decidir solo.

---

## Desarrollo

### Lo que `recolector.py` ya automatiza

Nuestro script del R5 automatiza la **repetición**: hace 250 requests,
compara cada respuesta contra una regla fija (¿tiene una clave extra con
forma de flag?), y reporta. Es automatización clásica: **nosotros** le dimos
el rango exacto, la regla exacta de qué buscar, y la condición exacta de
corte. El script no tiene margen de decisión — es determinístico: con la
misma entrada, siempre produce la misma secuencia de acciones.

### Qué agrega un agente de IA sobre eso

Un agente (como el que vamos a construir en el Lab 09) reemplaza la parte que
el script *no puede* hacer: **decidir la siguiente acción en base al
contenido de la respuesta anterior**, sin que el programador haya anticipado
ese caso puntual. Un script fijo no puede, por ejemplo: leer una respuesta
HTTP, notar que menciona una ruta nueva (`robots.txt` → `Disallow:
/vault-interno-x7`), y decidir por sí mismo "voy a pedir esa ruta ahora". Eso
requiere **interpretar lenguaje natural o datos semiestructurados y razonar
sobre ellos** — el LLM aporta exactamente eso: un modelo de lenguaje que
"lee" el resultado de una tool como lo haría un pentester, y decide el
próximo paso. El agente generaliza donde el script está hardcodeado: nuestro
`recolector.py` sabe buscar "una clave que no sea id/nombre/area"; un agente
podría, sin que se lo programemos así, notar un patrón distinto en una
estructura JSON totalmente diferente y seguir la pista igual.

### Qué NO debería decidir solo un agente ofensivo

Este es el punto central de la pregunta, y es la razón de ser del **guardrail
de alcance** que vamos a implementar en el Lab 09 (`_verificar_alcance()` en
`herramientas.py`):

1. **El alcance de la operación (scope).** Un agente no debería decidir por
   sí mismo *contra qué objetivo* actúa. Si en un resultado aparece mencionada
   una IP o dominio que no es el autorizado, el agente **no tiene criterio
   legal ni contractual** para decidir si tocarlo está bien — eso lo decide
   el humano que autorizó el pentest, por escrito, antes de empezar. Un LLM
   puede "razonar" que tocar ese otro host "ayudaría a entender mejor el
   entorno", y estaría both técnicamente capaz y completamente fuera de
   lugar: el guardrail existe precisamente porque el LLM no debe tener la
   última palabra sobre el scope.
2. **Qué constituye una acción destructiva o irreversible.** Un script de
   automatización bien acotado (como el nuestro) solo lee. Un agente con
   tools más amplias podría, en teoría, ejecutar algo que borra, modifica o
   tumba un servicio — y un LLM puede "decidir" hacerlo si interpreta que es
   el paso lógico siguiente, sin entender las consecuencias operativas reales
   (un servicio productivo caído, datos perdidos). Esa clase de acción debe
   requerir aprobación humana explícita, nunca quedar a discreción del
   razonamiento del modelo.
3. **La validación final de un hallazgo.** Un LLM puede "reportar" una
   vulnerabilidad con mucha confianza y estar equivocado (alucinación) — lo
   vamos a ver literalmente en el Lab 09, Ejemplo B. El humano con criterio
   de pentesting (los labs 05–08 de este curso) es quien confirma si el
   hallazgo es real antes de que entre en un informe que un cliente va a
   leer y actuar sobre.

### Automatización vs. agente, en una tabla mental

| | Script (recolector.py) | Agente de IA |
|---|---|---|
| Decide el rango/alcance | El programador, fijo en el código/args | **Debe** seguir siendo el humano (guardrail), no el LLM |
| Decide la siguiente acción | El programador, en el `for` | El LLM, en base al resultado anterior |
| Repite tareas tediosas | Sí, eso es su único trabajo | También, pero además encadena pasos distintos |
| Se equivoca | Nunca "interpreta mal" — es determinístico | Puede alucinar o malinterpretar un resultado |
| Responsabilidad final | Siempre humana | Sigue siendo humana (más aún: hay que auditar el razonamiento, no solo el resultado) |

---

## Fuentes (mín. 3, verificables)

- OWASP — "LLM08:2025 Excessive Agency" (Top 10 for LLM Applications): riesgos
  de que un agente tenga más permisos/autonomía de los necesarios:
  https://genai.owasp.org/llmrisk/llm08-excessive-agency/
- MITRE ATT&CK — táctica *Lateral Movement* (TA0008), marco usado para
  describir el pivoting de este lab en términos estándar de la industria:
  https://attack.mitre.org/tactics/TA0008/
- Anthropic — "Building effective agents": define el loop de tool-use
  (acción → ejecución → resultado → siguiente acción) que retomamos en el
  Lab 09: https://www.anthropic.com/research/building-effective-agents
- NIST AI Risk Management Framework (AI RMF 1.0) — sección sobre supervisión
  humana ("human-in-the-loop") para sistemas de IA con capacidad de actuar:
  https://www.nist.gov/itl/ai-risk-management-framework

---

## Reflexión (3–5 líneas)

Escribir `recolector.py` a mano nos hizo ver exactamente dónde termina la
automatización simple y dónde empezaría a hacer falta un agente: el script
nunca "decide" nada, solo ejecuta una regla fija que **nosotros**
diseñamos mirando la respuesta JSON primero. Un agente de IA agrega la
capacidad de interpretar un resultado nuevo y actuar en consecuencia sin que
se lo programemos caso por caso — pero esa misma flexibilidad es el riesgo:
si el agente puede "decidir" su siguiente paso, alguien tiene que decidir por
él los límites de qué puede tocar. Eso es, letra por letra, el guardrail que
vamos a construir en el Lab 09.
