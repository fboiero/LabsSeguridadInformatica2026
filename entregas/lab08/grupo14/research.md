# Mini-research — Laboratorio 08

**Tema elegido:** **D.** De scripts a agentes: qué agrega un agente de IA sobre
un script de automatización, y qué NO debería decidir solo.

## Desarrollo

Un script como `recolector.py` automatiza una tarea **fija y acotada**: el
humano ya decidió el objetivo (encontrar el legajo con el flag), la estrategia
(recorrer un rango de ids) y el criterio de éxito (una clave distinta a
`nombre`/`area`). El script ejecuta esa lógica más rápido y sin errores de
tipeo, pero no decide nada que no esté ya codificado: si el servicio cambiara
de forma (otro endpoint, otro formato de respuesta), el script simplemente
falla o devuelve nada; no se adapta.

Un **agente de IA** (como los que se usan en el Lab 09) agrega una capa de
**planificación y adaptación**: a partir de un objetivo en lenguaje natural
("encontrá la flag en este servicio"), el agente puede decidir *por sí mismo*
qué herramientas usar, en qué orden, cómo interpretar una respuesta inesperada
y cuándo reintentar con otro enfoque. MITRE documentó en 2024 agentes de IA
ofensivos capaces de encadenar reconocimiento, explotación y post-explotación
con intervención humana mínima, replicando en gran medida el flujo manual que
hicimos en este lab (recon → loot → privesc → pivoting) pero decidido por el
modelo en cada paso, no por un `if` escrito de antemano. Esa es la diferencia
cualitativa: un script ejecuta un plan humano; un agente **elabora** el plan
(y puede revisarlo sobre la marcha) a partir de observaciones.

Eso trae un riesgo directo. OWASP, en su *Top 10 para aplicaciones de LLM*
(2025), señala "Excessive Agency" como una categoría propia de riesgo: un
agente con demasiada autonomía, demasiados permisos o demasiada poca
supervisión puede tomar acciones dañinas o irreversibles que nadie aprobó
explícitamente, simplemente porque "parecían" el siguiente paso razonable
hacia el objetivo declarado.

**Qué NO debería decidir solo un agente**, aplicado a un contexto como el de
este lab:

- **El alcance y la autorización.** Qué sistemas están en alcance (en este
  lab: únicamente los contenedores provistos por la cátedra) es una decisión
  legal/contractual, no técnica. Un agente no debería poder "ampliar" el
  alcance porque encontró una ruta de red hacia otro host — es exactamente el
  tipo de decisión que haría falta frenar con un humano en el loop.
- **Acciones destructivas o irreversibles.** Borrar logs, modificar
  persistencia, exfiltrar datos reales: son pasos que convierten una prueba en
  un incidente. Esto debe requerir confirmación explícita, no inferencia del
  agente a partir de "es lo que haría un atacante real".
- **El criterio de "listo".** Cuándo declarar un objetivo cumplido o cuándo
  abandonar un camino sin éxito es, igual que en el P4 de este informe, una
  decisión de costo/beneficio que un humano debería validar, especialmente
  cuando el "costo" es tiempo contra un sistema ajeno.

## Fuentes (mín. 3, verificables)

1. OWASP — *OWASP Top 10 for LLM Applications 2025* (categoría
   "Excessive Agency"): https://genai.owasp.org/llm-top-10/
2. MITRE ATT&CK — Matriz y tácticas de post-explotación usadas de base en este
   lab (*Discovery*, *Credential Access*, *Privilege Escalation*, *Lateral
   Movement*): https://attack.mitre.org/
3. GTFOBins — catálogo de binarios Unix explotables para bypass de
   restricciones locales (SUID, sudo), referenciado en la Parte 3 del
   enunciado del lab: https://gtfobins.github.io/
4. NIST — *AI Risk Management Framework (AI RMF 1.0)*, sección sobre
   gobernanza y supervisión humana de sistemas autónomos:
   https://www.nist.gov/itl/ai-risk-management-framework

## Reflexión (3–5 líneas)

Hacer este lab a mano (encontrar el SUID, pivotear con un `curl`, y recién
después automatizar el R5 con un script) deja clara la diferencia entre
"saber ejecutar un paso" y "saber encadenar varios pasos con un criterio de
decisión". Un agente de IA no inventa esa diferencia: la hereda. Si uno no
puede explicar en código por qué el script corta al encontrar el flag o qué
hace con un 404, tampoco va a poder revisar si un agente tomó la decisión
correcta al hacer lo mismo de forma autónoma — y mucho menos va a poder
ponerle límites razonables antes de que actúe.
