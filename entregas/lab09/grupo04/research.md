# Mini-research — Laboratorio 09

**Tema elegido:** **B. Riesgos de agentes autónomos ofensivos**

- [ ] **A.** Tool-use / function calling: cómo lo implementan Claude y OpenAI a nivel de API, y en qué se parecen y diferencian.
- [X] **B.** Riesgos de agentes autónomos ofensivos: qué dicen los frameworks (OWASP para LLMs, etc.) y qué guardrails recomiendan.
- [ ] **C.** Prompt injection contra agentes: cómo un target podría "hablarle" al agente a través de sus respuestas para desviarlo (y cómo se mitiga).
- [ ] **D.** Estado del arte: herramientas reales de pentest asistido por IA y qué automatizan (y qué no).

## Desarrollo

### 1. ¿Qué son los agentes autónomos de IA?

Los agentes autónomos de inteligencia artificial son sistemas basados en modelos de lenguaje (LLM) que pueden interpretar objetivos, planificar tareas, utilizar herramientas externas y ejecutar acciones con distintos niveles de autonomía.

A diferencia de un chatbot tradicional, que principalmente genera respuestas a partir de las consultas del usuario, un agente puede interactuar con otros sistemas mediante APIs, ejecutar comandos, consultar bases de datos, navegar por páginas web y modificar archivos.

En el ámbito de la seguridad informática, estos agentes pueden utilizarse para automatizar actividades de pentesting, análisis de vulnerabilidades, reconocimiento de infraestructura y auditorías de seguridad.

Sin embargo, esta capacidad de actuar de manera autónoma introduce nuevos riesgos: un agente puede interpretar incorrectamente una instrucción, utilizar herramientas de forma inadecuada o realizar operaciones que excedan los permisos que debería tener.

### 2. Principales riesgos de seguridad

OWASP desarrolla diferentes frameworks para identificar y clasificar los riesgos asociados a las aplicaciones que utilizan inteligencia artificial.

En su publicación **OWASP Top 10 for LLM Applications (2025)** identifica diez categorías de vulnerabilidades relevantes para los sistemas basados en modelos de lenguaje.

Entre ellas se destacan:

- **Prompt Injection (LLM01):** manipulación de las instrucciones del modelo mediante entradas maliciosas, que pueden provocar comportamientos no deseados.
- **Sensitive Information Disclosure (LLM02):** exposición de información confidencial, como credenciales, datos personales o información empresarial.
- **Supply Chain (LLM03):** incorporación de componentes vulnerables o maliciosos provenientes de modelos, bibliotecas, extensiones o proveedores externos.
- **Improper Output Handling (LLM05):** utilización de resultados generados por el modelo sin validarlos adecuadamente, lo que puede producir vulnerabilidades en los sistemas que los procesan.
- **Excessive Agency (LLM06):** otorgamiento de demasiadas herramientas, permisos o autonomía al agente.
- **Unbounded Consumption (LLM10):** consumo excesivo de recursos computacionales, tokens o servicios externos, que puede generar costos elevados o problemas de disponibilidad.

Estos riesgos adquieren mayor importancia cuando los modelos dejan de limitarse a generar respuestas y comienzan a interactuar directamente con sistemas reales.

### 3. Riesgos específicos de los agentes autónomos

Además del framework general para LLMs, OWASP publicó el **Top 10 for Agentic Applications (2026)**, orientado específicamente a los sistemas que pueden planificar y ejecutar acciones de manera autónoma.

Este framework identifica diez riesgos principales:

| Identificador | Riesgo | Descripción |
|---|---|---|
| ASI01 | Agent Goal Hijack | Manipulación de los objetivos originales del agente. |
| ASI02 | Tool Misuse & Exploitation | Uso indebido de herramientas y funcionalidades disponibles. |
| ASI03 | Identity & Privilege Abuse | Abuso de identidades, credenciales y permisos. |
| ASI04 | Agentic Supply Chain Vulnerabilities | Incorporación de herramientas, modelos o dependencias comprometidas. |
| ASI05 | Unexpected Code Execution | Ejecución inesperada de código o comandos. |
| ASI06 | Memory & Context Poisoning | Manipulación de la memoria y del contexto utilizado por el agente. |
| ASI07 | Insecure Inter-Agent Communication | Comunicación insegura entre diferentes agentes. |
| ASI08 | Cascading Failures | Propagación de errores entre agentes y sistemas conectados. |
| ASI09 | Human-Agent Trust Exploitation | Aprovechamiento de la confianza que los usuarios depositan en los agentes. |
| ASI10 | Rogue Agents | Agentes que se desvían de su función o actúan fuera del alcance autorizado. |

Uno de los aspectos más importantes de esta clasificación es que los riesgos no se limitan al modelo de lenguaje. También involucran las herramientas, las identidades, las comunicaciones y los sistemas externos con los que interactúa.

### 4. Escenario de ataque: agente autónomo utilizado para pentesting

Imaginemos una organización que utiliza un agente de inteligencia artificial para realizar pruebas de seguridad sobre su infraestructura.

El agente tiene acceso a herramientas para:

- Consultar servicios y puertos de una infraestructura.
- Ejecutar scripts de análisis.
- Consultar bases de datos de vulnerabilidades.
- Generar reportes técnicos.
- Interactuar con APIs de la organización.

El objetivo es automatizar el reconocimiento y la detección de vulnerabilidades.

Sin embargo, si el agente dispone de permisos excesivos o no tiene controles adecuados, pueden producirse diferentes situaciones:

1. **Manipulación del objetivo:** una entrada maliciosa podría modificar las instrucciones que sigue el agente y desviarlo de la auditoría original.
2. **Uso indebido de herramientas:** el agente podría ejecutar operaciones que no son necesarias para la tarea solicitada.
3. **Acceso no autorizado:** si utiliza credenciales con privilegios elevados, podría acceder a información que no necesita.
4. **Ejecución de acciones destructivas:** podría modificar o eliminar información como consecuencia de una interpretación incorrecta de sus instrucciones.
5. **Propagación de errores:** si trabaja junto con otros agentes, una decisión incorrecta podría transmitirse al resto del sistema.

Este escenario demuestra que incluso un agente diseñado para mejorar la seguridad puede convertirse en un riesgo si no existen controles sobre sus capacidades y acciones.

### 5. ¿Qué guardrails recomiendan los frameworks?

Los guardrails son mecanismos de seguridad que permiten limitar, controlar y supervisar el comportamiento de los agentes de inteligencia artificial.

OWASP y NIST recomiendan implementar diferentes capas de protección para reducir los riesgos.

**Principales medidas de seguridad:**

**1. Principio de mínimo privilegio**

El agente debe contar únicamente con los permisos necesarios para cumplir su objetivo. Por ejemplo, si necesita consultar una base de datos, no debería disponer automáticamente de permisos para modificar o eliminar registros.

**2. Control de herramientas disponibles**

Es necesario limitar las funciones que puede utilizar el agente. Se recomienda evitar herramientas demasiado genéricas, como la ejecución libre de comandos, y utilizar funcionalidades específicas que permitan controlar mejor las operaciones.

**3. Supervisión humana (Human-in-the-loop)**

Las operaciones críticas deben requerir aprobación humana antes de ejecutarse. Por ejemplo, eliminar archivos, modificar configuraciones o realizar acciones que puedan afectar sistemas productivos.

**4. Validación de entradas y salidas**

Los datos que recibe y las respuestas que genera el modelo deben validarse antes de utilizarlos en otros sistemas. No se debe asumir que una respuesta generada por IA es segura o correcta.

**5. Aislamiento del entorno (Sandboxing)**

La ejecución de herramientas y código generado por el agente debe realizarse en entornos aislados, limitando el acceso al sistema operativo, los archivos y la red.

**6. Monitoreo y registro de actividades**

Es importante registrar las decisiones, herramientas utilizadas, permisos solicitados y acciones realizadas por el agente. Esto permite detectar comportamientos anómalos y facilitar investigaciones posteriores.

**7. Límites de ejecución**

Se deben establecer límites de tiempo, cantidad de operaciones, consumo de recursos y llamadas a herramientas para evitar ejecuciones descontroladas.

**8. Autorización externa al modelo**

Las decisiones de autorización no deben depender exclusivamente del propio LLM. Los sistemas externos deben verificar los permisos de cada operación mediante controles tradicionales de seguridad.

### 6. Conclusión técnica

Los agentes autónomos representan una evolución importante en la automatización de tareas de seguridad informática, pero también amplían la superficie de ataque de los sistemas que los utilizan.

La principal diferencia con una aplicación tradicional es que estos agentes pueden tomar decisiones y ejecutar múltiples acciones a partir de instrucciones y datos que reciben durante su funcionamiento.

Por este motivo, la seguridad no debe depender únicamente de las instrucciones proporcionadas al modelo o de su capacidad para reconocer comportamientos maliciosos. Es necesario implementar controles externos que limiten sus permisos, supervisen sus operaciones y eviten que una decisión incorrecta genere consecuencias sobre otros sistemas.

## Fuentes (mín. 3, verificables)

1. **OWASP – Top 10 for LLM Applications (2025).** Framework que identifica las principales vulnerabilidades de las aplicaciones basadas en modelos de lenguaje.  
   https://genai.owasp.org/llm-top-10/

2. **OWASP – Top 10 for Agentic Applications (2026).** Framework especializado en los riesgos de seguridad de los agentes autónomos, sus herramientas, identidades y comunicaciones.  
   https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

3. **OWASP – LLM06:2025 Excessive Agency.** Explica los riesgos derivados de otorgar demasiadas herramientas, permisos y autonomía a los agentes, además de sus principales estrategias de mitigación.  
   https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM06_ExcessiveAgency.md

4. **NIST – Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile (NIST AI 600-1, 2024).** Documento que propone prácticas para identificar, evaluar y gestionar los riesgos de los sistemas de inteligencia artificial generativa.  
   https://doi.org/10.6028/NIST.AI.600-1

## Reflexión (3–5 líneas)

Considero que los agentes autónomos representan un desafío importante para la seguridad informática, ya que no solamente procesan información, sino que también pueden ejecutar acciones sobre sistemas reales. El mayor riesgo aparece cuando se les otorgan permisos y herramientas sin establecer límites adecuados. Los frameworks de OWASP permiten comprender y clasificar estas amenazas, mientras que las recomendaciones de NIST ayudan a gestionar los riesgos durante todo el ciclo de vida de la IA. En mi opinión, la autonomía debe estar acompañada de controles externos, supervisión y el principio de mínimo privilegio.
