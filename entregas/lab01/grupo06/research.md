# Mini-research — Lab 01

**Grupo:** 06  
**Tema elegido:** Tema 3 — La disponibilidad, la propiedad descuidada de la tríada  
**Título:** La disponibilidad como propiedad crítica de la seguridad: economía del ransomware, métricas de continuidad y límites reales de recuperación

## Planteo

Al estudiar la evolución histórica de la seguridad, diversos autores destacan el foco inicial en la confidencialidad. Samonas y Coss (2014) [4] describen la influencia del ámbito militar en los primeros modelos formales, como Bell-LaPadula, orientados a proteger información clasificada. También explican la evolución del interés hacia la integridad y la disponibilidad, con antecedentes como el modelo Biba y el reconocimiento de la denegación de uso como amenaza.

En organizaciones cuyos procesos dependen de la operación continua, como centros de salud, bancos o empresas de logística, una interrupción de los sistemas puede generar consecuencias económicas y operativas inmediatas. Por eso, gestionar la disponibilidad exige contemplar tanto las fallas de infraestructura como los ataques intencionales que buscan paralizar las operaciones.

## Desarrollo

### Continuidad operativa frente a fallas y adversarios

Para este análisis, interesa distinguir la protección frente a fallas de componentes de la protección frente a acciones deliberadas. Ambas requieren coordinar controles de seguridad y mecanismos de continuidad.

La redundancia de equipamiento permite afrontar situaciones como la rotura de un disco o la caída de un servidor. Sin embargo, no basta por sí sola frente a un adversario que obtiene credenciales privilegiadas y puede actuar sobre varios componentes. Dos servidores redundantes pueden quedar comprometidos si comparten cuentas administrativas o dependen del mismo entorno de gestión.

Los acuerdos de nivel de servicio (SLA) establecen compromisos de prestación, pero deben acompañarse de mecanismos técnicos y procedimientos que permitan sostenerlos ante incidentes de seguridad.

### La economía del ransomware y el costo de la inactividad

El ransomware permite exigir un rescate mediante la interrupción del acceso a datos o sistemas necesarios para operar. La presión económica depende, entre otros factores, de las alternativas de recuperación disponibles para la víctima.

Hernandez-Castro et al. (2020) [3] analizan esta dinámica mediante modelos de fijación de precios de monopolio y discriminación de precios. La disposición a pagar depende del valor asignado a los archivos, la existencia de respaldos utilizables, los recursos disponibles y la confianza en que el delincuente permita recuperarlos.

Aplicado al contexto organizacional, las pérdidas por interrupción de ventas, prestación de servicios y cumplimiento contractual pueden aumentar el incentivo económico para considerar el pago. Esto no garantiza que pagar permita recuperar los sistemas ni elimina los demás costos del incidente.

Por su parte, IBM (2024) [5] identifica el negocio perdido y las actividades posteriores a una brecha entre los principales componentes del impacto económico. Por tanto, evaluar el daño únicamente a partir del rescate solicitado deja fuera una parte importante de sus consecuencias.

| Aspecto | Foco en confidencialidad, como una filtración | Foco en disponibilidad, como el ransomware |
|---|---|---|
| Efecto principal | Exposición de datos sensibles | Cifrado o bloqueo de datos y servicios |
| Dinámica del impacto | Costos inmediatos y posteriores, como investigación, litigios y daño reputacional | Costos operativos durante la interrupción y recuperación |
| Factores relevantes del daño | Tipo, volumen y sensibilidad de los datos | Duración de la interrupción y criticidad de los servicios |
| Métricas y objetivos relevantes | Tiempos de detección y contención | Objetivos de recuperación: RTO y RPO |

Estas categorías no son excluyentes: la doble extorsión combina la interrupción operativa con amenazas de divulgación de información.

### Métricas de continuidad: BIA, RTO y RPO

La guía NIST SP 800-34 Rev. 1 [2] utiliza el Análisis de Impacto en el Negocio (BIA) para identificar procesos críticos, dependencias y prioridades de recuperación. Entre los parámetros considerados se encuentran:

1. **RTO (Recovery Time Objective):** tiempo máximo que un recurso del sistema puede permanecer indisponible sin producir un impacto inaceptable. Debe permitir que la recuperación no supere el tiempo máximo tolerable de interrupción del proceso de negocio (MTD).
2. **RPO (Recovery Point Objective):** punto temporal al que deben recuperarse los datos tras una interrupción. Expresa la pérdida tolerable en términos de tiempo y condiciona la estrategia de respaldo y replicación.

La guía conjunta *#StopRansomware* [1] recomienda mantener respaldos fuera de línea y cifrados, probar su disponibilidad e integridad y protegerlos frente al acceso del atacante. También contempla soluciones de almacenamiento inmutable. Estas medidas deben complementarse con separación de privilegios y procedimientos de recuperación.

## Tensión / límites

Los objetivos documentados deben contrastarse con las capacidades reales de recuperación:

1. **Transferencia frente al RTO:** un plazo resulta inviable si el tiempo mínimo de descarga ya lo supera. Transferir 20 TB decimales a 100 Mb/s requiere aproximadamente 444 horas —18,5 días—; a 1 Gb/s, unas 44 horas. Este cálculo ilustrativo supone velocidad constante y excluye congestión, sobrecargas y tareas posteriores de restauración.

2. **Replicación del daño:** replicar continuamente puede reducir la pérdida de datos ante una falla, pero también puede propagar cambios maliciosos. Si se replican bloques o archivos cifrados sin conservar versiones recuperables y protegidas, el entorno secundario puede recibir el mismo daño. La replicación no sustituye automáticamente a un respaldo independiente.

3. **Sabotaje y doble extorsión:** los atacantes pueden localizar y borrar o cifrar respaldos accesibles para dificultar la recuperación [1]. Además, si sustrajeron información, restaurar los servicios no elimina la amenaza de divulgación. Recuperar disponibilidad resuelve una parte del incidente, pero no revierte la exposición de datos.

## Cierre

La disponibilidad requiere integrar seguridad y continuidad operativa. La redundancia y los acuerdos de servicio deben acompañarse de respaldos protegidos, segmentación de red, separación de privilegios y procedimientos de restauración probados.

El análisis también muestra que definir un RTO o un RPO no garantiza cumplirlo. Es necesario medir tiempos de transferencia y recuperación, comprobar qué versiones pueden restaurarse y evaluar si un atacante podría comprometer tanto la producción como los respaldos. Estas verificaciones permiten ajustar los objetivos a las necesidades del negocio y a las capacidades técnicas disponibles.

## Bibliografía

1. **[PRIMARIA]** Cybersecurity and Infrastructure Security Agency et al. (2023). *#StopRansomware Guide*. [Guía conjunta, copia alojada por el Departamento de Defensa de Estados Unidos](https://media.defense.gov/2023/May/23/2003227891/-1/-1/0/CSI-StopRansomware-Guide.PDF).

2. **[PRIMARIA]** National Institute of Standards and Technology. (2010). *Contingency Planning Guide for Federal Information Systems* (NIST Special Publication 800-34, Rev. 1). U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-34r1

3. **[ARBITRADA]** Hernandez-Castro, J., Cartwright, A., & Cartwright, E. (2020). An economic analysis of ransomware and its welfare consequences. *Royal Society Open Science, 7*(3), 190023. https://doi.org/10.1098/rsos.190023

4. **[ARBITRADA]** Samonas, S., & Coss, D. (2014). The CIA strikes back: Redefining confidentiality, integrity and availability in security. *Journal of Information System Security, 10*(3), 21–45. [Página del artículo](https://www.jissec.org/Contents/V10/N3/V10N3-Samonas.html).

5. **[SECUNDARIA]** IBM. (2024). *Surging data breach disruption drives costs to record highs*. IBM Think. https://www.ibm.com/think/insights/whats-new-2024-cost-of-a-data-breach-report

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se utilizó | Qué partes afectó | Cómo se revisaron los aportes |
|---|---|---|---|
| Gemini / Gemini Deep Research / ChatGPT | Búsqueda inicial de fuentes, redacción preliminar y revisión de estilo y consistencia conceptual | Planteo, desarrollo, tensión y límites, cierre y bibliografía | Se contrastaron las observaciones con las fuentes accesibles, se revisó el cálculo ilustrativo de transferencia y se ajustaron las afirmaciones para explicitar su alcance. |

El grupo declara comprender el contenido presentado y poder explicar sus argumentos, cálculos y limitaciones, independientemente de la asistencia recibida.
