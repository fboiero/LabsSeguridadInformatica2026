# Mini-research — Laboratorio 04

**Tema elegido:** *(uno)*
- [ ] **A.** ISO/IEC 27001: qué es un SGSI y el ciclo PDCA.
- [x] **B.** NIST Cybersecurity Framework: las cinco funciones y cómo se usan.
- [ ] **C.** Ley 26.388 y marco legal argentino de delitos informáticos.
- [ ] **D.** Análisis de riesgo cuantitativo vs cualitativo: ventajas y límites.

## Desarrollo

El **NIST Cybersecurity Framework (CSF)** es un marco voluntario del Instituto
Nacional de Estándares y Tecnología de EE. UU. para ayudar a las organizaciones a
gestionar y reducir su riesgo de ciberseguridad. No es una norma certificable ni
un checklist: describe **resultados** deseables (por ejemplo, "los backups se
crean, protegen, mantienen y prueban") y no prescribe cómo lograrlos. Apareció en
2014 orientado a la infraestructura crítica; la versión 2.0 (2024) amplió el
alcance de forma explícita a organizaciones de cualquier tamaño y sector.

**Las funciones.** La versión 1.1 (2018) organizaba el núcleo en cinco funciones:
**Identify** (entender activos y riesgos), **Protect** (salvaguardas),
**Detect** (descubrir eventos), **Respond** (actuar ante un incidente) y
**Recover** (restaurar operaciones). La versión 2.0 agrega una sexta,
**Govern**, que define la estrategia, las expectativas y la política de gestión
del riesgo y que, en el diagrama oficial, ocupa el centro de la rueda porque
informa a las otras cinco. Las funciones no son una secuencia: deben abordarse
de forma concurrente (Govern, Identify, Protect y Detect de manera continua;
Respond y Recover listas para cuando ocurra un incidente).

**Estructura.** Cada función se divide en *categorías* (p. ej. PR.AA, gestión de
identidades, autenticación y control de acceso) y estas en *subcategorías*, que
son los resultados concretos (p. ej. PR.DS-11, sobre backups). El orden y el
tamaño de las categorías no implican prioridad. Para pasar de los resultados a
las prácticas, el marco ofrece recursos en línea: *Informative References*
(mapeos a otros estándares, como ISO/IEC 27001 o NIST SP 800-53),
*Implementation Examples* y *Quick-Start Guides*.

**Cómo se usa.** Se crea un **perfil organizacional**: el *perfil actual*
(resultados que hoy se logran) y el *perfil objetivo* (los que se quieren
lograr). Luego se hace el **análisis de brecha**, se arma un plan de acción
priorizado y se implementa, repitiendo el ciclo. Los **Tiers** (Parcial, Informado
por riesgo, Repetible y Adaptativo) describen el rigor de la gobernanza y gestión
del riesgo, desde lo ad hoc hasta lo que mejora continuamente.

**Relación con la cuantificación del riesgo.** El CSF organiza *qué* hay que
hacer pero no dice *cuál* hacer primero. Para eso exige un método para calcular
y priorizar riesgos (GV.RM-06) y elegir y planificar las respuestas (ID.RA-06).
El documento reconoce cuatro respuestas al riesgo: mitigar, transferir, evitar y
aceptar. El cálculo de ALE y ROI de la Parte B es una forma concreta de dar ese
paso. Para la evaluación de riesgos, el CSF remite a guías como NIST SP 800-30.

**Comparación con ISO/IEC 27001.** ISO/IEC 27001 es una norma certificable para
construir un sistema de gestión de seguridad de la información; el CSF es más
flexible y no se certifica. No compiten: es común usar el CSF para comunicar y
priorizar y ISO 27001 como referencia de controles o para certificarse.

## Fuentes (mín. 3)

1. NIST (2024). *The NIST Cybersecurity Framework (CSF) 2.0.* NIST CSWP 29.
   https://doi.org/10.6028/NIST.CSWP.29
2. NIST (2018). *Framework for Improving Critical Infrastructure Cybersecurity,
   Version 1.1.* https://doi.org/10.6028/NIST.CSWP.04162018
3. NIST (2012). *Guide for Conducting Risk Assessments.* SP 800-30 Rev. 1
   (referenciada en la sección 5.2 de NIST CSWP 29).
   https://doi.org/10.6028/NIST.SP.800-30r1

## Reflexión

Aplicar el CSF a PhantomCorp mostró que el marco por sí solo ordena el problema
pero no lo prioriza: dice que hace falta MFA, políticas, un plan de respuesta y
backups confiables, pero no cuál conviene primero. Ahí aparece el valor de
combinarlo con el cálculo de ALE y ROI: el ranking de la Parte B convirtió una
lista de carencias en un plan ordenado por pérdida esperada y retorno.
También nos hizo ver que no todo se trata con "más controles": algunos riesgos
se mitigan (MFA), otros se transfieren (desastre físico) y otros se evitan
directamente (no guardar datos de tarjetas). Por último, vimos el límite de la
cuantificación: los números dependen de estimaciones de SLE y ARO, así que sirven
para comparar y decidir con criterio, no como una verdad exacta, y conviene
revisarlos periódicamente, como propone el ciclo de perfiles del marco.