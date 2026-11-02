# Mini-research — Laboratorio 04

**Tema elegido:** B. NIST Cybersecurity Framework: las cinco funciones y cómo se usan.

- [ ] **A.** ISO/IEC 27001: qué es un SGSI y el ciclo PDCA.
- [x] **B.** NIST Cybersecurity Framework: las cinco funciones y cómo se usan.
- [ ] **C.** Ley 26.388 y marco legal argentino de delitos informáticos.
- [ ] **D.** Análisis de riesgo cuantitativo vs cualitativo: ventajas y límites.

## Desarrollo

El NIST CSF es un marco de estándares, guías y buenas prácticas para gestionar el
riesgo de ciberseguridad. Lo desarrolló el NIST, el instituto de estándares de
EE. UU., a partir de una orden ejecutiva de 2014 y con aportes de empresas
públicas y privadas [1]. Se diseñó pensando originalmente en la infraestructura
crítica norteamericana, pero con la actualización a CSF 2.0 se amplió formalmente su
alcance a todo tipo de organizaciones, sectores y tamaños [1], [4].

Lo interesante del marco es que no te dice qué herramienta instalar ni qué
pasos seguir, sino que define **resultados** (outcomes) de seguridad [1]. Con eso
funciona como un "lenguaje común" entre el equipo técnico y la dirección:
los dos hablan de lo mismo, aunque el técnico lo traduzca a controles.

En la versión original las funciones eran cinco: **Identify, Protect, Detect,
Respond y Recover** [3]. En la 2.0 (febrero 2024) sumaron una sexta, **Govern**, que
queda en el centro de todo porque es la que fija la estrategia, la política y
las responsabilidades; el resto depende de ella [1], [2], [4]. Resumiendo cada una
de las seis funciones de CSF 2.0 [1], [2]:

- **Govern (GV):** que la política y la estrategia de riesgo existan, estén escritas y se auditen.
- **Identify (ID):** entender qué tenés (activos, sistemas, datos) y a qué riesgos estás expuesto. Es la base: no podés proteger lo que no sabés que existe.
- **Protect (PR):** las salvaguardas: control de acceso, seguridad de datos, capacitación, resiliencia.
- **Detect (DE):** descubrir el incidente a tiempo, con monitoreo y análisis continuo.
- **Respond (RS):** contener, comunicar y mitigar mientras pasa algo.
- **Recover (RC):** volver a operar rápido y quedarse con la lección.

Las funciones no se usan en orden ni una sola vez: se trabajan de forma
simultánea y continua. Para llevarlo a la práctica, el CSF ofrece el **Core**
(las funciones desglosadas en categorías y subcategorías), los **perfiles**
(dónde estás hoy vs a dónde querés llegar sobre el Core) y los **tiers** de
madurez [1]. Como es voluntario, no se "aprueba" ni se certifica: sirve para ver
las brechas y decidir en qué gastar.

## Fuentes

1. NIST. *The NIST Cybersecurity Framework (CSF) 2.0*. NIST Cybersecurity White Paper (CSWP) 29, 26 de febrero de 2024. DOI: [10.6028/NIST.CSWP.29](https://doi.org/10.6028/NIST.CSWP.29). PDF: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
2. NIST. *NIST Cybersecurity Framework 2.0: Resource and Overview Guide*. NIST Special Publication (SP) 1299, 26 de febrero de 2024. DOI: [10.6028/NIST.SP.1299](https://doi.org/10.6028/NIST.SP.1299). PDF: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1299.pdf
3. Mahn, A. / NIST. *Identify, Protect, Detect, Respond and Recover: The NIST Cybersecurity Framework*. Blog *Taking Measure*, NIST, 23 de octubre de 2018. https://www.nist.gov/blogs/taking-measure/identify-protect-detect-respond-and-recover-nist-cybersecurity-framework (Nota: Fuente histórica correspondiente a la versión previa CSF 1.1; documenta las cinco funciones originales, no las seis de CSF 2.0).
4. NIST. *NIST Releases Version 2.0 of Landmark Cybersecurity Framework*. NIST News Release, 26 de febrero de 2024. https://www.nist.gov/news-events/news/2024/02/nist-releases-version-20-landmark-cybersecurity-framework

## Reflexión

Estudiar el CSF sirvió bastante para la Parte A: las debilidades del
escenario de PhantomCorp cayeron solas en Protect (MFA, contraseñas, acceso
remoto, tarjetas), Respond (plan de incidentes) y Recover (backups). Y darme
cuenta de que el marco habla de resultados y no de instalables me obligó a
pensar en *qué se busca lograr* (por ejemplo, que el backup se pueda restaurar
y se pruebe) en vez de "poné tal herramienta".

También se vio un límite: el CSF te dice *qué* y *para qué*, pero no cuantifica
cuánto te importa cada brecha. Ahí entra la medición de la Parte B
(SLE/ARO/ALE): el marco ordena, el número prioriza.
