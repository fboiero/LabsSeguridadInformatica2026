# Mini-research — Lab 01

**Grupo:** 05
**Tema elegido:** 2 — La cadena de suministro de software como superficie de ataque
**Cantidad de palabras:** 912 (sin bibliografía)

---

## Planteo

Un atacante que quiere acceder a mil organizaciones tiene, en principio, que
vulnerar a las mil, una por una. O puede vulnerar a *una sola*: el proveedor
de software cuya actualización las mil instalan de forma rutinaria y
confiada. Esa es la lógica de un ataque a la cadena de suministro de
software, y 2020-2021 dio dos ejemplos que, aunque comparten el nombre,
funcionan de maneras casi opuestas: SolarWinds/SUNBURST y Log4Shell. La
pregunta que este trabajo intenta responder es por qué el modelo de
confianza tradicional —"si el proveedor lo firmó, es seguro instalarlo"—
falla estructuralmente frente a ambos, y hasta dónde llegan realmente las
respuestas que la industria propuso después: el *Software Bill of
Materials* (SBOM) y el marco SLSA.

## Desarrollo

SolarWinds es el caso de una cadena de suministro *deliberadamente*
comprometida en el origen. Entre marzo de 2020 y diciembre de 2020, un
actor estatal —atribuido por el gobierno de EE. UU. al Servicio de
Inteligencia Exterior de Rusia (SVR)— insertó el backdoor SUNBURST en el
binario `SolarWinds.Orion.Core.BusinessLayer.dll`, y ese binario fue firmado
con el certificado de code-signing legítimo de la empresa antes de
distribuirse como una actualización normal a unas 18.000 organizaciones
(Cybersecurity and Infrastructure Security Agency [CISA], 2020/2021).
FireEye —que descubrió el ataque en su propia red— documentó que el
backdoor se comunicaba con infraestructura de comando y control mediante
dominios por víctima que imitaban el protocolo legítimo de Orion, con
esteganografía para ocultar los comandos (FireEye/Mandiant, 2020). Lo
crítico acá es que la firma digital, el mecanismo que existe justamente
para garantizar integridad, no detectó nada: firmó fielmente un binario que
ya venía alterado. El problema no estuvo en el algoritmo de firma sino en
*qué* se firmaba y en la falta de un registro verificable que atara ese
binario a su código fuente auditado.

Log4Shell es un caso distinto: no hay un atacante que compromete un
build server, sino una vulnerabilidad —CVE-2021-44228, con el máximo puntaje
de severidad (CVSS 10.0)— descubierta el 9 de diciembre de 2021 en Log4j 2,
una biblioteca de logging para Java usada de forma transitiva en un número
de aplicaciones imposible de estimar con precisión (CISA, 2021). La función
de búsqueda JNDI de Log4j permitía, mediante una cadena de texto
cuidadosamente construida dentro de un mensaje de log común, cargar y
ejecutar código remoto sin autenticación. Ninguna organización afectada
escribió esa línea de código vulnerable: la heredó de una dependencia de una
dependencia, muchas veces sin saber siquiera que Log4j formaba parte de su
software. Ese es el segundo modo de falla de la cadena de suministro: no
hace falta que alguien la ataque activamente, alcanza con que nadie sepa
exactamente de qué está hecho su propio producto.

Las dos respuestas que la industria y el gobierno de EE. UU. impulsaron
después atacan cada modo de falla por separado. El SBOM —formalizado por la
Administración Nacional de Telecomunicaciones e Información (NTIA) en julio
de 2021, a partir de la Orden Ejecutiva 14028 sobre ciberseguridad nacional—
es, esencialmente, una lista de ingredientes: un registro formal de qué
componentes y qué versiones exactas componen un producto de software
(National Telecommunications and Information Administration [NTIA], 2021).
Frente a Log4Shell, un SBOM bien mantenido convierte una pregunta que tomó
semanas de inventario manual en muchas organizaciones ("¿en cuál de
nuestros cientos de sistemas corre Log4j 2.x?") en una consulta directa.
SLSA (*Supply-chain Levels for Software Artifacts*), propuesto originalmente
por Google en 2021 y hoy mantenido por la Open Source Security Foundation,
ataca el otro modo de falla: define niveles progresivos de garantías sobre
*cómo* se construyó un artefacto —desde tener un build reproducible hasta,
en su nivel más alto, provenance firmada criptográficamente generada en
infraestructura de build aislada y efímera (OpenSSF, s.f.). Es, en esencia,
la respuesta directa al problema de SolarWinds: si el binario hubiera
llevado un registro verificable de qué commit y qué build lo produjeron, la
discrepancia con el código auditado habría sido detectable antes de la
firma.

## Tensión / límites

Ninguna de las dos propuestas resuelve el problema por completo. Un SBOM
dice qué componentes tiene un producto, pero no dice si esos componentes
fueron construidos con integridad: un SBOM perfecto de Orion Platform en
2020 habría listado `SolarWinds.Orion.Core.BusinessLayer.dll` como parte
legítima del producto, porque a nivel de componentes lo era —el problema
estaba en el binario mismo, no en la lista de qué bibliotecas lo componían.
Y SLSA, del lado opuesto, certifica la integridad del proceso de build,
pero no dice nada sobre si una dependencia declarada como legítima contiene
una vulnerabilidad como la de Log4j: un artefacto puede tener una
procedencia perfectamente verificable y ser, aun así, catastróficamente
inseguro. Además, ambos marcos dependen de adopción voluntaria y de
madurez organizacional: exigir SLSA nivel 3 o un SBOM completo a un
proveedor pequeño de software libre mantenido por un puñado de voluntarios
—que es, literalmente, el perfil de quien mantenía Log4j— es una exigencia
que compite con recursos que simplemente no existen en ese contexto.

## Cierre

Lo que estos dos incidentes muestran, en conjunto, es que la cadena de
suministro de software no tiene un único punto de falla que un solo
control resuelva: hay un modo de falla en el *origen* del artefacto (a qué
integridad de build confiamos) y otro en su *composición* (qué contiene
realmente lo que instalamos). Para la práctica profesional, la conclusión
operativa es que confiar en una firma digital o en el nombre de un
proveedor conocido ya no alcanza como criterio de seguridad: hace falta
tanto visibilidad de composición (SBOM) como verificabilidad de proceso
(SLSA), y aun con ambos, seguir asumiendo que en algún eslabón de la cadena
—muchas veces uno mantenido por voluntarios sin presupuesto de seguridad—
puede haber una falla que ningún marco por sí solo habría prevenido.

---

## Bibliografía

1. [PRIMARIA] Cybersecurity and Infrastructure Security Agency. (2020, 17 de diciembre; actualizado 2021, 15 de abril). *Advanced persistent threat compromise of government agencies, critical infrastructure, and private sector organizations* (Cybersecurity Advisory AA20-352A). U.S. Department of Homeland Security. https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
2. [PRIMARIA] Cybersecurity and Infrastructure Security Agency. (2021). *Apache Log4j vulnerability guidance*. U.S. Department of Homeland Security. https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance
3. [PRIMARIA] FireEye/Mandiant. (2020, 13 de diciembre). *Highly evasive attacker leverages SolarWinds supply chain to compromise multiple global victims with SUNBURST backdoor*. https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
4. [PRIMARIA] National Telecommunications and Information Administration. (2021, julio). *The minimum elements for a software bill of materials (SBOM)*. U.S. Department of Commerce. https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf
5. [ARBITRADA] Open Source Security Foundation. (s.f.). *SLSA: Supply-chain Levels for Software Artifacts* [Documentación del marco]. https://slsa.dev

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí

| Herramienta | Para qué | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude Code (Anthropic, modelo Claude Sonnet 5) | Investigar el tema, redactar el planteo/desarrollo/tensión/cierre y armar la bibliografía. | El documento completo. | Cada fuente se obtuvo directamente de la página o el documento original (CISA, FireEye/Mandiant, NTIA, OpenSSF/SLSA) antes de citarla, en vez de confiar en el conocimiento del modelo sin contrastar. Ninguna cita se incluyó sin haber accedido a su contenido real durante esta sesión. |

**Verificación de fuentes:** el grupo declara haber accedido y verificado
individualmente cada una de las referencias citadas.
