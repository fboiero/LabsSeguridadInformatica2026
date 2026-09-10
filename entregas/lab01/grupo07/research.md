# Mini-research — Lab 01

**Grupo:** 07
**Tema elegido:** 2 — La cadena de suministro de software como superficie de ataque (SolarWinds/SUNBURST y Log4Shell)
**Cantidad de palabras:** 832 (sin bibliografía ni declaración de IA)

---

## Planteo

La cadena de suministro de software no es solamente el proveedor al que una organización le compra un producto. También incluye el código abierto, las dependencias transitivas, los repositorios, las herramientas de compilación, el proceso de distribución y las actualizaciones. Por eso, una organización puede mantener sus propios controles y aun así recibir software comprometido o vulnerable. SolarWinds/SUNBURST y Log4Shell muestran dos caminos distintos hacia el mismo problema: el primero abusó de la confianza depositada en un proceso de construcción y actualización; el segundo convirtió una dependencia ampliamente usada en una puerta de entrada. La respuesta no puede ser confiar ciegamente ni rechazar toda dependencia externa, sino hacer verificable qué se usa, cómo se construyó y qué riesgos permanecen.

## Desarrollo

SolarWinds/SUNBURST fue un compromiso de la cadena de suministro en sentido estricto. Según la propia empresa, el código malicioso fue insertado en el sistema de construcción de Orion y apareció en actualizaciones distribuidas entre marzo y junio de 2020, aunque no estaba presente en el repositorio de código fuente (SolarWinds, s. f.). CISA identificó como afectadas determinadas versiones de Orion y recomendó a las organizaciones desconectar los productos comprometidos y seguir las indicaciones de respuesta (Cybersecurity and Infrastructure Security Agency [CISA], 2020). El ataque no necesitó convencer a cada víctima para descargar un ejecutable extraño: aprovechó que el proveedor era una fuente legítima y que el mecanismo habitual de actualización era considerado confiable.

La debilidad central fue una relación de confianza demasiado amplia. La distribución oficial demostraba que el archivo provenía del canal esperado, pero no que el proceso interno que lo produjo hubiera sido íntegro. Al alterar la compilación, el atacante convirtió una actualización normal en un vehículo para alcanzar a muchos clientes.

Log4Shell tuvo una naturaleza diferente. No fue una puerta trasera insertada en una actualización, sino una vulnerabilidad presente en una biblioteca de código abierto utilizada por muchos productos. Apache documentó que ciertos mensajes podían activar resoluciones JNDI inseguras y publicó una corrección en Log4j 2.15.0 (Apache Logging Services, 2021). La alerta conjunta de CISA, FBI, NSA y organismos asociados describió explotación activa y pidió inventariar también los activos de nube para encontrar las versiones vulnerables (CISA et al., 2021).

La diferencia es importante. SUNBURST atacó la integridad del producto antes de que llegara al cliente: el artefacto podía ser legítimo por su canal de distribución y, al mismo tiempo, malicioso. Log4Shell afectó una dependencia legítima durante la ejecución. En SUNBURST había que verificar el binario y su proceso de construcción; en Log4Shell había que descubrir dónde estaba Log4j, incluso como dependencia transitiva, y qué versión se ejecutaba. Firmar paquetes no corrige una vulnerabilidad, y conocer una dependencia no demuestra que el artefacto no haya sido alterado.

Un SBOM intenta resolver la falta de visibilidad. La NTIA lo define como un registro formal de los componentes y relaciones usados para construir un software (National Telecommunications and Information Administration [NTIA], 2021). Debe permitir identificar componentes directos y transitivos, versiones y proveedores en formatos procesables automáticamente. Frente a Log4Shell, permite ubicar productos que incluyen Log4j y priorizar la actualización, en lugar de depender de una etiqueta comercial.

SLSA complementa al SBOM porque se ocupa de la procedencia y del proceso de construcción. Define la *provenance* como información verificable sobre dónde, cuándo y cómo se produjo un artefacto (SLSA, s. f.). Sus niveles agregan garantías progresivas, como procedencia firmada y controles contra la manipulación durante el build. NIST también recomienda conservar procedencia y entregar un SBOM para mejorar la comunicación entre productores y consumidores (Souppaya et al., 2022). La idea conjunta es reemplazar confianza implícita por evidencia verificable.

## Tensión / límites

Ni SBOM ni SLSA son una solución automática. Un SBOM puede estar incompleto, desactualizado o limitarse a componentes declarados, sin mostrar artefactos descargados dinámicamente. Enumerar una versión tampoco indica si está expuesta, si la vulnerabilidad es alcanzable o si el binario coincide con el documento publicado. Por eso mejora la detección y priorización, pero no reemplaza el parcheo, las pruebas ni la supervisión de runtime.

SLSA aporta evidencia, pero depende de que el consumidor la verifique y confíe en la plataforma que la genera. Los niveles bajos pueden ser incompletos o fáciles de falsificar y los altos exigen cambios costosos. Una procedencia auténtica incluso puede describir un build que incluyó una dependencia vulnerable. Para reducir SUNBURST se necesitan controles sobre repositorios, identidades, separación de funciones y validación independiente. Para Log4Shell se necesitan inventario continuo, gestión de vulnerabilidades y respuesta. La tensión consiste en convertir metadatos en decisiones operativas sin tratarlos como una garantía absoluta.

## Cierre

SolarWinds y Log4Shell demuestran que “viene de un proveedor confiable” no basta para aceptar software. La seguridad debe cubrir tanto la integridad del proceso de construcción como las dependencias indirectas. Una PyME puede aplicar el principio manteniendo un inventario, exigiendo versiones y procedencia, verificando actualizaciones y definiendo la respuesta ante vulnerabilidades críticas. SBOM y SLSA reducen el tiempo de descubrimiento y la superficie de confianza, pero no eliminan la evaluación de riesgo.

---

## Bibliografía

1. [PRIMARIA] Apache Logging Services. (2021). *Release notes: Apache Log4j 2*. https://logging.apache.org/log4j/2.x/release-notes.html
2. [PRIMARIA] Cybersecurity and Infrastructure Security Agency. (2020, 13 de diciembre). *Active exploitation of SolarWinds software*. https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software
3. [PRIMARIA] Cybersecurity and Infrastructure Security Agency, Federal Bureau of Investigation, National Security Agency, Australian Cyber Security Centre, Canadian Centre for Cyber Security, CERT NZ, & National Cyber Security Centre. (2021, 23 de diciembre). *AA21-356A: Mitigating Log4Shell and other Log4j-related vulnerabilities*. https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
4. [PRIMARIA] National Telecommunications and Information Administration. (2021, 12 de julio). *The minimum elements for a software bill of materials (SBOM)*. https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
5. [PRIMARIA] SLSA. (s. f.). *SLSA specification (Version 1.2)*. Recuperado el 8 de septiembre de 2026, de https://slsa.dev/spec/v1.2/
6. [PRIMARIA] SolarWinds. (s. f.). *Security advisory FAQ*. Recuperado el 8 de septiembre de 2026, de https://www.solarwinds.com/sa-overview/securityadvisory/faq
7. [PRIMARIA] Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| OpenAI Codex | Como apoyo para ubicar fuentes oficiales, proponer una estructura inicial, contrastar conceptos de SBOM/SLSA y revisar claridad y extensión. | Búsqueda orientativa, organización y revisión del planteo, desarrollo, tensión/límites y cierre. | Fernando accedió a las fuentes originales, comprobó que cada referencia existiera y fuera localizable, contrastó las afirmaciones técnicas con los documentos citados y revisó/reformuló el texto final antes de incorporarlo. |

**Verificación de fuentes:** el integrante declara haber accedido y verificado individualmente cada una de las referencias citadas.
