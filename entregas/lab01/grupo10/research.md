# Mini-research — Lab 01

**Grupo:** 10
**Tema elegido:** 2 — La cadena de suministro de software como superficie de ataque
**Cantidad de palabras:** 864 (sin bibliografía)

---

## Planteo

El modelo tradicional de seguridad informática asumía que el software provisto por fabricantes reconocidos o repositorios oficiales gozaba de legitimidad intrínseca. La protección organizacional se concentraba en el perímetro de red y en la autenticación de usuarios. Sin embargo, los incidentes recientes en la cadena de suministro de software evidenciaron el colapso de este paradigma de confianza implícita. Al comprometer a un único proveedor tecnológico o una dependencia compartida, un atacante evade las defensas perimetrales y alcanza simultáneamente a miles de organizaciones. La superficie de ataque ya no se restringe a la infraestructura propia, sino que abarca el ciclo de vida del software de terceros: código fuente, dependencias transitivas, entornos de compilación y canales de distribución. En este escenario, asegurar el software exige desarticular la confianza ciega y auditar con rigor técnico cada eslabón del ecosistema.

## Desarrollo

La gravedad de este vector se aprecia al contrastar dos incidentes paradigmáticos: el ataque a SolarWinds mediante SUNBURST en 2020 y la crisis de Log4Shell en 2021. Aunque ambos se catalogan como ataques a la cadena de suministro, su naturaleza técnica y punto de inserción son cualitativamente distintos.

El caso SolarWinds/SUNBURST constituyó un compromiso deliberado del proceso de compilación y distribución. Según documentó Mandiant (2020), el actor de amenazas infiltró la infraestructura de desarrollo de SolarWinds e intervino el sistema de compilación de la plataforma Orion. Mediante la herramienta Sunspot, el atacante monitoreó los procesos del compilador MSBuild e inyectó código malicioso en memoria milisegundos antes del ensamblado. Como consecuencia, la biblioteca maliciosa `SolarWinds.Orion.Core.BusinessLayer.dll` fue firmada con los certificados criptográficos legítimos de la empresa y distribuida a más de 18.000 clientes mediante el mecanismo oficial de actualización (Mandiant, 2020). En SolarWinds no falló el diseño del producto original; el ataque adulteró la canalización de compilación (*build pipeline*), convirtiendo un canal de distribución legítimo en vector de intrusión masiva.

En contraposición, Log4Shell (CVE-2021-44228) no implicó manipular un proceso de construcción ni vulnerar repositorios oficiales. De acuerdo con la Cybersecurity and Infrastructure Security Agency (CISA, 2021), el incidente derivó de un defecto de diseño en la biblioteca de registro de código abierto Apache Log4j. La funcionalidad de búsqueda JNDI interpretaba directivas en mensajes no saneados, permitiendo la ejecución remota de código arbitrario desde servidores maliciosos. A diferencia de SUNBURST, los binarios distribuidos de Log4j coincidían exactamente con el código fuente aprobado; el problema radicaba en una vulnerabilidad de software inherente distribuida silenciosamente a través de dependencias transitivas en aplicaciones globales (CISA, 2021).

Para mitigar esta exposición sistémica, surgieron dos iniciativas centrales: SBOM y SLSA.

El concepto de SBOM (*Software Bill of Materials*), formalizado por la National Telecommunications and Information Administration (NTIA, 2021), define los elementos mínimos para construir un inventario estructurado y legible por máquinas con los componentes, versiones y dependencias de una aplicación. Mediante estándares como SPDX o CycloneDX, un SBOM aporta visibilidad operativa inmediata. Su objetivo central es resolver la opacidad que caracterizó a Log4Shell, permitiendo a las organizaciones determinar con rapidez si una dependencia vulnerable integra sus sistemas (NTIA, 2021).

Por su parte, el marco SLSA (*Supply-chain Levels for Software Artifacts*), impulsado por la Open Source Security Foundation, aborda la integridad del proceso de construcción. En su especificación v1.2, SLSA establece niveles de madurez divididos entre el *Build Track* y el *Source Track* (OpenSSF, 2024). Mediante el *Build Track*, SLSA exige atestaciones de procedencia firmadas y generadas en entornos aislados, efímeros y herméticos. Su propósito es certificar criptográficamente que el artefacto binario resultante proviene sin adulteraciones del código fuente declarado en el repositorio, neutralizando ataques al pipeline como el de SolarWinds (OpenSSF, 2024).

## Tensión / límites

Pese a sus aportes, ni SBOM ni SLSA constituyen soluciones definitivas, y sus limitaciones deben comprenderse con precisión.

El límite principal de SBOM radica en que constituye un inventario descriptivo, no un juicio de seguridad. Un SBOM describe los componentes de una aplicación, pero no garantiza que carezcan de fallas ni detecta puertas traseras inyectadas durante la compilación. Un SBOM de SolarWinds Orion habría listado componentes legítimos sin alertar sobre el implante oculto en el binario compilado. Asimismo, no resuelve la explotabilidad contextual: identificar una dependencia no indica si el código vulnerable es ejecutable en producción, lo que puede saturar a los equipos de seguridad con alertas irrelevantes.

Por otro lado, SLSA v1.2 fortalece la integridad del proceso de construcción, pero su alcance se limita a la procedencia. SLSA certifica que un binario proviene fielmente de un commit específico, pero no audita la calidad ni la seguridad de ese código. Un pipeline con el nivel máximo SLSA Build L3 habría compilado Log4j de forma impecable y verificable, manteniendo la vulnerabilidad de diseño intacta. Además, SLSA no neutraliza la introducción de código malicioso por parte de desarrolladores autorizados o mediante cuentas comprometidas antes de la compilación.

## Cierre

La seguridad de la cadena de suministro no se resuelve con herramientas aisladas ni con confianza ciega en certificados. Demanda defensa en profundidad: SBOM aporta la visibilidad de inventario requerida ante fallas en dependencias como Log4Shell, mientras que SLSA provee la garantía de procedencia necesaria frente a ataques al proceso de compilación como SUNBURST. Para la ingeniería en sistemas, esto exige reemplazar la presunción de integridad por la verificación continua en cada fase del ciclo de vida del software.

---

## Bibliografía

Formato APA. Marcá cada fuente como [PRIMARIA], [ARBITRADA] o [SECUNDARIA].

1. [PRIMARIA] Cybersecurity and Infrastructure Security Agency. (2021, 22 de diciembre). *Alert AA21-356A: Mitigating Log4Shell and Other Log4j-Related Vulnerabilities*. CISA. https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
2. [PRIMARIA] Mandiant. (2020, 24 de diciembre). *SUNBURST Additional Technical Details*. Mandiant Threat Research. https://www.mandiant.com/resources/blog/sunburst-additional-technical-details
3. [PRIMARIA] National Telecommunications and Information Administration. (2021, 12 de julio). *The Minimum Elements For a Software Bill of Materials (SBOM)*. U.S. Department of Commerce. https://www.ntia.doc.gov/report/2021/minimum-elements-software-bill-materials-sbom
4. [PRIMARIA] Open Source Security Foundation. (2024). *Supply-chain Levels for Software Artifacts (SLSA) specification version 1.2*. SLSA Steering Committee. https://slsa.dev/spec/v1.2/

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí

| Herramienta | Para qué | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Asistente de IA (Gemini / Antigravity) | Asistencia en la estructuración, redacción inicial de la investigación | Secciones Planteo y Cierre | Revisión manual integral, verificación contra los documentos técnicos primarios de CISA, Mandiant, NTIA y OpenSSF, y comprobación algorítmica del conteo de palabras |

**Verificación de fuentes:** el grupo declara haber accedido y verificado individualmente cada una de las referencias citadas.

