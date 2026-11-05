# Mini-research — Lab 01

**Grupo:** 10
**Tema elegido:** 2 — La cadena de suministro de software como superficie de ataque
**Cantidad de palabras:** 869 (solo contenido, sin bibliografía ni declaración de IA)

---

## Planteo

El modelo tradicional de seguridad informática asumía que el software provisto por fabricantes reconocidos o repositorios oficiales gozaba de legitimidad intrínseca. La protección organizacional se concentraba en el perímetro de red y en la autenticación de usuarios. Sin embargo, los incidentes recientes en la cadena de suministro de software evidenciaron el colapso de este paradigma de confianza implícita. Al comprometer a un único proveedor tecnológico o una dependencia compartida, un atacante evade las defensas perimetrales y alcanza simultáneamente a miles de organizaciones. La superficie de ataque ya no se restringe a la infraestructura propia, sino que abarca el ciclo de vida del software de terceros: código fuente, dependencias transitivas, entornos de compilación y canales de distribución. En este escenario, asegurar el software exige desarticular la confianza ciega y auditar con rigor técnico cada eslabón del ecosistema.

## Desarrollo

La gravedad de esta exposición se aprecia al contrastar dos incidentes paradigmáticos: el ataque a SolarWinds mediante SUNBURST en 2020 y la crisis de Log4Shell en 2021. Ambos muestran riesgos de depender de software de terceros, pero no representan el mismo mecanismo: adulteración de la compilación frente a explotación de una dependencia legítima vulnerable.

El caso SolarWinds/SUNBURST constituyó un compromiso deliberado del proceso de compilación y distribución. Según CrowdStrike Intelligence Team (2021), SUNSPOT vigilaba los procesos de compilación de Orion y sustituía temporalmente un archivo fuente por una versión que incorporaba SUNBURST antes de su lectura por el compilador. No se trató de una inyección en memoria. La biblioteca adulterada `SolarWinds.Orion.Core.BusinessLayer.dll` conservaba una firma digital legítima de SolarWinds (Eckels et al., 2020). En su comunicación a la SEC del 14 de diciembre, SolarWinds Corporation (2020) estimó que menos de 18.000 clientes podían haber instalado una versión afectada; esa cifra no demuestra que todos sufrieran una intrusión posterior. El ataque convirtió la canalización de compilación (_build pipeline_) y el mecanismo oficial de actualización en vehículos de distribución maliciosa.

En contraposición, Log4Shell (CVE-2021-44228) no requirió adulterar la compilación ni comprometer repositorios oficiales. De acuerdo con la Cybersecurity and Infrastructure Security Agency (CISA, 2021), la vulnerabilidad afectaba a la biblioteca de registro Apache Log4j y permitía ejecución remota de código mediante el procesamiento de búsquedas JNDI en entradas controladas por un atacante. El problema estaba en el componente legítimo, no en una puerta trasera incorporada al distribuirlo. Su presencia en aplicaciones y dependencias transitivas multiplicó la exposición y dificultó identificar todas las instalaciones que requerían corrección.

Para mitigar esta exposición sistémica, surgieron dos iniciativas centrales: SBOM y SLSA.

El concepto de SBOM (_Software Bill of Materials_), formalizado por la National Telecommunications and Information Administration (NTIA, 2021), define los elementos mínimos para construir un inventario estructurado y legible por máquinas con los componentes, versiones y dependencias de una aplicación. Mediante estándares como SPDX o CycloneDX, un SBOM aporta visibilidad operativa inmediata. Su objetivo central es resolver la opacidad que caracterizó a Log4Shell, permitiendo a las organizaciones determinar con rapidez si una dependencia vulnerable integra sus sistemas (NTIA, 2021).

Por su parte, SLSA (_Supply-chain Levels for Software Artifacts_), impulsado por OpenSSF, distingue la seguridad de la construcción y la del código fuente. Su versión 1.2, publicada el 24 de noviembre de 2025, incorpora el _Source Track_ al _Build Track_ (SLSA Community, 2025a). Las garantías de construcción son graduales: Build L1 exige procedencia; L2 incorpora autenticidad verificable y plataforma alojada; L3 exige mayor resistencia a falsificación y aislamiento entre compilaciones, con entornos efímeros. Aislamiento no significa hermeticidad: SLSA v1.2 no exige universalmente compilar sin acceso a red. Estas evidencias ayudan a verificar el origen del artefacto, no a certificar que todo su código sea seguro (SLSA Community, 2025b).

## Tensión / límites

Pese a sus aportes, ni SBOM ni SLSA constituyen soluciones definitivas, y sus limitaciones deben comprenderse con precisión.

El límite principal de SBOM radica en que constituye un inventario descriptivo, no un juicio de seguridad (NTIA, 2021). Describe componentes, pero no garantiza que carezcan de fallas ni detecta por sí solo adulteraciones durante la compilación. En un caso como SolarWinds, una lista de componentes legítimos no habría bastado para descartar un implante en el binario. Asimismo, no resuelve la explotabilidad contextual: identificar una dependencia no indica si el código vulnerable es ejecutable en producción, lo que puede saturar a los equipos de seguridad con alertas irrelevantes.

El _Build Track_ tampoco evalúa la seguridad del código: un proceso conforme a Build L3 podría producir un Log4j vulnerable a partir del código esperado. La procedencia solo resulta útil si el consumidor la verifica contra expectativas y confía en la plataforma que la genera (SLSA Community, 2025b). Esto no debe generalizarse a todo SLSA: el _Source Track_ incorpora controles sobre historial, procedencia y revisión del código. Esos controles reducen riesgos de cambios no autorizados, pero no garantizan detectar toda lógica maliciosa aprobada ni todas las vulnerabilidades (SLSA Community, 2025c).

## Cierre

La seguridad de la cadena de suministro no se resuelve con herramientas aisladas ni con confianza ciega en certificados. Nuestra posición es combinar inventario, control de cambios y verificación: SBOM ayuda a localizar dependencias como Log4j; SLSA permite evaluar evidencias sobre construcción y origen. Ninguno reemplaza el análisis de vulnerabilidades ni la respuesta a incidentes. Para la ingeniería en sistemas, esto exige convertir esas evidencias en decisiones operativas, no tratarlas como sellos automáticos de seguridad.

---

## Bibliografía

1. [PRIMARIA] CrowdStrike Intelligence Team. (2021, 11 de enero). _SUNSPOT: An implant in the build process_. CrowdStrike. https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/
2. [PRIMARIA] Cybersecurity and Infrastructure Security Agency. (2021, 22 de diciembre). _Mitigating Log4Shell and other Log4j-related vulnerabilities_ (AA21-356A) [Aviso conjunto de ciberseguridad]. https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
3. [PRIMARIA] Eckels, S., Smith, J., & Ballenthin, W. (2020, 24 de diciembre). _SUNBURST additional technical details_. Mandiant, Google Cloud Blog. https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details
4. [PRIMARIA] National Telecommunications and Information Administration. (2021, 12 de julio). _The minimum elements for a software bill of materials (SBOM)_. U.S. Department of Commerce. https://www.ntia.doc.gov/report/2021/minimum-elements-software-bill-materials-sbom
5. [PRIMARIA] SLSA Community. (2025a, 24 de noviembre). _Announcing SLSA v1.2_. https://slsa.dev/blog/2025/11/announce-slsa-v1.2
6. [PRIMARIA] SLSA Community. (2025b). _Build: Requirements for producing artifacts (SLSA v1.2)_. https://slsa.dev/spec/v1.2/build-requirements
7. [PRIMARIA] SLSA Community. (2025c). _Source: Requirements for producing source (SLSA v1.2)_. https://slsa.dev/spec/v1.2/source-requirements
8. [PRIMARIA] SolarWinds Corporation. (2020, 14 de diciembre). _Current report_ [Form 8-K, Item 8.01]. U.S. Securities and Exchange Commission. https://www.sec.gov/Archives/edgar/data/1739942/000162828020017451/swi-20201214.htm

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí

| Herramienta                            | Para qué                                                               | Qué partes afectó          | Cómo se verificó                                                                                                                                                     |
| -------------------------------------- | ---------------------------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Asistente de IA (Gemini / Antigravity) | Asistencia en la estructuración, redacción inicial de la investigación | Secciones Planteo y Cierre | Revisión manual integral, verificación contra los documentos técnicos primarios de CISA, Mandiant, NTIA y OpenSSF, y comprobación algorítmica del conteo de palabras |

**Verificación de fuentes:** el grupo declara haber accedido y verificado individualmente cada una de las referencias citadas.
