# Tema 2 — La cadena de suministro de software como superficie de ataque

## Introducción

La cadena de suministro de software comprende las personas, herramientas, bibliotecas, repositorios, servicios de compilación y mecanismos de distribución que intervienen en la producción de una aplicación. Tradicionalmente, las organizaciones confiaban en que el software proveniente de un proveedor conocido era seguro. Sin embargo, esa confianza puede convertirse en una superficie de ataque: comprometer un componente, una dependencia o el proceso de actualización puede afectar a muchas organizaciones que utilizan el mismo producto.

El riesgo no se limita al código desarrollado por una empresa. También incluye bibliotecas de código abierto, herramientas de construcción y sistemas de distribución. El Instituto Nacional de Estándares y Tecnología de Estados Unidos (NIST) destaca la necesidad de gestionar los riesgos de seguridad asociados al software adquirido, sus proveedores y sus componentes (National Institute of Standards and Technology [NIST], 2024).

## Casos relevantes: SolarWinds y Log4Shell

El incidente de SolarWinds, identificado públicamente en diciembre de 2020, ejemplifica el compromiso de una cadena de suministro. Según la Cybersecurity and Infrastructure Security Agency (CISA, 2020), determinadas versiones de la plataforma Orion, distribuidas entre marzo y junio de ese año, fueron afectadas por una actividad maliciosa. El ataque incorporó el código malicioso SUNBURST al proceso de distribución del software, de modo que clientes que recibieron actualizaciones comprometidas podían quedar expuestos.

La importancia del caso radica en que el punto de entrada no fue necesariamente una vulnerabilidad explotada de forma directa en cada organización afectada. El software distribuido por un proveedor legítimo se convirtió en un vehículo para introducir código malicioso en los entornos de sus clientes. Por eso, verificar únicamente la identidad del proveedor o instalar actualizaciones oficiales no resulta suficiente si el propio proceso de desarrollo o distribución ha sido comprometido.

Log4Shell, divulgada en diciembre de 2021 como CVE-2021-44228, muestra otra dimensión del mismo problema. La vulnerabilidad afectaba a determinadas versiones de Apache Log4j 2, una biblioteca de registro utilizada por numerosas aplicaciones Java. La Apache Software Foundation (2021) documentó que las versiones afectadas podían permitir la ejecución remota de código en determinadas condiciones. El alcance potencial era amplio porque una aplicación podía incorporar Log4j indirectamente, sin que el equipo responsable conociera su presencia.

Es importante distinguir ambos casos: SolarWinds fue un ataque que comprometió el proceso de distribución de software, mientras que Log4Shell fue una vulnerabilidad en una dependencia ampliamente utilizada. No son incidentes idénticos, pero ambos demuestran que la seguridad de una aplicación depende también de elementos externos y de las relaciones entre sus componentes.

## De la confianza tradicional a la verificación

La confianza tradicional se basa en la reputación del proveedor, la procedencia aparente del software y la expectativa de que las actualizaciones legítimas son confiables. Estos criterios siguen siendo relevantes, pero no ofrecen evidencia técnica suficiente sobre qué componentes contiene un producto, cómo fue construido o si sufrió modificaciones no autorizadas.

Una estrategia más sólida combina inventario, verificación y gestión continua del riesgo. La lista de materiales de software, conocida como *Software Bill of Materials* (SBOM), registra los componentes que integran un producto y sus relaciones. Según NIST (2024), una SBOM puede facilitar la identificación de dependencias vulnerables y acelerar la respuesta cuando se publica una alerta de seguridad.

Por ejemplo, ante una vulnerabilidad como Log4Shell, una organización que mantiene inventarios actualizados de sus aplicaciones y dependencias puede localizar con mayor rapidez los sistemas potencialmente afectados. No obstante, una SBOM no garantiza que el software sea seguro: puede estar incompleta, desactualizada o no reflejar correctamente las dependencias incorporadas durante la compilación. Además, identificar un componente vulnerable no determina por sí solo si la aplicación es explotable; es necesario evaluar versiones, configuraciones y condiciones de uso.

## SBOM, SLSA y controles complementarios

Otra iniciativa es SLSA (*Supply-chain Levels for Software Artifacts*), un marco que propone niveles progresivos de seguridad para la producción de software. Incluye mecanismos de procedencia verificable (*provenance*) que permiten documentar qué plataforma construyó un artefacto, qué proceso utilizó y cuáles fueron sus entradas. Los niveles superiores incorporan garantías más estrictas para reducir la posibilidad de manipulación durante o después de la compilación (SLSA, s. f.).

La SBOM y SLSA cumplen funciones complementarias. La primera ayuda a responder qué componentes forman parte del software; la segunda contribuye a verificar cómo se produjo un artefacto y de dónde proviene. Para aprovecharlas, las organizaciones deberían mantener dependencias actualizadas, analizar vulnerabilidades, proteger repositorios y credenciales, limitar privilegios en los entornos de compilación y verificar las firmas y los metadatos de los artefactos antes de desplegarlos.

Estas medidas deben acompañarse de supervisión continua y procedimientos de respuesta a incidentes. También es conveniente evaluar a los proveedores y establecer responsabilidades claras para informar vulnerabilidades, distribuir correcciones y comunicar incidentes. Ningún control aislado puede cubrir toda la cadena.

## Límites y conclusión

La gestión de la cadena de suministro no elimina por completo el riesgo. Las SBOM pueden ser incompletas; la procedencia puede no cubrir todas las dependencias; y un proceso de compilación verificable no demuestra que el código sea inocuo. Asimismo, un proveedor puede desarrollar y distribuir software de forma legítima y, aun así, incorporar una vulnerabilidad. Por eso, la verificación técnica debe combinarse con revisión de código, gestión de vulnerabilidades, control de accesos y monitoreo.

SolarWinds evidencia el peligro de confiar ciegamente en actualizaciones distribuidas por un proveedor, mientras que Log4Shell muestra cómo una dependencia común puede ampliar la exposición de muchas aplicaciones. En conclusión, la cadena de suministro debe tratarse como parte del perímetro de seguridad: conocer los componentes, verificar su procedencia y mantener un proceso continuo de actualización y respuesta permite reducir el riesgo, aunque no garantiza una seguridad absoluta.

## Referencias

Apache Software Foundation. (2021, 14 de diciembre). *Apache Log4j CVEs*. https://news.apache.org/foundation/entry/apache-log4j-cves

Cybersecurity and Infrastructure Security Agency. (2020, 13 de diciembre). *Active exploitation of SolarWinds software*. https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software

National Institute of Standards and Technology. (2024, 1 de noviembre). *Software security in supply chains*. https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-security-supply-chains

SLSA. (s. f.). *SLSA specification*. https://slsa.dev/spec/v1.2/

## Declaración de uso de asistentes de IA

Se utilizó ChatGPT como apoyo para estructurar el texto, mejorar la redacción y organizar las referencias bibliográficas. El grupo debe revisar las fuentes originales, comprobar las afirmaciones técnicas, adaptar el texto a su comprensión y verificar que la versión final cumpla con la consigna del laboratorio.