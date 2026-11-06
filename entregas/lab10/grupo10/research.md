# Mini-research — Laboratorio 10

**Grupo:** 10  
**Tema elegido:** C — SIEM y correlación de logs: cómo se detecta lo que ninguna firma ve.

## Desarrollo

Un SIEM centraliza eventos provenientes de aplicaciones, sistemas operativos, dispositivos de red y herramientas de seguridad para que puedan consultarse y analizarse en conjunto. La centralización por sí sola no encuentra una intrusión: se necesitan registros suficientemente completos, tiempos comparables, campos consistentes y reglas o analistas que relacionen eventos. NIST define la correlación basada en reglas como la comparación de varias entradas de log mediante valores como marcas de tiempo, direcciones IP y tipos de evento (NIST, s. f.). Esto convierte múltiples señales débiles en una hipótesis que puede investigarse.

Una detección por firma suele buscar una cadena o condición conocida en un evento individual. Si solo mira una User-Agent conocida o la secuencia literal `UNION SELECT`, una variación de representación puede evitar esa coincidencia. La correlación permite observar contexto adicional: por ejemplo, una misma sesión o IP que recorre muchas rutas, obtiene respuestas de error y luego accede a una ruta administrativa. Esa secuencia puede ser sospechosa aunque ninguna solicitud aislada coincida con una firma. La correlación no equivale a prueba: proxies, NAT, relojes desincronizados o campos ausentes pueden unir eventos que no pertenecen a la misma actividad.

NIST SP 800-92 trata la gestión de logs como un proceso de generación, transmisión, almacenamiento, acceso, análisis y disposición de datos, y ofrece orientación para establecer una capacidad de gestión de logs en la organización (Kent & Souppaya, 2006). En 2023, NIST publicó un borrador inicial de la revisión SP 800-92 Rev. 1 centrado en la planificación de mejoras. El registro oficial consultado lo identifica como borrador, mientras que SP 800-92 sigue apareciendo como la publicación final. Por ello, no corresponde citar el borrador como estándar final vigente ni presentar el documento de 2006 como si cubriera por completo las tecnologías actuales.

La guía NIST SP 800-94 explica clases de sistemas IDS/IPS y considera SIEM como tecnología complementaria. Su publicación final data de 2007; NIST informa que la revisión 1 publicada en 2012 quedó como borrador y fue retirada en 2022. Esto limita su valor para recomendaciones de producto actuales, pero sus conceptos generales ayudan a distinguir sensores, análisis y respuesta. Para la respuesta a incidentes, NIST SP 800-61 Rev. 3, publicada en abril de 2025, conecta preparación, detección, respuesta y recuperación con el marco CSF 2.0. En conjunto, estas fuentes apoyan una arquitectura donde las reglas producen señales y los procesos de respuesta dan contexto, validan alertas y coordinan acciones.

Un caso pequeño como el SOC del laboratorio puede pensarse como una regla de correlación: una solicitud sospechosa más un código de respuesta exitoso o una secuencia rara de accesos debería elevar una alerta, aunque el patrón exacto no coincida con una expresión simple. Para que esa regla sirva, el equipo debe medir ruido y falsos positivos, guardar el evento original, registrar qué regla generó la alerta y revisar los casos que quedaron fuera. Las firmas y la correlación se complementan: una aporta rapidez sobre patrones conocidos; la otra puede revelar relaciones y comportamientos que no estaban codificados como una cadena única.

El evento R5 permite relacionar la investigación con lo observado en la práctica. En la salida de `/soc` aparece una solicitud externa a una ruta sospechosa, mezclada entre numerosos registros de actividad normal. Aunque el servidor respondió con un código HTTP 200 y la etiqueta `ALERT[path-traversal]`, eso no demuestra por sí solo que el archivo haya sido obtenido. En un entorno real, un SIEM con correlación basada en reglas (NIST, s. f.) podría ayudar a destacar este tipo de eventos y relacionarlos con otros registros para facilitar su análisis. En nuestro caso, la salida era estática, por lo que no se realizó una correlación automática.

## Fuentes

1. [PRIMARIA] Kent, K., & Souppaya, M. (2006). *Guide to computer security log management* (NIST Special Publication 800-92). National Institute of Standards and Technology. https://csrc.nist.gov/pubs/sp/800/92/final
2. [PRIMARIA] National Institute of Standards and Technology. (2007). *Guide to intrusion detection and prevention systems (IDPS)* (NIST Special Publication 800-94). https://csrc.nist.gov/pubs/sp/800/94/final
3. [PRIMARIA] Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025). *Incident response recommendations and considerations for cybersecurity risk management: A CSF 2.0 community profile* (NIST Special Publication 800-61 Rev. 3). National Institute of Standards and Technology. https://csrc.nist.gov/pubs/sp/800/61/r3/final
4. [PRIMARIA] National Institute of Standards and Technology. (s. f.). *Rule-based event correlation*. CSRC Glossary. https://csrc.nist.gov/glossary/term/Rule_Based_Event_Correlation

## Reflexión

Un SIEM no sustituye la calidad de los logs ni la interpretación humana. Correlacionar aporta contexto, pero también puede asociar eventos de forma incorrecta. La detección debe ser verificable: conservar el evento original, explicar qué condición disparó la regla y revisar sus falsos positivos y omisiones.
