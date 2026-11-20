# Mini-research — Laboratorio 11

**Grupo:** 06  
**Tema elegido:** C — Cadena de custodia: requisitos legales y efectos del manejo de la evidencia  
**Fecha:** 30/10/2026

## Desarrollo

### Qué es la cadena de custodia

Encontrar un archivo sospechoso no alcanza para convertirlo en una evidencia confiable. También hay que explicar de dónde salió, cómo se obtuvo y qué ocurrió con él hasta su presentación. La cadena de custodia documenta ese recorrido: identificación, recolección, almacenamiento, análisis y transferencias entre responsables.

El RFC 3227 recomienda registrar dónde, cuándo y quién encontró y recogió la evidencia, quién la examinó, durante qué período estuvo bajo cada custodia y cómo se realizó cada transferencia. También propone restringir y documentar el acceso al archivo de evidencias [1]. Es una guía técnica de buenas prácticas, no una ley argentina.

En evidencia digital, la cadena debe cubrir tanto los soportes físicos como los archivos y sus copias. Un volcado de memoria, por ejemplo, necesita un identificador, el equipo de origen, fecha y zona horaria, responsable, herramienta y versión utilizadas, ubicación de almacenamiento y registro de las operaciones relevantes. Si se realiza una captura sobre un sistema encendido, deben explicarse las modificaciones inevitables que introduce la adquisición.

### Preservación e integridad

Una práctica útil es conservar la adquisición original y analizar copias de trabajo, documentando su relación. Cuando corresponda al soporte, pueden utilizarse mecanismos de solo lectura para reducir modificaciones accidentales. Las transferencias deben dejar constancia de quién entrega y recibe, cuándo, con qué finalidad y en qué condiciones.

Los hashes, como SHA-256, permiten comparar el contenido de una copia o verificar si un archivo cambió respecto de un valor registrado previamente. El RFC 8493 describe un ejemplo de preservación mediante paquetes BagIt, cuyos manifiestos relacionan archivos con sumas de comprobación [2]. BagIt no es un requisito judicial universal ni sustituye una cadena de custodia.

Un hash coincidente no prueba por sí solo quién creó el archivo, si su contenido es verdadero o si fue obtenido legalmente. Incluso una evidencia alterada antes del primer cálculo puede conservar después un hash estable. Por eso hacen falta registros del procedimiento, controles de acceso y una referencia de integridad protegida, además del archivo.

### Requisitos legales: el contexto argentino

La recolección debe respetar las facultades de quien interviene, las autorizaciones que correspondan y las reglas procesales aplicables. Como marco general, el artículo 18 de la Constitución Nacional protege la defensa en juicio y la inviolabilidad del domicilio, la correspondencia y los papeles privados [3]. Ese artículo no detalla un protocolo forense, pero muestra por qué la corrección técnica no basta para justificar cualquier forma de obtención.

Los requisitos concretos dependen de la jurisdicción, del procedimiento y de la medida realizada. No debe presentarse una recomendación técnica internacional como si fuera una exigencia legal uniforme para todos los tribunales argentinos.

Una evidencia mal manejada puede ser cuestionada porque no sea posible establecer su identidad, procedencia o integridad. Por ejemplo, si un volcado pasa entre varias personas sin registro y después se presenta una copia distinta, resulta difícil explicar qué archivo fue analizado y qué cambios sufrió. Eso debilita la posibilidad de revisar y discutir las conclusiones periciales.

La expresión «se cae en un juicio» simplifica demasiado. Hay que distinguir la admisibilidad de una evidencia de su valor probatorio. No corresponde afirmar que cualquier omisión administrativa produce automáticamente su exclusión: la consecuencia exige analizar el defecto, su importancia y las reglas del caso. Tampoco una cadena perfectamente documentada subsana una obtención contraria a las garantías legales.

## Fuentes

1. Brezinski, D. y Killalea, T. (2002). [RFC 3227 — Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227.html), especialmente secciones 2.4, 3 y 4.1. Guía técnica sobre recolección, documentación y custodia.
2. Kunze, J. et al. (2018). [RFC 8493 — The BagIt File Packaging Format (V1.0)](https://www.rfc-editor.org/rfc/rfc8493.html), secciones 2 y 3. Referencia técnica para manifiestos y comprobación de integridad; no establece requisitos de admisibilidad judicial.
3. Congreso de la Nación Argentina. [Constitución Nacional — Primera Parte, Capítulo Primero](https://www.congreso.gob.ar/constitucionParte1Cap1.php), artículo 18. Marco constitucional de defensa en juicio y garantías sobre ámbitos privados.

Fuentes consultadas el 30/10/2026. El enfoque legal toma Argentina como referencia general; no se analiza un expediente ni un régimen procesal provincial específico.

## Reflexión

Para aplicar estas ideas al Laboratorio 11, guardaríamos la captura original, calcularíamos su hash y trabajaríamos sobre una copia identificada. Cada transferencia y transformación quedaría registrada. Si convirtiéramos la codificación de una salida para leerla mejor, conservaríamos también el archivo anterior y explicaríamos el cambio, en lugar de presentar la copia convertida como idéntica en bytes.

La conclusión más útil es que un hallazgo debe poder ser revisado por otra persona. Documentar la custodia permite explicar qué se analizó y con qué límites, sin depender solo de la memoria del equipo. Estos pasos son una propuesta para el laboratorio, no una afirmación de que ya se hayan realizado.

## Declaración de uso de IA

Se utilizó Codex para buscar fuentes públicas, organizar la investigación y redactar esta versión. Se consultaron las tres fuentes citadas.
