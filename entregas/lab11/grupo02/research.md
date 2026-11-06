# Mini-research — Laboratorio 11

**Tema elegido:** C — Cadena de custodia: requisitos legales y por qué una evidencia mal manejada puede perder valor probatorio.

## Desarrollo

La cadena de custodia es el registro documentado de quién tuvo acceso a una evidencia, cuándo y qué acciones se realizaron sobre ella, desde su obtención hasta su presentación como prueba. Su función es permitir que se pueda justificar la autenticidad e integridad de la evidencia y documentar su recorrido durante la investigación.

En informática forense, este registro resulta especialmente importante porque los archivos digitales pueden modificarse sin que los cambios sean evidentes a simple vista. Por eso, además de registrar quién manipula la evidencia, es necesario documentar los métodos utilizados para obtenerla, conservarla y analizarla.

### El mecanismo: hashing criptográfico

Una de las herramientas utilizadas para verificar la integridad de archivos es el hash criptográfico. En este laboratorio se utiliza SHA-256 y los valores de referencia se encuentran en el archivo `evidencia.sha256`.

La verificación consiste en calcular el hash del archivo y compararlo con el valor de referencia. Si ambos coinciden, los bytes comparados son iguales. Si no coinciden, existe una discrepancia que debe investigarse. Sin embargo, el hash por sí solo no indica qué contenido cambió, cuándo ocurrió el cambio ni quién lo realizó.

También es importante recordar que los hashes dependen de los bytes exactos del archivo. Por ejemplo, una conversión de finales de línea de LF a CRLF puede cambiar el hash de un archivo de texto aunque su contenido legible parezca igual.

### Por qué una evidencia sin cadena de custodia puede perder valor probatorio

En un proceso judicial, la evidencia digital debe poder evaluarse en términos de autenticidad, integridad y confiabilidad. Una cadena de custodia incompleta o una discrepancia de integridad sin explicación puede generar dudas sobre la conservación y el tratamiento de la evidencia.

Esto no significa que toda evidencia con una irregularidad sea automáticamente descartada. Su admisibilidad y valor probatorio dependen de las normas aplicables y de la evaluación del caso. Sin embargo, si no se puede explicar una discrepancia o documentar adecuadamente el manejo de un archivo, puede resultar más difícil sostener conclusiones basadas en él.

Entre las buenas prácticas de preservación se encuentran registrar quién obtuvo la evidencia, la fecha y hora, el método y las herramientas utilizados, los hashes calculados, las personas que tuvieron acceso y las operaciones realizadas. Cuando es posible, el análisis se lleva a cabo sobre copias de trabajo, preservando la evidencia original.

### Conexión con el laboratorio

En nuestro caso, la primera verificación mediante `shasum -a 256 -c evidencia.sha256` mostró discrepancias en los nueve archivos de la copia de trabajo de Windows.

Al ejecutar `git ls-files --eol`, observamos que Git registra los archivos con finales de línea LF (`i/lf`), mientras que las copias locales utilizan CRLF (`w/crlf`). Esta diferencia puede modificar los hashes aunque el texto sea visualmente equivalente.

Para distinguir este efecto de otras discrepancias, comparamos los hashes del manifiesto con los bytes de los archivos registrados en Git (`HEAD`). Ocho archivos coincidieron y `logs/auth.log` no coincidió con su hash de referencia.

Este resultado justifica investigar `auth.log` con precaución y contrastar su contenido con otras fuentes disponibles. No demuestra por sí solo quién produjo la discrepancia ni cuándo ocurrió. Tampoco permite concluir, sin evidencia adicional, que un atacante modificó el archivo.

La experiencia muestra por qué es importante documentar tanto los resultados de las verificaciones como las condiciones en las que se realizaron. Una discrepancia no debe ocultarse ni interpretarse automáticamente como prueba de manipulación maliciosa: debe analizarse, explicarse cuando sea posible y tenerse en cuenta al formular conclusiones.

## Fuentes

1. **NIST — SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response*.** Guía sobre la integración de técnicas forenses en la respuesta a incidentes, incluida la recolección y preservación de evidencia.
2. **RFC 3227 — *Guidelines for Evidence Collection and Archiving*.** Recomendaciones para la recolección, preservación y documentación de evidencia digital.
3. **SWGDE — Scientific Working Group on Digital Evidence.** Guías y buenas prácticas relacionadas con el manejo, la preservación y la documentación de evidencia digital.

## Reflexión

Lo que más nos marcó de este research es que la cadena de custodia no es un trámite burocrático: permite justificar por qué confiamos en una evidencia y cuáles son sus limitaciones. En nuestro caso, la primera verificación de hashes mostró nueve discrepancias, pero investigar los finales de línea permitió explicar ocho de ellas. `logs/auth.log` siguió sin coincidir con el valor de referencia, por lo que debemos tratarlo con precaución. Aprendimos que un hash ayuda a detectar diferencias, pero no explica por sí solo qué ocurrió ni quién fue responsable.