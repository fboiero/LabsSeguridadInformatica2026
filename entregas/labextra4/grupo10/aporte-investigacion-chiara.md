# Lab Extra 4 — aporte de investigación: PBKDF2 y costo del cracking

## ¿Qué hace PBKDF2?

PBKDF2 deriva una salida a partir de una contraseña, un salt, una función seudorrandómica (por ejemplo, HMAC-SHA-256), un número de iteraciones y la longitud solicitada. Para almacenar contraseñas, el verificador guarda el salt, la salida derivada y los parámetros necesarios; cuando se intenta iniciar sesión, repite el cálculo con la contraseña ingresada y compara el resultado. El salt no es secreto: su propósito incluye evitar que una tabla precalculada sirva directamente para muchas cuentas con el mismo valor.

## Por qué importan las iteraciones

El número de iteraciones aumenta el trabajo de cada cálculo de PBKDF2. En una verificación legítima ese costo se paga una vez por intento de inicio de sesión; si alguien obtiene la base de hashes, también debe pagarlo por cada candidato que prueba. El valor debe elegirse midiendo el costo que el servicio puede tolerar y revisarse a medida que aumenta la capacidad de cómputo.

## Hash rápido y derivación de contraseñas

Un hash criptográfico general, como SHA-256, busca calcular un resumen con rapidez para tareas como integridad. Esa rapidez también permite probar muchos candidatos por segundo en un ataque offline. PBKDF2 repite una función seudorrandómica muchas veces y requiere más trabajo por candidato. Por eso, comparar ambos como verificadores de contraseñas debe considerar el costo deliberado, el salt y los parámetros almacenados; el nombre del hash por sí solo no determina la resistencia.

## Relación con fuerza bruta y diccionario

Un ataque offline compara candidatos contra el hash robado sin consultar al servicio. PBKDF2 no elimina las contraseñas débiles ni evita que se prueben diccionarios; eleva el costo de cada prueba. El benchmark de esta entrega procesa exactamente 20 candidatos sintéticos por conjunto, con el mismo salt sintético y los mismos parámetros. Sus tiempos describen esa muestra en esta máquina: no estiman una búsqueda exhaustiva ni el tiempo para crackear una contraseña real.

## Fuentes consultadas

- [RFC 8018, PKCS #5 v2.1, secciones 4 y 5.2](https://www.rfc-editor.org/rfc/rfc8018.html): PBKDF2, salt, contador de iteraciones y derivación. Consultado el 6 de noviembre de 2026.
- [NIST SP 800-63B-4, sección 3.1.1.2](https://pages.nist.gov/800-63-4/sp800-63b.html): almacenamiento de contraseñas con esquema adecuado, salt y factor de costo ajustado a la capacidad del verificador. Consultado el 6 de noviembre de 2026.
