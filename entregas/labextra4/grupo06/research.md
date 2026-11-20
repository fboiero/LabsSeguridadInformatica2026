# Research — Lab Extra 4: cracking de contraseñas

**Grupo:** 06
**Opción elegida:** B — Hashcat y herramientas profesionales  
**Revisión:** 30/10/2026

## Hashcat y el paralelismo de GPU

Hashcat permite recuperar contraseñas mediante ataques fuera de línea sobre hashes y otros formatos compatibles. Puede utilizar CPU y GPU mediante CUDA, HIP, Metal y OpenCL, y repartir trabajo entre varios dispositivos. La compatibilidad depende del hardware, los controladores y el modo seleccionado [1].

En este tipo de ataque se generan candidatos y se comprueba si producen el resultado almacenado. Muchos candidatos pueden evaluarse de forma independiente, lo que permite aprovechar el paralelismo de una GPU. La tasa depende del algoritmo, sus parámetros, el equipo y la implementación; no existe una velocidad única de «cracking por GPU».

Un benchmark publicado en el foro de Hashcat para ocho RTX 4090 y versión 6.2.6 utiliza kernels optimizados y registra estas tasas agregadas [2]:

| Algoritmo y modo  | Parámetro indicado                      | Tasa agregada |
| ----------------- | --------------------------------------- | ------------: |
| MD5, modo 0       | Hash sin salt                           |  1.177,6 GH/s |
| bcrypt, modo 3200 | `Iterations: 32`, equivalente a costo 5 |  1.708,7 kH/s |

Al convertir las unidades, MD5 resulta aproximadamente 689.179 veces más rápido en esa prueba. Es un contraste entre un hash rápido y un esquema con trabajo configurable, no una comparación entre parámetros de seguridad equivalentes. El costo 5 de bcrypt está por debajo del mínimo 10 que recomienda OWASP para sistemas heredados que lo utilizan [3]. Una cifra de bcrypt sin su costo puede dar una impresión equivocada de su resistencia.

El MD5 del laboratorio incorpora salt. Su formato y el modo correspondiente deben identificarse antes de compararlo con Hashcat: la tasa del modo 0 no se traslada directamente al caso. Los benchmarks también omiten parte del trabajo de una recuperación real, como preparar los datos y generar los candidatos elegidos.

Argon2id agrega otra dificultad al paralelismo: cada derivación requiere memoria según sus parámetros. El RFC 9106 describe los parámetros de memoria, número de pasadas y paralelismo; deben acompañar cualquier tasa publicada [4]. La capacidad y el ancho de banda de memoria pueden limitar cuántos candidatos se procesan simultáneamente. Eso no impide usar GPUs ni garantiza que agregar dispositivos no aumente la tasa total.

Una contraseña previsible todavía puede aparecer al principio de un diccionario, aunque el algoritmo encarezca cada intento. Por eso no basta con conocer el nombre del KDF para estimar cuánto tardará una búsqueda.

## Máscaras, combinación de diccionarios y reglas

Hashcat ofrece distintas maneras de construir candidatos [5–7]:

- **Máscara:** define los caracteres permitidos en cada posición. `?u?l?l?l?d?d` representa una mayúscula, tres minúsculas y dos dígitos. Recorre las combinaciones de ese patrón; deja fuera las contraseñas que no lo cumplen.
- **Combinator:** concatena cada entrada de un diccionario con cada entrada de otro. Dos listas de tamaños A y B producen A × B pares; puede haber candidatos repetidos si las listas contienen duplicados o distintas parejas generan la misma cadena.
- **Reglas:** modifican palabras de un diccionario mediante operaciones como cambiar mayúsculas, agregar caracteres o eliminar posiciones. El lenguaje también incluye condiciones de rechazo.

La función `aplicar_reglas()` del práctico cubre un conjunto pequeño de capitalizaciones y sufijos. Se parece al enfoque de reglas de Hashcat, pero no reproduce todo su lenguaje. Una máscara, una combinación de listas y un conjunto de reglas cubren espacios diferentes: elegir uno no demuestra haber probado todas las contraseñas posibles.

## Rainbow tables y salt

Las rainbow tables utilizan cadenas de funciones hash y de reducción para intercambiar tiempo de cálculo por almacenamiento. Permiten reutilizar trabajo precalculado cuando los objetivos comparten el mismo esquema sin salt.

Un salt diferente por registro cambia el cálculo correspondiente a una misma contraseña. Una tabla preparada para un salt no sirve directamente para otro, de modo que un conjunto amplio de salts vuelve impráctica una tabla universal. El salt no necesita ser secreto [3].

Esto no detiene un ataque de diccionario: quien obtiene el hash y el salt puede calcular cada candidato y comparar el resultado. Para almacenar contraseñas se necesita además un esquema con costo ajustable, como Argon2id. OWASP lo prioriza y reserva bcrypt principalmente para sistemas heredados cuando Argon2id y scrypt no están disponibles [3].

## Contraseñas comprometidas y recomendaciones de NIST

NIST SP 800-63B-4 exige comparar la contraseña propuesta con una lista de valores comunes, esperables o comprometidos. También establece un mínimo de 15 caracteres cuando la contraseña es el único factor y permite un mínimo de ocho si solo se utiliza dentro de MFA. Prohíbe imponer reglas obligatorias de composición y exigir cambios periódicos sin evidencia de compromiso [8].

Agregar una mayúscula o un año a una palabra común puede satisfacer una regla formal y seguir siendo fácil de anticipar. La longitud ayuda, pero tampoco garantiza por sí sola una buena elección.

## Pwned Passwords y consultas por rango

Pwned Passwords permite consultar contraseñas expuestas sin enviar la contraseña ni su hash completo. El cliente calcula localmente su SHA-1 y consulta la API con los primeros cinco caracteres hexadecimales. El servicio devuelve sufijos y recuentos para ese prefijo; el cliente busca la coincidencia completa de forma local [9].

Este esquema suele describirse como una consulta con k-anonymity. Reduce la información enviada al servicio, aunque el prefijo revela información parcial y la conexión también tiene metadatos. SHA-1 se utiliza aquí como índice de búsqueda, no como recomendación para almacenar contraseñas. Una coincidencia indica que el valor aparece en el conjunto de contraseñas expuestas, no que una cuenta específica haya sufrido una filtración.

## Relación con el laboratorio

Las reglas del práctico muestran que priorizar candidatos previsibles puede ser más efectivo que enumerar cadenas sin criterio. Los benchmarks públicos ayudan a dimensionar la ventaja del hardware especializado, pero deben conservar su algoritmo, costo y contexto. El salt limita la reutilización de cálculos entre registros; el KDF encarece cada intento; la elección de la contraseña determina qué tan pronto puede aparecer entre los candidatos.

## Fuentes

1. Hashcat. [Página oficial: capacidades y requisitos](https://hashcat.net/hashcat/).
2. Foro de Hashcat. [Benchmark de ocho RTX 4090, Hashcat v6.2.6](https://hashcat.net/forum/thread-11750.html). Salida pública de un usuario del foro; no es una medición del grupo.
3. OWASP Cheat Sheet Series. [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
4. RFC 9106. [Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications](https://www.rfc-editor.org/rfc/rfc9106.html).
5. Hashcat Wiki. [Mask Attack](https://hashcat.net/wiki/doku.php?id=mask_attack).
6. Hashcat Wiki. [Combinator Attack](https://hashcat.net/wiki/doku.php?id=combinator_attack).
7. Hashcat Wiki. [Rule-based Attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack).
8. NIST. [SP 800-63B-4, sección 3.1.1.2](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver).
9. Have I Been Pwned. [API de Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords).

## Declaración de uso de IA

Opencode para buscar y sintetizar fuentes y redactar el análisis. Se utilizó ChatGPT para revisar la redacción, recalcular la relación del benchmark y ajustar afirmaciones técnicas.
