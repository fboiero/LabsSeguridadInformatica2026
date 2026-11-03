# Research — Laboratorio Extra 4: Cracking de contraseñas

> Borrador de investigación para la entrega del Grupo 10. Opción elegida: **B — herramienta profesional**. Extensión final prevista: 1–2 carillas. Completar referencias con URL, título, organización/autor y fecha de consulta. No presentar velocidades no verificadas como resultados propios.

**Declaración de uso de IA (obligatoria):** [Declarar herramientas y uso real; revisar y validar todas las afirmaciones y referencias antes de entregar.]

## Resumen

Esta investigación compara las estrategias de generación de candidatos de Hashcat con el mangling implementado en el laboratorio, explica por qué los salts inutilizan tablas precalculadas reutilizables y resume un mecanismo de consulta de contraseñas comprometidas que no transmite la contraseña en claro. Las cifras de rendimiento deben quedar ligadas a benchmarks públicos identificables y separadas de las mediciones locales que aporte el equipo.

## 1. Hashcat: paralelismo y velocidades

Hashcat está diseñado para aprovechar procesadores gráficos y otros dispositivos de cómputo compatibles, distribuyendo trabajo entre dispositivos y ejecutando evaluaciones en paralelo. El rendimiento depende del algoritmo, sus parámetros (por ejemplo, coste de bcrypt o memoria/iteraciones de Argon2), hardware, versión, configuración y ataque. MD5 suele permitir muchas más evaluaciones por segundo que funciones de derivación deliberadamente costosas como bcrypt o Argon2; las velocidades no son comparables sin indicar equipo y parámetros. Hashcat ofrece un modo de benchmark, pero cualquier cifra citada debe conservar el contexto del dispositivo y algoritmo.

**Datos de benchmark a incorporar:**

| Algoritmo y parámetros | GPU/entorno | Velocidad | Fuente y fecha |
|---|---|---:|---|
| MD5 | Pendiente de fuente pública verificable | Pendiente | Pendiente |
| bcrypt (coste especificado) | Pendiente de fuente pública verificable | Pendiente | Pendiente |
| Argon2 (parámetros especificados) | Pendiente de fuente pública verificable | Pendiente | Pendiente |

No comparar una velocidad de MD5 con bcrypt/Argon2 sin especificar parámetros y equipo: medir funciones con costes distintos y dispositivos distintos produce cifras no directamente intercambiables. Las mediciones locales del laboratorio se informan por separado de los benchmarks públicos y de los datos que proporcione Chiara.

## 2. Ataques mask y combinator frente a reglas de mangling

Un ataque de **mask** genera candidatos a partir de una estructura posicional y conjuntos de caracteres definidos, por ejemplo, una palabra de formato conocido con dígitos en ciertas posiciones. En Hashcat se asocia con el modo de ataque de fuerza bruta/máscara (`-a 3`). Es útil cuando se conoce o se supone un patrón; la máscara puede reducir el espacio frente a probar todas las combinaciones posibles, pero también puede excluir contraseñas que no respeten ese patrón.

Un ataque **combinator** combina dos listas de palabras para generar candidatos (modo `-a 1`). No es lo mismo que transformar cada palabra por reglas de mangling.

Las reglas de mangling modifican candidatos existentes mediante transformaciones —por ejemplo, cambiar mayúsculas o agregar un sufijo— y Hashcat puede aplicarlas a un ataque basado en diccionario. La función `aplicar_reglas()` implementada en `entregas/labextra4/grupo10/src/cracker.py` incluye la palabra base, mayúscula inicial, sufijos de año 2024–2026 y sufijos `1`, `12` y `123`, deduplicando y preservando el orden. Por tanto, mask define patrones posicionales, combinator une dos listas y las reglas transforman palabras candidatas.

## 3. Rainbow tables y salt

Una rainbow table es una estructura precalculada que permite invertir parcialmente hashes de un conjunto de candidatos, intercambiando almacenamiento y cómputo. Es reutilizable cuando la función y el espacio de candidatos coinciden con los hashes objetivo. Un salt aleatorio y único por contraseña cambia la entrada que se procesa: las tablas precalculadas para un salt ausente o distinto no sirven directamente, y el atacante debe recalcular para cada salt. El salt **no** hace que un hash rápido sea lento ni evita probar candidatos contra cada cuenta; el coste de cómputo debe provenir de una función de derivación de contraseñas deliberadamente lenta y bien parametrizada.

## 4. Pregunta de cierre: HIBP y k-anonymity

El modelo **range** de Have I Been Pwned evita enviar la contraseña en claro. El cliente calcula localmente el SHA-1 de la contraseña, envía solo los primeros cinco caracteres hexadecimales del hash y recibe una lista de sufijos asociados a ese prefijo. Después compara localmente el sufijo restante. El servicio no recibe la contraseña ni el hash completo. La consulta por prefijo ofrece k-anonymity porque corresponde a múltiples posibles hashes; no obstante, esto no oculta otros metadatos de red. SHA-1 se usa aquí como identificador de consulta, no como recomendación para almacenar contraseñas.

Consultar listas de contraseñas comprometidas reduce el riesgo de elección de contraseñas ya conocidas y reutilizadas. Es una política más basada en evidencia que obligar a incluir mayúscula, número y símbolo: esas reglas pueden producir variantes predecibles, mientras que una contraseña larga y no comprometida puede ser más resistente y fácil de recordar. El chequeo de listas no reemplaza una función de almacenamiento adecuada, MFA ni controles de autenticación.

## Fuentes por verificar y completar antes de entregar

1. **NIST**, *Digital Identity Guidelines: Authentication and Authenticator Management* (SP 800-63B; consultar revisión vigente). https://pages.nist.gov/800-63-4/sp800-63b.html — consultado el [completar fecha].
2. **Have I Been Pwned**, *Pwned Passwords — API v3, range*. https://haveibeenpwned.com/API/v3#PwnedPasswords — consultado el [completar fecha].
3. **Hashcat**, wiki/documentación oficial: modos de ataque, mask, combinator y reglas. https://hashcat.net/wiki/ — consultado el [completar fecha].
4. **Hashcat**, repositorio oficial, instrucciones y opciones de benchmark. https://github.com/hashcat/hashcat — citar la salida concreta usada e indicar GPU, versión, modo/algoritmo y parámetros; consultado el [completar fecha].

## Pendiente de integración

- Incorporar benchmarks públicos identificables (hardware, parámetros y fecha), no estimaciones sin fuente.
- Incorporar las mediciones de rendimiento proporcionadas por Chiara en `informe.md`, manteniendo clara la procedencia y sin mezclarlas con benchmarks externos.
- Verificar la edición vigente de NIST y la documentación oficial de HIBP/Hashcat al momento de cerrar la entrega.
