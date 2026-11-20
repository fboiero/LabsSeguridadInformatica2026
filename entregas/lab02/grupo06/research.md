# Mini-research — Laboratorio 02

**Tema elegido:** C — Derivación de claves desde contraseñas (PBKDF2, bcrypt,
scrypt, Argon2): por qué un `sha256(password)` no alcanza.

## Desarrollo

Un hash criptográfico como SHA-256 es determinístico y rápido. Esto resulta útil
para verificar la integridad de archivos, pero no es adecuado para almacenar
contraseñas: si una persona atacante obtiene una base de
`sha256(password)`, puede comprobar candidatos sin interactuar con el servidor.
El riesgo depende de la calidad de las contraseñas, del hardware disponible y de
los recursos del atacante; por eso no corresponde fijar una velocidad o tiempo
de ataque sin esos supuestos.

Para contraseñas se emplean funciones de derivación o hashing adaptativo, con
un salt único y un costo configurable. Su objetivo no es impedir por completo
un ataque offline después de una filtración, sino aumentar el costo de probar
cada contraseña candidata.

- **bcrypt (1999).** Provos y Mazières propusieron bcrypt a partir de
  eksblowfish, cuyo programa de expansión de clave es deliberadamente costoso
  [1]. Su factor de trabajo permite incrementar el costo de cálculo a medida
  que mejora el hardware. En la mayoría de las implementaciones, bcrypt limita
  la entrada a 72 bytes; además, no ofrece un parámetro de memoria configurable
  [5].
- **scrypt (2009).** Percival propuso scrypt como una función de derivación
  resistente al costo de memoria. Además de operaciones de cómputo, requiere
  memoria configurable, lo que aumenta el costo de ataques paralelos y de
  hardware especializado [2].
- **Argon2 (2015).** Argon2 fue la función ganadora de la Password Hashing
  Competition. La especificación RFC 9106 describe Argon2id, una variante que
  combina acceso a memoria independiente y dependiente de los datos en distintas
  fases [3]. Sus parámetros principales son memoria (`m`), número de pasadas
  (`t`) y grado de paralelismo (`p`).

PBKDF2 también incorpora un salt y un número de iteraciones. NIST describe que
el número de iteraciones debe elegirse tan alto como sea posible sin volver
inaceptable el tiempo de uso legítimo [4]. A diferencia de scrypt y Argon2id,
PBKDF2 no está diseñada para imponer un costo de memoria significativo.

La guía de OWASP recomienda Argon2id cuando está disponible. Como configuración
mínima presenta, entre otras opciones, `m=19456` KiB (19 MiB), `t=2` y `p=1`;
si Argon2id no está disponible, propone scrypt. Para sistemas heredados con
bcrypt, recomienda un factor de trabajo de al menos 10 [5]. Estos valores son
referencias mínimas: deben medirse y ajustarse al entorno de despliegue.

En síntesis, una función rápida como `sha256(password)` no ofrece un costo
suficiente frente a pruebas de contraseñas fuera de línea. Las funciones
adaptativas elevan ese costo mediante tiempo, memoria o ambos, pero no sustituyen
una contraseña robusta, salts únicos y controles contra ataques en línea.

## Fuentes (mín. 3, verificables)

1. Provos, N. y Mazières, D. (1999). _A Future-Adaptable Password Scheme_.
   USENIX Annual Technical Conference.
   https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf

2. Percival, C. (2009). _Stronger Key Derivation via Sequential Memory-Hard
   Functions_. BSDCan 2009.
   https://www.tarsnap.com/scrypt/scrypt.pdf

3. Biryukov, A., Dinu, D., Khovratovich, D. y Josefsson, S. (2021).
   _Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
   Applications_. RFC 9106. DOI: 10.17487/RFC9106.
   https://www.rfc-editor.org/rfc/rfc9106.html

4. Turan, M. S., Barker, E., Burr, W. y Chen, L. (2010).
   _Recommendation for Password-Based Key Derivation: Part 1: Storage
   Applications_. NIST SP 800-132, secciones 5.1–5.3.
   https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf

5. OWASP Foundation. _Password Storage Cheat Sheet_, secciones “Password
   Hashing Algorithms” y “Input Limits of bcrypt”. Consultado el 16/10/2026.
   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## Reflexión (3-5 líneas)

Las funciones adaptativas no eliminan el riesgo de una filtración: elevan el
costo de probar contraseñas fuera de línea. Por eso sus parámetros deben
revisarse cuando cambian el hardware, la carga del sistema o el modelo de
amenaza. Tampoco reemplazan contraseñas robustas ni evitan el reuso de
credenciales o los ataques en línea.
