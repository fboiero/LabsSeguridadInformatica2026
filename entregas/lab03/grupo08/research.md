# Mini-research — Laboratorio 03

**Tema elegido:**

- [x] **A.** PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".
- [ ] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] **C.** Autenticación vs autorización; modelos RBAC y ABAC.
- [ ] **D.** Ataques de timing reales y cómo se mitigan.

---

## Planteo y postura del grupo

En el caso LinkedIn (Parte A del informe) el problema no fue que SHA-1 estuviera "roto": fue que era **rápido**. Una función de hash común está diseñada para procesar gigabytes por segundo, y esa virtud se vuelve en contra cuando lo que se protege es una contraseña elegida por una persona, porque el atacante con la base robada puede probar candidatos offline a esa misma velocidad.

Los "hashes lentos" (más precisamente, *funciones de derivación de claves para contraseñas*) existen para invertir esa ecuación: que verificar **una** contraseña cueste unos milisegundos al servidor, y que probar **miles de millones** le cueste al atacante tiempo y dinero. Nuestra postura es que no todos los hashes lentos son equivalentes: PBKDF2 y bcrypt encarecen solo el **cómputo**, mientras que scrypt y Argon2 encarecen también la **memoria**, y eso es lo que de verdad le complica la vida a un atacante con GPUs o hardware dedicado.

---

## Desarrollo

### 1. PBKDF2: iterar para encarecer

PBKDF2 está especificado en PKCS #5 (RFC 8018) [1]. La idea es simple: aplicar una función pseudoaleatoria (en la práctica, HMAC-SHA256) en cadena miles de veces, con un salt por usuario. Cada vuelta depende de la anterior, así que no hay atajo: si son 600.000 iteraciones, cada intento del atacante cuesta 600.000 HMAC.

Es lo que implementamos en `src/auth.py` con 200.000 iteraciones. Su ventaja es que está en todas partes (la biblioteca estándar de Python lo trae como `hashlib.pbkdf2_hmac`) y tiene implementaciones validadas FIPS-140, por lo que OWASP lo recomienda cuando ese cumplimiento es obligatorio, con **600.000 iteraciones** o más para HMAC-SHA256 [5]. Su debilidad es que necesita muy poca memoria: cada intento entra en los registros de un núcleo de GPU, así que el atacante puede correr miles en paralelo.

### 2. bcrypt: un cifrado con arranque caro

bcrypt fue presentado por Provos y Mazières en 1999 para OpenBSD [2]. Se basa en *eksblowfish*, una variante del cifrado Blowfish con un *key schedule* deliberadamente costoso y un **factor de costo** ajustable: subir el costo en 1 duplica el trabajo. El título del paper, *A Future-Adaptable Password Scheme*, resume la idea central que después heredaron todos los demás: el costo tiene que poder **subir con los años**, a medida que el hardware se abarata.

bcrypt usa algo más de memoria que PBKDF2 (las tablas internas de Blowfish), lo que históricamente lo hizo algo más incómodo para GPUs, pero esa cantidad es fija y chica. Además, la mayoría de las implementaciones solo considera los primeros **72 bytes** de la contraseña [5]. OWASP hoy lo recomienda solo para sistemas heredados, con un factor de trabajo mínimo de 10 [5].

### 3. scrypt: la memoria como costo

Colin Percival propuso scrypt en 2009 con una observación clave: el cómputo es barato de paralelizar, pero la **memoria** no [3]. scrypt es una función *secuencialmente dura en memoria*: para calcularla hay que llenar un bloque grande de RAM y después leerlo en un orden que depende de los datos, de modo que reducir la memoria obliga a recalcular mucho más. Está estandarizada en el RFC 7914 [4].

Con los parámetros mínimos de OWASP (N = 2¹⁷, r = 8, p = 1) [5], cada intento necesita `128 · r · N` = **128 MiB** de RAM. Un servidor verifica un login sin problema; un atacante que quiera probar mil candidatos en paralelo necesita 128 GB de memoria rápida, que es justamente el recurso caro en una GPU o un ASIC.

### 4. Argon2: el ganador de la competencia

Entre 2013 y 2015 se realizó la *Password Hashing Competition*, una competencia abierta para elegir un nuevo estándar; en julio de 2015 se anunció a **Argon2** como ganador [6]. Hoy está especificado en el RFC 9106 [7], que define tres variantes:

- **Argon2d**: accesos a memoria que dependen de los datos; más resistente a GPUs, pero expuesto a ataques de canal lateral por tiempos.
- **Argon2i**: accesos independientes de los datos; resiste canales laterales.
- **Argon2id**: híbrido (empieza como Argon2i y sigue como Argon2d). El RFC lo exige como variante obligatoria y lo indica cuando no se sabe cuál elegir [7].

A diferencia de scrypt, Argon2 permite fijar por separado memoria, iteraciones y paralelismo. OWASP lo pone **primero** en su orden de preferencia, con un mínimo de 19 MiB de memoria, 2 iteraciones y paralelismo 1 [5].

### 5. Lo que medimos

Corrimos las funciones que trae la biblioteca estándar de Python en la máquina de un integrante (Windows 11, Python 3.12, mediana de 5 corridas):

| Función | Parámetros | Tiempo por intento | Memoria por intento |
|---|---|---:|---:|
| PBKDF2-HMAC-SHA256 | 200.000 iteraciones (nuestro `auth.py`) | ≈ 97 ms | despreciable |
| PBKDF2-HMAC-SHA256 | 600.000 iteraciones (mínimo OWASP) | ≈ 282 ms | despreciable |
| scrypt (`hashlib.scrypt`) | N = 2¹⁷, r = 8, p = 1 (mínimo OWASP) | ≈ 489 ms | 128 MiB |

El tiempo de PBKDF2 crece de forma lineal con las iteraciones (3 veces más iteraciones, ≈ 2,9 veces más tiempo), pero la columna que marca la diferencia es la última: para el atacante, la memoria es lo que no se puede paralelizar barato.

---

## Tensión y límites

1. **Lo ideal no siempre está a mano.** Argon2id es la recomendación principal, pero no está en la biblioteca estándar de Python (hace falta un paquete externo), y esta materia prohíbe bibliotecas externas en los labs de código. PBKDF2 tampoco es "malo": si FIPS-140 es obligatorio, es la opción recomendada [5]. Y NIST SP 800-63B exige salt de al menos 32 bits y un costo "tan alto como sea práctico", pero no nombra una función dura en memoria ni da números concretos [8].
2. **El costo es un compromiso.** Cuanto más caro el hash, más se protege la base robada, pero también se carga al servidor y se abre la puerta a la denegación de servicio con logins masivos. Por eso los parámetros se guardan en el registro y se suben con el tiempo, como hace nuestro `verify_password`.
3. **Un hash lento no salva una contraseña mala.** `123456` cae primero en cualquier diccionario, con cualquier función. El hash lento compra tiempo para las contraseñas razonables; para las débiles hacen falta chequeos contra contraseñas filtradas y un segundo factor.

---

## Reflexión

Nuestro `hash_password()` con PBKDF2 y 200.000 iteraciones habría evitado lo peor del caso LinkedIn, pero comparado con lo que se recomienda hoy queda corto: OWASP pide el triple de iteraciones, y prefiere funciones que además cuesten memoria. La lección que nos llevamos es que "hashear la contraseña" no alcanza como respuesta: hay que preguntarse **cuánto le cuesta al atacante cada intento** y revisar ese número periódicamente, porque el hardware del atacante mejora todos los años.

---

## Fuentes

1. Moriarty, K., Kaliski, B., & Rusch, A. (2017). *PKCS #5: Password-based cryptography specification version 2.1* (RFC 8018). IETF. https://www.rfc-editor.org/rfc/rfc8018 — **Primaria** (especificación de PBKDF2).
2. Provos, N., & Mazières, D. (1999). A future-adaptable password scheme. En *Proceedings of the 1999 USENIX Annual Technical Conference, FREENIX Track*. USENIX. https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf — **Arbitrada** (paper original de bcrypt).
3. Percival, C. (2009). *Stronger key derivation via sequential memory-hard functions* [Presentación en BSDCan 2009]. https://www.tarsnap.com/scrypt/scrypt.pdf — **Primaria** (paper original de scrypt).
4. Percival, C., & Josefsson, S. (2016). *The scrypt password-based key derivation function* (RFC 7914). IETF. https://www.rfc-editor.org/rfc/rfc7914 — **Primaria**.
5. OWASP Foundation. (s. f.). *Password storage cheat sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — **Secundaria** (guía de buenas prácticas).
6. Password Hashing Competition. (s. f.). *Password Hashing Competition*. https://www.password-hashing.net/ — **Primaria** (sitio oficial de la competencia).
7. Biryukov, A., Dinu, D., Khovratovich, D., & Josefsson, S. (2021). *Argon2 memory-hard function for password hashing and proof-of-work applications* (RFC 9106). IRTF. https://www.rfc-editor.org/rfc/rfc9106 — **Primaria**.
8. National Institute of Standards and Technology. (2025). *Digital identity guidelines: Authentication and authenticator management* (NIST SP 800-63B-4). https://pages.nist.gov/800-63-4/sp800-63b.html — **Primaria**.

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic) | Búsqueda de fuentes, borrador de la redacción y script para medir los tiempos de la sección 5. | Todo el mini-research. | Abrimos cada fuente para confirmar que existe y que dice lo que se le atribuye (los parámetros de OWASP y del RFC 9106 se contrastaron contra los documentos). Las mediciones se corrieron en la máquina de un integrante. El grupo revisó el texto y puede explicar cada parte. |
