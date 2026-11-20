# Mini-research — Laboratorio 03

**Tema elegido:** *(uno)*
- [x] **A.** PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".
- [ ] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] **C.** Autenticación vs autorización; modelos RBAC y ABAC.
- [ ] **D.** Ataques de timing reales y cómo se mitigan.

> **Aviso de honestidad:** las fuentes de abajo son documentos reales que conocemos, pero **no fueron abiertas ni consultadas en esta sesión**; el desarrollo sale de memoria. Las cifras y secciones puntuales hay que contrastarlas con la fuente antes de entregar. Este research fue redactado con Claude Code (ver declaración de IA en `informe.md`).

## Desarrollo

**El problema.** Las funciones hash de propósito general (MD5, SHA-1, SHA-256) se diseñaron para ser rápidas. Eso es una virtud para verificar archivos y un defecto para contraseñas: si se filtra la base, el atacante prueba candidatos a la velocidad que le permita su hardware (GPU, ASIC). Los "hashes lentos" (funciones de derivación de claves / *password hashing*) hacen que cada intento sea deliberadamente caro, con un costo configurable que se sube con el tiempo.

**PBKDF2** (RFC 2898, retomado en RFC 8018). Aplica una PRF (típicamente HMAC-SHA256) `c` veces sobre contraseña y salt. Es simple, está en la biblioteca estándar y es aceptado por NIST/FIPS, por eso es el que implementamos. Su debilidad: usa poca memoria, así que es muy paralelizable en GPU/ASIC.

**bcrypt.** Basado en el cifrado Blowfish, con un parámetro de costo. Usa una pequeña cantidad fija de memoria (~4 KB), lo que lo hace algo más incómodo para GPU que PBKDF2, aunque no es *memory-hard* en sentido fuerte. Limitación conocida: trunca la contraseña a 72 bytes.

**scrypt.** Diseñado para ser *memory-hard*: exige mucha memoria además de CPU, lo que encarece el hardware dedicado del atacante. Tiene parámetros de costo de CPU, memoria y paralelismo (N, r, p).

**Argon2.** Ganador de la Password Hashing Competition (2015), especificado en RFC 9106. Configurable en memoria, tiempo y paralelismo; la variante **Argon2id** es la que OWASP pone como primera opción.

**Qué se recomienda hoy.** Según OWASP (de memoria): Argon2id primero; si no está disponible, scrypt; bcrypt para sistemas legados; y PBKDF2 con muchas iteraciones (HMAC-SHA256, del orden de 600.000; a verificar) cuando se exige cumplimiento FIPS. NIST SP 800-63B exige almacenar los secretos memorizados con hash, salt y un factor de costo adecuado.

| | Memoria | Resistencia a GPU/ASIC | En stdlib de Python |
|---|---|---|---|
| PBKDF2 | baja | baja | sí (`hashlib.pbkdf2_hmac`) |
| bcrypt | baja, fija | media | no |
| scrypt | configurable, alta | alta | `hashlib.scrypt`, según cómo esté compilado Python |
| Argon2id | configurable, alta | muy alta | no |

(La tabla es de memoria, sin verificar.)

## Fuentes (mín. 3)

Ninguna fue abierta en esta sesión; se citan de memoria.

1. B. Kaliski, *PKCS #5: Password-Based Cryptography Specification Version 2.0*, **RFC 2898**, IETF, 2000; reemplazada por **RFC 8018**, IETF, 2017.
2. **RFC 4226**, *HOTP: An HMAC-Based One-Time Password Algorithm*, IETF, 2005.
3. **RFC 6238**, *TOTP: Time-Based One-Time Password Algorithm*, IETF, 2011.
4. **RFC 9106**, *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*, IETF, 2021.
5. OWASP, *Password Storage Cheat Sheet* (cheatsheetseries.owasp.org).
6. NIST, **SP 800-63B**, *Digital Identity Guidelines: Authentication and Lifecycle Management*.

## Reflexión

Implementar PBKDF2 con `hashlib` nos mostró que "hashear" no alcanza: lo que protege es el **costo por intento** (iteraciones) y la **unicidad** (salt). Medimos ~0,14 s para 200.000 iteraciones contra ~0,00008 s para una: ese factor de miles se le impone al atacante en cada candidato. También notamos que nuestro valor por defecto (200.000, el del esqueleto) probablemente queda por debajo de lo que hoy recomienda OWASP para PBKDF2, y que en una aplicación nueva elegiríamos Argon2id; en este lab no, porque la consigna pide solo stdlib. Las cifras exactas de las recomendaciones no pudimos confirmarlas en esta sesión, por eso quedan marcadas "a verificar".
