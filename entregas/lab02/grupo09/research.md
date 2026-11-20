# Mini-research — Laboratorio 02

**Tema elegido:** D

- [ ] **A.** Modos de operación de cifrado por bloques (ECB vs CBC vs GCM) y por
  qué ECB filtra estructura (el "pingüino" de Adobe).
- [ ] **B.** HMAC y el ataque de length-extension: cómo funciona el ataque y por
  qué HMAC lo previene.
- [ ] **C.** Derivación de claves desde contraseñas (PBKDF2, bcrypt, scrypt,
  Argon2): por qué un `sha256(password)` no alcanza.
- [x] **D.** Cifrado asimétrico y firmas digitales: qué problema resuelven que el
  simétrico no.

## Desarrollo

### El problema que deja abierto el cifrado simétrico

En el cifrado simétrico (AES, o el XOR de este lab) y en los MAC como HMAC, **la misma clave
cifra y descifra, o firma y verifica**. Eso deja tres problemas sin resolver:

1. **Distribución de claves.** Dos partes tienen que acordar la clave antes de hablar, por un
   canal que ya sea seguro. Con *n* participantes que quieran hablar de a pares hacen falta
   *n(n−1)/2* claves distintas.
2. **Quién verifica puede falsificar.** Con un MAC, el receptor tiene la misma clave que el
   emisor: puede fabricar mensajes "firmados" igual de válidos. Sirve para autenticar entre
   dos partes que confían entre sí, no para demostrarle algo a un tercero.
3. **No hay no repudio.** Como ambos tienen la clave, el emisor puede negar haber enviado un
   mensaje y nadie puede probar lo contrario.

### La idea asimétrica

Diffie y Hellman propusieron en 1976 separar la clave en dos [1]: una **pública**, que se
puede publicar sin riesgo, y una **privada**, que nunca sale de su dueño. La seguridad se
apoya en problemas matemáticos fáciles en un sentido y muy difíciles al revés: factorizar
números grandes (RSA) o el logaritmo discreto en curvas elípticas (ECDSA, Ed25519).

Esto resuelve los tres problemas:

- **Distribución:** cada uno publica su clave pública. Con intercambio de claves
  (Diffie-Hellman) dos partes acuerdan un secreto compartido por un canal público, y después
  usan cifrado simétrico, que es mucho más rápido. Así funciona TLS.
- **Firma digital:** el dueño firma con la privada y **cualquiera** verifica con la pública,
  pero nadie más puede firmar. Por eso sirve para firmar código: millones de PS3 pueden
  verificar el software de Sony sin poder firmar nada por su cuenta.
- **No repudio:** solo el dueño de la privada pudo producir la firma, así que puede
  demostrarse frente a terceros quién firmó.

### Las firmas en la práctica

Los algoritmos estándar están definidos por NIST en FIPS 186-5 (RSA, ECDSA y EdDSA) [2]. En
la práctica no se firma el mensaje completo, sino su hash, lo que obliga a usar un hash
resistente a colisiones: con MD5 roto se llegaron a falsificar certificados.

El caso de la PS3 muestra que una firma asimétrica es tan fuerte como su implementación. En
ECDSA el nonce *k* tiene que ser secreto, impredecible y único por firma; repetirlo una sola
vez filtra la clave privada con dos firmas públicas. Por eso los diseños modernos sacan esa
decisión de las manos del programador: **RFC 6979** deriva *k* de forma determinista a partir
del mensaje y la clave privada [3], y **Ed25519** incorpora ese mecanismo en el propio
algoritmo [4]. En ambos casos, firmar dos veces el mismo mensaje da la misma firma, y dos
mensajes distintos nunca comparten nonce.

### Simétrico y asimétrico juntos

No compiten: se combinan. El asimétrico resuelve **identidad y acuerdo de claves**, y el
simétrico hace el trabajo pesado de **cifrar y autenticar datos** porque es órdenes de
magnitud más rápido. TLS, SSH y Signal hacen exactamente eso: firman y acuerdan claves con
criptografía asimétrica y cifran el tráfico con AES o ChaCha20 y un MAC.

## Fuentes (mín. 3, verificables)

1. W. Diffie, M. Hellman, *New Directions in Cryptography*, IEEE Transactions on Information
   Theory, vol. 22, n.º 6, 1976.
   <https://ee.stanford.edu/~hellman/publications/24.pdf>
2. NIST, *FIPS 186-5 — Digital Signature Standard (DSS)*, 2023.
   <https://csrc.nist.gov/pubs/fips/186-5/final>
3. T. Pornin, *RFC 6979 — Deterministic Usage of DSA and ECDSA*, IETF, 2013.
   <https://www.rfc-editor.org/rfc/rfc6979>
4. S. Josefsson, I. Liusvaara, *RFC 8032 — Edwards-Curve Digital Signature Algorithm
   (EdDSA)*, IETF, 2017. <https://www.rfc-editor.org/rfc/rfc8032>

## Reflexión (3–5 líneas)

Lo que más nos sorprendió es que, tanto en la PS3 como en el XOR o en el MAC ingenuo, el
algoritmo no era el problema: lo era cómo se usaba. La criptografía asimétrica resuelve
problemas que el simétrico no puede (distribución de claves, verificación pública, no
repudio), pero agrega requisitos sutiles, como el nonce único, que si se ignoran tiran abajo
todo. La lección práctica es usar construcciones que no dejen esas decisiones al
programador: HMAC en lugar de un hash con clave, Ed25519 o RFC 6979 en lugar de manejar el
nonce a mano.
