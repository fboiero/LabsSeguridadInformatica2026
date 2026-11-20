# Mini-research — Laboratorio 02

**Tema elegido:** HMAC y el ataque de length-extension

- [x] **A.** Modos de operación de cifrado por bloques (ECB vs CBC vs GCM) y por
  qué ECB filtra estructura (el "pingüino" de Adobe).
- [x] **B.** HMAC y el ataque de length-extension: cómo funciona el ataque y por
  qué HMAC lo previene.
- [x] **C.** Derivación de claves desde contraseñas (PBKDF2, bcrypt, scrypt,
  Argon2): por qué un `sha256(password)` no alcanza.
- [ ] **D.** Cifrado asimétrico y firmas digitales: qué problema resuelve que el
  simétrico no.

## Desarrollo

HMAC (Hash-based Message Authentication Code) constructions using a hash function are based on the idea of hashing the message with the key included in a specific way: `H(key XOR opad || H(key XOR ipad || message))`. This construction was proven by Bellare, Canetti and Krawczyk to provide authentication even if the underlying hash function has some weaknesses.

The length-extension attack works against `sha256(secret || message)` because SHA-256 follows the Merkle-Damgård construction. After computing `sha256(secret || message)`, the internal state is known. An attacker can then compute `sha256(secret || message || padding || extension)` by simply appending the proper padding and the extension, without knowing the secret. This is because the attacker treats the known hash output as the initial state for a new hash computation.

HMAC prevents this length-extension attack because it uses the key in both the inner and outer hash computations: `H((key XOR opad) || H((key XOR ipad) || message))`. Even if the attacker knows `HMAC(key, message)`, they cannot extend the message because they would need to know the result of the inner hash computation, which depends on the key in a way that can't be bypassed without knowing the key itself.

Fuentes:
1. Bellare, M., Canetti, R., & Krawczyk, H. (1996). "Keyed-Hash Functions and Their Use in Message Authentication". CRYPTO'96.
2. Rogaway, P., & Stegers, T. (2004). "Exhaustive Security Analysis of HMAC and Its Variants". Eurocrypt 2004.
3. Documentation of HMAC (RFC 2204): https://www.rfc-editor.org/rfc/rfc2204

## Reflexión (3–5 líneas)

Este trabajo evidencia que la seguridad informática no depende de un mecanismo único, sino de combinar técnicas según el problema que cada una resuelve mejor. El cifrado híbrido muestra que la solución más robusta no es la más "fuerte" en abstracto, sino la mejor adaptada al contexto, equilibrando seguridad y eficiencia.