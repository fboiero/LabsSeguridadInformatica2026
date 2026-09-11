# Mini-research — Laboratorio 03

**Tema elegido:** _(uno)_

- [ ] **A.** PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".
- [x] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] **C.** Autenticación vs autorización; modelos RBAC y ABAC.
- [ ] **D.** Ataques de timing reales y cómo se mitigan.

## Desarrollo

### TOTP como segundo factor

TOTP (Time-Based One-Time Password) está definido en RFC 6238 y permite generar códigos de un solo uso a partir de un secreto compartido y del tiempo actual. En una implementación como la desarrollada en este laboratorio, el usuario introduce manualmente el código generado por su aplicación autenticadora.

Incorporar TOTP mejora la seguridad frente a una autenticación basada únicamente en contraseña. Por ejemplo, si un atacante obtiene una contraseña mediante credential stuffing, todavía necesita el segundo factor para completar el inicio de sesión.

Sin embargo, TOTP presenta una limitación frente al phishing: el código debe ser introducido por el usuario y no está vinculado criptográficamente al sitio al que se está autenticando. Un atacante puede solicitar el código desde una página falsa y utilizarlo inmediatamente contra el sitio legítimo, mientras todavía sea válido. Por este motivo, NIST no considera a los OTP introducidos manualmente como mecanismos resistentes al phishing.

En consecuencia, TOTP es eficaz para mitigar el credential stuffing, pero no proporciona protección completa frente al phishing.

### FIDO2 y WebAuthn

FIDO2 es un conjunto de estándares de autenticación basado en criptografía de clave pública. Incluye WebAuthn, que permite a sitios web utilizar credenciales de clave pública, y CTAP, que permite la comunicación entre navegadores o sistemas operativos y determinados autenticadores.

A diferencia de TOTP, FIDO2/WebAuthn no depende de un secreto que deba ser compartido con el servidor ni de un código que el usuario tenga que introducir. Durante el registro se genera un par de claves criptográficas: una clave pública y una clave privada. La clave privada permanece protegida por el autenticador, mientras que el servidor almacena la clave pública.

Durante la autenticación, el servidor genera un desafío (challenge) y el autenticador utiliza la clave privada para generar una respuesta criptográfica. El servidor verifica esa respuesta mediante la clave pública registrada. De esta manera, se demuestra la posesión de la clave privada sin transmitirla al servidor.

Una característica fundamental de WebAuthn es la vinculación de la credencial con el servicio para el que fue registrada, conocido como Relying Party. El origen del sitio forma parte de los datos considerados durante la autenticación, lo que permite detectar que una solicitud proviene de un sitio diferente al registrado.

Las passkeys utilizan esta tecnología para ofrecer una forma de autenticación basada en claves criptográficas, evitando que el usuario tenga que recordar contraseñas o introducir códigos OTP.

### Por qué las passkeys superan al TOTP

La principal diferencia entre ambos mecanismos está en su resistencia al phishing. TOTP requiere que el usuario introduzca un código temporal que puede ser capturado y utilizado por un atacante antes de que expire.

Las passkeys, en cambio, utilizan las credenciales de clave pública de FIDO2/WebAuthn y vinculan la autenticación con el servicio correspondiente. La autenticación se realiza mediante una respuesta criptográfica al desafío generado por el servidor, sin revelar la clave privada ni introducir un código que pueda ser interceptado.

Por esta razón, las passkeys ofrecen una ventaja importante frente a TOTP: son resistentes al phishing. TOTP continúa siendo un segundo factor eficaz para mitigar ataques como el credential stuffing, pero las passkeys proporcionan una protección adicional frente a la captura y reutilización de credenciales mediante sitios fraudulentos.

## Fuentes (mín. 3)

1. M'Raihi, D. et al. (2011). _RFC 6238 — TOTP: Time-Based One-Time Password Algorithm_. IETF / RFC Editor.  
   https://www.rfc-editor.org/rfc/rfc6238.html

2. W3C Web Authentication Working Group (2026). _Web Authentication: An API for accessing Public Key Credentials — Level 3_. W3C.  
   https://www.w3.org/TR/webauthn-3/

3. FIDO Alliance. _FIDO User Authentication Specifications_.  
   https://fidoalliance.org/specifications/

4. FIDO Alliance. _Passkeys — Passwordless Authentication_.  
   https://fidoalliance.org/passkeys/

## Reflexión

La comparación muestra que la seguridad de un método de autenticación depende también de las amenazas que busca enfrentar. TOTP representa una mejora frente a la autenticación basada únicamente en contraseñas, mientras que las passkeys incorporan mecanismos que dificultan ataques de phishing. Por eso, la elección del método debe considerar no solo su facilidad de implementación, sino también el nivel de protección que ofrece.
