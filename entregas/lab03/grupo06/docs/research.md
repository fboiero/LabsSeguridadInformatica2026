# Mini-research — Laboratorio 03

**Tema elegido:** B — TOTP vs FIDO2/WebAuthn: por qué las passkeys ofrecen mayor resistencia al phishing que TOTP.

- [ ] **A.** PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".
- [x] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] **C.** Autenticación vs autorización; modelos RBAC y ABAC.
- [ ] **D.** Ataques de timing reales y cómo se mitigan.

## Desarrollo

### TOTP como segundo factor

TOTP (_Time-Based One-Time Password_) es un mecanismo que genera contraseñas de
un solo uso a partir de un secreto compartido y del tiempo. RFC 6238 lo define
como una variante de HOTP en la que el contador se deriva del tiempo actual y
del tamaño del intervalo; el valor predeterminado recomendado para ese intervalo
es 30 segundos [1, §§4–5].

Cuando se utiliza junto con una contraseña, TOTP agrega un segundo factor: aunque
una persona atacante conozca la contraseña, necesita también generar o capturar
un código válido. Por ello puede reducir el impacto de credential stuffing,
siempre que el atacante no posea el secreto TOTP ni el dispositivo autenticador.

Sin embargo, TOTP no es resistente al phishing en tiempo real. El usuario debe
ingresar manualmente el código y ese valor no queda vinculado criptográficamente
al sitio ni a la sesión que lo solicita. Un sitio falso puede pedir el código y
reenviarlo inmediatamente al servicio legítimo antes de que expire. NIST indica
que los autenticadores con ingreso manual de una salida, incluidos OTP, no se
consideran resistentes al phishing [2, §3.2.5].

### FIDO2 y WebAuthn

FIDO2 combina WebAuthn, la API web estandarizada por W3C, y CTAP, el protocolo
que permite la comunicación entre clientes y autenticadores. WebAuthn permite
registrar y usar credenciales de clave pública para autenticar usuarios en
aplicaciones web [3].

Durante el registro, el autenticador crea un par de claves para el servicio. La
clave privada permanece en el autenticador y la clave pública se entrega al
servidor. Durante la autenticación, el servidor envía un desafío y el
autenticador produce una respuesta firmada; el servidor la verifica con la clave
pública registrada [3, §§1 y 5].

La credencial está vinculada al _Relying Party_ y a su origen. Por ello, una
credencial registrada para un dominio no debe poder utilizarse en otro dominio.
La validación correcta del origen por parte del servidor es parte esencial de
esa protección [3, §13.4.9].

Las passkeys son credenciales FIDO basadas en pares de claves. Pueden estar
vinculadas a un dispositivo o sincronizarse entre dispositivos del usuario,
según la implementación. No transmiten la clave privada al servidor y están
diseñadas para autenticar frente al servicio al que se encuentran vinculadas
[4].

### Por qué las passkeys ofrecen ventajas frente a TOTP

La principal diferencia es la resistencia al phishing. TOTP requiere introducir
un código temporal que puede ser solicitado por un sitio fraudulento y reutilizado
por una persona atacante dentro de su período de validez. En cambio, WebAuthn
utiliza una respuesta criptográfica asociada al desafío y al servicio
correspondiente.

Las passkeys también pueden reemplazar el uso de una contraseña como factor
principal. Esto elimina el riesgo específico de reuso de contraseñas entre
servicios, que es la condición necesaria para credential stuffing. FIDO Alliance
describe las passkeys como credenciales de clave pública, únicas por servicio y
diseñadas para resistir phishing [4].

Esto no significa que las passkeys eliminen todos los riesgos: la recuperación
de cuentas, el compromiso del dispositivo, una implementación incorrecta de la
validación de origen o ingeniería social siguen siendo aspectos relevantes. Su
ventaja principal frente a TOTP es que evitan depender de un código que el
usuario pueda entregar a un sitio falso.

## Fuentes (mín. 3)

1. M'Raihi, D.; Machani, S.; Pei, M.; Rydell, J. (2011). _TOTP: Time-Based
   One-Time Password Algorithm_. RFC 6238. DOI: 10.17487/RFC6238.
   https://www.rfc-editor.org/rfc/rfc6238.html

2. National Institute of Standards and Technology. (2025). _Digital Identity
   Guidelines: Authentication and Authenticator Management_. NIST SP 800-63B-4,
   sección 3.2.5.
   https://pages.nist.gov/800-63-4/sp800-63b.html

3. W3C Web Authentication Working Group. (2026). _Web Authentication: An API
   for Accessing Public Key Credentials — Level 3_. W3C Recommendation,
   25 de agosto de 2026.
   https://www.w3.org/TR/webauthn-3/

4. FIDO Alliance. (s.f.). _FIDO User Authentication Specifications_.
   https://fidoalliance.org/specifications/

## Reflexión

TOTP representa una mejora importante frente a usar únicamente una contraseña,
pero su ingreso manual permite ataques de phishing en tiempo real. Las passkeys
reducen ese riesgo mediante credenciales de clave pública vinculadas al servicio.
La elección de un método de autenticación debe considerar tanto la resistencia
técnica como la recuperación de cuentas y la experiencia del usuario.
