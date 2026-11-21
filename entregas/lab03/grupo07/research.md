# Mini-research — Laboratorio 03

**Tema elegido:** B — TOTP vs FIDO2/WebAuthn.

- [ ] **A.** PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".
- [x] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] **C.** Autenticación vs autorización; modelos RBAC y ABAC.
- [ ] **D.** Ataques de timing reales y cómo se mitigan.

## Desarrollo

### TOTP: qué agrega y dónde termina su protección

TOTP calcula `HOTP(K, T)`, con un secreto compartido `K` y el contador
`T = floor((t - T0) / X)`. En el laboratorio usamos `T0 = 0` y `X = 30`
segundos. El autenticador y el servidor pueden calcular el mismo código sin
transmitir el secreto en cada acceso. Si el atacante obtiene solamente la
contraseña, todavía le falta ese secreto para generar los códigos. [1]

La limitación es que el código no identifica al sitio donde se introduce.
Una página falsa puede pedir contraseña y TOTP y retransmitirlos al servicio
real mientras el código siga vigente. NIST clasifica los OTP como susceptibles
al phishing: que el valor cambie no autentica al servidor frente al usuario. [4]

Además, el servidor debe proteger `K` y rechazar un segundo uso de un código
ya validado. La ventana de 30 segundos no garantiza por sí sola ese rechazo.
Nuestro `src/auth.py` genera TOTP, pero no implementa un servidor que registre
códigos consumidos o limite intentos. El vector `t=59` produce `287082` a seis
dígitos y `94287082` a ocho; valida el cálculo, no un flujo completo de login. [1]

### FIDO2, WebAuthn y passkeys

FIDO2 reúne WebAuthn, la API para autenticación web, y CTAP, el protocolo de
comunicación con autenticadores. Las passkeys son credenciales FIDO que permiten
iniciar sesión sin contraseña; pueden quedar vinculadas a un dispositivo o
sincronizarse entre dispositivos mediante un proveedor. El usuario autoriza su
uso con un PIN o biometría local; la información biométrica no se envía al sitio.
Por eso no corresponde afirmar que toda passkey vive exclusivamente en una
llave física ni que toda autenticación requiere una huella. [3]

En el registro se asocia una credencial de clave pública al servicio, llamado
*Relying Party* (RP). El servidor conserva la clave pública. Durante el acceso,
envía un desafío nuevo y el autenticador firma datos que vinculan la respuesta
al RP y a los datos del cliente, incluidos el desafío y el origen. El servidor
debe verificar la firma, el desafío esperado, el origen, el hash del RP ID y las
indicaciones de presencia y verificación del usuario que exija su política. [2]

En un dominio impostor, el navegador no permite solicitar libremente la
credencial del dominio legítimo. Esa vinculación permite resistir la
retransmisión que funciona con TOTP; comprobar solo que una firma sea válida
no alcanza si se omiten las demás verificaciones. [2]

### Comparación y límites

| Aspecto | Contraseña + TOTP | Passkey con WebAuthn |
|---|---|---|
| Material del servidor | Registro de contraseña y secreto TOTP compartido. [1] | Clave pública de la credencial. [2] |
| Phishing en tiempo real | El código puede retransmitirse. [4] | La credencial está vinculada al RP y al origen. [2] |
| Interacción | Escribir contraseña y código temporal. | Autorizar el uso con el mecanismo local disponible. [3] |
| Recuperación | Debe protegerse el alta de un nuevo autenticador. [4] | Deben protegerse la recuperación y la sincronización, si existe. [4] |

Resistir el phishing no elimina todos los riesgos. Un dispositivo comprometido
puede permitir usos indebidos del autenticador; además, una sesión ya robada
no vuelve segura por cambiar el mecanismo de inicio de sesión. NIST trata la
protección del dispositivo, las sesiones y la recuperación como problemas que
también deben atenderse. [4]

## Fuentes (mín. 3)

1. M'Raihi, D. et al. (2011). [RFC 6238 — TOTP: Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238).
   Secciones 4 y 5.2, y apéndice B: cálculo, prevención del segundo uso y vectores.
2. W3C (2021). [Web Authentication: An API for accessing Public Key Credentials — Level 2](https://www.w3.org/TR/webauthn-2/).
   Secciones 5.1.4, 6.1 y 7.2: alcance de las credenciales y verificaciones del servidor.
3. FIDO Alliance. [Passkeys](https://fidoalliance.org/passkeys/).
   Preguntas frecuentes: relación con FIDO2, claves sincronizadas o ligadas a un dispositivo y verificación local.
4. NIST (2025). [SP 800-63B-4 — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html).
   Secciones 3.1.4, 4, 5 y 6, y apéndice B: OTP, recuperación, sesiones, amenazas y autenticadores sincronizables.

## Reflexión

La comparación nos permite distinguir dos objetivos: agregar una prueba de
posesión y verificar para qué servicio se genera esa prueba. TOTP mejora el
escenario de una contraseña filtrada, pero sigue dependiendo de que el usuario
entregue el código al sitio correcto. WebAuthn incorpora esa vinculación al
protocolo. Como criterio de diseño derivado de lo investigado, elegiríamos
passkeys cuando el entorno las soporte, cuidando que la recuperación de cuenta
no permita eludirlas mediante un mecanismo más débil. El laboratorio también
muestra por qué un vector correcto es necesario pero insuficiente: comprueba
una función criptográfica, no todos los controles de una autenticación real.

**Uso de IA:** Fernando Cagliero (@Ferca19) utilizó OpenAI Codex para organizar
la investigación, contrastar fuentes y asistir en la redacción de este archivo.
La verificación realizada durante esta sesión incluyó la consulta de las cuatro
fuentes primarias, la lectura de `src/auth.py`, la autoevaluación de la cátedra
y los seis vectores SHA-1 del RFC 6238 a seis y ocho dígitos. No se implementó ni
se probó un servicio WebAuthn; su comparación es documental.
