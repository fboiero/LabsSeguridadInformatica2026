# Mini-research — Laboratorio 03

**Tema elegido:**
- [ ] A. PBKDF2 vs bcrypt vs scrypt vs Argon2
- [x] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] C. Autenticación vs autorización; modelos RBAC y ABAC
- [ ] D. Ataques de timing reales y cómo se mitigan

## Desarrollo

### 1. Qué hace TOTP y dónde está su límite
En el laboratorio implementamos `totp()` (RFC 6238): el servidor y la app del usuario comparten un secreto y derivan el mismo código de 6 dígitos a partir del tiempo, en pasos de 30 segundos [1]. Es un segundo factor "algo que tenés" y frena el uso de una contraseña robada. Pero el código es solo un número que el usuario tipea: no sabe en qué sitio lo está escribiendo. Si un sitio de phishing (por ejemplo con un proxy tipo Evilginx) le pide contraseña y código y los reenvía al sitio real en el momento, el atacante entra dentro de la ventana de 30 segundos [2]. Además, el secreto compartido existe en dos lugares (servidor y dispositivo), así que una filtración del lado del servidor o de un backup lo expone.

### 2. Cómo funciona FIDO2/WebAuthn
WebAuthn es la API del navegador y CTAP2 es el protocolo con el que el navegador habla con el autenticador (una llave física o el propio dispositivo) [3]. En lugar de un secreto compartido, se usa criptografía de clave pública: al registrarse, el autenticador genera un par de claves, entrega la pública al servidor y guarda la privada, que nunca sale del dispositivo. Para entrar, el servidor envía un desafío (nonce) y el autenticador lo firma con la clave privada [3].

### 3. Por qué supera al TOTP: origin binding
La clave que crea el autenticador queda asociada al dominio (RP ID) del sitio donde se registró. Si el usuario intenta autenticarse en un sitio falso, por ejemplo con una letra cambiada en el dominio, el navegador informa el dominio real y el autenticador no tiene ninguna credencial para ese dominio, así que no
firma [2][4]. El usuario no puede ser "engañado para tipear" nada, porque no hay nada que tipear. Lo mismo vale para el reenvío en tiempo real: la firma corresponde al origen verificado, no sirve contra el sitio legítimo [3].

Por eso la agencia de ciberseguridad de EE.UU. (CISA) describe FIDO/WebAuthn como la única forma de MFA resistente al phishing ampliamente disponible, y advierte que el MFA basado en apps, SMS o voz es más vulnerable a estos ataques
[5][6].

### 4. Passkeys
Las passkeys son credenciales FIDO descubribles que además pueden sincronizarse entre dispositivos del mismo ecosistema (iCloud Keychain, Google Password Manager), lo que mejora la usabilidad frente a una llave física única [7].

### 5. Matices y límites
- **No es magia:** una fuente del sector plantea que las passkeys son
  "necesarias pero no suficientes": hay que sumar monitoreo, recuperación de
  cuentas y control de dispositivos [3].
- **Recuperación y sincronización:** una passkey sincronizada depende de la
  seguridad de la cuenta de nube; el proceso de recuperación puede volverse el
  eslabón débil.
- **Compatibilidad:** requiere soporte de navegador y sistema operativo, hoy
  amplio pero no universal [4].
- **TOTP sigue siendo útil:** cualquier MFA es mejor que ninguno [6]. Para
  23andMe (Parte A) incluso un TOTP habría cortado el credential stuffing; el
  salto a WebAuthn aporta además resistencia al phishing.
- **Las fuentes no coinciden del todo:** la documentación de Duende califica la
  resistencia al phishing de TOTP como "alta" y la de passkeys como
  "excelente" [4], mientras que otras fuentes tratan al TOTP como vulnerable
  [2][5]. Conviene decir que TOTP es resistente a robo de contraseña, pero no al
  reenvío en tiempo real.

### Tabla comparativa
| Aspecto | TOTP | FIDO2/WebAuthn (passkey) |
|---|---|---|
| Secreto | Compartido (servidor y app) | Clave privada que nunca sale del dispositivo |
| Atado al sitio | No | Sí (origin binding) |
| Phishing en tiempo real | Vulnerable | Resistente |
| Qué tipea el usuario | Un código de 6 dígitos | Nada (gesto/biometría/PIN local) |
| Soporte | Universal, sin hardware | Requiere navegador/SO compatible |

## Fuentes (mín. 3)
[1] IETF — RFC 6238, *TOTP: Time-Based One-Time Password Algorithm*.
    https://datatracker.ietf.org/doc/html/rfc6238
[2] Token2 — *Why FIDO2 is More Secure Than TOTP: Understanding Phishing Protection*.
    https://www.token2.com/pages/why-fido2-is-more-secure-than-totp-understanding-phishing-protection
[3] Petronella Technology Group — *From Passwords to Passkeys: Phishing-Resistant MFA with FIDO2/WebAuthn*.
    https://petronellatech.com/blog/from-passwords-to-passkeys-fido2-webauthn-mfa-for-the-zero-trust-saas/
[4] Duende Software — *Passkey Authentication* (documentación).
    https://docs.duendesoftware.com/identityserver/usermanagement/authentication/passkeys/
[5] CISA — *Implementing Phishing-Resistant MFA* (fact sheet).
    https://cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf
[6] Bricker Graydon — *CISA Discourages Use of App-Based, SMS and Voice MFAs...*
    https://www.bricker.com/hitech-law/cisa-guidance-discourages-use-of-app-based-sms-and-voice-mfas-and-encourages-phishing-resistant-mfas
[7] Enterno — *Passkeys vs 2FA: The Future of Authentication*.
    https://enterno.io/en/articles/passkeys-vs-2fa

## Reflexión

Al implementar `totp()` nos dimos cuenta de lo simple que es el mecanismo: un secreto compartido, el tiempo dividido en pasos de 30 segundos y un HMAC. Esa simpleza es su ventaja (funciona en cualquier teléfono, sin hardware ni soporte especial del navegador), pero investigando WebAuthn entendimos que también es su límite: el código es solo un número, y un número no sabe en qué sitio se está escribiendo. En la sección B.2 del informe ya habíamos señalado que el TOTP no protege contra phishing en tiempo real; este research nos mostró que no es un detalle menor, sino la diferencia de diseño con FIDO2. Con WebAuthn la autenticación está atada criptográficamente al dominio, de modo que el usuario ya no tiene que "darse cuenta" de que el sitio es falso: el autenticador directamente no responde.

También cambió nuestra mirada sobre el caso 23andMe. Para ese ataque (credential stuffing) un TOTP obligatorio hubiera sido suficiente, porque el atacante tenía contraseñas filtradas pero no el segundo factor. Es decir, la mejor opción técnica no siempre es la necesaria para cada amenaza: el problema de 23andMe no fue elegir un 2FA débil, sino no exigir ninguno. Pasar a passkeys agregaría resistencia al phishing, pero a cambio de más fricción de adopción y de depender de la compatibilidad de navegadores y dispositivos.

Otra conclusión es que las passkeys no eliminan el problema, lo desplazan. Si una passkey se sincroniza a través de una cuenta en la nube, la seguridad de esa cuenta y el proceso de recuperación pasan a ser el punto débil. Esto nos recordó algo que ya vimos en el laboratorio: la autenticación suele fallar por la implementación y los procesos que la rodean, no por la teoría.

Si tuviéramos que decidir para un sistema real, usaríamos passkeys o llaves de seguridad como método principal para cuentas sensibles y mantendríamos el TOTP como alternativa, entendiendo sus límites, en lugar de quedarnos solo con contraseña. Cualquier segundo factor es mejor que ninguno, pero no todos protegen contra los mismos ataques.