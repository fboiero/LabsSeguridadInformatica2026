# Mini-research — Laboratorio 03

**Tema elegido:**
- [ ] **A.** PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".
- [x] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] **C.** Autenticación vs autorización; modelos RBAC y ABAC.
- [ ] **D.** Ataques de timing reales y cómo se mitigan.

## Desarrollo

### Dos formas distintas de demostrar que somos quienes decimos ser

TOTP y WebAuthn resuelven una parte parecida del problema —probar que quien inicia sesión controla un autenticador—, pero usan mecanismos diferentes. TOTP genera códigos numéricos breves a partir de un secreto compartido y la hora. WebAuthn usa criptografía de clave pública: el autenticador conserva una clave privada y el sitio conserva la clave pública asociada. Las passkeys son credenciales de ese ecosistema pensadas para que el usuario no tenga que memorizar ni copiar un código. Por eso, compararlas no es solo preguntar cuál genera un código más seguro: también importa cómo se verifica el sitio y qué datos debe guardar el servidor.

### TOTP: un código válido que se puede retransmitir

En TOTP, el dispositivo del usuario y el servidor conocen el mismo secreto. Ambos calculan un valor de un solo uso aplicando HOTP a un contador derivado del tiempo actual y de un intervalo acordado. Por ejemplo, con un paso de 30 segundos, el código cambia según la ventana temporal. El servidor debe guardar o poder recuperar el secreto de cada autenticador para calcular el valor esperado, además de permitir una tolerancia pequeña frente a diferencias de reloj [1].

El código es de corta duración, pero quien lo ingresa lo presenta como texto. Un sitio falso puede pedir la contraseña y el TOTP, y un atacante que actúe como intermediario puede reenviar ambos datos al sitio legítimo antes de que venza el intervalo. El segundo factor reduce el riesgo de que una contraseña robada baste por sí sola, pero el código no está vinculado criptográficamente al dominio ni a esa sesión específica. NIST por eso no considera resistentes al phishing los autenticadores cuyo resultado se escribe manualmente: un verificador impostor puede retransmitir la salida al verificador real [3].

### WebAuthn y el vínculo con el sitio

En el registro WebAuthn, el autenticador crea un par de claves asociado a un identificador de la parte confiante (RP ID). La clave privada queda bajo control del autenticador; el servicio recibe y guarda la clave pública y el identificador de la credencial. En cada autenticación, el servidor entrega un desafío nuevo. El autenticador produce una firma sobre los datos de la ceremonia, que incluyen el desafío y el origen desde donde se inició. El servidor verifica la firma y que el desafío y el origen correspondan a lo esperado [2].

Ese vínculo con el RP ID/origen cambia la experiencia ante el phishing. Una passkey registrada para `banco.example` no debería firmar una autenticación para `banco-ejemplo.invalid`; el navegador y el autenticador limitan la credencial al sitio registrado. Aunque la persona esté en una página impostora, no tiene que leer un código para copiarlo al atacante. NIST describe WebAuthn como un ejemplo de autenticación resistente al phishing mediante *verifier name binding*: la salida se vincula criptográficamente al identificador autenticado del verificador [3]. La protección depende de que el servicio valide correctamente origen, desafío y RP ID; aceptar orígenes inesperados debilitaría esa barrera [2].

### Qué cambia para el servidor

Con TOTP hay un secreto simétrico compartido: si el servidor lo expone, un atacante puede generar códigos futuros para esa cuenta. Ese secreto debe protegerse como una credencial de alto valor. Con WebAuthn, el servidor mantiene la clave pública necesaria para verificar firmas, no la clave privada que las produce. Una filtración de la base de claves públicas no permite por sí sola firmar una autenticación válida. Esto no vuelve invulnerable al sistema: siguen importando la seguridad de la cuenta, la validación criptográfica, el control de sesiones y la protección del dispositivo y del proceso de recuperación.

### Postura y límites

Para una cuenta que permita ambas opciones, recomendaría una passkey como método principal y conservaría un mecanismo de recuperación cuidadosamente protegido. La ventaja más clara frente al TOTP es que dificulta el robo de autenticación mediante páginas impostoras, porque no hay un código manual reutilizable dentro de su ventana ni una contraseña que el usuario deba entregar al mismo formulario. También reduce el riesgo de que una base de datos robada contenga un secreto simétrico que permita generar códigos.

Sin embargo, “resistente al phishing” no equivale a “sin riesgos”. Una passkey sincronizada puede depender de la cuenta y del servicio de sincronización del ecosistema elegido; una recuperación débil de esa cuenta podría convertirse en el camino alternativo del atacante. Si se pierde el acceso al dispositivo o al proveedor, recuperar la cuenta puede ser difícil, por lo que conviene registrar más de un autenticador o diseñar una recuperación con controles fuertes. Además, la sincronización facilita la disponibilidad, pero amplía qué cuentas y dispositivos deben protegerse: NIST exige proteger las claves sincronizables en el servicio de sincronización y el acceso a ese servicio [3].

La decisión práctica no debería ser “TOTP es inútil” ni “passkeys resuelven todo”. TOTP sigue siendo una mejora frente a usar solo una contraseña cuando no hay un autenticador resistente al phishing disponible, pero el usuario puede ser engañado para retransmitir el código. WebAuthn ofrece una barrera criptográfica más fuerte contra ese escenario; para aprovecharla, la organización debe proteger la recuperación, mantener la validación del origen y explicar a los usuarios cómo recuperar el acceso sin rebajar la seguridad.

## Fuentes (mín. 3)

1. [PRIMARIA] M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011, mayo). *TOTP: Time-Based One-Time Password Algorithm* (RFC 6238). RFC Editor. https://www.rfc-editor.org/rfc/rfc6238
2. [PRIMARIA] World Wide Web Consortium. (2026, 25 de agosto). *Web Authentication: An API for accessing Public Key Credentials, Level 3*. https://www.w3.org/TR/webauthn-3/
3. [PRIMARIA] Temoshok, D., Fenton, J., Choong, Y.-Y., Lefkovitz, N., Regenscheid, A., Galluzzo, R., & Richer, J. (2025, julio). *Digital Identity Guidelines: Authentication and Authenticator Management* (NIST SP 800-63B-4). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-63b-4

## Reflexión

La diferencia más importante que me queda es que TOTP protege contra el uso aislado de una contraseña, pero todavía confía en que la persona no entregue el código a un impostor. WebAuthn desplaza parte de esa decisión al navegador y al autenticador, que vinculan la respuesta al sitio registrado. Aun así, la recuperación y la cuenta que sincroniza las passkeys también forman parte de la seguridad: una buena autenticación necesita un camino de recuperación que no sea más débil que el acceso normal.
