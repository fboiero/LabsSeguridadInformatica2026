# Informe — Laboratorio 03 · Autenticación

**Grupo:** 06 · **Integrantes:**

| Nombre y apellido  | Legajo | Usuario de GitHub |
| ------------------ | ------ | ----------------- |
| Martín Beccereca   | 15154  | @martinbeccereca  |
| María Belén Benito | 14625  | @belubenito603    |
| Alejo De Miguel    | 15138  | @AlejoDM          |
| Tomás Giudici      | 14977  | @TomasGiudici     |
| Carolina Suppo     | 15057  | @carosuppo        |

**Fecha:** 16/10/2026

---

## 0. Declaración de uso de IA

- **Claude Code:** se utilizó como apoyo para estructurar el informe en Markdown,
  organizar el mini-research y revisar la rúbrica.

- **ChatGPT/Codex (OpenAI):** se utilizó para revisar el formato del informe,
  organizar la bibliografía, contrastar la correspondencia entre afirmaciones y
  fuentes, y mejorar la precisión técnica de la redacción.

Las herramientas de IA se utilizaron como asistencia. El grupo revisó el
contenido final, las fuentes citadas y las pruebas declaradas en la bitácora.

---

## 1. Parte A — Análisis de la brecha: Credential stuffing

**Caso asignado:** Credential stuffing — grupo 06, ya que `6 mod 4 = 2`.

### Qué se explota

El _credential stuffing_ no rompe un algoritmo criptográfico ni requiere una
vulnerabilidad en el sistema objetivo. Consiste en automatizar intentos de inicio
de sesión con pares de usuario y contraseña obtenidos en filtraciones previas de
otros servicios. Su éxito depende de que una parte de los usuarios reutilice la
misma contraseña en más de un sitio [1].

No debe confundirse con la fuerza bruta, que prueba muchas contraseñas para una
cuenta, ni con el _password spraying_, que prueba pocas contraseñas frecuentes
contra muchas cuentas. En credential stuffing, las credenciales ya son reales:
el atacante intenta comprobar si continúan siendo válidas en otro servicio.

La efectividad del ataque aumenta cuando el servicio objetivo carece de
autenticación multifactor, límites eficaces de intentos y mecanismos para
detectar actividad automatizada [1].

### Cómo se explotó: el caso Zoom, abril de 2020

En abril de 2020, BleepingComputer informó que se ofrecían en foros más de
500.000 credenciales de Zoom. Según Cyble, se adquirieron aproximadamente
530.000 credenciales por USD 0,002 por cuenta. Los registros incluían dirección
de correo electrónico, contraseña, URL personal de reunión y Host Key [2].

La fuente indicó que las credenciales se obtenían mediante credential stuffing:
atacantes probaban en Zoom combinaciones de correo y contraseña expuestas en
brechas anteriores. Los inicios de sesión exitosos se recopilaban y luego se
ofrecían o vendían en foros [2].

El caso ilustra que un servicio puede ser afectado sin que se haya producido una
intrusión directa en sus servidores: el reuso de una contraseña filtrada en otro
sitio puede permitir el acceso a una cuenta válida.

### La forma correcta: mitigaciones

**Autenticación multifactor.** Si una persona atacante posee una contraseña
válida, un segundo factor agrega una condición adicional para iniciar sesión.
OWASP señala que MFA es una defensa importante frente a credential stuffing y
password spraying; cita un análisis de Microsoft según el cual podría haber
evitado el 99,9 % de los compromisos de cuentas [1]. Esta cifra es una
estimación citada por OWASP, no una garantía aplicable a cualquier sistema.

**Bloqueo de contraseñas comprometidas.** NIST SP 800-63B establece que, al
crear o cambiar una contraseña, el verificador debe compararla con una lista de
valores comunes, previsibles o comprometidos. Esa lista puede incluir
contraseñas presentes en filtraciones anteriores [3, §3.1.1.2].

**Límite de intentos.** NIST también requiere limitar los intentos consecutivos
fallidos de autenticación por cuenta; salvo que se especifique otra condición,
el máximo es 100 antes de deshabilitar el autenticador [3, §3.2.2]. OWASP suma
medidas complementarias como detección de bots, CAPTCHA y análisis de señales de
riesgo [1].

Estas defensas se complementan: MFA reduce el valor de una contraseña reutilizada;
las blocklists disminuyen la probabilidad de registrarla; y el rate limiting
reduce la capacidad de automatizar intentos masivos.

---

## 2. Parte B.1 — Contraseñas

### Por qué el salt debe ser único por usuario

El _salt_ es un valor no secreto y aleatorio que se combina con la contraseña
antes de aplicar la función de derivación. En esta implementación se genera con
`secrets.token_bytes(16)`, por lo que cada registro recibe un salt de 16 bytes.

Un salt único evita que dos personas con la misma contraseña produzcan el mismo
valor almacenado. Sin salt, o con un salt global fijo, una persona atacante que
obtenga la base de datos puede identificar inmediatamente qué usuarios comparten
contraseña. Con un salt independiente, debe trabajar contra cada registro por
separado.

Además, el salt impide reutilizar una única tabla precalculada para atacar todos
los registros de una base de datos. No evita un ataque dirigido contra un salt
concreto, pero obliga a recalcular los intentos para ese registro [4, §§5.1–5.3].

### Por qué conviene un número alto de iteraciones

Las funciones hash generales, como SHA-256, están diseñadas para ser rápidas.
Esa propiedad es útil al verificar la integridad de archivos, pero no al
almacenar contraseñas: una vez filtrada la base, una persona atacante puede
probar candidatos fuera de línea.

PBKDF2 incorpora un número de iteraciones configurable. Cada intento de
contraseña debe repetir la función derivadora, por lo que una base filtrada
resulta más costosa de atacar que si se almacenara `sha256(password)`
directamente. El valor de 200.000 iteraciones usado en este laboratorio
representa un factor de trabajo; su impacto concreto debe medirse en el entorno
de despliegue [4, §5.2].

### Comparación en tiempo constante

En `verify_password()`, el hash calculado se compara con el valor almacenado
mediante `hmac.compare_digest()` y no mediante `==`. Python recomienda esa
función al comparar un digest recibido externamente porque está diseñada para
evitar el cortocircuito basado en el contenido y reducir el riesgo de ataques de
temporización [5].

No garantiza que toda comparación tarde exactamente lo mismo: diferencias de
tipo o longitud pueden revelar esos metadatos. Sin embargo, en este programa se
comparan dos valores de tipo `bytes` y de longitud esperada equivalente, por lo
que se evita una comparación que termine al encontrar el primer byte diferente.

---

## 3. Parte B.2 — TOTP

### Por qué TOTP frena el robo de una contraseña

TOTP genera códigos temporales a partir de un secreto compartido y del tiempo.
El algoritmo usa HOTP con el tiempo dividido en intervalos; RFC 6238 recomienda
un intervalo de 30 segundos como valor predeterminado [6, §§4–5].

Si un atacante obtiene una contraseña mediante credential stuffing, todavía debe
presentar un TOTP válido para completar una autenticación que requiera ambos
factores. Por eso, conocer solo la contraseña no es suficiente mientras el
atacante no posea también el secreto TOTP o el dispositivo autenticador.

El script del laboratorio demuestra la generación de un TOTP. Una implementación
completa de MFA también debe verificar el código en el servidor, proteger el
secreto compartido y aplicar límites a los intentos fallidos.

### Qué no protege TOTP

TOTP no es resistente al phishing en tiempo real. Una persona atacante puede
crear un sitio falso, solicitar el código a la víctima y reenviarlo al servicio
legítimo antes de que venza. NIST indica que los autenticadores que requieren
ingresar manualmente una salida, incluidos OTP, no se consideran resistentes al
phishing porque la salida no queda vinculada a la sesión específica [3, §3.2.5].

TOTP tampoco protege si se compromete el secreto compartido o el dispositivo que
lo contiene. Además, no protege frente al robo de una sesión ya autenticada.

---

## 4. Bitácora de pruebas

Para verificar el funcionamiento de las implementaciones correspondientes a B.1
y B.2 se ejecutaron pruebas desde la terminal.

### Prueba de generación de hash PBKDF2

```bash
python src/auth.py hash --password 'Phantom-2026!'
```

Resultado:

```text
pbkdf2_sha256$200000$3e30ebaf1b76edf4184af14b3c425feb$74135466481bdc6dc8e5007c65ce53f08198761f6e6ce45d0102160b5ec1dc8a
```

El resultado confirma que la contraseña se almacena utilizando PBKDF2 con SHA-256, 200.000 iteraciones y un salt aleatorio.

### Prueba de verificación de contraseña

```bash
python src/auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$3e30ebaf1b76edf4184af14b3c425feb$74135466481bdc6dc8e5007c65ce53f08198761f6e6ce45d0102160b5ec1dc8a'
```

Resultado:

```text
OK
```

También se realizó una prueba utilizando una contraseña incorrecta para comprobar que el registro no sea validado:

```powershell
$registro = python src/auth.py hash --password "Phantom-2026!"
python src/auth.py verify --password "ContraseñaIncorrecta" --registro $registro
```

Resultado:

```text
FALLO
```

De esta manera se comprobó que `verify_password()` acepta la contraseña correcta y rechaza una contraseña que no corresponde al registro almacenado.

### Prueba de TOTP

Se utilizó el vector de prueba indicado para RFC 6238:

```bash
python src/auth.py totp --secret 12345678901234567890 --t 59
```

Resultado:

```text
287082
```

El resultado coincide con el código de seis dígitos del vector oficial de RFC 6238. El valor de ocho dígitos correspondiente es 94287082 [6, apéndice B].

## 5. Fuentes consultadas

1. OWASP Foundation. “Credential Stuffing Prevention Cheat Sheet”, sección
   “Multi-Factor Authentication”. Consultado el 16/10/2026.
   https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html

2. Abrams, Lawrence. “Over 500,000 Zoom Accounts Sold on Hacker Forums, the
   Dark Web.” BleepingComputer, 13 de abril de 2020.
   https://www.bleepingcomputer.com/news/security/over-500-000-zoom-accounts-sold-on-hacker-forums-the-dark-web/

3. National Institute of Standards and Technology. Digital Identity
   Guidelines: Authentication and Authenticator Management. NIST SP 800-63B-4,
   2025, §§3.1.1.2, 3.2.2 y 3.2.5.
   https://pages.nist.gov/800-63-4/sp800-63b.html

4. Turan, M. S., Barker, E., Burr, W. y Chen, L. Recommendation for
   Password-Based Key Derivation: Part 1: Storage Applications. NIST SP
   800-132, diciembre de 2010, §§5.1–5.3.
   https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf

5. Python Software Foundation. “hmac — Keyed-Hashing for Message
   Authentication”, apartado hmac.compare_digest.
   https://docs.python.org/3/library/hmac.html

6. M'Raihi, D.; Machani, S.; Pei, M.; Rydell, J. “TOTP: Time-Based One-Time
   Password Algorithm.” RFC 6238, mayo de 2011. DOI: 10.17487/RFC6238.
   https://www.rfc-editor.org/rfc/rfc6238.html
