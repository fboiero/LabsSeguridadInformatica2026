# Informe — Laboratorio 03 · Autenticación

**Grupo:** 14 · **Integrantes:** Fede Peron (@fedeeperon), Laureano Gomez Redondo (@Laureano-GR), Martín Cesano (@martincesano), Martín Gaido (@martingaidoo), Valentina Chiapero (@valechiapero) — ver `INTEGRANTES.md`.
**Fecha:** 19/11/2026 · **Alcance:** solo código propio (`src/auth.py`) ejecutado en la máquina del grupo. Ley 26.388.

## 0. Declaración de uso de IA

- **Herramienta:** Claude Code (asistente de IA de Anthropic).
- **Para qué:** generación del código de `hash_password`, `verify_password` y `totp` en `src/auth.py`, y redacción de este informe y de `research.md`.
- **Qué partes:** todo `src/auth.py` (salvo `hotp()`, que venía en el esqueleto), `informe.md` y `research.md`. Los datos de `INTEGRANTES.md` son reales y se copiaron de la entrega del lab04.
- **Cómo se verificó:** se corrió `src/verificar.py` (3/3 OK), el vector oficial RFC 6238 (`t=59` → `287082`) y los comandos de la bitácora (sección 4). Las fuentes citadas **no fueron abiertas en esta sesión**: se citan de memoria y el grupo debe contrastarlas antes de entregar. Las explicaciones deben ser revisadas y entendidas por los integrantes; la IA no reemplaza esa revisión.

## 1. Parte A — Credential stuffing (grupo 14 mod 4 = 2)

**Qué se guardó/comparó mal.** El problema no es del sitio atacado sino del usuario y del ecosistema: la gente **reutiliza la misma contraseña en varios sitios**. Cuando un sitio A sufre una filtración (contraseñas en claro, o con hashes rápidos/sin salt que luego se crackean, como en LinkedIn 2012 o RockYou 2009), el par `usuario:contraseña` queda circulando. El sitio B, que puede estar perfectamente bien implementado, acepta ese par porque *es* correcto: la credencial es válida, solo que ya no es secreta.

**Cómo se explota.** El atacante toma listas de credenciales filtradas y las prueba de forma automatizada contra el login de otros servicios (bancos, correo, tiendas, streaming), con herramientas de scripting y redes de IPs rotativas para esquivar límites por IP. La tasa de éxito por intento es baja, pero con millones de intentos alcanza para tomar muchas cuentas. No requiere romper ningún hash en el sitio víctima ni explotar una vulnerabilidad: es abuso de credenciales legítimas.

**Lo correcto.**
- **Segundo factor (TOTP, o mejor FIDO2/WebAuthn):** la contraseña robada sola ya no alcanza (ver sección 3). Es la mitigación más efectiva.
- **Gestor de contraseñas y contraseñas únicas por sitio:** corta el reuso en origen.
- **Rechazar contraseñas conocidas como filtradas** al registrarse o cambiarlas (NIST SP 800-63B pide contrastar contra listas de contraseñas comprometidas) y no imponer reglas de composición arbitrarias.
- **Rate limiting y detección de automatización** (por cuenta y no solo por IP, bloqueo progresivo, CAPTCHA/chequeos de riesgo), y alertar al usuario ante logins desde dispositivos nuevos.
- **Del lado de quien almacena:** hash lento con salt (B.1), para que una filtración propia no alimente el stuffing de otros.

**Fuentes** (no abiertas en esta sesión; ver aviso en `research.md`):
- OWASP, *Credential Stuffing Prevention Cheat Sheet*.
- NIST SP 800-63B, *Digital Identity Guidelines: Authentication and Lifecycle Management*, sección sobre verificadores de secretos memorizados.
- OWASP, *Authentication Cheat Sheet*.

## 2. Parte B.1 — Contraseñas

**Qué hace el código** (`hash_password` / `verify_password` en `src/auth.py`):
- `hash_password` genera un salt de 16 bytes con `secrets.token_bytes(16)` (si no se pasa uno), calcula `hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)` con `iters=200_000` por defecto, y devuelve `pbkdf2_sha256$iters$salt_hex$dk_hex`. El registro guarda algoritmo, iteraciones y salt junto al hash, así se puede verificar sin estado extra y subir las iteraciones en el futuro.
- `verify_password` separa el registro por `$`, rechaza si el algoritmo no es `pbkdf2_sha256`, recalcula el PBKDF2 con el salt e iteraciones **del registro** y compara con `hmac.compare_digest`. Un registro mal formado (cantidad de campos distinta, hex inválido, iteraciones no numéricas) lanza `ValueError` y se devuelve `False` en vez de romper.

**¿Por qué salt por usuario?** Sin salt, `hash(clave)` es una función fija: dos usuarios con la misma contraseña tienen el mismo hash, así que quien lee la base ve de inmediato quiénes comparten clave y un solo cálculo (o una *rainbow table* precomputada) sirve para todos. Con un salt aleatorio único, cada registro obliga a un cálculo propio: el atacante no puede reutilizar trabajo entre cuentas ni usar tablas precalculadas, y debe atacar usuario por usuario. El salt **no es secreto**; su función es la unicidad. Evidencia real: la misma contraseña `hola` hasheada dos veces dio registros distintos (bitácora, sección 4), y `verificar.py` lo chequea ("salt por usuario").

**¿Por qué muchas iteraciones?** Un hash común (SHA-256 pelado) está pensado para ser rápido, y una GPU calcula miles de millones por segundo, por lo que si se filtra la base las contraseñas débiles caen casi al instante. PBKDF2 repite HMAC `iters` veces: para el usuario legítimo son unos pocos cientos de milisegundos por login (medimos ~0,14 s con 200.000 iteraciones contra ~0,00008 s con 1), pero para el atacante multiplica por 200.000 el costo de **cada** candidato. Es una carrera de costos: hay que ajustar las iteraciones al hardware disponible y subirlas con el tiempo. Limitación honesta: PBKDF2 solo gasta CPU, no memoria, así que las GPU/ASIC lo aceleran bien; bcrypt, scrypt y Argon2 resisten mejor (ver `research.md`). Además, OWASP recomienda hoy para PBKDF2-HMAC-SHA256 una cantidad de iteraciones bastante mayor a 200.000 (del orden de 600.000, de memoria, a verificar); el valor 200.000 es el del esqueleto de la consigna y se mantiene, pero en producción habría que subirlo.

**¿Por qué `hmac.compare_digest`?** Un `==` entre cadenas corta en el primer byte distinto; el tiempo de respuesta depende de cuántos bytes iniciales coinciden, y eso puede filtrar información (ataque de timing). `compare_digest` tarda lo mismo sin importar dónde difieran. Con PBKDF2 el riesgo práctico es menor (el atacante no controla el hash comparado, que sale de un cómputo con salt), pero es la práctica correcta y la rúbrica la exige. Nota: el código compara las representaciones hex (`dk.hex()` contra `dk_hex`) en vez de los bytes; es equivalente a efectos de tiempo constante, aunque un `dk_hex` en mayúsculas en el registro no coincidiría.

## 3. Parte B.2 — TOTP

**Qué hace el código.** `totp(secret, t, paso=30, digitos=6)` toma el tiempo `t` (o `time.time()` si es `None`), calcula el contador `int(t) // paso` y llama a `hotp()` (RFC 4226: HMAC-SHA1 del contador de 8 bytes big-endian, truncamiento dinámico con el offset del último nibble, módulo `10**digitos`). Resultado verificado: con el secreto ASCII `12345678901234567890` y `t=59` da `287082` (y `94287082` con 8 dígitos), igual al vector oficial del RFC 6238.

**¿Por qué frena al que robó la contraseña?** Porque la contraseña es "algo que sabés" y se puede copiar, filtrar o adivinar; el TOTP agrega "algo que tenés": el secreto compartido guardado en el celular (o app autenticadora), del cual sale un código que cambia cada 30 s. Un atacante con solo `usuario:contraseña` (credential stuffing, phishing de clave, filtración) no puede generar el código vigente. Además el código caduca, así que uno espiado o filtrado sirve poco tiempo.

**Ventana y deriva del reloj.** El código depende del tiempo: cliente y servidor deben coincidir en el paso actual. Con relojes desfasados, el servidor suele aceptar también el paso anterior y el siguiente (±1 paso, ±30 s). Se comprobó que `t=29` da `755224` (contador 0) y `t=30` y `t=59` dan `287082` (contador 1): el código cambia exactamente en el límite del paso. Un `verify_totp` real debería probar `totp(secret, t + k*30)` para `k` en `{-1, 0, 1}` comparando con `compare_digest`, y limitar los intentos. Ampliar la ventana tolera más deriva pero aumenta la chance de que un código adivinado o interceptado sirva. Además, un mismo código no debería aceptarse dos veces dentro de su ventana (anti-replay). Esas medidas **no** están implementadas en `auth.py`: la consigna solo pide generar el código.

**Qué NO protege el TOTP.**
- **Phishing en tiempo real (proxy/AiTM):** el atacante hace pasar por el sitio falso el código que el usuario tipea y lo reenvía al sitio real dentro de los 30 s. Por eso FIDO2/WebAuthn, atado al origen, es más fuerte.
- **Robo del secreto** (base del servidor comprometida, QR de alta fotografiado, malware en el teléfono): con el secreto se generan códigos para siempre. El servidor debe protegerlo.
- **Malware o sesión robada:** si el atacante toma la sesión ya autenticada (cookie), el segundo factor ya pasó.
- **Fuerza bruta online sin límite de intentos:** 6 dígitos son 10^6 combinaciones; sin rate limiting no alcanza.
- **Recuperación de cuenta débil** o ingeniería social al soporte que se salta el 2FA.
- No protege el almacenamiento de la contraseña ni el control de acceso: son capas distintas.

**Control de acceso en el servidor.** La autenticación dice quién sos; la autorización, qué podés hacer. Se verifica siempre **en el servidor** porque todo lo que viene del cliente (campos ocultos, rol en una cookie sin firmar, botones deshabilitados en la interfaz) lo controla el atacante y puede modificarlo; el cliente solo mejora la experiencia, nunca puede ser la barrera.

## 4. Bitácora de comandos

Todos corridos con `PYTHONUTF8=1` desde `entregas/lab03/grupo14/` (Python 3.13, solo stdlib). Las salidas son las reales de esta sesión (registros abreviados con `...` donde se indica).

```
$ python src/verificar.py
== Lab 03 · Autenticación ==
  ✓ hash_password / verify_password
  ✓ salt por usuario (hashes distintos)
  ✓ totp coincide con el vector del RFC 6238

3 OK · 0 a revisar · 0 sin implementar

$ python src/auth.py hash --password 'Phantom-2026!'
pbkdf2_sha256$200000$d7bb1cf4a609f8f9098f0f7a7a1c2fbc$1cf3087b4956a42645e19142b51c1003b6729bcd3a4d5bd5600321105c452211

$ python src/auth.py verify --password 'Phantom-2026!' --registro '<registro de arriba>'
OK
$ python src/auth.py verify --password 'otra' --registro '<registro de arriba>'
FALLO          (código de salida 1)

$ python src/auth.py hash --password hola      # dos veces: salts distintos, hashes distintos
pbkdf2_sha256$200000$79075ea7da0977e2dc466e5a45707e55$5573199ff493fcddcf147d028171137a175e1a73a1e355fe1df67f3d12143125
pbkdf2_sha256$200000$8d748b1756015f5c02efa012a2b14b90$65d4531f11c07f0f70b20e5fa408b2096fca85988b8d55e66af2ac09aa3f6217

$ python src/auth.py totp --secret 12345678901234567890 --t 59
287082
```

Comprobaciones adicionales con `python -c` importando `auth` (secreto `12345678901234567890`):

```
hotp(s,1,8) = 94287082      totp(s,59) = 287082      totp(s,1111111109) = 081804
totp(s,29)  = 755224        totp(s,30) = 287082
tiempo hash_password con 200.000 iteraciones: 0.144 s (una sola medición, esta máquina)
tiempo hash_password con 1 iteración:         0.000079 s
```
