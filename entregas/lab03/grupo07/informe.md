# Informe — Laboratorio 03 · Autenticación

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc — @LoloBlanc · Fernando Cagliero — @Ferca19 · Guadalupe Gómez — @guadagomezgg8 · Lautaro Mariño — @lautaromarino0

## 0. Declaración de uso de IA

Se utilizaron asistentes de IA. Se detallan los aportes y las verificaciones
siguiendo lo que pide el `CONTRIBUTING.md`:

**Parte A (Guadalupe Gómez — @guadagomezgg8):**

- **Qué herramienta:** Claude (Anthropic).
- **Qué partes:** la redacción de la Parte A (análisis de timing).
- **Para qué:** explicación de los conceptos y mejoras en la redacción.
- **Cómo se verificó:** se corrió `python3 src/verificar.py` (las tres pruebas en verde) y se contrastó el TOTP contra el vector oficial del RFC 6238 (`t=59` → `287082`); el grupo revisó y comprendió el contenido antes de entregarlo.
- **B.1 (Lautaro Mariño — @lautaromarino0):** el desarrollo original de esta
  sección corresponde a su commit `0b6e6be`. Durante el armado final, a cargo
  de Fernando, se utilizó **OpenAI Codex** para revisar las explicaciones de
  salt, costo de PBKDF2 y diferencias entre algoritmos, y precisar las
  afirmaciones sobre rendimiento. Esa revisión se contrastó con OWASP,
  NIST SP 800-63B-4 y el código del grupo. En esta sesión se ejecutaron la
  autoevaluación, una comparación contra `hashlib.pbkdf2_hmac`, pruebas de
  contraseñas correctas e incorrectas, salts distintos, parámetros almacenados
  y el uso de `hmac.compare_digest`.
- **B.2 (Lorenzo Blanc — @LoloBlanc):** se usó ChatGPT para organizar y redactar la explicación sobre TOTP, sus límites y la comparación con FIDO2/passkeys. Se verificó el vector `t=59` con `src/auth.py` y `src/verificar.py`, y se contrastaron los conceptos con RFC 6238 y las guías de OWASP; el texto fue revisado para confirmar que describe lo que implementa el laboratorio.
- **Mini-research y armado final (Fernando Cagliero — @Ferca19):** se usó
  **OpenAI Codex** para investigar y redactar `research.md`, reunir los datos
  de `INTEGRANTES.md` de la entrega anterior, revisar el informe y preparar
  el PR. Se consultaron las fuentes primarias de IETF, W3C, FIDO Alliance y
  NIST; se verificaron los seis vectores SHA-1 del RFC 6238 a seis y ocho
  dígitos, los límites de ventana, la CLI y la compilación del código. La
  comparación con WebAuthn es documental. Los detalles reproducibles de
  las comprobaciones figuran en la bitácora.

## 1. Parte A — Análisis de la brecha: ataques de timing (caso del grupo 07)

Según el número de grupo, corresponde analizar los ataques de timing, ya que 7 mod 4 = 3. En este caso, el tema es la filtración de información que puede producirse cuando se comparan tokens o MAC sin utilizar un método de comparación en tiempo constante.

### A.1 — El caso y qué prometía el sistema

Los ataques de timing no están relacionados con una única empresa o una brecha puntual, como ocurre con los casos de LinkedIn o RockYou. Se trata de un tipo de vulnerabilidad que puede aparecer en diferentes sistemas cuando se verifican contraseñas, tokens de sesión, firmas digitales o códigos de autenticación de mensajes (MAC).

En principio, el funcionamiento de estos mecanismos es sencillo: el sistema recibe un valor del cliente, calcula o recupera el valor esperado y compara ambos. Si coinciden, permite continuar con la operación. El problema aparece cuando esa comparación se realiza de una manera que permite obtener información sobre el valor correcto a partir del tiempo que tarda en responder.

Un caso conocido fue el de Google Keyczar, una biblioteca criptográfica en la que Nate Lawson identificó este problema en 2009. La verificación del HMAC se realizaba mediante comparaciones convencionales, como `self.Sign(msg) == sig_bytes` en Python o `Arrays.equals(...)` en Java. Este tipo de comparación también aparecía en otras bibliotecas. Por ejemplo, se reportó un problema relacionado con `MessageDigest.isEqual` de Java en el bug de Sun n.º 6863503, en julio de 2009.

### A.2 — ¿Dónde está la falla?

Una comparación convencional de bytes suele detenerse cuando encuentra la primera diferencia entre los dos valores. Es decir, no continúa revisando el resto si ya sabe que no son iguales. Esto sucede, por ejemplo, al utilizar `==`, `Arrays.equals` o una función que devuelve un resultado negativo apenas encuentra un byte diferente.

Aunque este comportamiento es eficiente en situaciones comunes, puede convertirse en un problema de seguridad cuando se comparan valores que deben mantenerse en secreto.

El motivo es que **el tiempo de respuesta depende de cuántos bytes coinciden al comienzo de los valores comparados**. Si un token tiene un primer byte incorrecto, la comparación termina rápidamente. En cambio, si los primeros bytes coinciden, el sistema necesita avanzar un poco más antes de detectar la diferencia.

Esa diferencia de tiempo puede parecer insignificante, pero si se mide repetidamente, puede revelar información sobre el valor esperado. A este fenómeno se lo conoce como *canal lateral temporal* o *timing side channel*. El atacante no obtiene directamente el token correcto, sino que utiliza los tiempos de respuesta para deducirlo.

### A.3 — ¿Cómo se puede explotar?

En lugar de intentar adivinar el token completo de una sola vez, el atacante puede intentar descubrirlo byte por byte, aprovechando las diferencias en el tiempo de comparación.

El procedimiento, de manera simplificada, sería el siguiente:

1. Envía diferentes candidatos para el primer byte del MAC, manteniendo constantes los demás datos de la solicitud.
2. Mide cuánto tarda el sistema en responder a cada intento. Si uno de los candidatos coincide con el primer byte real, la comparación puede continuar un poco más antes de detenerse.
3. Una vez identificado ese byte, repite el proceso con el siguiente y continúa hasta reconstruir el valor completo.

De esta manera, en lugar de probar todas las combinaciones posibles de un token de n bytes, el atacante podría reducir la búsqueda a aproximadamente 256 × n candidatos, siempre que pueda distinguir correctamente las diferencias de tiempo y que el sistema permita realizar suficientes intentos.

Coda Hale explica este problema en su artículo *A Lesson In Timing Attacks (or, Don't use MessageDigest.isEqual)* y menciona que, en determinados escenarios, la cantidad de solicitudes necesarias puede llegar a varios millones. Aunque parece una cifra elevada, puede ser suficiente para que el ataque resulte viable si el sistema no limita los intentos y las mediciones son lo bastante precisas.

Una de las principales dificultades es que los tiempos de respuesta también dependen de otros factores, como la latencia de la red y la carga del servidor. Sin embargo, esto no significa que el ataque sea imposible de realizar de forma remota. Crosby, Riedi y Wallach estudiaron los límites de este tipo de ataques y demostraron que, mediante mediciones repetidas y técnicas estadísticas, es posible detectar diferencias temporales muy pequeñas.

Otro antecedente importante es el trabajo de Brumley y Boneh, publicado en USENIX Security en 2003, titulado *Remote Timing Attacks are Practical*. En esa investigación demostraron que era posible recuperar una clave privada RSA de 1024 bits de una implementación de OpenSSL mediante mediciones remotas de tiempo. El experimento requirió aproximadamente un millón de consultas y unas dos horas de ejecución en el entorno estudiado.

Estos trabajos demostraron que los ataques de timing no son un problema limitado a dispositivos físicos, como las tarjetas inteligentes, sino que también pueden afectar a sistemas accesibles a través de una red.

### A.4 — ¿Cómo se soluciona?

La principal medida para evitar este tipo de filtración es utilizar una **comparación en tiempo constante**. El objetivo es que el tiempo de ejecución no dependa de la cantidad de bytes que coinciden entre los valores comparados.

Para conseguirlo, se deben revisar todos los bytes sin detener la comparación ante la primera diferencia. Una implementación habitual acumula las diferencias mediante operaciones como XOR y determina al final si los valores son iguales.

En Python existe una función específica para esto: `hmac.compare_digest`, disponible desde Python 3.3. También se puede utilizar `secrets.compare_digest`. Ambas están pensadas para comparar datos sensibles, como hashes, MAC y tokens, reduciendo el riesgo de filtraciones a través del tiempo de ejecución.

En nuestro laboratorio, la función `verify_password` utiliza esta comparación de la siguiente manera:

```python
return hmac.compare_digest(calculado, esperado)
```

Esto es preferible a utilizar directamente `calculado == esperado` cuando se comparan valores sensibles, ya que evita depender de una comparación convencional que podría finalizar antes de revisar todos los bytes.

De todas formas, hay que tener en cuenta que **no todos los ataques de timing se solucionan únicamente cambiando la comparación**. En el caso estudiado por Brumley y Boneh, por ejemplo, la vulnerabilidad estaba relacionada con el comportamiento temporal de las operaciones RSA. Para mitigarla se puede utilizar *RSA blinding*, una técnica que introduce aleatoriedad en las operaciones criptográficas para reducir la posibilidad de obtener información sobre la clave privada a partir de los tiempos de ejecución.

Por otro lado, en nuestra función `verify_password`, el valor calculado es el hash PBKDF2 de la contraseña ingresada, que se compara con el hash almacenado. Por eso, el escenario no es exactamente igual al de un atacante que intenta reconstruir un MAC o un token byte por byte. Aun así, utilizar `hmac.compare_digest` es una buena práctica de seguridad y resulta especialmente importante cuando se verifican firmas, tokens o códigos de autenticación proporcionados por un cliente.

En conclusión, este caso demuestra que no alcanza con que un sistema compare correctamente dos valores. También es importante analizar cómo realiza esa comparación, porque incluso pequeñas diferencias en el tiempo de respuesta pueden convertirse en una fuente de información para un atacante.

### Fuentes consultadas

1. Coda Hale. [A Lesson In Timing Attacks (or, Don't use MessageDigest.isEqual)](https://web.archive.org/web/20250103104602/https://codahale.com/a-lesson-in-timing-attacks/). Copia archivada consultada en la revisión final; el dominio original no resolvió DNS.

2. Brumley, D. y Boneh, D. *Remote Timing Attacks are Practical*. 12th USENIX Security Symposium, 2003. Disponible en: https://www.usenix.org/legacy/events/sec03/tech/brumley/brumley_html/index.html

3. Crosby, S., Wallach, D. y Riedi, R. *Opportunities and Limits of Remote Timing Attacks*. ACM Transactions on Information and System Security (TISSEC), 12(3), artículo 17, 2009.

4. Python Software Foundation. *hmac — Keyed-Hashing for Message Authentication*. Documentación oficial de `hmac.compare_digest`. Disponible en: https://docs.python.org/3/library/hmac.html#hmac.compare_digest

## 2. Parte B.1 — Contraseñas (por qué salt por usuario, por qué muchas iteraciones)

El código vive en `src/auth.py`: `hash_password()` y `verify_password()`, solo con
stdlib (`hashlib`, `hmac`, `secrets`). El registro se guarda autodescriptivo:

```
pbkdf2_sha256$200000$<salt_hex>$<dk_hex>
```

así la verificación rederiva con los mismos parámetros sin constantes externas.
Nunca se guarda la contraseña en claro ni un `sha256` pelado. La autoevaluación
(`python3 src/verificar.py`) da verde en las dos checks de B.1.

### B.1.1 — ¿Por qué salt por usuario?

Un hash sin salt es **determinístico**: la misma contraseña produce siempre el mismo
digest. Dos usuarios con `123456` quedan con **hashes idénticos** en la base, y eso le
regala al atacante dos cosas:

1. **Precómputo:** calcula una sola vez una tabla gigante `hash(palabra)` (rainbow
   tables / diccionarios) y la compara contra **toda la base de golpe**. Crackear a 1
   o a 1.000.000 de usuarios cuesta casi lo mismo.
2. **Correlación:** ve de inmediato qué usuarios comparten contraseña (hashes
   repetidos).

El salt **aleatorio y único por usuario** rompe las dos: como cada registro usa un
salt distinto, la misma contraseña genera hashes distintos, así que (a) las tablas
precomputadas quedan inútiles —habría que recomputarlas **por cada salt**— y (b) el
atacante está obligado a **atacar cada hash por separado**, sin amortizar. El salt
**no es secreto**: se guarda junto al hash; su valor está en ser **único e
impredecible**, no en estar oculto. Por eso usamos 16 bytes de un CSPRNG
(`secrets.token_bytes(16)`, 128 bits), muy por encima del piso de 32 bits de NIST.
Caso real: **LinkedIn 2012** guardó 6,5 M de hashes **SHA-1 sin salt** → crackeo masivo.

### B.1.2 — ¿Por qué muchas iteraciones (y no una)?

SHA-256 es **rápido por diseño**. Esa velocidad facilita que un atacante con
GPUs pruebe muchos candidatos contra una base robada; un hash rápido solo no
es adecuado para almacenar contraseñas. [Fuente 1]

En este registro de 32 bytes, PBKDF2 realiza **200.000 evaluaciones de
HMAC-SHA256**, frente a una con `iters=1`. El trabajo crece aproximadamente
en proporción al conteo, comparando el mismo algoritmo y parámetros. Esto
encarece cada intento del atacante, mientras un login legítimo deriva una
sola vez. No significa que el ataque tarde exactamente 200.000 veces más que
con SHA-256 directo: son operaciones distintas y los tiempos dependen del
hardware y la implementación. La latencia aceptable debe medirse en el
servidor real. [Fuentes 1 y 3]

El **factor de costo** se ajusta a medida que mejora el hardware. NIST
SP 800-63B-4 recomienda elegirlo tan alto como sea práctico sin perjudicar el
rendimiento del verificador y aumentarlo con el tiempo. [Fuente 2]

Conservamos las **200.000 iteraciones del ejercicio**, aunque OWASP recomienda
**600.000 para PBKDF2-HMAC-SHA256**. Como el registro guarda el conteo, pueden
verificarse registros anteriores al aumentar el valor para nuevas altas; la
migración de los existentes requiere volver a derivar al disponer de la
contraseña, por ejemplo en el siguiente login. OWASP prioriza Argon2id y luego
scrypt; reserva bcrypt para sistemas heredados. **Argon2id y scrypt** permiten
exigir mucha memoria; no corresponde atribuir esa misma propiedad a bcrypt.
Usar PBKDF2 tampoco certifica por sí solo conformidad FIPS-140: eso depende
del módulo y su validación. Las iteraciones encarecen el ataque, pero no
convierten una contraseña débil en fuerte. [Fuente 1]

### B.1.3 — Verificación en tiempo constante

`verify_password` compara con `hmac.compare_digest`, que **no corta en el primer byte
distinto**. Una comparación ingenua (`==`) puede retornar antes y filtrar, por el
tiempo, cuántos bytes iniciales coincidían (ataque de *timing*, el caso de la Parte A).
Acá comparamos digests derivados y no la contraseña en claro, así que el riesgo
concreto es menor, pero es la práctica correcta y cuesta cero.

### Fuentes (B.1)

1. OWASP Foundation. [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) (salt y factores de costo; selección de algoritmos).
2. NIST. [SP 800-63B-4 — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.1.1.2 (salt y factor de costo).
3. RFC 8018 — *PKCS #5: Password-Based Cryptography Specification v2.1* (PBKDF2). https://www.rfc-editor.org/rfc/rfc8018
4. Python Software Foundation. `hashlib.pbkdf2_hmac`, módulos `hmac` y `secrets`. https://docs.python.org/3/library/hashlib.html

## 3. Parte B.2 — TOTP (por qué frena el robo de contraseña; qué NO protege)

### B.2.1 — ¿Por qué el TOTP frena el robo de una contraseña?

La contraseña es un factor de autenticación basado en **algo que se sabe**. TOTP agrega un segundo factor basado en **algo que se tiene**: un autenticador que comparte un secreto con el servidor. A partir de ese secreto y del tiempo actual, ambos calculan un código de un solo uso que cambia cada 30 segundos. Por eso, si alguien obtiene únicamente la contraseña —por ejemplo, mediante reutilización o una filtración— no puede calcular el código vigente sin obtener también el secreto del segundo factor. El servidor exige ambos factores y rechaza el inicio de sesión si falta el código correcto.

En esta implementación, `totp()` convierte el tiempo en un contador con `t // 30` y lo entrega a HOTP. El vector oficial del RFC 6238 confirma el cálculo: para el secreto ASCII `12345678901234567890` y `t=59`, el código de seis dígitos es `287082` (los ocho dígitos del vector son `94287082`). Esto valida el cálculo, aunque por sí solo no demuestra que toda implementación de autenticación o recuperación de cuenta sea segura.

### B.2.2 — ¿Qué NO protege el TOTP?

TOTP **no evita el phishing en tiempo real**: una víctima puede ingresar el código en una página falsa y el atacante reenviarlo al sitio legítimo antes de que venza la ventana. Tampoco protege si malware controla el teléfono o lee el código, si se roba el secreto compartido guardado por el servidor, ni si se secuestra una sesión después de que la víctima ya inició sesión. Además, si el secreto se copia, puede generarse el mismo código desde otro dispositivo; el código temporal no vuelve secreto al secreto compartido.

En síntesis, TOTP mitiga el uso de una contraseña robada por sí sola, pero sigue siendo **susceptible al phishing**. FIDO2/WebAuthn con passkeys vincula criptográficamente la autenticación al sitio legítimo y no entrega un código reutilizable que una página falsa pueda retransmitir; por eso ofrece resistencia al phishing que TOTP no proporciona.

### Fuentes (B.2)

1. M'Raihi, D. et al. *RFC 6238: TOTP: Time-Based One-Time Password Algorithm*, especialmente §4 y §5. https://www.rfc-editor.org/rfc/rfc6238
2. OWASP Foundation. *Multifactor Authentication Cheat Sheet* (límites del MFA, phishing y factores). https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
3. W3C. [Web Authentication — Level 2](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion), §7.2 (verificación del desafío, origen, RP ID y firma en WebAuthn).

## 4. Bitácora de comandos

Ejecutado desde `entregas/lab03/grupo07/`:

```
$ python3 src/auth.py hash --password hola
pbkdf2_sha256$200000$dc538a00f7e4ea5a275871c960d31550$b8b0730888dbda948df6721247ce6bc55b8e1e377a1cdac2df4d42a36099aaa3

$ python3 src/auth.py hash --password 'Phantom-2026!'
pbkdf2_sha256$200000$e579108764c609873bcdb3de66e191eb$be9dc16e3239f251c097f805b2f4826cb9fe171b5244f02be5a1af192197eea2

$ python3 src/auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$e579108764c609873bcdb3de66e191eb$be9dc16e3239f251c097f805b2f4826cb9fe171b5244f02be5a1af192197eea2'
OK

$ python3 src/auth.py totp --secret 12345678901234567890 --t 59
287082

$ python3 src/verificar.py
== Lab 03 · Autenticación ==
  OK hash_password / verify_password
  OK salt por usuario (hashes distintos)
  OK totp coincide con el vector del RFC 6238
3 OK / 0 a revisar / 0 sin implementar
```

### Verificación del armado final — Fernando (@Ferca19)

Entorno: Python 3.12.2 en Windows; se utilizó `python -B` para evitar generar
archivos `__pycache__` en la entrega. En Linux puede usarse `python3 -B`.

```text
$ python -B src/verificar.py
3 OK · 0 a revisar · 0 sin implementar

$ python -B src/auth.py totp --secret 12345678901234567890 --t 59
287082
```

También se ejecutaron comprobaciones adicionales con la biblioteca estándar:
PBKDF2 contra `hashlib`, contraseña UTF-8, salt de 16 bytes y distinto en cada
alta, rechazo de contraseña y digest incorrectos, registros con parámetros
propios, registros mal formados y uso de `hmac.compare_digest`. Se probaron los
subcomandos `hash`, `verify` y `totp`, sus salidas y códigos de retorno,
incluido el rechazo de una contraseña incorrecta (`FALLO`, código 1).

Los seis vectores **SHA-1** del apéndice B de RFC 6238 pasaron a ocho dígitos
y con su reducción a seis. No se probaron los modos SHA-256/SHA-512 del RFC:
`totp()` en este ejercicio usa SHA-1.

| Tiempo Unix | Esperado y obtenido (8 dígitos) | Esperado y obtenido (6 dígitos) |
|---|---|---|
| 59 | `94287082` | `287082` |
| 1111111109 | `07081804` | `081804` |
| 1111111111 | `14050471` | `050471` |
| 1234567890 | `89005924` | `005924` |
| 2000000000 | `69279037` | `279037` |
| 20000000000 | `65353130` | `353130` |

Para reproducir los vectores desde la carpeta del grupo:

```python
import sys
sys.path.insert(0, "src")
from auth import totp

secret = b"12345678901234567890"
vectores = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]
for tiempo, esperado in vectores:
    assert totp(secret, tiempo, digitos=8) == esperado
    assert totp(secret, tiempo) == esperado[-6:]
print("6 vectores SHA-1 OK a 6 y 8 dígitos")
```

Se verificaron además los límites `t=30`, `59` y `60`, un paso configurable
y el caso de reloj actual con `unittest.mock`. Se comprobó que ambos archivos
Python compilan. Estas pruebas validan los requisitos del ejercicio; no
constituyen una auditoría de un servicio de autenticación completo.

Desde la raíz del repositorio se ejecutaron `git diff --check` y
`bash bin/validar-repo.sh`: ambos pasaron. Para el segundo, Git Bash en
Windows usó una función `python3` que delega en el mismo Python 3.12.2 y
`PYTHONPYCACHEPREFIX` apuntó a una carpeta temporal externa al repositorio.
La validación comprobó compilación, sintaxis shell, manifiestos, ausencia de
soluciones y flags expuestas, y enlaces internos. Se revisaron los enlaces
externos: se sustituyó una referencia de OWASP inaccesible por la
especificación W3C y se enlazó la copia archivada del artículo de Coda Hale.
También se verificó que los cambios se limitan a `entregas/lab03/grupo07/`
y que `src/auth.py` y `src/verificar.py` coinciden con los de la rama remota
recibida antes de comenzar la integración.
