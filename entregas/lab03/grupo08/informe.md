# Informe — Laboratorio 03 · Autenticación

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919

**Caso asignado (Parte A):** 8 mod 4 = 0 → **LinkedIn 2012**

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Búsqueda y verificación de fuentes de la Parte A; borrador de la redacción de las secciones 1 a 3; ejecución de los comandos de la bitácora. | `informe.md`, secciones 1 a 4. No se usó para `src/auth.py`. | Las salidas de la sección 4 son las reales de la terminal. Los vectores TOTP se contrastaron contra la tabla del Apéndice B del RFC 6238. Cada fuente de la Parte A se abrió para confirmar que existe y que dice lo que se le atribuye. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del código y del análisis.

---

## 1. Parte A — Análisis de la brecha: LinkedIn 2012

### Qué pasó

El 6 de junio de 2012 apareció en un foro ruso de cracking de contraseñas una lista de unos **6,5 millones de hashes SHA-1**, sin nombres de usuario, publicada con un pedido de ayuda para crackearlos. Investigadores de seguridad confirmaron que en la lista estaban hashes de contraseñas que usaban **solo** en LinkedIn, lo que la ataba al sitio [1]. LinkedIn confirmó que parte de los hashes correspondían a cuentas suyas y reseteó las contraseñas afectadas [2]. Sophos informó en esos días que al menos el 60 % ya estaba crackeado [2].

Cuatro años después se vio que la lista era sólo una parte. En mayo de 2016 un vendedor con el alias *Peace* puso a la venta en un mercado de la dark web, por unos USD 2.200 en bitcoin, un volcado del mismo robo de 2012 con **167 millones de cuentas**, de las cuales unos **117 millones** tenían correo y hash de contraseña. Según Motherboard, el 90 % de las contraseñas se crackeó en 72 horas. LinkedIn dijo que no se trataba de una brecha nueva e invalidó las contraseñas de las cuentas afectadas [3]. En 2016 la policía checa detuvo en Praga al ruso Yevgeniy Nikulin. Fue extraditado a EE.UU., un jurado lo declaró culpable en julio de 2020 y el 29 de septiembre de 2020 lo condenaron a **88 meses de prisión** por las intrusiones de 2012 en LinkedIn, Dropbox y Formspring [4].

### Qué se guardó mal

LinkedIn guardaba cada contraseña como `SHA-1(contraseña)`: un hash criptográfico **rápido** y **sin salt** [1], [3]. Son dos fallas distintas que se potencian:

1. **Sin salt.** El hash depende sólo de la contraseña. Dos usuarios con `linkedin123` tienen exactamente el mismo hash, así que el atacante crackea cada contraseña distinta **una sola vez** y obtiene a la vez todas las cuentas que la usan. Peor: sirven tablas precalculadas (diccionarios hasheados de antemano, *rainbow tables*) que se construyen una vez y se reusan contra cualquier sitio que hashee igual. Además, contar hashes repetidos le dice al atacante cuáles son las contraseñas más populares, y empieza por ésas.
2. **Hash rápido.** SHA-1 está diseñado para procesar gigabytes por segundo. Una GPU de 2012 ya calculaba cientos de millones a miles de millones de SHA-1 por segundo, así que recorrer un diccionario de filtraciones con reglas de mutación (mayúsculas, números al final, `a`→`4`) cuesta minutos.

Lo que **no** fue la falla: que SHA-1 tenga colisiones. Para crackear contraseñas no hace falta romper ninguna propiedad de SHA-1: alcanza con **adivinar** y comparar. El problema es que esa adivinanza era barata.

### Cómo se explotó

1. **Robo de la base.** Con acceso a los sistemas de LinkedIn se extrajo la tabla de usuarios: correos y hashes [3], [4]. Para todo lo que sigue no hizo falta tocar más a LinkedIn: el crackeo es **offline**, en máquinas propias, sin límite de intentos ni bloqueo de cuenta.
2. **Crackeo offline.** Se hashean candidatos (diccionarios como RockYou, palabras con reglas, fuerza bruta en contraseñas cortas) y se busca cada resultado en la lista. Sin salt, **un solo cálculo** se compara contra los millones de hashes al mismo tiempo. Por eso el 60 % cayó en días en 2012 [2] y el 90 % en 72 horas en 2016 [3].
3. **Uso de las contraseñas en otros sitios.** El daño principal no fue LinkedIn sino el **reuso**: un par correo + contraseña crackeado sirve para *credential stuffing* contra correo, bancos o redes sociales. Ese es el motivo por el que LinkedIn tuvo que invalidar en 2016 contraseñas de cuentas de 2012 que nunca se habían cambiado [3].

Además del daño a los usuarios, LinkedIn pagó USD 1,25 millones en una demanda colectiva de usuarios premium, y en ese acuerdo se comprometió a mantener por al menos cinco años la práctica de hashear con salt [5]. En la causa penal se fijó una restitución de USD 1 millón a favor de LinkedIn [4].

### Lo correcto

- **Función lenta para contraseñas, con salt aleatorio por usuario:** Argon2id, scrypt, bcrypt o PBKDF2-HMAC-SHA256 con muchas iteraciones (OWASP recomienda hoy 600.000 para PBKDF2-HMAC-SHA256) [6], [7]. Es lo que implementa nuestro `hash_password()`: PBKDF2-HMAC-SHA256, salt de 16 bytes de `secrets.token_bytes` y 200.000 iteraciones, todo guardado en el registro `pbkdf2_sha256$iters$salt$dk`. El salt anula las tablas precalculadas y obliga a atacar cada cuenta por separado. Las iteraciones multiplican el costo de cada intento.
- **Comparación en tiempo constante** al verificar (`hmac.compare_digest`).
- **Parámetros en el registro** (algoritmo, iteraciones, salt) para poder subir el costo con el tiempo y re-hashear en el siguiente login, sin forzar un reseteo masivo.
- **Segundo factor** (TOTP, ver sección 3): aunque el hash se crackee, la contraseña sola no alcanza para entrar.
- **Chequeo contra contraseñas filtradas** al registrarse o cambiar la contraseña, como pide NIST SP 800-63B [8]. Esto ataca justamente el reuso que explotó el caso.

### Fuentes (Parte A)

1. Clausing, J. (2012, 6 de junio). *Potential leak of 6.5+ million LinkedIn password hashes*. SANS Internet Storm Center. https://isc.sans.edu/diary/13390 — Secundaria (análisis técnico de un centro de respuesta).
2. PCWorld. (2012, junio). *LinkedIn hack FAQ: What you need to know*. https://www.pcworld.com/article/465110/linkedin_hack_faq_what_you_need_to_know.html — Secundaria.
3. Perez, S. (2016, 18 de mayo). *117 million LinkedIn emails and passwords from a 2012 hack just got posted online*. TechCrunch. https://techcrunch.com/2016/05/18/117-million-linkedin-emails-and-passwords-from-a-2012-hack-just-got-posted-online — Secundaria (incluye el comunicado de LinkedIn).
4. Dinzeo, M. (2020, 29 de septiembre). *Russian hacker sentenced for 2012 data theft of LinkedIn, Dropbox users*. Courthouse News Service. https://www.courthousenews.com/russian-hacker-sentenced-for-2012-data-theft-of-linkedin-dropbox-users/ — Secundaria. Primaria asociada: U.S. Attorney's Office, Northern District of California. (2020). *Russian hacker sentenced to over 7 years in prison for hacking into three Bay Area tech companies*. https://www.justice.gov/usao-ndca/pr/russian-hacker-sentenced-over-7-years-prison-hacking-three-bay-area-tech-companies
5. Roman, J. (2014, 24 de agosto). *LinkedIn settles data breach lawsuit*. BankInfoSecurity. https://www.bankinfosecurity.com/linkedin-settles-data-breach-lawsuit-a-7229 — Secundaria.
6. Moriarty, K., Kaliski, B., & Rusch, A. (2017). *RFC 8018: PKCS #5: Password-based cryptography specification version 2.1*. IETF. https://www.rfc-editor.org/rfc/rfc8018 — Primaria (especificación de PBKDF2).
7. OWASP Foundation. (s. f.). *Password storage cheat sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — Secundaria.
8. Grassi, P. A., et al. (2017). *NIST SP 800-63B: Digital identity guidelines — Authentication and lifecycle management*. NIST. https://doi.org/10.6028/NIST.SP.800-63b — Primaria.

---

## 2. Parte B.1 — Contraseñas

### ¿Por qué salt por usuario?

Sin salt, la función es `H(contraseña)` y el mismo input da siempre el mismo output. Eso tiene tres consecuencias que explotó el caso LinkedIn: dos usuarios con la misma contraseña quedan con el mismo hash (crackear uno es crackear todos); el atacante puede hashear un diccionario **una vez** y comparar ese resultado contra la base entera, o contra cualquier otra base que use el mismo esquema (tablas precalculadas); y la frecuencia de cada hash revela cuáles son las contraseñas más comunes.

Con un salt aleatorio distinto por registro, la función pasa a ser `H(salt ‖ contraseña)`, y cada usuario tiene, en la práctica, su propia función de hash. Se ve en la bitácora: hasheamos dos veces `Phantom-2026!` y salieron dos registros distintos (`c796f79b...` → `264966b5...` y `70942b37...` → `f43ae3b9...`). Para un atacante con la base robada, eso significa que no hay tablas precalculadas posibles (tendría que haber hecho una por cada salt de 128 bits), que el trabajo se multiplica por la cantidad de usuarios (cada candidato se hashea de nuevo para cada salt), y que no se ve qué usuarios comparten contraseña.

El salt **no es secreto**: se guarda en claro en el registro (`pbkdf2_sha256$200000$<salt>$<dk>`), porque hace falta para verificar. Su función es ser **único**, no oculto. Por eso se genera con `secrets.token_bytes(16)`: 128 bits de un generador criptográfico hacen que la probabilidad de repetir un salt sea despreciable. Lo que el salt **no** hace es volver lenta la adivinanza contra **un** usuario: una contraseña débil sigue cayendo rápido si la función es rápida. Para eso están las iteraciones.

### ¿Por qué muchas iteraciones?

El atacante con la base robada trabaja offline y su costo es (cantidad de candidatos) × (costo de un hash). No podemos achicar el espacio de contraseñas que eligen las personas, pero sí el segundo factor del producto. PBKDF2 aplica HMAC-SHA256 en cadena `iters` veces, cada vuelta depende de la anterior, así que no hay atajo: cada candidato cuesta 200.000 HMAC en lugar de un hash.

Lo medimos en esta máquina (sección 4): un SHA-256 simple tarda unos **0,46 µs** y `hash_password` con 200.000 iteraciones unos **64 ms**, **unas 140.000 veces más**. Para el usuario legítimo, 64 ms en el login no se notan. Para el atacante es la diferencia entre probar mil millones de candidatos por segundo por GPU y probar miles. Un diccionario de 10.000 millones de candidatos por cuenta pasa de segundos a meses, y además se multiplica por cada usuario gracias al salt. El número de iteraciones se guarda en el registro, y `verify_password` lo lee de ahí: así se puede subir con los años (el hardware se abarata) sin invalidar los hashes viejos.

El límite de PBKDF2 es que sólo es caro en **cómputo**, no en memoria: una GPU o un ASIC lo paralelizan bien, porque cada intento necesita muy poca RAM. Por eso hoy se prefiere **Argon2id** o **scrypt**, que además exigen mucha memoria por intento. PBKDF2 sigue siendo aceptable (es lo que está en la biblioteca estándar de Python y lo que exige FIPS) pero con un número de iteraciones alto: OWASP pide hoy 600.000 para PBKDF2-HMAC-SHA256 [7], así que nuestras 200.000 quedarían cortas para producción.

### Verificación en tiempo constante

`verify_password` recalcula el derivado con el salt y las iteraciones del registro y compara con `hmac.compare_digest`, no con `==`. `==` corta en el primer byte distinto, y el tiempo de respuesta le diría al atacante cuántos bytes acertó. Además, un registro mal formado devuelve `False` en vez de lanzar una excepción, y el largo del derivado se exige en 32 bytes. Si se aceptara el largo que viene en el registro, uno manipulado con un derivado de 1 byte dejaría pasar 1 de cada 256 contraseñas. Lo probamos en la bitácora: registro alterado y registro con hex inválido dan `FALLO`.

---

## 3. Parte B.2 — TOTP

### Cómo funciona y verificación

TOTP (RFC 6238) es HOTP (RFC 4226) con un contador derivado del reloj: `contador = floor(t / 30)`. El código es `HOTP(K, contador)`: un HMAC-SHA1 del contador con el secreto compartido, truncado dinámicamente a 6 dígitos. Nuestro `totp()` da los **seis** vectores del Apéndice B del RFC 6238 para SHA-1, incluido el pedido: `t = 59` → **287082** (8 dígitos: **94287082**). Ver sección 4.

### ¿Por qué el TOTP frena el robo de contraseña?

Lo que se robó en LinkedIn fue un **conocimiento** (algo que sabés). Con TOTP el login exige además una prueba de **posesión** (algo que tenés): el secreto `K` que vive en el teléfono del usuario y en el servidor. El código de 6 dígitos sale de un HMAC con ese secreto, así que sin `K` no se puede calcular, y la contraseña crackeada de la base no dice nada sobre `K`. El atacante que hace *credential stuffing* con el volcado de 2012 llega al segundo paso y no puede pasar.

Tampoco le sirve observar un código: vale sólo durante su ventana de 30 segundos (más una o dos de tolerancia por desfase de reloj). De un código no se puede recuperar `K`, porque el HMAC es unidireccional y sólo se ven 6 dígitos truncados. Adivinar es 1 en 10⁶ por intento, y eso sí es controlable en el servidor con límite de intentos. Esa es la diferencia con el ataque de LinkedIn: allá el crackeo era **offline** y sin límite; el TOTP obliga al atacante a jugar **online**, donde el servidor controla cuántas veces puede probar.

### ¿Qué NO protege el TOTP?

- **Phishing en tiempo real (adversario en el medio).** Un sitio falso que pide usuario, contraseña y código, y los reenvía al instante al sitio real, entra dentro de la ventana de 30 segundos. Kits como Evilginx lo automatizan y además roban la **cookie de sesión** resultante. TOTP no está atado al dominio. Lo que sí resiste esto son los autenticadores FIDO2/WebAuthn (passkeys, llaves de seguridad), porque firman un desafío que incluye el origen del sitio.
- **Robo de la sesión después del login.** El TOTP protege el momento de autenticarse, no la sesión. Malware que roba cookies o tokens se saltea los dos factores.
- **Robo del secreto `K`.** Es un secreto **compartido**: si se filtra la base del servidor donde están los `K` (a diferencia de las contraseñas, no pueden guardarse hasheados porque el servidor necesita calcular el HMAC), o el QR de alta, o el respaldo del teléfono, el atacante genera códigos válidos para siempre. Tampoco sirve si el dispositivo del usuario está comprometido.
- **Recuperación de cuenta y canales débiles.** Si "perdí mi teléfono" se resuelve con un correo o un SMS (SIM swapping), el atacante ataca ese camino y el TOTP queda de adorno.
- **Fallas de implementación del servidor:** no limitar intentos (6 dígitos se pueden barrer), aceptar ventanas de tiempo amplias, permitir reusar un código ya usado, o comparar el código con `==`.
- **Autorización.** El TOTP responde "¿sos quien decís ser?", no "¿podés hacer esto?". Un usuario legítimo autenticado con dos factores igual tiene que pasar los controles de acceso, y esos se verifican en el servidor.

Y no arregla el almacenamiento de contraseñas: con TOTP la contraseña crackeada no basta para entrar **a este sitio**, pero sigue sirviendo en todos los demás sitios donde el usuario la reusó y que no tienen segundo factor.

---

## 4. Bitácora de comandos

Entorno: Windows 10, Python 3.13.15, Git Bash. Comandos ejecutados desde `entregas/lab03/grupo08/`. Salidas copiadas tal cual de la terminal; el código de salida se imprimió con `echo "código de salida: $?"` después de cada comando.

### B.1 — Hash: dos corridas con la misma contraseña dan registros distintos (salt aleatorio)

```
$ python src/auth.py hash --password 'Phantom-2026!'
pbkdf2_sha256$200000$c796f79b353b163d22a0bf71968ab1a0$264966b5ac58fd82a7d8314600fe48fcac0bcb6ba77e17e77b8a84b2294ae751
código de salida: 0

$ python src/auth.py hash --password 'Phantom-2026!'
pbkdf2_sha256$200000$70942b374213e511a3c95600f912d281$f43ae3b9fb3c9711f170478824d02fd5fdbccba200ed280fc255ad1271addcd3
código de salida: 0
```

### B.1 — Verify

Registro usado (otra corrida de `hash`):
`pbkdf2_sha256$200000$ac03b867c2146ef76da9ea85916dd544$998ce8c49ba382a64ffaad0c5518351c41fde02c29c992ea31ca8fa699bda3f2`

```
$ python src/auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$ac03b867c2146ef76da9ea85916dd544$998ce8c49ba382a64ffaad0c5518351c41fde02c29c992ea31ca8fa699bda3f2'
OK
código de salida: 0

# contraseña incorrecta (sólo cambia la mayúscula inicial)
$ python src/auth.py verify --password 'phantom-2026!' --registro 'pbkdf2_sha256$200000$ac03b867c2146ef76da9ea85916dd544$998ce8c49ba382a64ffaad0c5518351c41fde02c29c992ea31ca8fa699bda3f2'
FALLO
código de salida: 1

# registro alterado: últimos dos dígitos hex del derivado cambiados a 00
$ python src/auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$ac03b867c2146ef76da9ea85916dd544$998ce8c49ba382a64ffaad0c5518351c41fde02c29c992ea31ca8fa699bda300'
FALLO
código de salida: 1

# registro mal formado (salt no hexadecimal): FALLO, sin excepción
$ python src/auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$zz$00'
FALLO
código de salida: 1
```

### B.1 — Costo medido: PBKDF2 (200.000 iteraciones) contra SHA-256 simple

```
$ python -c "...mide hash_password() contra 100.000 hashlib.sha256()..."
PBKDF2 200000 iter: 64.4 ms por intento
SHA-256 simple: 0.455 us por intento
relación: 141,768x
```

### B.2 — TOTP: vector pedido por la consigna

```
$ python src/auth.py totp --secret 12345678901234567890 --t 59
287082
código de salida: 0
```

### B.2 — TOTP: resto de los vectores SHA-1 del Apéndice B del RFC 6238

```
$ python src/auth.py totp --secret 12345678901234567890 --t 1111111109
081804
código de salida: 0

$ python src/auth.py totp --secret 12345678901234567890 --t 1111111111
050471
código de salida: 0

$ python src/auth.py totp --secret 12345678901234567890 --t 1234567890
005924
código de salida: 0

$ python src/auth.py totp --secret 12345678901234567890 --t 2000000000
279037
código de salida: 0

$ python src/auth.py totp --secret 12345678901234567890 --t 20000000000
353130
código de salida: 0
```

Con 8 dígitos (llamando a `totp(..., digitos=8)` directamente, porque la CLI no expone ese parámetro):

```
$ python -c "...totp(b'12345678901234567890', t, digitos=8) para cada t..."
59 94287082
1111111109 07081804
1111111111 14050471
1234567890 89005924
2000000000 69279037
20000000000 65353130
```

Los seis coinciden con la tabla del RFC 6238 para SHA-1 (`94287082`, `07081804`, `14050471`, `89005924`, `69279037`, `65353130`). Los códigos que empiezan con 0 (`081804`, `005924`) confirman además que el `zfill` de `hotp()` conserva los ceros a la izquierda.

### Fuentes (Parte B)

- M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011). *RFC 6238: TOTP: Time-based one-time password algorithm*. IETF. https://www.rfc-editor.org/rfc/rfc6238 — Primaria.
- M'Raihi, D., Bellare, M., Hoornaert, F., Naccache, D., & Ranen, O. (2005). *RFC 4226: HOTP: An HMAC-based one-time password algorithm*. IETF. https://www.rfc-editor.org/rfc/rfc4226 — Primaria.
- RFC 8018, OWASP Password Storage Cheat Sheet y NIST SP 800-63B: ver fuentes [6], [7] y [8] de la Parte A.
