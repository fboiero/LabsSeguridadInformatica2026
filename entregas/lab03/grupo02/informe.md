# Informe — Laboratorio 03 · Autenticación

**Grupo:** 02

**Integrantes:**

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Romero Jimena Soledad | 15377 | @Jimena-Romero |
| Milanesio Hebe Del Lourdes | 15343 | @hebemilanesio1 |
| Toranzo Juan Cruz | 15308 | @JuanToranzo |
| Torres Damaris | 14563 | @damaris412 |

## 0. Declaración de uso de IA
Para este trabajo utilizamos Claude (Anthropic) como herramienta de apoyo para:

- **Parte A:** investigar y estructurar el análisis del caso asignado
  (credential stuffing, 23andMe 2023) y buscar fuentes oficiales y de análisis.
- **Mini-research (tema B):** buscar fuentes y armar un borrador de estructura
  del desarrollo y de la reflexión, que el equipo verificó y adaptó.
- **Informe:** revisar redacción, formato y consistencia de citas.
- **Soporte de git/terminal:** consultar comandos de Git y resolver errores de
  sintaxis entre PowerShell y Git Bash.

Todo el código fue revisado, ejecutado y verificado por el equipo antes de incorporarlo a la entrega, y las salidas de la bitácora son las reales de nuestras corridas. Las respuestas conceptuales (por qué salt por usuario, por qué iteraciones, por qué el 2FA frena credential stuffing, qué no protege el TOTP) fueron redactadas por el equipo con apoyo de la IA para organizar y revisar la claridad de la explicación.

## 1. Parte A — Análisis de la brecha (caso, falla, explotación, lo correcto; con fuentes)
**Caso:** Credential stuffing — 23andMe (2023)

### Qué se guardó/comparó mal
23andMe no sufrió una intrusión directa a sus sistemas: entre abril y septiembre de 2023, un atacante probó de forma automatizada credenciales filtradas en *otras* brechas contra el login de 23andMe [1][3]. Accedió directamente a unas 14.600 cuentas [7] porque muchos usuarios reutilizaban contraseñas ya expuestas en otros sitios. A diferencia de los casos de LinkedIn o RockYou, la falla no fue un algoritmo de hash roto ni una comparación insegura, sino de **diseño de control de acceso**: según las autoridades, 23andMe no tuvo en cuenta el riesgo de credential stuffing al diseñar sus salvaguardas, y para más de tres cuartos de los usuarios la contraseña era el único control que protegía la cuenta [1]. Tampoco había verificación adicional para descargar los datos genéticos crudos [3].

### Cómo se explotó
Lo que convirtió esto en una catástrofe fue una función de la plataforma: "DNA Relatives" comparte datos entre perfiles emparentados genéticamente. A partir de las cuentas comprometidas directamente, esa función expuso unos 5,5 millones de perfiles, y "Family Tree" expuso 1,4 millones más [8]; en total el incidente afectó a casi siete millones de clientes [6]. Es decir, cada cuenta vulnerada por reuso de contraseña filtraba en cascada los datos de familiares que nunca reutilizaron nada.

Hubo además fallas de detección. En julio de 2023 el atacante inició sesión más de un millón de veces en un solo día, con un programa automatizado, sobre una cuenta gratuita [4]; 23andMe hizo solo investigaciones aisladas de esa actividad [3]. En agosto, un reclamo de robo de datos de más de 10 millones de usuarios fue descartado como un hoax [3][5]. Recién en octubre, cuando datos de clientes aparecieron a la venta en foros, la empresa reabrió la investigación y notificó a los clientes el 6 de octubre [5].

### La forma correcta
- **MFA obligatorio** (lo que implementamos en la Parte B.2): aunque el atacante tenga el par usuario/contraseña correcto, sin el segundo factor no entra. 23andMe no tenía pasos de verificación adicionales [3], y el regulador británico rechazó su argumento de que los clientes mayores no podían usar MFA [5].
- **Rate limiting y detección de anomalías** en el login: más de un millón de inicios de sesión automatizados en un día [4] deberían haber disparado una alerta o un bloqueo, no una investigación aislada. Las autoridades recomiendan monitoreo de actividad anormal [6].
- **Screening de credenciales contra listas de contraseñas filtradas** (por ejemplo, la API de Have I Been Pwned) al registro o al login, para forzar el cambio de una contraseña ya comprometida en otro sitio [6].
- **Diseño de "blast radius" limitado:** una función social o colaborativa como los perfiles familiares vinculados no debería heredar sin más el nivel de exposición de una cuenta individual comprometida; a datos más sensibles, mayor exigencia de salvaguardas [7].

### Fuentes
1. OPC Canadá e ICO Reino Unido — *Joint investigation into a data breach at 23andMe* (PIPEDA Findings #2025-001).
   https://www.priv.gc.ca/en/opc-actions-and-decisions/investigations/investigations-into-businesses/2025/pipeda-2025-001/
2. OPC Canadá — *Backgrounder: Summary of joint investigation into data breach at 23andMe*.
   https://www.priv.gc.ca/en/opc-news/news-and-announcements/2025/bg_23andme_250617/
3. ICO — *23andMe fined £2.31 million for failing to protect UK users' genetic data*.
   https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2025/06/23andme-fined-for-failing-to-protect-uk-users-genetic-data
4. ICO (newsroom) — *ICO fines 23andMe £2.31 million for failing to protect UK users' genetic data* (versión ampliada).
   https://ico-newsroom.prgloo.com/news/ico-fines-23andme-gbp-2-31-million-for-failing-to-protect-uk-users-genetic-data-1
5. Alston & Bird — *ICO fines 23andMe*.
   https://www.alstonprivacy.com/ico-fines-23andme/
6. Bennett Jones — *23andMe's Data Breach: Key Takeaways*.
   https://www.bennettjones.com/Insights/Blogs/2025/06/23andMes-Data-Breach
7. Lewis Silkin — *ICO fines 23andMe £2.3 million: key takeaways on security measures and data breach management*.
   https://www.lewissilkin.com/insights/2025/07/05/ico-fines-23andme-2-3-million-key-takeaways-on-security-measures-and-data-brea-102krc5
8. Breachsense — *23andMe Data Breach: How Credential Stuffing Exposed Genetic Data*.
   https://www.breachsense.com/blog/23andme-data-breach-case-study/

## 2. Parte B.1 — Contraseñas (por qué salt por usuario, por qué muchas iteraciones)

### Por qué salt por usuario

Sin salt, dos usuarios con la misma contraseña producen exactamente el mismo hash. Eso le da al atacante dos ventajas gratis: puede detectar contraseñas repetidas entre cuentas con solo comparar los hashes, y lo peor es que puede precomputar una **rainbow table** (hashes de millones de contraseñas comunes) una única vez y reutilizarla contra cualquier base de datos filtrada, como pasó en el caso LinkedIn 2012 (uno de los casos de la parte A), donde los hashes SHA-1 sin salt se crackearon masivamente apenas se filtraron. Con un salt aleatorio distinto por usuario, el mismo password produce salidas completamente distintas, así que la rainbow table deja de tener valor: el atacante tiene que atacar cada hash individualmente, uno por uno, en lugar de una sola vez para toda la base.

### Por qué muchas iteraciones (200.000) y no una

Un solo hash SHA-256 se calcula en el orden de nanosegundos, y hardware especializado (GPUs, o directamente ASICs) puede evaluar miles de millones de hashes por segundo. Eso hace que probar diccionarios completos sea trivial incluso con salt, si el hash es "barato".

PBKDF2 aplica la función hash en cadena miles de veces a propósito, de modo que un solo intento de verificación toma un tiempo perceptible pero aceptable para un login legítimo (milisegundos), mientras que multiplica por 200.000 el costo de cada intento del atacante. Esto no vuelve el ataque imposible, pero lo vuelve órdenes de magnitud más lento y caro, lo cual en la práctica es lo que separa una contraseña robada explotable de una que no vale la pena atacar por fuerza bruta.

## 3. Parte B.2 — TOTP (por qué frena el robo de contraseña; qué NO protege)

Implementamos `totp()` a partir de `hotp()` (ya provista): el contador de HOTP se reemplaza por el tiempo actual dividido en pasos de 30 segundos (`contador = t // paso`), de modo que el código de 6 dígitos cambia automáticamente cada 30 segundos sin que el servidor y el usuario necesiten sincronizar un contador explícito — alcanza con que ambos tengan el reloj razonablemente sincronizado. Verificado contra el vector oficial del RFC 6238: con el secreto ASCII `12345678901234567890` y `t=59`, `totp()` devuelve `287082`, el valor esperado por la norma.

### Por qué el TOTP frena el robo de contraseña

El TOTP es un segundo factor de autenticación de tipo **"algo que tenés"** (el dispositivo o app que genera el código, inicializado con un secreto compartido), a diferencia de la contraseña, que es **"algo que sabés"**. Si un atacante consigue la contraseña — ya sea por credential stuffing, por un volcado de hashes crackeados, o por phishing — todavía necesita el código TOTP vigente en ese momento para completar el login. Como el código se deriva del secreto compartido (que no se transmite en cada login, solo en el alta inicial) y cambia cada 30 segundos, el atacante no puede reconstruirlo a partir de la contraseña filtrada ni reutilizar un código capturado más allá de su corta ventana de validez. Esto es exactamente lo que le faltaba a 23andMe (Parte A): con MFA obligatorio, las 14.600 cuentas con contraseña reutilizada no habrían sido vulnerables aunque el par usuario/contraseña ya estuviera filtrado en otra brecha.

### Qué NO protege el TOTP

- **No protege si el propio dispositivo/secreto del segundo factor es
  robado o su secreto compartido se filtra** (por ejemplo, extrayendo el
  secreto de un backup en la nube mal protegido): con el secreto en mano, el
  atacante puede generar los mismos códigos válidos que el usuario legítimo,
  sin necesitar volver a "robar" nada en cada login.
- **No protege contra phishing en tiempo real (man-in-the-middle / adversary-in-the-middle):**
  si el usuario es engañado para tipear tanto la contraseña como el código TOTP
  vigente en un sitio falso, el atacante puede reenviar ambos de inmediato al
  sitio real y autenticarse dentro de la ventana de 30 segundos, antes de que
  el código expire.
- **No protege contra malware en el dispositivo del usuario** que pueda leer
  el código generado (o el secreto) directamente desde la pantalla o la
  memoria del teléfono/app.
- **No reemplaza un buen manejo de contraseñas:** sigue siendo necesario el
  almacenamiento correcto (Parte B.1) — el TOTP es una capa adicional, no un
  sustituto de la primera.

## 4. Bitácora de comandos

```powershell
# Parte B.1: hash y verificación de contraseña
python auth.py hash --password 'Phantom-2026!'
# -> pbkdf2_sha256$200000$dc516e9a2dd52b7f6269d52faccd8327$2f2dbc61a8395ffc92b9aa77170c5cfbd7141712fb4c57975547d9412079f17f

python auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$dc516e9a2dd52b7f6269d52faccd8327$2f2dbc61a8395ffc92b9aa77170c5cfbd7141712fb4c57975547d9412079f17f'
# -> OK
```

```powershell
# Parte B.2: TOTP contra el vector del RFC 6238
python auth.py totp --secret 12345678901234567890 --t 59
# -> 287082 (coincide con el vector oficial del RFC 6238)
```

```powershell
# Autoevaluación
python verificar.py
# == Lab 03 · Autenticación ==
#   ✓ hash_password / verify_password
#   ✓ salt por usuario (hashes distintos)
#   ✓ totp coincide con el vector del RFC 6238
#
# 3 OK · 0 a revisar · 0 sin implementar
```