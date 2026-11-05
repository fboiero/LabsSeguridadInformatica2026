# Informe — Laboratorio 03 · Autenticación

**Grupo:** 10 · **Integrantes:** Belén Rocío Ramello — @belramello · Carolina Paula Corazza — @carocor1 · Chiara Agustina Kordek — @chiarakordek · Juan Pablo Saby — @JuanSaby

## 0. Declaración de uso de IA

## 1. Parte A — Análisis de la brecha: credential stuffing

### 1.1 El caso

Entre fines de 2023 e inicios de 2024, la plataforma de dispositivos y servicios de transmisión digital **Roku, Inc.** sufrió un ataque masivo y distribuido de *credential stuffing* que comprometió el acceso a más de **591.000 cuentas de usuarios**, revelado públicamente en dos fases consecutivas [A1, A2]:

1. **Primera oleada (marzo de 2024):** detectada inicialmente en actividades anómalas entre el 28 de diciembre de 2023 y el 21 de febrero de 2024. Fue notificada formalmente el 8 de marzo de 2024 ante reguladores estatales, incluida la Fiscalía General del Estado de Maine, confirmando el compromiso de **15.363 cuentas** [A2].
2. **Segunda oleada (abril de 2024):** como resultado del monitoreo intensificado y el análisis forense posterior, el 12 de abril de 2024 Roku divulgó el hallazgo de una segunda campaña que afectó a aproximadamente **576.000 cuentas adicionales** mediante la misma modalidad [A1].

**Impacto del incidente:** los atacantes utilizaron el acceso no autorizado para tomar el control de las cuentas (*account takeover*), alterando en varios casos las credenciales de inicio de sesión e información de contacto para bloquear a los titulares legítimos. En menos de 400 cuentas de la segunda oleada, los atacantes lograron realizar compras no autorizadas de suscripciones a paquetes de streaming y dispositivos de hardware Roku empleando los métodos de pago precargados (tarjetas de crédito asociadas al perfil) [A1]. Roku aclaró en su comunicado oficial que los números completos de tarjeta de crédito, números de seguridad social o fechas de nacimiento **no** fueron expuestos a los atacantes, y procedió a revertir y reembolsar la totalidad de los cargos fraudulentos registrados [A1].

Ante la magnitud del compromiso, Roku ejecutó el restablecimiento forzoso de contraseñas de todas las cuentas afectadas, revocó las sesiones activas e implementó como medida de remediación estructural la **autenticación de dos factores (2FA) obligatoria** para toda su base de más de 80 millones de cuentas activas [A1].

### 1.2 Qué se guardó o comparó mal

Para comprender la causa raíz técnica de este incidente, es necesario delimitar con rigor conceptual tres vectores de ataque sobre mecanismos de autenticación que suelen confundirse [A3]:

* **Fuerza bruta clásica (*brute force*):** intento exhaustivo de probar múltiples combinaciones de contraseñas (mediante listas de palabras o permutaciones alfanuméricas) contra **un único nombre de usuario o cuenta específica**, hasta dar con la correcta.
* **Ataque de pulverización (*password spraying*):** intento horizontal donde el atacante toma **una o dos contraseñas extremadamente comunes** (por ejemplo, `Password2024!` o `12345678`) y las prueba contra **miles de nombres de usuario distintos**, con el fin deliberado de evitar los bloqueos de cuenta tras pocos intentos fallidos.
* **Relleno de credenciales (*credential stuffing*):** prueba automatizada y a escala masiva de pares exactos de `usuario:contraseña` **obtenidos previamente de filtraciones de datos ajenas a la plataforma atacada** [A3]. El ataque explota el hábito extendido de los usuarios de reutilizar las mismas credenciales de acceso a través de múltiples servicios de Internet.

**¿Por qué el sistema víctima acepta credenciales válidas sin haber sufrido una filtración interna?**  
Roku confirmó de forma categórica que sus sistemas de almacenamiento centrales, bases de datos y redes internas **no** fueron vulnerados ni constituyeron el origen de la fuga de datos [A1]. El ataque tuvo éxito debido a una asimetría estructural: los usuarios reutilizaron en Roku las mismas combinaciones de correo electrónico y contraseña que ya habían sido comprometidas y publicadas en filtraciones masivas de terceros (por ejemplo, brechas históricas como LinkedIn, Adobe, foros o agregadores de credenciales tipo *Collection #1*). Por lo tanto, cuando el sistema de autenticación de Roku recibió la solicitud, contrastó la credencial con sus registros internos legítimos y determinó que la contraseña ingresada en claro era matemáticamente correcta.

**Las fallas en la arquitectura de autenticación y verificación:**
1. **Esquema de autenticación monofactorial (1FA):** la plataforma dependía exclusivamente de un secreto memorizado estático ("algo que sabés"). No se exigía ningún factor de posesión adicional para autorizar el inicio de sesión o las operaciones financieras sensibles.
2. **Omisión de control de contraseñas comprometidas:** el sistema de registro y cambio de contraseñas no cotejaba las claves de los usuarios contra listados de credenciales vulneradas de dominio público, incumpliendo la directriz establecida por el estándar **NIST SP 800-63B (§5.1.1.2)**, la cual obliga a los verificadores de identidad a comparar los secretos memorizados contra diccionarios de contraseñas expuestas en incidentes previos [A4].
3. **Verificación ciega y descontextualizada:** el subsistema de login verificaba las credenciales en forma aislada y atómica, asumiendo erróneamente que la presentación de una contraseña correcta garantizaba en todos los casos la legitimidad del operador humano, ignorando la telemetría del cliente y la frecuencia de los accesos.

### 1.3 Cómo se explotó

La campaña contra Roku se apoyó en una cadena de explotación automatizada y distribuida, tipificada en el estándar OWASP como la amenaza **OAT-008 (Credential Stuffing)** [A3]:

1. **Obtención y curación de listas de credenciales (*combo lists*):** los atacantes adquirieron volcados masivos estructurados en formato `email:password` disponibles en foros especializados y repositorios de datos robados.
2. **Uso de herramientas de automatización ofensiva:** se emplearon suites de prueba automatizada de autenticación (como *OpenBullet*, *SilverBullet* o bots basados en scripts modulares), configuradas con analizadores de respuesta específicos para los endpoints de inicio de sesión de Roku (tanto interfaces web como APIs orientadas a aplicaciones y dispositivos).
3. **Distribución mediante redes de proxies rotativos:** para evitar los mecanismos de detección perimetral, los atacantes dirigieron las solicitudes a través de extensas redes de **proxies residenciales y móviles rotativos**. Cada solicitud de inicio de sesión individual provino de una dirección IP legítima perteneciente a proveedores de servicios residenciales (ISP), a menudo ubicadas detrás de NAT de nivel de operador (CGNAT).
4. **Técnicas de evasión de baja cadencia (*low and slow*):** los intentos se espaciaron en el tiempo para evitar la generación de picos abruptos de tráfico o tasas alarmantes de fallos por dirección IP. Asimismo, las herramientas falsificaron cabeceras HTTP, cadenas de *User-Agent* y huellas digitales del protocolo TLS/HTTP2 para simular la navegación de clientes reales y navegadores legítimos.

**Por qué el rate limiting basado únicamente en dirección IP resulta insuficiente:**  
Una política tradicional de bloqueo perimétrico (por ejemplo, *«bloquear una IP tras 5 intentos fallidos en 5 minutos»*) es ineficaz contra el *credential stuffing* distribuido moderno. Al contar con cientos de miles de direcciones IP residenciales distintas, cada nodo o IP efectúa únicamente uno o dos intentos sobre cuentas diferentes y luego rota a otra dirección. Desde la perspectiva del firewall o servidor web, cada dirección IP individual exhibe un comportamiento estadísticamente inocuo, lo que permite al atacante probar millones de combinaciones sin alcanzar los umbrales estáticos por origen.

### 1.4 La forma correcta

La prevención eficaz del *credential stuffing* no puede resolverse con una regla aislada; exige una estrategia de **defensa en profundidad en capas** alineada con las pautas de **NIST SP 800-63B** [A4] y **OWASP** [A3]:

1. **Autenticación multifactorial obligatoria (MFA/2FA):** la mitigación más contundente consiste en exigir un segundo factor independiente de posesión («algo que tenés»), como **TOTP (RFC 6238)** o autenticadores resistentes al phishing basados en **FIDO2/WebAuthn** [A4, A5]. Aunque el atacante cuente con la contraseña exacta, no puede superar el desafío en tiempo real, cortando de raíz la viabilidad del ataque.
2. **Cotejo contra contraseñas vulneradas (NIST SP 800-63B §5.1.1.2):** el servicio debe verificar de manera obligatoria que ninguna contraseña elegida o modificada coincida con credenciales filtradas conocidas [A4]. Esto se implementa de forma eficiente y preservando la privacidad mediante APIs seguras de anonimato $k$ (como el servicio *Pwned Passwords* de *Have I Been Pwned*), denegando el registro de contraseñas expuestas antes de que puedan ser reutilizadas.
3. **Detección y mitigación avanzada de bots:** despliegue de sistemas WAF y protección contra bots capaces de analizar la reputación de IP/ASN (bloqueando proxies anónimos y centros de datos sospechosos), fingerprinting de cliente (análisis de firmas JA3/JA4 en TLS, HTTP/2, y características del motor JavaScript) y desafíos adaptativos (*proof-of-work* o CAPTCHAs modernos) activados exclusivamente ante indicios de anomalía.
4. **Control de tasa (*rate limiting*) contextual y multidimensional:** complementar el límite por IP con restricciones multidimensionales:
   * **Por cuenta/usuario:** limitar o aplicar demoras y pasos adicionales si una cuenta determinada recibe múltiples intentos fallidos en un lapso corto, sin importar desde cuántas direcciones IP distintas se originen las solicitudes.
   * **Por segmento de red o ASN:** detectar incrementos repentinos de tráfico de autenticación provenientes de un mismo operador o rango CIDR.
5. **Monitoreo conductual y telemetría de autenticación:** detección de inicios de sesión físicamente inverosímiles (*impossible travel* o saltos geográficos incompatibles en ventanas cortas de tiempo) y alertas de seguridad enviadas al usuario por canal alternativo (correo/SMS) informando de nuevos accesos o cambios de configuración en la cuenta.

### 1.5 Relación con lo que implementamos

El análisis técnico de este incidente se conecta de manera directa con los dos pilares criptográficos desarrollados en el código de este laboratorio (`src/auth.py`):

#### PBKDF2 (`hash_password` / `verify_password`)
* **Qué protege:** en `src/auth.py`, `hash_password()` utiliza `hashlib.pbkdf2_hmac` con SHA-256, un salt pseudoaleatorio individual por usuario generado con `secrets.token_bytes` y un factor de costo de $200.000$ iteraciones. Como se demostró experimentalmente en las mediciones de la sección 4.2 de este informe, este diseño protege de forma robusta las contraseñas **en reposo ante una filtración de la propia base de datos**, encareciendo computacionalmente el descifrado offline mediante ataques de diccionario y anulando el uso de tablas precalculadas (*rainbow tables*).
* **Por qué PBKDF2 NO previene el credential stuffing:** si un usuario de Roku reutilizó su contraseña y esta fue filtrada previamente en otro sitio, el atacante presenta la contraseña en texto claro **correcta** en el formulario de acceso. Al ejecutar `verify_password(password, almacenado)`:
  1. El servidor extrae los parámetros y el salt legítimo del registro del usuario.
  2. Calcula `hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iters, dklen=32)`.
  3. Ejecuta `hmac.compare_digest(dk_hex, almacenado_dk_hex)`.
  4. Dado que la contraseña suministrada coincide exactamente con la que el usuario registró, la función devuelve inexorablemente `True`.
* **Efecto adverso colateral en el servidor:** lejos de impedir el ataque, un factor de costo elevado como $200.000$ iteraciones de PBKDF2 exige una cantidad considerable de ciclos de procesador por cada verificación. Si un atacante ejecuta una campaña masiva de *credential stuffing* enviando decenas de miles de solicitudes concurrentes, el cálculo repetido de PBKDF2 puede saturar la CPU del backend de autenticación, degradando el servicio hasta provocar una **denegación de servicio (DoS)**.

#### TOTP (`totp()` / RFC 6238)
* **Por qué TOTP sí corta el ataque:** la función `totp(secret, t, paso=30, digitos=6)` implementa la derivación temporal establecida en RFC 6238 [A5]. El código de un solo uso resultante depende de un secreto simétrico compartido custodiado en el dispositivo físico del usuario y del contador de tiempo actual $\lfloor t / 30 \rfloor$.
* Aunque el atacante cuente con el usuario y la contraseña correctos obtenidos de la filtración ajena («algo que sabés»), **carece del secreto TOTP y del generador sincronizado en el dispositivo del usuario («algo que tenés»)**. Al interponer este segundo paso en el flujo de autenticación, el atacante no puede producir el código de 6 dígitos válido para esa ventana de 30 segundos, neutralizando el acceso automatizado y evitando la toma de control de la cuenta.

#### Fuentes de la sección 1

Referencias abiertas y contrastadas para esta sección. Su numeración es local hasta que se integren en la lista general de «Fuentes consultadas».

- **[A1] [PRIMARIA]** Roku, Inc. (2024, 12 de abril). *Protecting your Roku account*. Roku Blog. https://www.roku.com/blog/protecting-your-account — Comunicado oficial sobre el incidente de credential stuffing, afectación de 576.000 cuentas adicionales, compras no autorizadas y despliegue mandatorio de 2FA.
- **[A2] [PRIMARIA]** Office of the Maine Attorney General. (2024, 8 de marzo y 12 de abril). *Data Breach Notifications: Roku, Inc.* (Notificaciones de brecha N° 2024-03-08 y 2024-04-12). State of Maine Data Breach Database. https://apps.web.maine.gov/online/aeviewer/ME/ — Documentación regulatoria oficial que certifica el compromiso inicial de 15.363 cuentas y la subsiguiente notificación masiva.
- **[A3] [PRIMARIA]** OWASP Foundation. (2020). *OWASP Automated Threat Handbook: Web Applications* (Identificador OAT-008: Credential Stuffing). OWASP Foundation. https://owasp.org/www-project-automated-threats-to-web-applications/ — Definición técnica, caracterización del vector automatizado, herramientas y directrices de mitigación.
- **[A4] [PRIMARIA]** National Institute of Standards and Technology. (2020/2025). *Digital Identity Guidelines: Authentication and Lifecycle Management* (NIST Special Publication 800-63B, §5.1.1.2 Memorized Secret Verifiers y §5.2.2 Multi-Factor Authentication). U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-63b — Estándar oficial que exige contrastar contraseñas contra listas de credenciales comprometidas y detalla los requisitos de autenticación multifactor.
- **[A5] [PRIMARIA]** M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011, mayo). *TOTP: Time-Based One-Time Password Algorithm* (RFC 6238). RFC Editor. https://www.rfc-editor.org/rfc/rfc6238.txt — Especificación estándar del algoritmo TOTP de segundo factor implementado en el laboratorio.

## 2. Parte B.1 — Contraseñas

### 2.1 Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Generación del salt | `secrets.token_bytes(16)`: 128 bits aleatorios nuevos en cada llamada sin salt explícito. | `secrets` es el generador criptográficamente seguro de Python; el módulo `random` está pensado para simulación, no para seguridad [B4]. NIST exige un salt de al menos 32 bits [B3]. |
| Salt explícito | Si la función recibe un `salt`, usa ese valor en lugar de generar uno. | Permite reproducir un registro en pruebas (con salt fijo se obtiene el mismo registro, verificado en 4.2). En uso normal siempre se genera un salt nuevo. |
| Derivación | `hashlib.pbkdf2_hmac("sha256", ..., iters)`, con 200.000 iteraciones por defecto. | PBKDF2 es una función de derivación con factor de costo configurable [B1]; un hash simple como SHA-256 es rápido por diseño, lo que favorece al atacante [B2]. |
| Formato del registro | `pbkdf2_sha256$iters$salt_hex$dk_hex`. | El registro conserva todo lo necesario para verificar (algoritmo, costo y salt), y permite aumentar las iteraciones en el futuro sin invalidar los registros existentes. |
| Codificación | `password.encode("utf-8")`. | PBKDF2 opera sobre bytes; UTF-8 representa de forma determinista contraseñas con tildes o eñes. |
| Comparación | `hmac.compare_digest(calculado, esperado)` sobre los bytes de la clave derivada. | Evita el cortocircuito por contenido de `==` [B5] (ver 2.2). |
| Registro mal formado | Un algoritmo distinto de `pbkdf2_sha256` o cualquier `ValueError` (campos de más o de menos, hexadecimal inválido, iteraciones no numéricas) devuelve `False`. | La verificación no debe aceptar un registro inválido ni interrumpir el inicio de sesión por un dato corrupto. |

### 2.2 Preguntas de análisis

**¿Por qué salt por usuario?**

Sin salt, la derivación es determinista: la misma contraseña produce siempre el mismo valor. Dos usuarios con la contraseña `Phantom-2026!` tendrían registros idénticos, de modo que, ante una filtración, el atacante sabría que comparten contraseña y bastaría con descifrar uno para obtener ambos. Además, podría emplear tablas precalculadas que asocian contraseñas frecuentes con sus hashes y resolver una gran cantidad de registros con una simple búsqueda [B2].

El salt es un valor aleatorio, distinto para cada registro, que se combina con la contraseña antes de la derivación. Según el RFC 8018, su función es producir un conjunto amplio de claves posibles para una misma contraseña, lo que impide al atacante precomputarlas [B1]. La bitácora (4.1) lo evidencia: dos ejecuciones de `hash` con la misma contraseña generan salts y claves derivadas diferentes.

Cabe señalar que el salt no es secreto, ya que se almacena en el propio registro, y que no encarece cada intento: obliga a atacar cada registro por separado, pero probar un candidato contra un registro dado sigue teniendo el mismo costo. Ese costo lo controla el número de iteraciones.

**¿Por qué muchas iteraciones?**

Las funciones de hash de propósito general, como SHA-256, están diseñadas para ser rápidas. En el almacenamiento de contraseñas esa velocidad beneficia al atacante: ante una filtración, puede probar candidatos fuera de línea tan rápido como lo permita su hardware, incluidas GPU que evalúan muchos candidatos en paralelo [B2]. El factor de trabajo, es decir, el número de iteraciones, vuelve cada cálculo deliberadamente costoso [B1; B2].

La medición de la sección 4.2 cuantifica el efecto en el equipo de prueba (AMD Ryzen 7 5700U, ejecución secuencial): con una iteración se alcanzan unos 83.873 intentos por segundo, y recorrer las 14.344.392 entradas de `rockyou.txt` contra un registro llevaría unos 2,85 minutos; con 200.000 iteraciones la tasa cae a 3,59 intentos por segundo y el mismo recorrido se extiende a unos 46 días, un costo aproximadamente 23.356 veces mayor. Para el servidor, en cambio, el impacto se limita a unos 0,28 segundos por inicio de sesión. Esa asimetría es el fundamento de las iteraciones: el costo se paga una vez por cada autenticación legítima, mientras que el atacante debe pagarlo por cada candidato y por cada registro.

La medida tiene límites. Los tiempos corresponden a una CPU sin paralelismo, por lo que un atacante con GPU obtendría tasas muy superiores y los 46 días no constituyen una garantía (ver 4.2). Tampoco protege una contraseña débil: si figura entre los primeros candidatos de la lista, se encontrará mucho antes de recorrerla completa. Por último, 200.000 es el valor predeterminado del laboratorio; la guía de OWASP recomienda actualmente 600.000 iteraciones para PBKDF2-HMAC-SHA-256 y prioriza Argon2id en diseños nuevos [B2], y NIST indica que el factor de costo debe ser tan alto como resulte práctico sin degradar el rendimiento del verificador [B3].

**¿Por qué comparar en tiempo constante?**

La comparación con `==` finaliza en el primer byte distinto, de modo que su duración depende de la longitud del prefijo coincidente. Si un atacante puede medir con precisión los tiempos de respuesta, esa diferencia constituye un canal lateral que permite inferir un valor secreto por partes. `hmac.compare_digest` evita ese cortocircuito: devuelve el mismo resultado que `a == b`, pero sin que el tiempo dependa del contenido [B5].

En `verify_password` lo que se compara es la clave derivada, no la contraseña. El atacante controla la contraseña que envía, pero no puede elegir directamente los bytes de la clave derivada resultante, por lo que explotar esta fuga sería mucho más difícil que en la verificación directa de un MAC. Aun así, comparar secretos en tiempo constante es la práctica correcta, ya que elimina el canal sin costo apreciable y no depende de suponer qué controla el atacante.

## 3. Parte B.2 — TOTP

### 3.1 Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Tiempo por defecto | Si `t` es `None`, se usa `int(time.time())`. | El RFC 6238 mide el tiempo en segundos Unix con origen `T0 = 0` por defecto [B6]. |
| Contador | `t // paso`, con `paso = 30`. | El RFC define `T = (tiempo Unix − T0) / X` con división entera y `X = 30` segundos por defecto [B6]. Todos los instantes de una misma ventana de 30 segundos producen el mismo código. |
| Reutilización | `totp` delega en la función `hotp()` provista. | El RFC 6238 define `TOTP = HOTP(K, T)` y exige construir TOTP sobre HOTP [B6]; reutilizar la función evita duplicar el truncamiento dinámico. |
| Dígitos | Se propaga el parámetro `digitos` (6 por defecto). | Permite verificar también el vector de ocho dígitos del RFC. |
| Verificación | Para `t = 59`: `287082` con seis dígitos y `94287082` con ocho (4.1); los cinco vectores restantes, en 4.2. | Coinciden con el apéndice B del RFC 6238 [B6]. |

### 3.2 Preguntas de análisis

**Si un atacante robó la contraseña, ¿por qué el TOTP lo frena?**

La autenticación de dos factores combina algo que el usuario sabe (la contraseña) con algo que tiene (el dispositivo que genera los códigos). El TOTP se calcula a partir de un secreto compartido entre el servidor y el dispositivo del usuario y del instante actual [B6]. Quien solo posee la contraseña no conoce ese secreto y, por lo tanto, no puede calcular el código vigente: la contraseña robada deja de ser suficiente para iniciar sesión.

Esto neutraliza el ataque analizado en la sección 1. En el credential stuffing, el atacante dispone de contraseñas válidas filtradas en otros servicios y las prueba de forma automatizada; si la cuenta exige además un TOTP, cada credencial correcta se detiene en el segundo factor. Por otra parte, cada código solo es válido durante su ventana de 30 segundos [B6], por lo que un código antiguo interceptado no sirve para un intento posterior.

**¿Qué NO protege el TOTP?**

- **Phishing en tiempo real.** NIST establece que la autenticación por OTP no es resistente al phishing [B3]. Un sitio falso puede solicitar la contraseña y el código, y reenviarlos al servicio legítimo dentro de la misma ventana de 30 segundos. Los autenticadores FIDO2/WebAuthn (passkeys) sí resisten este ataque, como se desarrolla en el mini-research.
- **Robo del secreto o del dispositivo.** Quien obtiene el secreto, por ejemplo a partir del código QR de alta, de una copia de seguridad o de malware en el teléfono, puede generar códigos válidos indefinidamente.
- **Compromiso del servidor.** A diferencia de la contraseña, el secreto TOTP no puede almacenarse con un hash, porque el verificador lo necesita para calcular el código esperado. Por eso NIST exige protegerlo de forma estricta contra accesos no autorizados [B3]; si la base de secretos se filtra, el segundo factor queda anulado para todas las cuentas.
- **La propia base de contraseñas.** El TOTP no reemplaza al almacenamiento seguro: si se filtran los registros, la protección de las contraseñas sigue dependiendo de PBKDF2 (sección 2).
- **Ingeniería social y recuperación de cuenta.** Si el procedimiento de recuperación permite desactivar el segundo factor con verificaciones débiles, el atacante puede eludirlo sin vulnerar el TOTP.

#### Fuentes de las secciones 2 y 3

Referencias abiertas y contrastadas para estas secciones. Su numeración es local hasta que se integren en la lista general de «Fuentes consultadas».

- **[B1] [PRIMARIA]** Moriarty, K. (Ed.), Kaliski, B., & Rusch, A. (2017, enero). *PKCS #5: Password-Based Cryptography Specification Version 2.1* (RFC 8018, §§4.1–4.2). RFC Editor. https://www.rfc-editor.org/rfc/rfc8018 — Función del salt (impedir la precomputación) y del número de iteraciones (aumentar el costo de derivar claves).
- **[B2] [PRIMARIA]** OWASP Foundation. (s. f.). *Password Storage Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — Salt único contra tablas precalculadas, factor de trabajo, lentitud deseable frente a hashes rápidos, 600.000 iteraciones para PBKDF2-HMAC-SHA-256 y preferencia por Argon2id.
- **[B3] [PRIMARIA]** National Institute of Standards and Technology. (2025). *Digital Identity Guidelines: Authentication and Authenticator Management* (NIST SP 800-63B-4, §§3.1.1.2, 3.1.4 y 3.2.5). https://pages.nist.gov/800-63-4/sp800-63b.html — Salt de al menos 32 bits, factor de costo tan alto como sea práctico, OTP no resistente al phishing y protección de las claves simétricas del verificador.
- **[B4] [PRIMARIA]** Python Software Foundation. (s. f.). *secrets — Generate secure random numbers for managing secrets*. Python 3 Documentation. https://docs.python.org/3/library/secrets.html — Uso de `secrets` en lugar de `random` y comportamiento de `token_bytes`.
- **[B5] [PRIMARIA]** Python Software Foundation. (s. f.). *hmac — Keyed-Hashing for Message Authentication*. Python 3 Documentation. https://docs.python.org/3/library/hmac.html — `compare_digest` evita el cortocircuito por contenido para impedir el análisis de tiempos.
- **[B6] [PRIMARIA]** M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011, mayo). *TOTP: Time-Based One-Time Password Algorithm* (RFC 6238, §§3–4 y apéndice B). RFC Editor. https://www.rfc-editor.org/rfc/rfc6238 — Definición `TOTP = HOTP(K, T)`, paso de 30 segundos, `T0 = 0`, secreto compartido y vectores de prueba.

## 4. Bitácora de comandos

### 4.1 Bitácora de comandos

Comandos ejecutados desde `entregas/lab03/grupo10/` en Git Bash (Windows 11, Python 3.10.5), con `PYTHONUTF8=1` para que la salida de `verificar.py` conserve los símbolos. Se pegan las salidas reales; en la última se muestran solo las líneas finales del resumen. Los códigos de salida se obtuvieron con `echo "Código de salida: $?"`.

```text
$ python src/verificar.py

== Lab 03 · Autenticación ==
  ✓ hash_password / verify_password
  ✓ salt por usuario (hashes distintos)
  ✓ totp coincide con el vector del RFC 6238

3 OK · 0 a revisar · 0 sin implementar

Código de salida: 0

$ python src/auth.py hash --password 'Phantom-2026!'
pbkdf2_sha256$200000$56edf3432a8c5b61696ff602a0d08772$0e50bd99566ff1e88ab731a3462c513250eab3206dc7ec64ca8ff713f374ad82
Código de salida: 0

$ python src/auth.py hash --password 'Phantom-2026!'
pbkdf2_sha256$200000$f1ed255cb4ce30be7cd1e9c0ecca03a0$a1cbd16729154a8558f5775fee7a7678dc7d992d890817a5ef8b7457e52d5067
Código de salida: 0

$ python src/auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$56edf3432a8c5b61696ff602a0d08772$0e50bd99566ff1e88ab731a3462c513250eab3206dc7ec64ca8ff713f374ad82'
OK
Código de salida: 0

$ python src/auth.py verify --password 'otra' --registro 'pbkdf2_sha256$200000$56edf3432a8c5b61696ff602a0d08772$0e50bd99566ff1e88ab731a3462c513250eab3206dc7ec64ca8ff713f374ad82'
FALLO
Código de salida: 1

$ python src/auth.py totp --secret 12345678901234567890 --t 59
287082
Código de salida: 0

$ python -c "import sys; sys.path.insert(0,'src'); import auth; print(auth.totp(b'12345678901234567890', 59, digitos=8))"
94287082
Código de salida: 0

$ python src/pruebas_auth.py
...
----------------------------------------------------------------------
Ran 15 tests in 1.404s

OK
Código de salida: 0
```

Las dos ejecuciones de `hash` con la misma contraseña producen registros distintos porque cada una genera un salt nuevo. La verificación acepta la contraseña correcta (código 0) y rechaza la incorrecta (código 1). El TOTP coincide con el vector oficial del RFC 6238 tanto en seis dígitos (`287082`) como en ocho (`94287082`).

### 4.2 Pruebas y medición

#### Pruebas automatizadas

Se agregó `src/pruebas_auth.py`, que usa únicamente `unittest` y otros módulos de la biblioteca estándar. Importa el `auth.py` de la misma carpeta, sin reemplazar sus funciones ni simular resultados. Incluye 15 métodos de prueba:

- Cinco vectores TOTP con HMAC-SHA-1 y seis dígitos, derivados de los vectores de ocho dígitos del apéndice B de RFC 6238; se conservan los ceros iniciales. También se verifica el vector de ocho dígitos para `t=59`. [1]
- Igualdad de códigos para `t=30` y `t=59`, y cambio entre `t=59` y `t=60`, con el secreto de prueba. Ambos primeros tiempos pertenecen a la misma ventana de 30 segundos. La desigualdad del segundo caso es un resultado esperado para ese secreto y esos tiempos, no una garantía de que nunca existan colisiones entre ventanas. [1]
- Dos registros distintos para la misma contraseña con salt aleatorio; formato de cuatro campos y prefijo `pbkdf2_sha256`; parámetros predeterminados del laboratorio y derivación contrastada con `hashlib.pbkdf2_hmac`. [4]
- Reproducción del registro con salt fijo; aceptación de la contraseña correcta; rechazo de una incorrecta y de un registro con un carácter hexadecimal del hash alterado.
- Ocho subcasos de registros mal formados: campos faltantes o sobrantes, algoritmo desconocido, iteraciones no numéricas y salt o hash no hexadecimales.

**Estado real de la ejecución:** la base revisada, commit `aa37fe0`, todavía contiene los tres `TODO` de `auth.py`. Por eso las pruebas no pasan: las llamadas a `hash_password`, `verify_password` y `totp` lanzan `NotImplementedError`. No se modificó `auth.py`. Los 22 errores corresponden a 14 métodos con un error cada uno y un método con ocho subcasos con error; no son 22 métodos diferentes.

Se ejecutó `python src/pruebas_auth.py` desde `entregas/lab03/grupo10/`, en Windows PowerShell; la segunda ejecución usó `PYTHONUTF8=1` en el subproceso para conservar los acentos. Extracto literal del resumen de esa segunda ejecución (se omiten las trazas repetidas):

```text
----------------------------------------------------------------------
Ran 15 tests in 0.010s

FAILED (errors=22)
```

Código de salida real: **1**. Mensajes de excepción observados:

```text
NotImplementedError: Completá hash_password()
NotImplementedError: Completá verify_password()
NotImplementedError: Completá totp()
```

Para repetirlo en Git Bash, desde `entregas/lab03/grupo10/`:

```sh
export PYTHONUTF8=1
python src/pruebas_auth.py
echo "Código de salida: $?"
```

#### Vectores de TOTP

Secreto ASCII público de prueba: `12345678901234567890`; HMAC-SHA-1, paso de 30 segundos y origen temporal cero. RFC 6238 publica los resultados de ocho dígitos; los de seis se obtienen tomando sus últimos seis dígitos, de acuerdo con el truncamiento decimal. [1] La columna «obtenido» corresponde a llamadas reales a `auth.totp`, no a valores copiados del RFC como si se hubieran ejecutado correctamente.

| t (segundos) | Dígitos | Esperado | Obtenido en `auth.totp` |
|---:|---:|:---:|:---|
| 59 | 6 | `287082` | `NotImplementedError` |
| 1111111109 | 6 | `081804` | `NotImplementedError` |
| 1111111111 | 6 | `050471` | `NotImplementedError` |
| 1234567890 | 6 | `005924` | `NotImplementedError` |
| 2000000000 | 6 | `279037` | `NotImplementedError` |
| 59 | 8 | `94287082` | `NotImplementedError` |

**Pendiente de integración:** cuando esté disponible la implementación de Belén, volver a ejecutar las pruebas y actualizar la salida y la columna «obtenido». Estas pruebas funcionales no demuestran por sí solas una comparación en tiempo constante ni la calidad estadística del generador de salt; esas propiedades necesitan además revisión de la implementación.

#### Medición del costo de PBKDF2

La medición es independiente del core pendiente: se llamó directamente a `hashlib.pbkdf2_hmac('sha256', ...)`, no a `auth.hash_password`. Se usaron datos públicos de laboratorio: contraseña `b'Phantom-2026!'`, salt fijo hexadecimal `00112233445566778899aabbccddeeff` (16 bytes) y clave derivada de 32 bytes. Mantenerlos constantes permite variar solo las iteraciones; el salt fijo es exclusivo del experimento, no una recomendación para almacenar contraseñas. [4]

**Equipo medido:** AMD Ryzen 7 5700U with Radeon Graphics, 8 núcleos y 16 procesadores lógicos; Windows 11, compilación 26300; Python 3.12.10 de 64 bits y OpenSSL 3.0.16. Se obtuvo el modelo mediante `Get-CimInstance Win32_Processor` y las versiones mediante `sys.version`, `platform.platform()` y `ssl.OPENSSL_VERSION`.

**Método:** un solo proceso con llamadas secuenciales, sin paralelizar intentos ni usar GPU. Para cada configuración se hicieron tres llamadas de calentamiento, excluidas del tiempo, y siete lotes medidos con `time.perf_counter()`. [5] Cada lote tuvo 100.000 llamadas para una iteración, 1.000 llamadas para 1.000 iteraciones y cinco llamadas para 200.000 iteraciones. Se dividió el tiempo de cada lote por su cantidad de llamadas y se calculó la media de los siete valores. El tiempo incluye el bucle y la llamada desde Python, pero no la generación del salt, el formato del registro ni la comparación de hashes de `verify_password`.

Para la proyección se tomó **N = 14.344.392 entradas**, cantidad de líneas de `rockyou.txt` mostrada en la documentación de Kali. [3] No se descargó ni se recorrió esa lista: se calculó el tiempo de probarla completa contra **un solo hash/salt**, con la tasa secuencial observada y sin detenerse antes por encontrar una coincidencia.

- `tiempo por intento = media(tiempo del lote / llamadas del lote)`.
- `intentos por segundo = 1 / tiempo por intento`.
- `tiempo para la lista completa = N × tiempo por intento`.

| Iteraciones | Tiempo medio por intento (ms) | Desviación estándar entre lotes (ms por intento) | Intentos/s | Tiempo estimado para 14.344.392 entradas |
|---:|---:|---:|---:|---|
| 1 | 0,011923 | 0,000221 | 83.872,83 | 171,03 s ≈ 2,85 min |
| 1.000 | 1,467827 | 0,064494 | 681,28 | 21.055,08 s ≈ 5,85 h |
| 200.000 | 278,464126 | 11,347980 | 3,59 | 3.994.398,58 s ≈ 46,23 días |

Los tiempos son mediciones locales; las duraciones de la lista son **extrapolaciones**, no tiempos de un ataque ejecutado. Se redondeó solo al presentar la tabla. Con una iteración, el costo fijo del bucle y de la llamada influye proporcionalmente más, por lo que no se debe esperar que el cociente de tiempos sea exactamente el cociente de iteraciones. La carga del equipo, las frecuencias del procesador, el código y la longitud de los candidatos también pueden cambiar las tasas.

**Reproducción del núcleo del experimento:** el script de medición se ejecutó desde una carpeta temporal fuera del repositorio, para no agregarlo a la entrega. Este bloque permite repetir el mismo método desde Git Bash sin crear otro archivo; imprimirá nuevos resultados, que pueden diferir de los anteriores:

```sh
python - <<'PY'
import hashlib
import statistics
import time

password = b"Phantom-2026!"
salt = bytes.fromhex("00112233445566778899aabbccddeeff")
n = 14_344_392
for iters, llamadas in ((1, 100_000), (1_000, 1_000), (200_000, 5)):
    for _ in range(3):
        hashlib.pbkdf2_hmac("sha256", password, salt, iters, dklen=32)
    muestras = []
    for _ in range(7):
        inicio = time.perf_counter()
        for _ in range(llamadas):
            hashlib.pbkdf2_hmac("sha256", password, salt, iters, dklen=32)
        muestras.append((time.perf_counter() - inicio) / llamadas)
    media = statistics.mean(muestras)
    print(f"{iters=}, segundos/intento={media:.12f}, "
          f"desviacion={statistics.stdev(muestras):.12f}, "
          f"intentos/s={1 / media:.6f}, segundos/lista={n * media:.6f}")
PY
```

#### Interpretación frente a un atacante

En este equipo, pasar de una a 200.000 iteraciones multiplicó el costo medido por aproximadamente **23.356**. Las iteraciones encarecen cada candidato y reducen los intentos que pueden realizarse en un tiempo dado. El salt, en cambio, separa los hashes de usuarios diferentes y evita reutilizar tablas precalculadas; no sustituye al factor de trabajo. [2]

OWASP advierte que un atacante puede usar GPU y otros recursos para evaluar candidatos en paralelo. Por lo tanto, los 46,23 días **no son una predicción para una GPU ni una garantía de seguridad**: no se midió ninguna GPU y no se atribuye una tasa a un modelo no probado. El experimento demuestra el costo creciente en este entorno, no la velocidad máxima de un atacante. Aumentar el costo tampoco convierte una contraseña débil en fuerte: si está entre las primeras candidatas, puede encontrarse mucho antes de recorrer toda la lista; si no está en ella, recorrerla completa no la recupera. [2]

Se midieron 200.000 iteraciones porque son las predeterminadas del laboratorio, **no porque constituyan una recomendación actual para producción**. La guía de OWASP consultada recomienda 600.000 iteraciones para PBKDF2-HMAC-SHA-256 y prioriza Argon2id para diseños nuevos; también exige equilibrar seguridad, tiempo de autenticación y carga del servidor. [2] No se cambió el parámetro de `auth.py` ni se instalaron bibliotecas externas.

#### Fuentes de la sección 4.2

Referencias abiertas y contrastadas para esta sección. Su numeración es local hasta que se integren en la lista general de «Fuentes consultadas».

- **[1] [PRIMARIA]** M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011). *TOTP: Time-Based One-Time Password Algorithm* (RFC 6238, §§4–5 y apéndice B). RFC Editor. https://www.rfc-editor.org/rfc/rfc6238.txt
- **[2] [PRIMARIA]** OWASP Foundation. (s. f.). *Password Storage Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — Respalda salt, factor de trabajo, ataques con GPU y recomendaciones de configuración.
- **[3] [PRIMARIA]** Kali Linux. (2026, 25 de mayo). *wordlists*. Kali Linux Tools. https://www.kali.org/tools/wordlists/ — El ejemplo de `wc -l` documenta 14.344.392 líneas en `rockyou.txt`.
- **[4] [PRIMARIA]** Python Software Foundation. (s. f.). *hashlib — Secure hashes and message digests*. Python 3.12 Documentation. https://docs.python.org/3.12/library/hashlib.html#hashlib.pbkdf2_hmac — Documenta PBKDF2-HMAC, sus parámetros y el tamaño de la salida.
- **[5] [PRIMARIA]** Python Software Foundation. (s. f.). *time — Time access and conversions*. Python 3.12 Documentation. https://docs.python.org/3.12/library/time.html#time.perf_counter — Documenta el contador de alta resolución y el uso de diferencias para medir duraciones.

## Cierre

### Dificultades encontradas

- **Historial del fork.** La rama `main` del fork quedó desactualizada y con una historia distinta de la del repositorio de la cátedra, que fue reescrita. Para evitar que el PR arrastrara archivos ajenos a la entrega, la rama `lab03-grupo10` se creó a partir de `upstream/main` y no de `main`. Un intento de traer cambios desde la rama `main` del fork produjo conflictos en archivos del enunciado; se canceló con `git merge --abort` y se dejó la rama local igual a la remota.
- **Dependencia entre tareas.** Las pruebas automatizadas se escribieron en paralelo con la implementación, por lo que su primera ejecución falló con `NotImplementedError` (sección 4.2). Una vez integrado `auth.py`, se volvieron a ejecutar y las 15 pruebas pasaron (sección 4.1).
- **Entorno Windows.** El registro del hash contiene el carácter `$`, que PowerShell y Git Bash interpretan como variable si se usan comillas dobles; por eso todos los comandos de `verify` usan comillas simples. Además, el comando disponible es `python` y no `python3`, y fue necesario definir `PYTHONUTF8=1` para que la consola mostrara correctamente los símbolos de `verificar.py`.
- **Número de iteraciones.** Se mantuvieron las 200.000 iteraciones que el enunciado fija como valor predeterminado, para no modificar las firmas del esqueleto, aunque la guía de OWASP consultada recomienda hoy 600.000 para PBKDF2-HMAC-SHA-256. La diferencia se documenta en las secciones 2.2 y 4.2.

### Distribución del trabajo

La distribución coincide con el historial de commits de la rama `lab03-grupo10`.

| Integrante | Aportes realizados |
|---|---|
| Belén Rocío Ramello | Coordinación del laboratorio: estructura de la entrega, implementación de `hash_password`, `verify_password` y `totp` en `src/auth.py`, integración del código, secciones 2, 3 y 4.1, y cierre del informe. |
| Carolina Paula Corazza | Pruebas automatizadas (`src/pruebas_auth.py`) y medición del costo de PBKDF2 según el número de iteraciones (sección 4.2). |
| Chiara Agustina Kordek | Mini-research: TOTP frente a FIDO2/WebAuthn (`research.md`). |
| Juan Pablo Saby | Parte A: análisis del credential stuffing a partir del caso Roku 2024 (sección 1). |

### Fuentes consultadas

Lista general de las referencias del informe. Cada sección conserva su numeración local; entre corchetes se indica con qué clave se cita cada fuente. Las fuentes del mini-research figuran en `research.md`.

1. **[PRIMARIA]** Roku, Inc. (2024, 12 de abril). *Protecting your Roku account*. Roku Blog. https://www.roku.com/blog/protecting-your-account — Citada como [A1].
2. **[PRIMARIA]** Office of the Maine Attorney General. (2024). *Data Breach Notifications: Roku, Inc.* State of Maine Data Breach Database. https://apps.web.maine.gov/online/aeviewer/ME/ — Citada como [A2].
3. **[PRIMARIA]** OWASP Foundation. (2020). *OWASP Automated Threat Handbook: Web Applications* (OAT-008: Credential Stuffing). https://owasp.org/www-project-automated-threats-to-web-applications/ — Citada como [A3].
4. **[PRIMARIA]** National Institute of Standards and Technology. *Digital Identity Guidelines: Authentication and Lifecycle Management* (NIST SP 800-63B). https://doi.org/10.6028/NIST.SP.800-63b — Citada como [A4].
5. **[PRIMARIA]** National Institute of Standards and Technology. (2025). *Digital Identity Guidelines: Authentication and Authenticator Management* (NIST SP 800-63B-4). https://pages.nist.gov/800-63-4/sp800-63b.html — Citada como [B3].
6. **[PRIMARIA]** M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011, mayo). *TOTP: Time-Based One-Time Password Algorithm* (RFC 6238). RFC Editor. https://www.rfc-editor.org/rfc/rfc6238 — Citada como [A5], [1] y [B6].
7. **[PRIMARIA]** Moriarty, K. (Ed.), Kaliski, B., & Rusch, A. (2017, enero). *PKCS #5: Password-Based Cryptography Specification Version 2.1* (RFC 8018). RFC Editor. https://www.rfc-editor.org/rfc/rfc8018 — Citada como [B1].
8. **[PRIMARIA]** OWASP Foundation. (s. f.). *Password Storage Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — Citada como [2] y [B2].
9. **[PRIMARIA]** Kali Linux. (2026, 25 de mayo). *wordlists*. Kali Linux Tools. https://www.kali.org/tools/wordlists/ — Citada como [3].
10. **[PRIMARIA]** Python Software Foundation. (s. f.). *hashlib — Secure hashes and message digests*. https://docs.python.org/3.12/library/hashlib.html — Citada como [4].
11. **[PRIMARIA]** Python Software Foundation. (s. f.). *time — Time access and conversions*. https://docs.python.org/3.12/library/time.html — Citada como [5].
12. **[PRIMARIA]** Python Software Foundation. (s. f.). *secrets — Generate secure random numbers for managing secrets*. https://docs.python.org/3/library/secrets.html — Citada como [B4].
13. **[PRIMARIA]** Python Software Foundation. (s. f.). *hmac — Keyed-Hashing for Message Authentication*. https://docs.python.org/3/library/hmac.html — Citada como [B5].
