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

### 2.2 Preguntas de análisis

## 3. Parte B.2 — TOTP

### 3.1 Decisiones de implementación

### 3.2 Preguntas de análisis

## 4. Bitácora de comandos

### 4.1 Bitácora de comandos

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

### Distribución del trabajo

### Fuentes consultadas
