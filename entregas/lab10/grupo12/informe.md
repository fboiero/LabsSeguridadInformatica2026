# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149  
**Fecha:** 30 de Octubre de 2026

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini 3.8 Flash).
- **Alcance de la asistencia:** Asistencia en la inicialización de la entrega, estructuración de las plantillas del informe técnico pericial, registro de la captura de banderas del CTF (R1–R5) y redacción técnica de la bitácora de comandos con eventos generados (@matiasmariatticasc); elaboración de la tabla comparativa de firmas, técnicas de evasión y mejoras defensivas del Blue Team (@ColqueAlvaro); asistencia en la redacción y fundamentación técnica de las preguntas de análisis P1, P2 y P3 (@Gonza149).
- **Partes originadas o modificadas:** Inicialización de `INTEGRANTES.md`, Sección 0 (Declaración de uso de IA), Sección 1 (Flags capturadas de R1 a R5) y Sección 4 (Bitácora de comandos) por @matiasmariatticasc; Sección 2 (Tabla comparativa de firmas, técnicas de evasión y mejoras defensivas del Blue Team) por @ColqueAlvaro; Sección 3: preguntas de análisis P1, P2 y P3 por @Gonza149; preguntas P4 y P5 y `research.md` a completar por @gerbaudo19.
- **Verificación humana:** Se validó la coherencia de los retos R1 a R5 contra `retos.manifest` y el servidor `phantomcorp-soc`. Se verificaron los comandos `curl` ejecutados, comprobando los códigos de respuesta HTTP (`403 Forbidden` para alertas del IDS y `200 OK` para evasiones), contrastando las firmas activas del ruleset (`server.py`), probando la reescritura de la expresión regular de P2 frente a payloads ofuscados con `/**/` y validando la detección en los logs del SOC.

---

## 1. Flags capturadas

Salida de `./ctf status 10`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 10                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Acceso a la consola del SOC (/soc)
   ✓  R2     Deteccion disparada por User-Agent
   ✓  R3     Inspeccion del ruleset de firmas (/soc/reglas)
   ✓  R4     Evasion de firma sqli-union con ofuscacion
   ✓  R5     Identificacion de intrusion real en logs del SOC

  ██████████████████████████████  5/5 (100%)

  ✓ ¡Lab 10 COMPLETO! Ponete las pilas con la próxima unidad.
```

### Detalle de retos resueltos y flags obtenidas

| Reto | Perspectiva | Técnica empleada | Comando de descubrimiento | Flag capturada |
|---|---|---|---|---|
| **R1** | Blue Team | Acceso y visualización de eventos en consola SOC | `curl -s http://phantomcorp/soc` | `FLAG{soc_log_access}` |
| **R2** | Red Team | Generación de alerta intencional por User-Agent conocido | `curl -s -A sqlmap http://phantomcorp/` | `FLAG{detection_triggered}` |
| **R3** | Blue Team | Extracción y auditoría del ruleset activo de firmas IDS | `curl -s http://phantomcorp/soc/reglas` | `FLAG{signature_ruleset}` |
| **R4** | Red Team | Evasión de firma mediante comentario SQL inline (`/**/`) | `curl -s "http://phantomcorp/api?q=union/**/select"` | `FLAG{signature_evaded}` |
| **R5** | Blue Team | Filtrado y triaje de logs identificando intrusión ajena no atribuida | `curl -s http://phantomcorp/soc \| grep ALERT` | `FLAG{intrusion_in_the_noise}` |

---

## 2. Tabla de firmas

A continuación se analizan en profundidad las cuatro firmas del ruleset del IDS/WAF (`/soc/reglas`), detallando la técnica de evasión empleada (perspectiva Red Team) y las medidas de endurecimiento estructural necesarias para neutralizar los falsos negativos (perspectiva Blue Team):

| Firma | Patrón detectado en el IDS | Cómo la evadiste (o cómo se evade) | Cómo la mejorarías (Defensa / Blue Team) |
|---|---|---|---|
| **scanner-ua** | Expresión regular sobre la cabecera HTTP: `re.search(r"sqlmap\|nikto\|nmap\|dirb", ua, re.I)`. | **Modificación del encabezado User-Agent:** El User-Agent es un metadato controlado al 100% por el cliente. Para evadir la firma, se instruye a la herramienta a utilizar una cadena de User-Agent que imite a un navegador legítimo (ej. en curl con `-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"` o en sqlmap con `--random-agent`). Al eliminarse la subcadena `sqlmap`, la firma no coincide y la petición pasa como tráfico ordinario. | 1. **Detección comportamental y límites de tasa (*Rate Limiting*):** No depender de strings declarativos; detectar patrones de ráfagas anómalas de peticiones por segundo/minuto por IP.<br>2. **Fingerprinting de TLS y HTTP (JA3 / JA4):** Los escáneres utilizan stacks de red propios (ej. librerías Python `requests`, Go o libcurl) cuyas firmas de apretón de manos TLS (ciphers, extensiones, orden de curvas elípticas) difieren totalmente de navegadores reales como Chrome o Firefox.<br>3. **Análisis de entropía y payloads en parámetros:** Inspeccionar el contenido del cuerpo y query string en lugar de los encabezados cosméticos. |
| **sqli-union** | Expresión regular: `re.search(r"union\s+select", q, re.I)`. Exige **uno o más caracteres de espacio** (`\s+`) entre `UNION` y `SELECT`. | **Reemplazo del espacio por comentarios SQL inline (`/**/`):** De acuerdo a la gramática SQL (especificación ANSI y motores como SQLite, MySQL o PostgreSQL), los comentarios multilínea `/**/` actúan como delimitadores sintácticos válidos equivalentes al espacio en blanco. Enviando `q=union/**/select` (o variantes como `UNION(SELECT...)`, tabulaciones `%09`, saltos de línea `%0A`, o comentarios de versión `/*!50000UNION*//*!50000SELECT*/`), el motor de base de datos ejecuta la inyección normalmente, pero la regex del IDS falla al no hallar el espacio literal esperado. | 1. **Normalización y sanitización canónica previa:** El WAF debe procesar la entrada eliminando comentarios (`/\*.*?\*/`), resolviendo encodings recursivos y normalizando espacios en blanco antes de evaluar cualquier regla.<br>2. **Inspección semántica basada en AST (*Abstract Syntax Tree*):** Utilizar analizadores sintácticos reales de SQL como **libinjection** en lugar de expresiones regulares estáticas. Libinjection tokeniza la sentencia como un compilador real, detectando la estructura relacional anómala sin importar ofuscaciones.<br>3. **Consultas preparadas (Prepared Statements):** Parametrizar en el backend con placeholders (`?`), haciendo imposible la inyección a nivel de código. |
| **path-traversal** | Búsqueda estática lineal de subcadena: `"../" in path or "../" in q`. | **Ofuscación de secuencias de escape de directorio:**<br>1. *Doble URL encoding:* `%252e%252e%252f` (si el backend decodifica dos veces y el WAF una sola).<br>2. *Secuencias anidadas de auto-eliminación:* `....//` o `..././` (si el filtro elimina `../` de forma no recursiva, al borrar el bloque central se reconstituye el `../`).<br>3. *Separadores alternativos de ruta:* En servidores Windows o entornos heterogéneos, uso de barras invertidas (`..\` o `%5c%2e%2e%5c`).<br>4. *Encoding Unicode/Overlong:* `%c0%ae%c0%ae%c0%af`. | 1. **Resolución de ruta canónica previa en el WAF:** Decodificar de forma exhaustiva y resolver la ruta absoluta canónica antes de comparar con las firmas.<br>2. **Validación estricta en el servidor web / aplicación:** Resolver la ruta canónica en código mediante llamadas de bajo nivel (`os.path.realpath()`) y verificar obligatoriamente que comience con el prefijo del directorio base autorizado (`commonpath`), rechazando cualquier petición que intente escapar de la raíz pública. |
| **git-probe** | Coincidencia estática de subcadena: `"/.git" in path`. | **Variaciones de codificación y rutas redundantes:**<br>1. *URL-encoding parcial:* `/%2e%67%69%74` o `/.%67it`.<br>2. *Inyección de directorios relativos superfluos:* `/app/./.git/` o `/app/dummy/../.git/`.<br>3. *Variaciones de mayúsculas/minúsculas:* `/.GIT/config` en sistemas de archivos *case-insensitive*.<br>4. *Peticiones directas a archivos internos:* Consultar objetos directamente vía `/.git/objects/...` o ramas en `/.git/refs/heads/master`. | 1. **Bloqueo global en servidor web (Nginx/Apache):** Implementar una regla genérica y robusta en el servidor HTTP que bloquee el acceso a cualquier archivo o directorio oculto que comience con un punto (`location ~ /\. { deny all; return 404; }`), eliminando la dependencia de firmas en el WAF.<br>2. **Normalización integral de la URI en el motor de detección:** Aplicar transformaciones canónicas de minúsculas (`lowercase`), resolución de `.` y `..`, y decodificación completa antes de cotejar contra la lista negra. |

---

## 3. Preguntas de análisis (P1–P5)

### P1 — ¿Por qué la detección por firmas es evadible por diseño y qué la complementa?

**Por qué es evadible por diseño:**  
La detección basada en firmas opera bajo un modelo de **lista negra sintáctica (*blacklisting*)**: busca coincidencias exactas contra un catálogo finito de cadenas o expresiones regulares que describen cómo se vio un ataque en el pasado. Su fragilidad estructural radica en dos principios fundamentales:
1. **Diferencial de interpretación (*Parser Differential / Impedance Mismatch*):** Mientras que el IDS evalúa una expresión regular superficial sobre el texto crudo de la petición HTTP, el componente de destino (un motor SQL, un intérprete bash o el subsistema de archivos del kernel) interpreta una gramática formal completa. Esa gramática admite múltiples representaciones sintácticas semánticamente equivalentes (*polimorfismo*: comentarios inline `/**/`, codificaciones URL/hexadecimal/Unicode, paréntesis `UNION(SELECT...)`, concatenación de strings). Al atacante le basta encontrar **una sola variante** que sea válida para el parser del backend pero que no calce con el patrón literal del IDS para lograr un **falso negativo** (evasión).
2. **Ceguera ante ataques desconocidos y de lógica de negocio:** Una firma solo reconoce lo que ya fue codificado en su ruleset; es incapaz de detectar vulnerabilidades *zero-day*, uso legítimo de credenciales robadas o abusos de lógica de negocio (como un IDOR `/perfil?id=1`, cuya sintaxis HTTP es idéntica a una petición benigna `/perfil?id=3`).

**Qué la complementa en una arquitectura de defensa en profundidad:**
- **Detección basada en comportamiento y anomalías (UEBA / Análisis heurístico y estadístico):** En lugar de buscar un string específico, establece una línea base del tráfico normal y alerta ante desviaciones de comportamiento: picos en la tasa de peticiones por minuto (*rate limiting*), ráfagas de respuestas `404`/`401`/`500` desde una misma IP, tiempos de respuesta inusualmente largos o secuencias anómalas de acceso a endpoints.
- **Análisis léxico y semántico con normalización previa:** Motores como **libinjection** (integrado en OWASP ModSecurity CRS) que primero decodifican y normalizan el input y luego lo tokenizan en un árbol sintáctico SQL/XSS en lugar de depender de regex simples.
- **Correlación de logs (SIEM) y Threat Hunting humano en el SOC:** Analistas que correlacionan telemetría de distintas capas (WAF, servidor web, base de datos, EDR en el host) para descubrir intrusiones silenciosas que pasaron como `200 OK` frente al filtro perimetral.
- **Controles preventivos en la capa de aplicación:** Consultas parametrizadas, validación de rutas canónicas y control de acceso en el servidor, garantizando que aunque un payload evada el IDS, no pueda explotar la aplicación.

---

### P2 — Reescritura de la firma `sqli-union` contra `/**/` y análisis de la firma "perfecta"

**Por qué se evadió la regla original:**  
En `server.py`, la firma original está definida como:
```python
("sqli-union", lambda path, q, ua: bool(re.search(r"union\s+select", q, re.I)))
```
El cuantificador `\s+` exige obligatoriamente al menos un carácter de espacio en blanco (` `, `\t`, `\n`) entre `union` y `select`. Cuando enviamos `q=union/**/select`, el comentario de bloque C-style `/**/` separa ambos tokens para el motor SQL sin emplear ningún carácter de espacio, haciendo que `\s+` evalúe a `False`.

**Reescritura mejorada de la regla:**  
Para impedir la evasión mediante `/**/==================`, URL-encoding (`%2f%2a%2a%2f`), paréntesis (`UNION(SELECT...)`) o modificadores como `UNION ALL SELECT`, la regla debe combinar **decodificación + normalización de comentarios** antes de evaluar la expresión regular:

```python
import re
from urllib.parse import unquote_plus

def firma_sqli_union_mejorada(path: str, q: str, ua: str) -> bool:
    # 1. Decodificar URL-encoding de forma iterativa (mitiga %2f* y doble encoding %252f*)
    normalizado = unquote_plus(unquote_plus(q))
    # 2. Reemplazar cualquier comentario SQL /* ... */ por un espacio en blanco
    normalizado = re.sub(r"/\*.*?\*/", " ", normalizado, flags=re.S)
    # 3. Evaluar regex que contempla espacios, ALL/DISTINCT o delimitadores como paréntesis
    patron = r"\bunion\b(?:\s+|\b(?:all|distinct)\b|[()+~!-])+\bselect\b"
    return bool(re.search(patron, normalizado, re.I))
```
Con esta regla, tanto `union select`, `union/**/select`, `UNION/*comentario*/ALL/*x*/SELECT` como `UNION(SELECT 1,2)` son detectados y bloqueados con `403`.

**¿Se puede hacer una firma "perfecta"?**  
**No, es teórica y prácticamente imposible construir una firma perfecta.** Las razones son:
1. **Límite formal de las expresiones regulares:** Las firmas regex pertenecen a los lenguajes regulares (Tipo 3 en la jerarquía de Chomsky), mientras que SQL es un lenguaje libre de contexto (Tipo 2) con extensiones específicas de cada motor (ej. comentarios condicionales ejecutables en MySQL `/*!50000UNION*/`, funciones de construcción dinámica de cadenas `CHAR()`, o inyecciones *Blind* booleanas `AND 1=1` / basadas en tiempo que ni siquiera contienen las palabras `UNION` ni `SELECT`).
2. **El dilema fundamental entre Falsos Negativos y Falsos Positivos:** Si endurecemos la firma para bloquear cualquier aparición suelta de las palabras `union` o `select`, una búsqueda legítima de un cliente o empleado en el portal (por ejemplo, buscar el producto *"unión selectora industrial"* o *"Reunión de selección de personal"*) será bloqueada erróneamente (**Falso Positivo**), degradando la disponibilidad del negocio. Si relajamos la firma para no bloquear usuarios reales, siempre existirá algún dialecto u ofuscación que pase (**Falso Negativo**). Por ello, las firmas en un WAF son una barrera de contención (*virtual patching*), pero la solución definitiva reside únicamente en parametrizar las consultas en el backend.

---

### P3 — Detectar por `User-Agent`: por qué es débil y qué mirar en lugar de "quién dice ser"

**Por qué detectar por `User-Agent` es una detección débil:**  
El encabezado HTTP `User-Agent` es una cadena puramente declarativa y no autenticada que el cliente define a voluntad en cada petición. Confiar en la firma `scanner-ua` (`sqlmap|nikto|nmap|dirb`) equivale a preguntarle a un intruso en la puerta si viene a robar:
- En la **Pirámide del Dolor (*Pyramid of Pain*)** de David Bianco, el `User-Agent` se ubica en los escalones más bajos (costo de modificación nulo para el atacante).
- Basta agregar un flag estándar (`curl -A "Mozilla/5.0..."`, `sqlmap --random-agent`, `dirb ... -a "..."`) para que la herramienta ofensiva se mimetice instantáneamente con un navegador Chrome o Firefox legítimo. La firma solo detiene escaneos automáticos descuidados (ruido de bots masivos), pero es completamente inútil frente a un atacante humano o un agente mínimamente configurado.

**Qué indicadores mirar en lugar de "quién dice ser" (analizar *qué hace* y *cómo habla su pila de red*):**
1. **Patrones comportamentales y volumétricos del tráfico (*Behavioral Detection*):**
   - **Velocidad y cadencia (*Request Rate*):** Un usuario humano no solicita 80 rutas distintas por segundo con intervalos exactos de 10 milisegundos.
   - **Tasa de errores HTTP por IP:** Un escáner de directorios (`dirb`/`ffuf`) o un fuzzer de SQLi genera una proporción anormalmente alta de respuestas `404 Not Found`, `400 Bad Request`, `403 Forbidden` o `500 Internal Server Error` en pocos segundos.
   - **Patrón de navegación antinatural:** Un navegador real que carga `/` descarga inmediatamente los recursos estáticos asociados (`.css`, `.js`, `.png`, `favicon.ico`); una herramienta de línea de comandos (`curl`, `sqlmap`, `nikto`) golpea directamente endpoints de API o rutas de diccionario sin cargar jamás un asset visual ni ejecutar JavaScript.
2. **Inspección de la carga útil (*Payload Inspection & Entropy*):**
   - Analizar los parámetros de consulta (`query string`), cuerpo `POST` y cookies en busca de alta densidad de caracteres no alfanuméricos o metacaracteres de control (`'`, `"`, `--`, `/**/`, `;`, `|`, `../`, `%00`), independientemente de qué `User-Agent` declare la petición.
3. **Fingerprinting criptográfico y de protocolo (JA3 / JA4 y HTTP/2 Fingerprinting):**
   - Aunque `sqlmap` o un script en Python envíen el header `User-Agent: Mozilla/5.0 (Chrome/120)`, durante el handshake TLS (`ClientHello`) y el armado de tramas HTTP/2 la librería subyacente (`urllib`, `python-requests`, `libcurl`, `Go net/http`) negocia una lista específica de *cipher suites*, extensiones TLS y orden de cabeceras HTTP que no coincide con la huella criptográfica real de un motor Chromium. Contrastar el `User-Agent` declarado contra el hash **JA3/JA4** permite detectar de inmediato que el cliente está falsificando su identidad.

---

### P4 — Detección automática de la intrusión en el log (R5)

**El problema observado en R5:**  
En la consola del SOC (`http://phantomcorp/soc`), en medio de más de 120 eventos monótonos y benignos correspondientes a consultas internas de usuarios (`10.0.x.x - GET /catalogo?item=N 200 BENIGN`), se encontraba oculta en la línea 73 la siguiente entrada:
```text
185.220.101.42 - GET /admin/../../etc/passwd 200 ALERT[path-traversal] # intrusion no atribuida -> FLAG{intrusion_in_the_noise}
```
A pesar de que el motor del IDS evaluó la regla y etiquetó la petición con `ALERT[path-traversal]`, **la intrusión se consumó con éxito**: el servidor web entregó el contenido confidencial de `/etc/passwd` con código `HTTP 200 OK`. La alerta permaneció latente en el log sin que ningún operador se percatara hasta que se realizó una búsqueda manual explícita (`grep ALERT`).

**Mecanismos técnicos para lograr la detección, alerta y contención automática en un SOC moderno:**

1. **Transformación de IDS Pasivo a IPS en Modo Bloqueo (*Inline Prevention*):**
   - El entorno operaba como un IDS puramente pasivo (modo *sniffer/monitor*), que se limita a inspeccionar el tráfico en una copia (*port mirroring/SPAN*) y emitir alertas a un archivo de registro sin interferir en la sesión.
   - En una arquitectura robusta, el sensor debe operar en modo **IPS (*Intrusion Prevention System*)** o WAF en línea (*blocking mode*). Ante la coincidencia con la firma `path-traversal`, el motor corta inmediatamente la conexión emitiendo paquetes `TCP RST` en ambas direcciones o respondiendo con un `HTTP 403 Forbidden`, impidiendo que el backend llegue a procesar la ruta en disco ni devuelva el archivo sensible.

2. **Reglas de Correlación Automática en SIEM por Severidad Crítica:**
   - En una plataforma SIEM (como Splunk, Elastic Security, Wazuh o Microsoft Sentinel), se define una regla de correlación automatizada basada en la combinación de alerta y resultado:
     $$\text{Regla: } (\text{event.type} == \text{"ALERT"} \land \text{http.response.status\_code} == 200)$$
   - Un ataque reconocido que devuelve código `200 OK` denota una **explotación confirmada y exitosa**. Esta condición debe catalogarse automáticamente con severidad **P1 / Crítica**, disparando notificaciones inmediatas por webhook a canales de guardia (PagerDuty, Opsgenie, Slack SOC) y abriendo un ticket automático de incidente en Jira/ServiceNow sin depender de la revisión humana periódica.

3. **Enriquecimiento con Inteligencia de Amenazas (*Threat Intelligence*) y Georreferenciación:**
   - La IP origen `185.220.101.42` es una dirección pública externa (típica de rangos de nodos de salida Tor o proxies anónimos), en contraste con el 100% del tráfico legítimo que provenía del direccionamiento privado corporativo `10.0.0.0/8`.
   - La correlación automática de logs debe cotejar las IPs entrantes contra listas de reputación dinámica (*Threat Feeds* como AbuseIPDB, AlienVault OTX o Spamhaus). Al detectar que una IP externa no autenticada intenta alcanzar rutas administrativas internas (`/admin/`), el sistema debe asignarle un *Risk Score* elevado y alertar de inmediato.

4. **Detección basada en el Host (HIDS / EDR / Falco):**
   - Más allá de la red, la intrusión debió ser detectada en el propio sistema operativo del host mediante auditoría del kernel (`auditd`, OSSEC/Wazuh o Falco).
   - Una regla de integridad como `file_read: path=/etc/passwd` ejecutada por un proceso no privilegiado (`www-data`, `nobody` o el servidor web Python) constituye una anomalía crítica a nivel de host que genera una alerta independiente de la red y puede congelar el proceso atacado de forma instantánea.

5. **Automatización y Respuesta con SOAR (*Security Orchestration, Automation, and Response*):**
   - Implementación de un *playbook* automatizado que, ante la confirmación del evento crítico, ejecute acciones de contención sin intervención humana: inserción automática de una regla de descarte (*drop*) para la IP `185.220.101.42` en el firewall perimetral (`iptables`/Cloud Security Group) con un período de gracia de 24 horas y revocación de cualquier sesión activa asociada.

---

### P5 — Cierre del curso: por qué un buen atacante debe entender al defensor, y viceversa

Este laboratorio cierra el arco formativo completo de la asignatura: tras haber recorrido el reconocimiento perimetral (Lab 05), la enumeración exhaustiva (Lab 06), la explotación web y de inyecciones (Lab 07), la post-explotación con elevación de privilegios y pivoting (Lab 08), y la orquestación autónoma mediante agentes de inteligencia artificial (Lab 09), el Laboratorio 10 nos coloca del otro lado del monitor para observar la telemetría que cada una de esas acciones generó en el SOC.

La premisa epistemológica fundamental de la ciberseguridad es que **la ofensiva (Red Team) y la defensiva (Blue Team) no son disciplinas independientes ni saberes aislados, sino dos aplicaciones simétricas del mismo conocimiento técnico profundo**:

```text
       CONOCIMIENTO FUNDAMENTAL (Protocolos, Kernels, Parsers, Arquitectura de Software)
                                      ▲
                                     ╱ ╲
                                    ╱   ╲
     PERSPECTIVA OFENSIVA (Red)    ╱     ╲    PERSPECTIVA DEFENSIVA (Blue)
   - Explotar desajustes de parsers       - Normalizar e inspeccionar sintaxis
   - Descubrir supuestos no validados     - Implementar validación estricta y Least Privilege
   - Moverse silencioso (low-and-slow)    - Correlacionar telemetría y detectar anomalías
   - Evadir firmas por polimorfismo       - Diseñar defensas en profundidad resilientes
                                    ╲   ╱
                                     ╲ ╱
                                      ▼
                        ENFOQUE UNIFICADO (Purple Team)
```

#### 1. Por qué un buen atacante (Red Team) debe entender al defensor:
- **Evitar la torpeza operativa y la detección temprana:** Un atacante que no comprende cómo funciona un IDS, un WAF o un SIEM es ruidoso e ineficiente. Disparará herramientas con sus valores de fábrica (`sqlmap`, `nikto`, `nmap` con flags agresivos) que saturan las firmas estáticas más elementales (`scanner-ua`, picos volumétricos), provocando el bloqueo de su IP antes de siquiera entender la lógica del objetivo.
- **Capacidad de evasión y operaciones encubiertas:** Para diseñar ataques avanzados, el pentester debe conocer con precisión qué artefactos deja en el sistema: qué líneas se escriben en `/var/log/auth.log`, cómo normaliza el WAF los comentarios SQL (`/**/`) o qué llamadas al sistema activan las reglas de un EDR en memoria. Solo quien sabe qué mira el analista del SOC puede modular su cadencia (*low-and-slow*), ofuscar sus cargas útiles y permanecer por debajo del radar de detección.
- **Aportar valor profesional a la organización:** El propósito de un ejercicio de *Red Team* o prueba de penetración no es "ganar" ni demostrar superioridad técnica destruyendo infraestructura, sino **ayudar al defensor a robustecer sus controles**. Un auditor que no entiende cómo funciona una regla de ModSecurity, cómo se parametriza una consulta en código o cómo correlaciona un SIEM no puede redactar un informe con recomendaciones de remediación prácticas y aplicables.

#### 2. Por qué un buen defensor (Blue Team) debe entender al atacante:
- **Superar la ingenuidad de la "seguridad por oscuridad" y las listas negras:** Un defensor que nunca explotó una vulnerabilidad tiende a confiar ciegamente en firmas de fábrica y manuales estáticos. Como quedó demostrado con la regla `sqli-union`, creer que la base de datos está a salvo porque una expresión regular exige un espacio literal (`union\s+select`) es una ilusión que se derrumba ante un atacante con conocimientos mínimos de la gramática SQL.
- **Anticipación y Threat Hunting Proactivo:** Quien comprende la mentalidad y las metodologías del adversario (como la cadena de ataque de MITRE ATT&CK) no espera pasivamente a que suene una alarma prefabricada. Sabe que tras una shell inicial vendrá la búsqueda de credenciales en `.env` (Lab 08), el abuso de binarios SUID indebidos, el pivoting hacia la red interna o la automatización mediante agentes (Lab 09). Esta comprensión le permite buscar proactivamente indicadores de compromiso (*IOCs*) y comportamientos sospechosos antes de que el adversario consolide su persistencia.
- **Diseño de defensas en profundidad bajo el paradigma Zero Trust:** Conocer cómo los atacantes encadenan vectores débiles para lograr compromisos totales enseña que ninguna capa perimetral es infalible. El defensor que piensa como atacante no se conforma con instalar un WAF; aplica principio de mínimo privilegio en el sistema operativo, segmentación estricta de redes internas en Capa 3 y parametrización en la capa de datos.

#### 3. Conclusión: La integración en el Purple Team
El estadio más maduro de la seguridad informática contemporánea es la superación de la rivalidad artificial entre atacantes y defensores mediante el modelo de **Purple Teaming**. La seguridad efectiva no se alcanza jugando al gato y al ratón, sino cuando el conocimiento ofensivo alimenta de forma continua la ingeniería de detección y el endurecimiento de la infraestructura, y cuando las restricciones defensivas desafían a los auditores a elevar su rigor técnico. Red y Blue son, en definitiva, dos mitades indisolubles de una misma disciplina profesional.

---

## 4. Bitácora de comandos

Comandos ejecutados desde la consola del atacante (`make shell`) contra el entorno monitoreado `http://phantomcorp`:

```bash
# ==========================================
# R1: Acceso a la consola del SOC (Blue Team)
# ==========================================
# Inspección inicial del endpoint del SOC y visor de eventos
curl -s http://phantomcorp/soc | head -n 15

# Enviar flag R1 al evaluador CTF
./ctf submit 10 R1 'FLAG{soc_log_access}'

# ==========================================
# R2: Provocar detección intencional (Red Team)
# ==========================================
# Envío de User-Agent clasificado como escáner en firmas (sqlmap)
# Respuesta esperada: HTTP 403 Forbidden con alerta del IDS
curl -i -s -A sqlmap http://phantomcorp/

# Enviar flag R2 al evaluador CTF
./ctf submit 10 R2 'FLAG{detection_triggered}'

# ==========================================
# R3: Auditoría del Ruleset de Firmas (Blue Team)
# ==========================================
# Consulta de las reglas y expresiones regulares activas en el IDS
curl -s http://phantomcorp/soc/reglas

# Enviar flag R3 al evaluador CTF
./ctf submit 10 R3 'FLAG{signature_ruleset}'

# ==========================================
# R4: Evasión de Firma sqli-union (Red Team)
# ==========================================
# La regla exige 'union\\s+select' con espacio. Se reemplaza el espacio por un comentario SQL inline:
# Petición enviada: /api?q=union/**/select
# Respuesta esperada: HTTP 200 OK (bypass exitoso, no detectado por IDS)
curl -s "http://phantomcorp/api?q=union/**/select"

# Enviar flag R4 al evaluador CTF
./ctf submit 10 R4 'FLAG{signature_evaded}'

# ==========================================
# R5: Correlación e Identificación de Intrusión (Blue Team)
# ==========================================
# Filtrado de eventos de alerta en los logs del SOC para aislar la intrusión externa (IP 185.220.101.42)
curl -s http://phantomcorp/soc | grep ALERT

# Enviar flag R5 al evaluador CTF
./ctf submit 10 R5 'FLAG{intrusion_in_the_noise}'

# ==========================================
# Verificación de estado del laboratorio
# ==========================================
./ctf status 10
```
