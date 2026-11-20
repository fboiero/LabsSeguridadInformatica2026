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
| **Total** | **4** | **Auditoría en proceso coordinado por el Grupo 12** |

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
<!-- SECCIÓN 3: NARRATIVA DEL ATAQUE (A redactar por Luis Alvaro Colque)        -->
<!-- ========================================================================= -->
## 3. Narrativa del ataque
*(Sección asignada a Luis Alvaro Colque — Grupo 12)*

---

## 4. Hallazgos (detalle técnico)

<!-- ========================================================================= -->
<!-- H-01 (CRÍTICA): Inyección de Comandos RCE (A redactar por Gonzalo Rodriguez) -->
<!-- ========================================================================= -->
### H-01 · Inyección de Comandos del Sistema Operativo (RCE) en API de Reportes
*(Hallazgo técnico asignado a Gonzalo Rodriguez — Grupo 12)*

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
<!-- H-03 (ALTA): Exposición de Backups (A redactar por Luis Alvaro Colque)     -->
<!-- ========================================================================= -->
### H-03 · Exposición Pública de Archivos de Respaldo y Fuga de Token de API
*(Hallazgo técnico asignado a Luis Alvaro Colque — Grupo 12)*

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
<!-- SECCIÓN 5: CONCLUSIÓN Y POSTURA (A redactar por Gonzalo Rodriguez)        -->
<!-- ========================================================================= -->
## 5. Conclusión y postura de seguridad
*(Sección asignada a Gonzalo Rodriguez — Grupo 12)*

---

<!-- ========================================================================= -->
<!-- SECCIÓN 6: ANEXO Y STATUS DEL CTF (A completar por Gonzalo Rodriguez)      -->
<!-- ========================================================================= -->
## 6. Anexo
*(Sección asignada a Gonzalo Rodriguez — Grupo 12)*
