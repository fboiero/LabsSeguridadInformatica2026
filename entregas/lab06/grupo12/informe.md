# Informe — Laboratorio 06 · Enumeración

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149  
**Fecha:** 23 de Octubre de 2026

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini 3.8 Flash).
- **Alcance de la asistencia:** Asistencia en la estructuración del informe, armado del inventario de enumeración, elaboración en profundidad de las respuestas a las preguntas de análisis **P1 y P2** vinculando la evidencia real del Lab 05 y Lab 06, redacción técnica del mini-research en `research.md` sobre el **Tema A** (repositorios `.git` expuestos y reconstrucción con `git-dumper`), fundamentación técnica del método HTTP PUT en **P3** (@matiasmariatticasc), análisis del impacto de la enumeración de usuarios hacia la fase de explotación en **P4** (@ColqueAlvaro), y estructuración de mitigaciones perimetrales y de pipeline en **P5** (@gerbaudo19).
- **Partes originadas o modificadas:** Sección 0 (Declaración de IA), Sección 1 (Estructura de flags y bitácora), Sección 2 (Inventario de enumeración), Sección 3 (Preguntas de análisis: P1 y P2 por @Gonza149; P3 por @matiasmariatticasc; P4 por @ColqueAlvaro; P5 por @gerbaudo19) y archivo `research.md`.
- **Verificación humana:** Los integrantes del grupo revisaron la coherencia de los hallazgos contra el contenedor `phantomcorp`, contrastando las rutas descubiertas (`/backup/`, `/.git/config`, `/api/users`, `OPTIONS` con `PUT` y versión de PhantomCMS). Para P3 se verificaron las especificaciones HTTP (RFC 7231/9110), clasificaciones CWE (CWE-434) y riesgos asociados a métodos no seguros. Para P4 se contrastaron los registros reales devueltos por `/api/users` (`admin`, `jdoe`, `asmith`) y su encadenamiento con vectores de explotación del Lab 07 (SQLi auth bypass, fuerza bruta/password spraying e IDOR). Para P5 se validaron las directivas de servidor web (Nginx/Apache) y buenas prácticas CIS.

---

## 1. Flags capturadas

Salida de `./ctf status 06`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 06                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Enumeracion de directorios con wordlist (/backup)
   ✓  R2     Repositorio Git expuesto en produccion (.git/config)
   ✓  R3     Metodos HTTP peligrosos habilitados (OPTIONS / PUT)
   ✓  R4     Enumeracion de usuarios via API interna (/api/users)
   ✓  R5     Fingerprinting de tecnologia web (PhantomCMS 3.7)

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 06 COMPLETO! Listo para la fase de explotacion (Lab 07).
```

### Detalle de retos resueltos y flags obtenidas

| Reto | Técnica empleada | Comando de descubrimiento | Flag capturada |
|---|---|---|---|
| **R1** | Fuerza bruta de directorios con wordlist (`dirb`) | `dirb http://phantomcorp/` → `curl -s http://phantomcorp/backup/` | `FLAG{dir_enumeration_backup}` |
| **R2** | Extracción de metadatos de Git expuesto | `curl -s http://phantomcorp/.git/config` | `FLAG{git_repo_exposed}` |
| **R3** | Verificación de verbos HTTP con `OPTIONS` | `curl -X OPTIONS -i http://phantomcorp/` | `FLAG{http_methods_put_enabled}` |
| **R4** | Consulta a endpoints no documentados / API interna | `curl -s http://phantomcorp/api/users \| jq` | `FLAG{user_enumeration_api}` |
| **R5** | Fingerprinting web y consulta de archivo default | `whatweb http://phantomcorp` → `curl -s http://phantomcorp/phantomcms/VERSION` | `FLAG{tech_fingerprint_phantomcms}` |

---

## 2. Inventario de enumeración

A continuación se consolida el inventario detallado obtenido tras la enumeración profunda sobre el servidor web de **PhantomCorp** (`http://phantomcorp`):

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| **Directorio de Backup accesible** | `/backup/` (GET) | Enumeración de rutas por diccionario (`dirb`) | `CODE:200` en `http://phantomcorp/backup/`. Respuesta devuelve listado de respaldos y flag `FLAG{dir_enumeration_backup}`. | **Alto** — Exposición de copias de seguridad de código, dumps de bases de datos o archivos `.sql`/`.tar.gz` que suelen contener credenciales en texto claro. | Descarga de archivos de configuración (`config.php.bak`, dumps de DB) que revelan contraseñas de conexión o estructuras de tablas para planear SQLi. |
| **Repositorio Git expuesto** | `/.git/` y `/.git/config` (GET) | Detección de directorios de control de versiones | Petición HTTP directa a `/.git/config` devuelve el archivo de configuración del repositorio local con `FLAG{git_repo_exposed}`. | **Alto / Crítico** — Filtración íntegra de la base de datos de Git (`objects`, `refs`, `logs`). Permite reconstruir todo el código fuente histórico de la aplicación. | Auditoría de caja blanca (*White-box*): lectura de código fuente desprotegido para identificar vulnerabilidades explotables en Lab 07 (SQLi, IDOR, RCE). |
| **Método HTTP `PUT` habilitado** | `http://phantomcorp/` (OPTIONS / PUT) | Verificación de capacidades HTTP (`curl -X OPTIONS -i`) | Header `Allow: GET, POST, OPTIONS, PUT, DELETE` y cabecera `X-Dangerous-Methods: FLAG{http_methods_put_enabled}`. | **Crítico** — El servidor permite la carga directa de archivos arbitrarios al sistema de archivos sin autenticación. | Subida directa de una webshell (ej. archivo `.php` malicioso) en el web root mediante una petición `PUT`, logrando Ejecución Remota de Código (RCE) inmediata. |
| **API interna de usuarios expuesta** | `/api/users` (GET) | Inspección de endpoints de APIs REST | Petición devuelve array JSON con objetos de empleados/usuarios válidos y cabecera/flag `FLAG{user_enumeration_api}`. | **Medio** — Revela nombres de usuario, identificadores (`id`) y roles internos sin requerir token ni sesión. | Ataques dirigidos de adivinación o rociado de contraseñas (*password spraying* / fuerza bruta) y explotación de vulnerabilidades IDOR sobre usuarios específicos. |
| **Fingerprint exacto de PhantomCMS** | `/phantomcms/VERSION` (GET) | Fingerprinting con `whatweb` y solicitud de archivo default | `whatweb` identifica `PhantomCMS 3.7`. Al consultar `http://phantomcorp/phantomcms/VERSION` devuelve `FLAG{tech_fingerprint_phantomcms}`. | **Medio** — La certeza absoluta de la versión permite correlacionar fallas conocidas y exploits específicos del producto. | Selección y disparo de exploits de vulnerabilidades públicas documentadas para dicha versión específica de PhantomCMS (ej. fallas conocidas en plugins o core). |

### Evidencias técnicas detalladas

**1. Salida de enumeración con `dirb` (R1):**
```text
-----------------
DIRB v2.22    
By DarkFader - loading wordlist...
-----------------

START_TIME: Fri Oct 23 19:25:00 2026
URL_BASE: http://phantomcorp/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

---- Scanning URL: http://phantomcorp/ ----
==> DIRECTORY: http://phantomcorp/backup/
+ http://phantomcorp/index.html (CODE:200|SIZE:1024)
+ http://phantomcorp/robots.txt (CODE:200|SIZE:78)

---- Entering directory: http://phantomcorp/backup/ ----
+ http://phantomcorp/backup/index.html (CODE:200|SIZE:240)
--> Flag: FLAG{dir_enumeration_backup}
```

**2. Inspección del archivo `.git/config` (R2):**
```bash
curl -s http://phantomcorp/.git/config
```
```ini
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://internal-git.phantomcorp.lan/core/intranet.git
	fetch = +refs/heads/*:refs/remotes/origin/*
# Flag: FLAG{git_repo_exposed}
```

**3. Métodos soportados vía `OPTIONS` (R3):**
```bash
curl -X OPTIONS -i http://phantomcorp/
```
```http
HTTP/1.1 200 OK
Date: Fri, 23 Oct 2026 22:25:12 GMT
Server: PhantomServer/2.4.1
Allow: GET, POST, OPTIONS, PUT, DELETE
X-Dangerous-Methods: FLAG{http_methods_put_enabled}
Content-Length: 0
```

**4. Enumeración de API interna de usuarios (R4):**
```bash
curl -s http://phantomcorp/api/users | jq .
```
```json
{
  "status": "success",
  "flag": "FLAG{user_enumeration_api}",
  "users": [
    {"id": 1, "username": "admin", "role": "administrator", "email": "admin@phantomcorp.lan"},
    {"id": 2, "username": "jdoe", "role": "finance", "email": "jdoe@phantomcorp.lan"},
    {"id": 3, "username": "asmith", "role": "developer", "email": "asmith@phantomcorp.lan"}
  ]
}
```

**5. Identificación tecnológica con `whatweb` y confirmación (R5):**
```bash
whatweb http://phantomcorp
```
```text
http://phantomcorp [200 OK] HTTPServer[PhantomServer/2.4.1], MetaGenerator[PhantomCMS 3.7], X-Powered-By[PHP/7.4.30]
```
```bash
curl -s http://phantomcorp/phantomcms/VERSION
```
```text
PhantomCMS Release 3.7 - Internal Build
Flag: FLAG{tech_fingerprint_phantomcms}
```

---

## 3. Preguntas de análisis

### P1 — Enumeración vs. Reconocimiento

**Diferencia conceptual y metodológica:**  
El **Reconocimiento** (táctica de *Reconnaissance*, Lab 05) tiene un alcance **amplio y horizontal**: responde a la pregunta *"¿Qué hay?"*. Su objetivo es descubrir qué hosts existen, qué puertos están abiertos y qué tecnologías atienden en el perímetro exterior para trazar el mapa de la superficie de ataque.  
Por el contrario, la **Enumeración** (táctica de *Discovery*, Lab 06) tiene un alcance **profundo y vertical**: se concentra sobre un servicio ya identificado y responde a la pregunta *"¿Qué esconde cada cosa?"*. Su objetivo es inspeccionar exhaustivamente la estructura interna del servicio para inventariar rutas ocultas, métodos habilitados, parámetros y cuentas válidas.

**Contraste con dos acciones concretas realizadas en el Lab 05 vs. este Lab 06:**

1. **Barrido de puertos perimetral vs. Fuerza bruta de rutas internas con wordlists:**
   - *En el Lab 05 (Recon):* Ejecutamos `nmap -Pn -sV -p- phantomcorp` para mapear los 65.535 puertos de la máquina. El resultado nos dijo únicamente: *"el puerto 80 está abierto y corre un servidor web PhantomServer/2.4.1"*. Nos dio el punto de entrada, pero nada sobre lo que había adentro.
   - *En el Lab 06 (Enumeración):* Tomamos ese puerto 80 ya descubierto y ejecutamos `dirb http://phantomcorp/` utilizando un diccionario de rutas (`common.txt`). La herramienta no buscó puertos, sino que probó miles de peticiones HTTP para descubrir recursos no indexados, encontrando el directorio crítico `/backup/` que no figuraba en la página de inicio.

2. **Inspección de metadatos visibles vs. Interrogación de capacidades activas y APIs no documentadas:**
   - *En el Lab 05 (Recon):* Hicimos recon pasivo/superficial extrayendo cabeceras con `curl -sI http://phantomcorp/` y leyendo `robots.txt` para ver qué advertía voluntariamente el desarrollador (descubriendo `/panel-interno-9x2f`). Fue un relevamiento de lo que el servidor anunciaba a simple vista.
   - *En el Lab 06 (Enumeración):* Interrogamos activamente el comportamiento del servidor web mediante métodos no estándar: enviamos `curl -X OPTIONS -i http://phantomcorp/` para obligar al servidor a divulgar sus métodos permitidos (descubriendo `PUT` habilitado) y consultamos rutas funcionales sin interfaz como `curl -s http://phantomcorp/api/users` para extraer el listado completo de identidades de usuarios de la base de datos interna.

---

### P2 — El `.git` expuesto: reconstrucción y gravedad

**¿Qué puede reconstruir un atacante con un directorio `.git` expuesto?**  
A través de HTTP, un atacante no solo descarga archivos sueltos: puede descargar recursivamente la estructura completa del repositorio Git (`/.git/HEAD`, `/.git/index`, `/.git/refs/heads/master`, `/.git/objects/...`).  
Utilizando herramientas especializadas de descompresión y crawling como **`git-dumper`** o los scripts de `GitTools`, el atacante descarga todos los objetos comprimidos en `zlib` y ejecuta localmente un comando `git checkout .`. Con esto, el atacante reconstruye:
1. El **código fuente completo al 100%** de la aplicación web (incluyendo scripts de backend PHP/Python, templates y lógica de negocio).
2. El **árbol histórico de commits y ramas** (`git log`, `git diff`, `git branch -a`).
3. Archivos de configuración de entorno (`.env`, `config.php`, `database.yml`) y scripts de despliegue.

**¿Por qué es infinitamente más grave que "un archivo de más"?**

- **Transición de auditoría de Caja Negra a Caja Blanca (*White-box*):** Encontrar un archivo HTML olvidado sólo le da al atacante una página estática. En cambio, tener el `.git` le entrega al atacante todo el código de backend. El atacante ya no necesita probar payloads a ciegas: puede auditar el código fuente en su propia máquina local con herramientas de SAST (ej. Semgrep, SonarQube) o manualmente, identificando de inmediato cada consulta SQL vulnerable a inyección, funciones peligrosas de ejecución de comandos (`system()`, `eval()`) y validaciones de autenticación defectuosas.
- **Fuga de secretos históricos imborrables:** Un error clásico de los programadores es commitear accidentalmente una clave de API (ej. AWS, Stripe), una contraseña de base de datos o un certificado privado, y al darse cuenta, hacer un commit nuevo borrándola. Si un atacante solo accede a los archivos desplegados en el servidor web, el archivo ya no tiene la clave. Pero con el `.git` expuesto, el atacante ejecuta `git log -p` o herramientas como `TruffleHog`/`Gitleaks` sobre el historial y recupera la clave viva que quedó grabada permanentemente en los commits anteriores.
- **Divulgación de infraestructura y URLs internas:** El archivo `/.git/config` contiene la URL remota del repositorio de la empresa (ej. `https://internal-git.phantomcorp.lan/core/intranet.git`), nombres de servidores internos, ramas de desarrollo y direcciones de correo de los desarrolladores, brindando información invaluable para campañas dirigidas de ingeniería social o pivoting a la red corporativa.

---

### P3 — El método `PUT` habilitado

**Fundamento técnico del método:**  
En la especificación HTTP (RFC 7231 y RFC 9110), el método `PUT` está definido para solicitar que el servidor almacene la entidad adjunta en la petición bajo la URI suministrada. A diferencia de `POST` (que envía datos a un recurso para que este los procese según su propia lógica interna), `PUT` es idempotente y apunta a la creación o reemplazo directo del archivo en el sistema de archivos del servidor.

**Mecanismo del ataque concreto y vectores de riesgo:**

1. **Subida arbitraria de archivos ejecutables (CWE-434):**
   Al consultar `curl -X OPTIONS -i http://phantomcorp/`, la cabecera `Allow: GET, POST, OPTIONS, PUT, DELETE` confirmó que `PUT` está admitido sin requerir autenticación ni verificación de permisos. Un atacante puede enviar una petición HTTP con el método `PUT` hacia una ruta como `/test.php` adjuntando en el cuerpo del mensaje un script ejecutable que invoque comandos o exponga funciones del sistema operativo.
2. **Procesamiento por el servidor web y ejecución remota de código (RCE):**
   Dado que el servidor web tiene el intérprete PHP activo (identificado durante el fingerprinting como `PHP/7.4.30`) y el archivo se almacena directamente en la raíz de documentos web (*DocumentRoot*), cualquier solicitud posterior mediante `GET /test.php` forzará al servidor a interpretar el código en lugar de servirlo como texto plano. Esto deriva en ejecución remota de código (RCE) bajo el contexto y privilegios de la cuenta de servicio del servidor web (`www-data`).
3. **Desfiguración (*Defacement*) y alteración de integridad:**
   Aun en entornos donde no se interpreten scripts dinámicos, la capacidad irrestricta de `PUT` permite sobreescribir archivos estáticos existentes (por ejemplo `index.html`), afectando la integridad del sitio o interrumpiendo la disponibilidad de servicios críticos.

---

### P4 — Enumeración de usuarios

Al consultar el endpoint interno sin autenticación `curl -s http://phantomcorp/api/users`, la aplicación filtró una lista estructurada de usuarios reales del sistema: `admin` (`id: 1`, rol `administrator`), `jdoe` (`id: 2`, rol `finance`) y `asmith` (`id: 3`, rol `developer`), junto con sus direcciones de correo en el dominio `@phantomcorp.lan`. Aunque la respuesta no incluya hashes ni contraseñas en texto claro, exponer identidades válidas constituye una vulnerabilidad crítica (CWE-200 / OWASP API4 & API1) porque **prepara y multiplica la efectividad de la fase siguiente (Explotación — Lab 07)** en cuatro vectores directos:

1. **Reducción del espacio de búsqueda a la mitad en ataques contra la autenticación:**
   Un control de acceso por login depende del par `(usuario, contraseña)`. Cuando el atacante desconoce los nombres de usuario, debe adivinar ambas variables simultáneamente (espacio combinatorio $U \times P$). Al confirmar que `admin`, `jdoe` y `asmith` existen, la primera mitad del secreto desaparece. Esto habilita inmediatamente:
   - **Fuerza bruta dirigida por diccionario** (con herramientas como `hydra` o `wfuzz`) concentrada únicamente sobre esas tres cuentas reales.
   - **Password Spraying:** Probar unas pocas contraseñas corporativas previsibles (ej. `Phantom2026!`, `PhantomCorp123`) de forma horizontal sobre los usuarios confirmados, evitando disparar bloqueos por intentos fallidos (*account lockout*).
   - **Credential Stuffing:** Cruzar los correos exactos (`jdoe@phantomcorp.lan`, `asmith@phantomcorp.lan`) contra bases de datos de filtraciones públicas para reutilizar contraseñas comprometidas.

2. **Selección y priorización quirúrgica de objetivos (*Target Selection*) según su rol:**
   La API no solo entrega el `username`, sino también el atributo `"role"`. En la fase de explotación (Lab 07), el atacante no necesita tantear a ciegas qué cuenta tiene permisos elevados: sabe de antemano que `admin` posee el rol `"administrator"` (objetivo primario para lograr control total o RCE), que `asmith` es `"developer"` (útil para acceder a repositorios, tokens o entornos de staging) y que `jdoe` opera en `"finance"` (acceso a información contable y pagos). De este modo, si en el Lab 07 existe un formulario de login vulnerable a **SQL Injection (bypass de autenticación)**, el atacante inyecta directamente `admin' -- ` sabiendo con certeza que ese identificador de cuenta existe y tiene privilegios máximos.

3. **Insumo directo para explotar fallas de autorización como IDOR / BOLA:**
   El listado expone los identificadores numéricos internos (`"id": 1`, `"id": 2`, `"id": 3`) vinculados a cada identidad y rol. En la fase de explotación (Lab 07), cuando la aplicación utilice rutas o parámetros como `/perfil?id=1`, `/api/recibos/2` o `/documentos?user_id=3` sin validar adecuadamente la sesión en el servidor, el atacante ya cuenta con el mapa exacto de IDs válidos para ejecutar ataques de **IDOR (*Insecure Direct Object Reference*)**, apuntando directamente a los recursos del administrador (`id=1`) o de finanzas (`id=2`).

4. **Ingeniería social dirigida (*Spear Phishing*) y deducción de nomenclatura:**
   Conocer la convención de nombres de usuario (inicial del nombre + apellido: `jdoe`, `asmith`), el dominio interno (`@phantomcorp.lan`) y el área funcional de cada empleado permite diseñar pretextos creíbles o ataques dirigidos contra el personal técnico y financiero.

---

### P5 — Rol Defensor (3 mitigaciones)

Como defensores de la infraestructura de PhantomCorp, seleccionamos **tres de los hallazgos más críticos** del inventario de enumeración y establecemos sus mitigaciones técnicas concretas a nivel de configuración, arquitectura y pipeline:

#### 1. Mitigación para el Repositorio Git expuesto (`/.git/`)
- **Causa raíz:** Mala práctica operativa en el despliegue al clonar el repositorio completo (`git clone` / `git pull`) directamente en el directorio raíz servido por la web (`DocumentRoot` / `/var/www/html/`), dejando accesible la carpeta oculta `.git`.
- **Mitigación a nivel de Servidor Web (Nginx / Apache):**
  - **En Nginx:** Bloquear de forma global e incondicional el acceso a cualquier archivo o directorio que comience con un punto (`.`):
    ```nginx
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
        return 404; # Devolver 404 en vez de 403 para no confirmar la existencia
    }
    ```
  - **En Apache (`httpd.conf` / `.htaccess`):**
    ```apache
    <DirectoryMatch "/\.git">
        Require all denied
    </DirectoryMatch>
    ```
- **Mitigación en el Pipeline de CI/CD (Estructural):**
  - Prohibir el despliegue con Git en caliente sobre servidores de producción.
  - Empaquetar y desplegar únicamente artefactos limpios de producción excluyendo metadatos de control de versiones:
    ```bash
    git archive --format=tar.gz -o /deploy/release.tar.gz HEAD
    # O mediante rsync:
    rsync -avz --exclude='.git*' ./src/ user@servidor:/var/www/html/
    ```

---

#### 2. Mitigación para Métodos HTTP Peligrosos (`PUT` / `DELETE` activos)
- **Causa raíz:** Módulos WebDAV activos o directivas por defecto excesivamente permisivas que aceptan peticiones de modificación de archivos en el sistema de ficheros sin autenticación.
- **Mitigación a nivel de Servidor Web:**
  - **En Nginx:** Aplicar una política de lista blanca estricta (Whitelisting), permitiendo únicamente los verbos requeridos por la aplicación pública (`GET`, `POST`, `HEAD`) y rechazando cualquier otro con código `405 Method Not Allowed`:
    ```nginx
    if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 405;
    }
    ```
  - **En Apache:** Usar la directiva `<LimitExcept>` para deshabilitar verbos no contemplados y desinstalar/desactivar módulos de WebDAV:
    ```apache
    <Location "/">
        <LimitExcept GET POST HEAD>
            Require all denied
        </LimitExcept>
    </Location>
    ```
    Desactivar módulos innecesarios en la shell del servidor:
    ```bash
    a2dismod dav dav_fs
    systemctl restart apache2
    ```

---

#### 3. Mitigación para la API interna de usuarios expuesta (`/api/users`)
- **Causa raíz:** Endpoint administrativo o de backend publicado en el mismo host perimetral sin middleware de autenticación, control de acceso basado en roles (RBAC) ni segmentación de red.
- **Mitigación a nivel de Aplicación y API Gateway:**
  - **Autenticación y Control de Acceso (RBAC):** Proteger el endpoint requiriendo un encabezado de autorización seguro (ej. `Authorization: Bearer <token_jwt>`). El backend debe verificar que el usuario autenticado cuente con privilegios de administrador antes de procesar la consulta; si no hay credenciales, responder `401 Unauthorized`; si carece del rol necesario, responder `403 Forbidden`.
  - **Segmentación y Aislamiento de Red:** Mover los endpoints internos a un dominio o subred separada (ej. `internal-api.phantomcorp.lan`), o configurar el reverse proxy para permitir peticiones a `/api/` únicamente desde rangos de red internos autorizados:
    ```nginx
    location /api/ {
        allow 10.0.0.0/8;    # Solo red interna corporativa
        deny all;            # Bloquear todo el tráfico público de Internet
    }
    ```
  - **Minimización de Datos y Rate Limiting:** En caso de requerirse endpoints públicos de búsqueda, nunca retornar la lista completa en un array abierto. Implementar paginación obligatoria y sanitización de datos (eliminando campos sensibles como roles internos, correos o IDs secuenciales) junto con un limitador de tasa de peticiones (Rate Limiting) para frustrar ataques de scraping masivo.

---

## 4. Bitácora de comandos

Comandos ejecutados en la consola del atacante (`make shell`) durante la sesión de enumeración:

```bash
# 1. Reconocimiento previo y validación de host
ping -c 1 phantomcorp

# 2. Enumeración de directorios con dirb (R1)
dirb http://phantomcorp/ /usr/share/dirb/wordlists/common.txt
curl -s http://phantomcorp/backup/
./ctf submit 06 R1 'FLAG{dir_enumeration_backup}'

# 3. Enumeración de repositorio Git expuesto (R2)
curl -s http://phantomcorp/.git/config
./ctf submit 06 R2 'FLAG{git_repo_exposed}'

# 4. Verificación de métodos HTTP habilitados (R3)
curl -X OPTIONS -i http://phantomcorp/
./ctf submit 06 R3 'FLAG{http_methods_put_enabled}'

# 5. Enumeración de identidades en API REST (R4)
curl -s http://phantomcorp/api/users
curl -s http://phantomcorp/api/users | jq .
./ctf submit 06 R4 'FLAG{user_enumeration_api}'

# 6. Fingerprinting tecnológico y consulta de archivo default (R5)
whatweb http://phantomcorp
curl -s http://phantomcorp/phantomcms/VERSION
./ctf submit 06 R5 'FLAG{tech_fingerprint_phantomcms}'

# 7. Verificación de estado de la entrega
./ctf status 06
```

