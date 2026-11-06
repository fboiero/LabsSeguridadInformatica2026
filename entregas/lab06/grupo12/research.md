# Mini-research — Laboratorio 06

**Grupo:** 12  
**Tema elegido:**
- [x] **A.** Cómo un `.git` expuesto permite reconstruir el código (`git-dumper`) y casos reales de credenciales filtradas por esta vía.
- [ ] **B.** Wordlists de enumeración: qué son SecLists, cómo se eligen, por qué una wordlist mala hace fallar la enumeración.
- [ ] **C.** El método HTTP `PUT` y el WebDAV: cómo se pasa de "método habilitado" a subir un webshell.
- [ ] **D.** Fingerprinting pasivo vs. activo: cómo `whatweb` deduce el stack.

---

## Desarrollo

### 1. El directorio `.git` y la arquitectura interna de Git
Git es un sistema de control de versiones distribuido. A diferencia de los modelos centralizados antiguos (como SVN o CVS), cada copia de un repositorio Git contiene la totalidad de la historia del proyecto almacenada en una carpeta oculta denominada `.git/`.

Cuando una aplicación web se despliega en producción realizando simplemente un comando `git clone` o `git pull` dentro del directorio servido por el servidor web (`/var/www/html/` o `DocumentRoot`), la carpeta `.git/` queda accesible al público por HTTP si el servidor no tiene reglas explícitas de bloqueo.

Los componentes esenciales de esta estructura son:
- **`HEAD`:** Archivo de texto plano que apunta a la rama activa actual (ej. `ref: refs/heads/main`).
- **`config`:** Archivo INI que almacena la configuración local y remota, incluyendo URLs de repositorios privados (`https://github.com/org/repo.git` o repositorios internos de GitLab), nombres de usuarios y credenciales de acceso embebidas.
- **`index`:** Archivo binario fundamental (formato *Git Index format*) que actúa como el área de preparación (*staging area*). Contiene el listado completo de todos los archivos del repositorio, sus rutas relativas en el proyecto, marcas de tiempo, permisos UNIX y el hash SHA-1 de 40 caracteres del objeto *blob* correspondiente a cada archivo.
- **`objects/`:** Base de datos de objetos clave-valor indexada por el hash SHA-1. Cada objeto se almacena comprimido mediante el algoritmo **zlib** bajo una subcarpeta nombrada con los primeros 2 dígitos del hash (ej. `.git/objects/4b/825dc642cb6eb9a060e54bf8d69288fbee4904`). Existen cuatro tipos de objetos:
  1. *blob:* Contenido crudo de un archivo.
  2. *tree:* Directorios que asocian nombres de archivos con sus respectivos hashes SHA-1.
  3. *commit:* Metadatos de un cambio (autor, fecha, mensaje, árbol raíz y hash del commit padre).
  4. *tag:* Referencia estática a un commit.
- **`refs/` y `logs/`:** Almacenan punteros a las cabezas de las ramas locales (`refs/heads/`), ramas remotas (`refs/remotes/`) y el historial secuencial de movimientos de punteros (`logs/HEAD`, `logs/refs/...`).

---

### 2. Mecanismo de descarga y reconstrucción automatizada (`git-dumper`)
En un servidor web con la indexación de directorios (*Directory Listing*) desactivada, un atacante no puede navegar libremente para listar los archivos de `.git/objects/`. Sin embargo, la propia arquitectura interna de Git permite sortear esta restricción de forma determinística:

```
[Atacante]
    |
    |-- (1) GET /.git/config  ---------> Descubre URLs internas y configuración
    |-- (2) GET /.git/HEAD    ---------> Identifica rama activa (ej. refs/heads/main)
    |-- (3) GET /.git/index   ---------> Descarga el índice binario con todos los hashes SHA-1
    |                                            |
    |                                            v (Parsea paths y hashes de objetos)
    |-- (4) GET /.git/objects/xx/xxxx... ------> Descarga recursiva de blobs zlib
    |                                            |
    v                                            v
[Reconstrucción local] ------------------------> git checkout . (Código fuente 100% restaurado)
```

Herramientas especializadas como **`git-dumper`** (desarrollada por *arthaud*) y el conjunto de scripts **`GitTools`** (*internetwache*) automatizan este proceso:

1. **Obtención del índice:** La herramienta descarga el archivo `/.git/index` mediante una petición HTTP estándar.
2. **Parseo del archivo de índice:** Lee la cabecera `DIRC` (*Directory Cache*), la versión del formato y la cantidad de entradas. Itera sobre cada registro extrayendo el hash SHA-1 de 40 caracteres y la ruta relativa del archivo en el proyecto.
3. **Descarga selectiva de objetos:** Como el hash de cada archivo es conocido gracias al índice, la herramienta solicita de manera predecible y directa cada objeto al servidor: `/.git/objects/<hash[0:2]>/<hash[2:]>`.
4. **Descompresión y extracción de la historia:** Utilizando la librería `zlib`, descomprime los objetos descargados. Además, lee `/.git/logs/HEAD` y los objetos *commit* y *tree* para reconstruir el historial completo de versiones.
5. **Reconstrucción del working directory:** Al completar la descarga de la base de datos de objetos, invoca internamente `git checkout -f` o recrea el árbol de carpetas en el disco local del atacante, dejando la totalidad del proyecto exactamente igual a como lo tenía el desarrollador en su entorno local.

---

### 3. Casos reales y vectores de fuga de credenciales
La exposición de directorios `.git` es clasificada por OWASP dentro de la categoría **A05:2021 — Security Misconfiguration** y ha provocado incidentes de seguridad de escala global:

1. **Filtración masiva en sistemas de las Naciones Unidas (ONU, 2021):**
   Investigadores de seguridad de la consultora Sakura Samurai descubrieron directorios `.git` expuestos en portales de la Organización de las Naciones Unidas (UNEP e ILPI). Utilizando herramientas de volcado de Git, descargaron el código fuente de los portales, dentro de cuyo historial de commits encontraron credenciales de acceso en texto claro a bases de datos de producción y credenciales de cuentas de administración de WordPress y AWS. El incidente expuso más de 100.000 registros personales de empleados de la ONU.
2. **Caso de portales gubernamentales australianos (2018):**
   Un escaneo coordinado sobre dominios gubernamentales descubrió decenas de sitios municipales y estatales con carpetas `.git` abiertas. La reconstrucción de los repositorios reveló archivos de configuración de bases de datos que contenían cadenas de conexión completas (incluyendo usuarios `root` y passwords sin ofuscar) y certificados SSL privados, permitiendo la toma de control de los servidores de bases de datos sin necesidad de explotar vulnerabilidades en la aplicación web.
3. **Casos recurrentes en Bug Bounty (HackerOne / Bugcrowd):**
   En programas de divulgación de vulnerabilidades de empresas como Uber, Yahoo y Shopify, reportes de `/.git/` expuestos han sido calificados recurrentemente con severidad **Alta** o **Crítica**, otorgando recompensas de miles de dólares debido a que los atacantes acceden a tokens de plataformas de mensajería (Slack/Discord Webhooks), llaves de API de pasarelas de pago (Stripe) y secretos de firma de tokens de sesión (JWT Secrets), lo que permite falsificar identidades administrativas (*Privilege Escalation*).

---

## Fuentes

1. **Git Project Documentation (2024).** *Git Internals — Plumbing and Porcelain & Git Objects*. Software Freedom Conservancy.  
   Disponible en: https://git-scm.com/book/en/v2/Git-Internals-Git-Objects
2. **OWASP Foundation (2021).** *OWASP Top 10:2021 — A05: Security Misconfiguration*. Open Worldwide Application Security Project.  
   Disponible en: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
3. **Sakura Samurai Security Research (2021).** *United Nations Data Breach: How Exposed .git Directories Leaked Over 100k Records*. HackerOne Disclosure & Public Advisory.  
   Disponible en: https://sakurasamurai.org/blog/united-nations-breach/
4. **Internetwache / Arthaud (2020).** *GitTools & Git-Dumper: A repository dumper when directory listing is disabled*. GitHub Open Source Archive.  
   Disponible en: https://github.com/arthaud/git-dumper

---

## Reflexión

La exposición de un directorio `.git` evidencia la peligrosa brecha que suele existir entre el desarrollo de software y las operaciones en producción. Subir un proyecto mediante un simple `git pull` en la raíz web es una mala práctica que anula todas las medidas de seguridad del código: expone el historial de desarrollo, secretos que alguna vez fueron commiteados por descuido y entrega al atacante el plano exacto para planificar su explotación en caja blanca. La seguridad en el ciclo de vida de desarrollo exige aislar los artefactos de compilación mediante pipelines de CI/CD automatizados y configurar los servidores web con políticas defensivas estrictas que denieguen por defecto el acceso a cualquier archivo o carpeta que comience con un punto.

