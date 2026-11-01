# Mini-research — Laboratorio 06

**Tema elegido:** *(uno)*

- [x] **A.** Cómo un `.git` expuesto permite reconstruir el código (git-dumper) y
  casos reales de credenciales filtradas por esta vía.
- [ ] **B.** Wordlists de enumeración: qué son SecLists, cómo se eligen, por qué
  una wordlist mala hace fallar la enumeración.
- [ ] **C.** El método HTTP `PUT` y el WebDAV: cómo se pasa de "método habilitado"
  a subir un webshell.
- [ ] **D.** Fingerprinting pasivo vs. activo: cómo `whatweb` deduce el stack.

---

## Desarrollo

### 1. El problema: cuando el control de versiones queda expuesto

Uno de los errores más comunes al poner un sitio web en producción es realizar un despliegue rápido usando `git clone` o `git pull` directo sobre la carpeta raíz que sirve el servidor web (por ejemplo, en `/var/www/html`), o empaquetar un archivo `.zip` con todo el contenido del proyecto sin acordarse de excluir las carpetas ocultas.

A simple vista, un administrador puede pensar: *"no pasa nada, el servidor web no tiene listado de directorios habilitado (directory listing desactivado), así que nadie puede ver lo que hay adentro de `/.git/`"*. Sin embargo, Git no es una simple carpeta de backups: es una base de datos de objetos altamente estructurada y completamente predecible. Si el servidor web responde a peticiones directas de archivos estáticos dentro de `/.git/`, un atacante no necesita listar el directorio para descargarse el proyecto entero.

### 2. Cómo funciona la reconstrucción con herramientas como `git-dumper`

Herramientas automáticas como `git-dumper` (escrita en Python) o `rip-git` explotan la propia lógica del protocolo de Git para reconstruir el repositorio en local, petición por petición:

1. **Sondeo de archivos clave:** La herramienta empieza pidiendo los archivos estándar que sabe que siempre existen en la raíz de Git: `/.git/HEAD` y `/.git/config`. Al leer `HEAD`, descubre a qué rama apunta el entorno (por ejemplo, `ref: refs/heads/main` o `ref: refs/heads/master`).
2. **Descubrimiento del commit actual:** Conociendo la rama activa, solicita `/.git/refs/heads/main`. Ese archivo contiene una sola línea de texto plano: el hash SHA-1/SHA-256 de 40 caracteres del último commit (por ejemplo, `a1b2c3d4...`).
3. **Descarga del árbol de objetos:** En Git, los objetos se guardan comprimidos con el algoritmo zlib bajo la ruta `/.git/objects/<2 primeros caracteres>/<38 caracteres restantes>`. La herramienta pide `/.git/objects/a1/b2c3d4...`, lo descomprime en memoria y parsea el objeto de tipo `commit`.
4. **Recorrido de árboles (trees) y blobs:** Dentro del commit está el hash del objeto `tree` raíz del proyecto. Al descargarlo y descomprimirlo, obtiene el listado de todos los nombres de archivos y carpetas del código fuente, junto con los hashes de cada uno (los `blobs`).
5. **Reconstrucción del working directory:** La herramienta repite este proceso de forma recursiva: solicita cada objeto por su hash, lo descomprime y lo va guardando en disco en su estructura de directorios original. Al terminar, ejecuta un `git checkout` y el atacante obtiene una copia exacta del código fuente que los desarrolladores tienen en sus máquinas.
6. **Recuperación de historia y branches:** Si además están accesibles `/.git/index` (el staging) o `/.git/logs/HEAD` (el reflog), el atacante puede descubrir commits antiguos, ramas secundarias de prueba y cambios que fueron modificados o borrados en el tiempo.

### 3. Casos reales: cuando un directorio expuesto expone a organizaciones enteras

El impacto de esta mala configuración no es teórico, sino uno de los hallazgos más reportados en auditorías de seguridad y programas de Bug Bounty:

* **Filtración masiva en Naciones Unidas (ONU / UNEP, 2021):** El grupo de investigación *Sakura Samurai* detectó directorios `.git` expuestos en subdominios oficiales del Programa de las Naciones Unidas para el Medio Ambiente (UNEP) y la OCHA. Utilizando técnicas de volcado de Git, descargaron repositorios que contenían credenciales de bases de datos hardcodeadas, configuraciones `.env` de WordPress y claves de acceso que terminaron exponiendo más de 100.000 registros personales de empleados y datos de viajes oficiales.
* **Fuga de tokens de infraestructura en Bug Bounty (HackerOne):** Son frecuentes los reportes donde investigadores encuentran subdominios olvidados (entornos de *staging* o desarrollo antiguos) que dejaron la carpeta `.git` accesible. En múltiples casos reportados a empresas de transporte y plataformas de comercio electrónico, los repositorios no solo revelaron la lógica del backend, sino tokens de servicios en la nube (AWS Access Keys, cuentas de SendGrid para enviar correos y webhooks internos de Slack) que habían sido commiteados en versiones iniciales. Aunque los programadores habían borrado las claves en un commit posterior, seguían guardadas en los objetos históricos del repositorio.

---

## Fuentes (mín. 3, verificables)

1. **Chacon, S., & Straub, B. (2014).** *Pro Git (2nd Edition) — Chapter 10: Git Internals*. Apress. Disponible en: https://git-scm.com/book/en/v2/Git-Internals-Git-Objects  
   *(Explica la estructura interna de los objetos Git en disco: commits, trees, blobs y empaquetado zlib).*
2. **Arthaud, M. (2020).** *git-dumper: A tool to dump a git repository from a website*. Repositorio oficial en GitHub: https://github.com/arthaud/git-dumper  
   *(Documenta la metodología práctica para consultar recursivamente objetos Git mediante peticiones HTTP sin listado de directorios).*
3. **Cimpanu, C. / ZDNet & BleepingComputer (2021).** *UN data breach exposed personal data of over 100k staff via exposed Git directories*. Disponible en: https://www.bleepingcomputer.com/news/security/over-100k-un-employee-records-exposed-in-recent-data-breach/  
   *(Caso real documentado donde el grupo Sakura Samurai utilizó repositorios Git expuestos para comprometer infraestructura y credenciales de la ONU).*

---

## Reflexión (3–5 líneas)

Este análisis demuestra que la seguridad no suele fallar por vulnerabilidades complejas en el código, sino por descuidos graves durante el despliegue. Considerar que la carpeta `.git` es inofensiva por estar "oculta" es un error crítico: un repositorio no muestra únicamente lo que se ve en la web hoy, sino todo lo que alguna vez se commiteó y se creyó borrado. La lección fundamental para cualquier equipo de desarrollo es desterrar los despliegues manuales y utilizar pipelines de CI/CD que aíslen y empaqueten exclusivamente los artefactos finales de producción.
