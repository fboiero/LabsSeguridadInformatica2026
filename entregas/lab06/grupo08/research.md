# Mini-research — Laboratorio 06

**Tema elegido:** A — Cómo un `.git` expuesto permite reconstruir el código (git-dumper) y la fuga de secretos por esta vía.

- [x] **A.** Cómo un `.git` expuesto permite reconstruir el código (git-dumper) y
  casos reales de credenciales filtradas por esta vía.
- [ ] **B.** Wordlists de enumeración: qué son SecLists, cómo se eligen, por qué
  una wordlist mala hace fallar la enumeración.
- [ ] **C.** El método HTTP `PUT` y el WebDAV: cómo se pasa de "método habilitado"
  a subir un webshell.
- [ ] **D.** Fingerprinting pasivo vs. activo: cómo `whatweb` deduce el stack.

## Desarrollo

### Qué es realmente el directorio `.git`

Cuando se hace `git init` en un proyecto, git crea un directorio `.git/` que es
la **base de datos completa del repositorio**: no guarda solo el código actual,
sino toda su historia. Sus piezas clave son:

- `HEAD` — apunta a la rama activa (`ref: refs/heads/main`).
- `config` — configuración local: nombre del repo, remotos, URLs internas.
- `index` — el *staging area*: una lista binaria de **todos** los archivos
  versionados, cada uno con el hash SHA-1 de su contenido.
- `objects/` — el almacén de contenido. Cada versión de cada archivo (*blob*),
  cada árbol de directorios (*tree*) y cada *commit* se guarda como un objeto
  comprimido con zlib, nombrado por el SHA-1 de su contenido. Pueden estar
  sueltos (`objects/ab/cdef...`) o agrupados en *packfiles* (`objects/pack/`).
- `refs/` y `logs/` — punteros a commits (ramas, tags) y el historial de
  movimientos de cada ref.

El punto que hace esto peligroso: **no hace falta un directorio listable**. Aunque
el servidor no muestre un *index of* de `/.git/`, el atacante puede pedir los
archivos por su nombre conocido y, a partir de ahí, seguir la cadena de hashes.

### Cómo se reconstruye el código con `git-dumper`

El flujo que automatizan herramientas como **git-dumper** (arthaud) o
**GitTools/Dumper+Extractor** (internetwache) es:

1. Comprobar que `/.git/` existe pidiendo `/.git/HEAD` o `/.git/config`.
2. Si el servidor lista el directorio, bajar todo recursivamente. Si **no** lista
   (el caso más común y más interesante), partir de archivos de nombre fijo:
   `HEAD`, `config`, `index`, `packed-refs`, `logs/HEAD`, `objects/info/packs`.
3. Parsear `.git/index` para obtener los SHA-1 de todos los blobs versionados y
   pedir cada objeto por su ruta derivada del hash (`objects/ab/cdef…`).
4. Para cada objeto descargado, descomprimirlo, leer a qué otros objetos
   referencia (un commit apunta a su árbol y a su commit padre; un árbol apunta a
   blobs y subárboles) y **seguir recursivamente** esas referencias. Así se baja
   todo el grafo sin necesidad de listado.
5. Con los objetos locales, un `git checkout` reconstruye el *working tree*: el
   código fuente completo queda en disco.

El resultado es que el atacante pasa de atacar **a ciegas (caja negra)** a tener
el código y **leer la lógica**: cómo valida el login, qué endpoints existen
aunque no estén linkeados, y qué parámetros llegan sin sanitizar a una consulta
SQL o a un comando del sistema.

### Por qué filtra secretos (y no solo el código actual)

Lo más grave no es el código de hoy, sino la **historia**. Un secreto commiteado
por error —una contraseña de base de datos, una API key, un `.env`— y "borrado"
en un commit posterior **sigue vivo** en los objetos anteriores: `git log -p`,
`git show <hash>` o un `git checkout` de un commit viejo lo recuperan. Borrar el
archivo en `HEAD` no lo saca del almacén de objetos. Por eso, tras reconstruir el
repo, el paso típico es pasarle un buscador de secretos (gitleaks, trufflehog)
sobre **toda** la historia, no solo sobre la copia actual.

### Escala del problema

No es un caso de laboratorio aislado. Relevamientos públicos de internet han
encontrado **cientos de miles** de dominios sirviendo `/.git/` accesible por HTTP,
producto de desplegar haciendo `git clone`/`git pull` directo sobre el *docroot*
en lugar de publicar un artefacto limpio. Es una exposición de código fuente
clasificada como **CWE-527** (*Exposure of Version-Control Repository to an
Unauthorized Control Sphere*) y es una de las verificaciones estándar de la guía
de testing de OWASP (WSTG).

### Qué vimos en PhantomCorp

En nuestro Lab 06, `/.git/config` respondió `200` y filtró un remoto interno
(`https://git.internal.phantomcorp/intranet.git`), lo que confirma que el `.git`
quedó en el *docroot* (`bare = false` → copia de trabajo desplegada con git). Sin
embargo, `/.git/HEAD` y `/.git/` devolvieron `404`, así que **en este target no se
pudo bajar el repo entero**: faltaban los puntos de entrada (`HEAD`, `index`) que
git-dumper necesita para seguir la cadena de objetos. Es la diferencia entre "hay
un `.git` mal configurado" (lo que probamos) y "se puede reconstruir todo" (lo que
pasaría en un servidor que sirviera también `HEAD`, `index` y `objects/`).

### Mitigación

- **No desplegar el repositorio.** Publicar solo el artefacto construido (un
  export sin `.git`), por ejemplo con un pipeline de CI que copie los archivos y
  deje el repo afuera del *docroot*.
- **Bloquear el acceso a ocultos** en el servidor: `location ~ /\.(git|svn|env) { deny all; }`
  en nginx, o equivalente, devolviendo `403/404` a todo lo que empiece con `.`.
- **Rotar todo secreto que alguna vez estuvo en la historia.** Si una credencial
  fue commiteada, hay que cambiarla: reescribir la historia (`git filter-repo`)
  reduce el riesgo pero no deshace que ya pudo ser clonada.

## Fuentes (mín. 3, verificables)

1. Git — *Git Internals: Git Objects* (modelo de objetos blob/tree/commit):
   https://git-scm.com/book/en/v2/Git-Internals-Git-Objects
2. Git — *Git Internals: Plumbing and Porcelain* (`HEAD`, `index`, `refs`):
   https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain
3. git-dumper (arthaud), herramienta de reconstrucción de `.git` expuestos:
   https://github.com/arthaud/git-dumper
4. GitTools (internetwache), *Dumper*/*Extractor* para `.git` sin listado:
   https://github.com/internetwache/GitTools
5. MITRE — CWE-527: *Exposure of Version-Control Repository to an Unauthorized
   Control Sphere*: https://cwe.mitre.org/data/definitions/527.html
6. OWASP Web Security Testing Guide — *Review Webserver Metafiles / exposed
   source code*: https://owasp.org/www-project-web-security-testing-guide/

## Reflexión (3–5 líneas)

Lo que más nos sorprendió es que un `.git` expuesto no necesita que el servidor
liste el directorio: alcanza con `HEAD` e `index` para que una herramienta siga
la cadena de hashes y reconstruya todo. También entendimos por qué es peor que un
backup suelto: no expone un archivo, expone la historia entera, y un secreto
"borrado" sigue recuperable. En nuestro target el daño quedó acotado porque solo
`config` era accesible, pero la lección es que la mitigación no es ocultar la ruta
sino no desplegar el repositorio y rotar cualquier secreto que haya pasado por él.
