# Laboratorio 06 — Enumeración de servicios

**Unidad 6** · Discovery (ATT&CK `TA0007`) sobre PhantomCorp
**Grupo:** 02
**Integrantes:** _(completar)_
**Entorno:** Docker — target `phantomcorp` (puerto 80)

> Continúa el engagement del Lab 05. Partimos del mapa de recon (puerto 80,
> PhantomCMS) y pasamos a enumerar en profundidad cada servicio.

---

## 1. Inventario de enumeración

> Pegá en la columna **Evidencia** la línea literal de la salida de cada tool
> (ej. la fila `CODE:200` de dirb, el header `Allow:`, el JSON de la API).

| # | Hallazgo | Ruta / Método | Técnica usada | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|---|
| R1 | Directorio de backups accesible y listable | `/backup/` (CODE:200) | `dirb` (fuerza bruta de rutas) | `+ http://phantomcorp/backup (CODE:200\|SIZE:249)` → lista `respaldo-db-2024.sql.gz`, `config.old`, `notas-infra.txt`. Flag: `FLAG{dir_enumeration_backup}` | **Alto** | Backup de base de datos y `config.old` accesibles → credenciales / dump de datos → acceso inicial |
| R2 | Repositorio Git expuesto | `/.git/config` (CODE:200) | `curl` sobre rutas `.git` | `.git/config` servido por HTTP, con `url = https://git.internal.phantomcorp/intranet.git`. Flag: `FLAG{git_repo_exposed}` | **Crítico** | Reconstrucción del código fuente e historia completa (git-dumper) → host Git interno, posibles secretos commiteados |
| R3 | Métodos HTTP peligrosos habilitados | `OPTIONS /` → header `Allow` | `curl -X OPTIONS -i` | `Allow: GET, POST, PUT, DELETE, OPTIONS` + `X-Dangerous-Methods: FLAG{http_methods_put_enabled}` | **Alto** | `PUT`/`DELETE` activos → subida de webshell → RCE en el servidor |
| R4 | API interna que enumera usuarios | `/api/users` (JSON) | `curl … \| python3 -m json.tool` | 3 usuarios con rol: `admin/superuser`, `jperez/editor`, `mgomez/viewer`; nota "endpoint interno de RRHH - no exponer". Flag: `FLAG{user_enumeration_api}` | **Medio-Alto** | Lista de usuarios válidos + roles → password spraying / brute force dirigido a `admin` |
| R5 | Fingerprinting: CMS + versión y archivo default | `PhantomCMS 3.7` — `/phantomcms/VERSION` | `whatweb -a 3` + `curl` del archivo default | `whatweb`: `HTTPServer[PhantomServer/3.7]`, `MetaGenerator[PhantomCMS 3.7]`, `X-Powered-By[PhantomCMS/3.7]`; `/phantomcms/VERSION` → `PhantomCMS 3.7 (build 2024-11)`. Flag: `FLAG{tech_fingerprint_phantomcms}` | **Medio** | Producto + versión exactos → búsqueda de CVE específico de PhantomCMS 3.7 (metodología Lab 05) |

**Flags obtenidas: 5/5** → R1 `FLAG{dir_enumeration_backup}` · R2 `FLAG{git_repo_exposed}` · R3 `FLAG{http_methods_put_enabled}` · R4 `FLAG{user_enumeration_api}` · R5 `FLAG{tech_fingerprint_phantomcms}`. Ver captura de `./ctf status 06` (sección 3).

---

## 2. Preguntas de análisis

### P1 · Enumeración vs. reconocimiento

En el **Lab 05 (recon)** la pregunta fue *"¿qué hay?"*: escaneo de puertos con
`nmap` que reveló el puerto 80 abierto, y lectura de banners/headers que
identificaron el servicio como PhantomCMS. Salida: el **mapa** (qué servicios
corren y dónde).

En este **Lab 06 (enumeración)** la pregunta es *"¿qué esconde ese servicio?"*:
fuerza bruta de rutas con `dirb` para encontrar `/backup/` (que no estaba
linkeado en ningún lado) y consulta directa del `.git/config` por HTTP. Salida:
el **inventario detallado** del interior de un único servicio.

En una frase: el recon nos dijo *que había* un web server; la enumeración nos
dijo *qué contiene* ese web server. Lo primero es una observación, lo segundo
es un plan de ataque.

### P2 · El `.git` expuesto

Un directorio `/.git/` servido por HTTP expone toda la base de datos interna de
Git: `config`, `HEAD`, los `refs`, el índice y, sobre todo, los **objetos**
(`.git/objects/`) que contienen cada versión de cada archivo commiteado.

Con una herramienta como `git-dumper` un atacante descarga todo ese árbol y
**reconstruye el repositorio completo**: no solo el código fuente actual, sino
**toda la historia de commits**. Eso le da:

- La lógica de negocio y la estructura de la app (rutas internas, validaciones,
  endpoints no documentados).
- Credenciales, API keys o cadenas de conexión que alguien commiteó "por un
  momento" y después borró — pero que **siguen vivas en la historia** del repo,
  aunque no estén en la versión actual.
- Comentarios, TODOs y nombres de archivos que revelan dónde están las partes
  débiles.

Por eso es mucho más grave que "un archivo de más": un archivo filtrado expone
un dato puntual; un `.git` expuesto expone **el programa entero y su pasado**, y
convierte un ataque de caja negra en uno de caja blanca.

### P3 · El método `PUT` habilitado

El método HTTP `PUT` le dice al servidor *"guardá este cuerpo en esta ruta"*. Si
está habilitado sin autenticación ni validación, el ataque concreto es **subir un
webshell**:

```bash
# El atacante sube un script ejecutable del lado del servidor
curl -X PUT http://phantomcorp/shell.php --data-binary @shell.php
# Luego lo invoca para ejecutar comandos
curl "http://phantomcorp/shell.php?cmd=id"
```

Donde `shell.php` contiene algo como `<?php system($_GET['cmd']); ?>`. El
resultado es **ejecución remota de comandos (RCE)** en el servidor: el atacante
pasa de "puedo leer el sitio" a "puedo correr comandos como el usuario del web
server". Por eso un `Allow: ... PUT ...` en la respuesta a `OPTIONS` es una
alarma roja y conecta directo con la fase de explotación.

### P4 · La API que enumera usuarios

Aunque `/api/users` no muestre contraseñas, **enumerar usuarios válidos ya es
media autenticación resuelta** para el atacante. El login tiene dos incógnitas:
usuario y contraseña. Una lista de usuarios reales elimina una de las dos y
convierte un ataque inviable en uno práctico:

- **Password spraying:** probar una contraseña débil común (`Verano2025`,
  `Phantom123`) contra *todos* los usuarios conocidos, evitando el bloqueo por
  intentos fallidos sobre una sola cuenta.
- **Brute force dirigido:** concentrar el esfuerzo en cuentas que existen, en
  vez de adivinar nombres.
- **Phishing / ingeniería social:** con nombres y roles reales, los señuelos son
  mucho más creíbles.

Pensando en la fase siguiente (Lab 07): la enumeración de usuarios es el insumo
que hace realista el ataque a credenciales. "No muestra contraseñas" no mitiga
el riesgo, solo lo demora un paso.

### P5 · Como defensor — mitigaciones

**1. `.git` expuesto**
Bloquear el acceso HTTP a directorios ocultos en el servidor web
(`location ~ /\.git { deny all; }` en nginx, o `RedirectMatch 404 /\.git` en
Apache) y, sobre todo, **desplegar sin el `.git`**: usar `git archive`, un
pipeline de CI que copie solo los artefactos, o `.gitignore`/exclusiones en el
despliegue. Nunca servir el árbol de trabajo del repo.

**2. Método `PUT` habilitado**
Deshabilitar los métodos de escritura en la configuración del servidor
(`LimitExcept` en Apache / limitar a `GET POST HEAD` en nginx) y, si WebDAV no se
usa, quitar el módulo por completo. Verificar con `OPTIONS` que el header `Allow`
solo liste los métodos necesarios.

**3. Directorio `/backup/` accesible**
Sacar los backups fuera del document root (no deben ser alcanzables por URL),
denegar el listado de directorios (`autoindex off` / `Options -Indexes`) y rotar
cualquier credencial que haya quedado expuesta en esos archivos.

_(Alternativa para la API `/api/users`: exigir autenticación y autorización en el
endpoint, devolver solo los datos del propio usuario y aplicar rate limiting.)_

---

## 3. Captura de `./ctf status 06`

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 06                        │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Enumeracion de directorios
   ✓  R2     Repositorio Git expuesto
   ✓  R3     Metodos HTTP peligrosos habilitados
   ✓  R4     Enumeracion de usuarios via API
   ✓  R5     Fingerprinting de tecnologia

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 06 COMPLETO!
```

---

## 4. Conclusión

La enumeración transformó el "hay un PhantomCMS en el puerto 80" del Lab 05 en un
inventario accionable: un `/backup/` accesible, el código fuente filtrado por un
`.git`, una API que lista usuarios y métodos de escritura habilitados. Cada
hallazgo es un punto de entrada concreto para la fase de explotación (Lab 07),
priorizado por riesgo en la tabla de la sección 1.
