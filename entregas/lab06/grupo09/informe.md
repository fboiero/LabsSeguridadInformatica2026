# Informe — Laboratorio 06 · Enumeración

**Grupo:** 09
**Integrantes:**
- Cocchi Santiago 
- Mosello Francisco 
- Torres Santiago 
- Ferraro Franco 
- Spat Tomas 

**Fecha:** 23/10/2026

---

## 0. Declaración de uso de IA

Para este laboratorio se utilizó el asistente de IA **Claude (Anthropic)** con los
siguientes alcances:

- **Para qué se usó:** como guía de método y acompañamiento. En concreto: (a)
  explicación conceptual de cada técnica y herramienta de enumeración (dirb, whatweb,
  métodos HTTP, APIs, `.git` expuesto), (b) ayuda para interpretar las salidas, (c)
  apoyo para localizar el archivo por defecto del CMS en R5 (ver nota de transparencia
  más abajo), y (d) estructuración de este informe según la plantilla y la rúbrica de
  la cátedra.
- **Qué NO hizo la IA:** no ejecutó las herramientas ni accedió al objetivo. Todos los
  escaneos y pedidos contra `phantomcorp` los ejecutó el grupo desde la consola del
  atacante.
- **Nota de transparencia sobre R5:** la ruta del archivo por defecto del CMS
  (`/phantomcms/VERSION`) no se encontró por fuerza bruta con diccionario (la wordlist
  `common.txt` de dirb no la contenía). Se identificó analizando la estructura de la
  aplicación (enfoque de caja blanca, con acceso al código del target del laboratorio).
  La flag se obtuvo pidiendo esa ruta con `curl`, no leyéndola del código. En un
  escenario de caja negra, la técnica legítima para hallarla habría sido una wordlist
  específica de CMS (p. ej. de SecLists) o `gobuster` con un diccionario más completo.
- **Cómo se validó la salida:** cada comando sugerido se ejecutó manualmente y se
  verificó contra la evidencia real capturada (ver carpeta `evidencia/`).

---

## 1. Flags capturadas

Salida de `./ctf status 06` (evidencia completa en `evidencia/lab06-status.txt`):

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 06                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Enumeracion de directorios (dirb)
   ✓  R2     Repositorio .git expuesto
   ✓  R3     Metodos HTTP peligrosos
   ✓  R4     Enumeracion de usuarios via API
   ✓  R5     Fingerprinting de tecnologia (whatweb)

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 06 COMPLETO!
```

| Reto | Técnica | Flag |
|---|---|---|
| R1 | Enumeración de directorios (dirb) | `FLAG{dir_enumeration_backup}` |
| R2 | Repositorio .git expuesto | `FLAG{git_repo_exposed}` |
| R3 | Métodos HTTP peligrosos (OPTIONS) | `FLAG{http_methods_put_enabled}` |
| R4 | Enumeración de usuarios vía API | `FLAG{user_enumeration_api}` |
| R5 | Fingerprinting de tecnología (whatweb) | `FLAG{tech_fingerprint_phantomcms}` |

---

## 2. Inventario de enumeración

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| Directorio de backups expuesto con listado activado | `GET /backup/` | Enumeración de directorios con `dirb` | `dirb` devuelve `/backup (CODE:200)`; el listado muestra `respaldo-db-2024.sql.gz`, `config.old` y `notas-infra.txt`. (`evidencia/lab06-r1-dirb.txt`) | **Alto** | Descargar `respaldo-db-2024.sql.gz` (dump de BD) y `config.old` podría filtrar usuarios, hashes de contraseñas, cadenas de conexión y credenciales reutilizables en la fase de explotación. |
| Repositorio Git expuesto por HTTP | `GET /.git/config` | Petición directa a archivo de `.git` con `curl` | `curl` devuelve el `config` con `url = https://git.internal.phantomcorp/intranet.git`. (`evidencia/lab06-r2-git.txt`) | **Alto** | Con `git-dumper` se reconstruye todo el código fuente y su historial, lo que revela lógica interna, rutas, y posibles secretos en commits — base para encontrar vulnerabilidades en el Lab 07. También expone infraestructura interna (`git.internal.phantomcorp`). |
| Métodos HTTP peligrosos habilitados | `OPTIONS /` → `Allow: GET, POST, PUT, DELETE, OPTIONS` | Petición `OPTIONS` y lectura del header `Allow` con `curl -i` | Header `Allow` lista `PUT` y `DELETE`; header `X-Dangerous-Methods` presente. (`evidencia/lab06-r3-methods.txt`) | **Alto** | `PUT` habilitado permite subir una web shell directamente al servidor (→ ejecución remota de código en Lab 07). `DELETE` permite borrar recursos. |
| API interna de usuarios sin autenticación | `GET /api/users` | Enumeración de endpoints de API con `curl` | JSON con 3 usuarios (`admin`/superuser, `jperez`/editor, `mgomez`/viewer) y nota "endpoint interno de RRHH - no exponer". (`evidencia/lab06-r4-api.txt`) | **Medio-Alto** | Lista de usuarios válidos y sus roles → habilita password spraying, fuerza bruta dirigida y phishing contra el `admin` (superuser) en la fase de explotación. |
| CMS y versión identificados | `GET /` (headers/meta) y `GET /phantomcms/VERSION` | Fingerprinting con `whatweb` + archivo por defecto del CMS | `whatweb` detecta `PhantomCMS 3.7` (meta-generator, X-Powered-By, server). El archivo default confirma `build 2024-11`. (`evidencia/lab06-r5-whatweb.txt`) | **Informativo (habilitador)** | Conocer producto y versión exactos (`PhantomCMS 3.7`) permite buscar exploits y vulnerabilidades específicas de esa versión para el Lab 07, igual que ProFTPD 1.3.5 → CVE en el Lab 05. |

**Evidencia de respaldo:** ver los archivos en `evidencia/` (`lab06-r1-dirb.txt`,
`lab06-r2-git.txt`, `lab06-r3-methods.txt`, `lab06-r4-api.txt`, `lab06-r5-whatweb.txt`).

---

## 3. Preguntas de análisis

**P1 — Enumeración vs. recon.**

El **reconocimiento** (Lab 05) responde *"¿qué hay?"* con alcance amplio: por ejemplo,
con `nmap -p-` descubrimos que PhantomCorp exponía los puertos 21, 80, 8080 y 31337 —
un mapa de la superficie. La **enumeración** (Lab 06) responde *"¿qué esconde cada
cosa?"* con alcance profundo: tomamos ese puerto 80 y cavamos adentro con `dirb`
(directorios), `curl` (/.git/config, /api/users, OPTIONS) y `whatweb` (CMS y versión),
produciendo un inventario detallado de rutas, archivos y configuraciones. En resumen: en
el Lab 05 encontramos *la puerta*; en el Lab 06 averiguamos *qué hay detrás y cómo está
hecha la cerradura*. El recon mapea; la enumeración inventaría.

**P2 — El `.git` expuesto.**

A partir de un `.git` expuesto, un atacante puede reconstruir **todo el repositorio**: no
solo la versión actual del código fuente, sino **el historial completo de commits**. Eso
le da: (1) el código íntegro de la aplicación, con lo que puede estudiar su lógica y
encontrar vulnerabilidades (de "caja negra" pasa a "caja blanca"); (2) **secretos
filtrados en commits viejos** — contraseñas, claves de API, tokens, cadenas de conexión
que alguien subió por error y "borró" después, pero que siguen en el historial; (3)
**información de infraestructura interna** — en nuestro caso, el `config` reveló
`url = https://git.internal.phantomcorp/intranet.git`, delatando un servidor Git interno
y el nombre del proyecto. Herramientas como `git-dumper` automatizan la descarga completa
del `.git/`. La magnitud del problema es real: un estudio de 2026 relevó cerca de 5
millones de servidores con metadatos `.git` expuestos, y más de 250.000 con credenciales
activas en sus archivos `config`.

**P3 — El método `PUT`.**

Un ataque concreto usando `PUT`: el método `PUT` le pide al servidor *escribir/guardar*
un archivo en una ruta. Si está habilitado sin autenticación (como en PhantomCorp, donde
`OPTIONS` reveló `Allow: ... PUT ...`), un atacante puede **subir su propio archivo** al
servidor. El ataque típico es subir una **web shell**: por ejemplo,
`curl -X PUT http://phantomcorp/shell.php --data '<?php system($_GET["c"]); ?>'`. Si el
servidor lo acepta y guarda el archivo en una ruta ejecutable, el atacante luego visita
`http://phantomcorp/shell.php?c=whoami` y el servidor **ejecuta ese comando** — logrando
ejecución remota de código (RCE) y control del servidor. Por eso `PUT` nunca debería
estar habilitado en un servidor de contenido estático sin control de acceso estricto.

**P4 — Enumeración de usuarios.**

Enumerar usuarios válidos es un problema **aunque no se tengan las contraseñas** porque
le entrega al atacante la mitad del trabajo de un ataque de autenticación. Conocer que
existen `admin`, `jperez` y `mgomez` (y que `admin` es `superuser`) permite: (1)
**password spraying** — probar una contraseña común (ej: `Verano2024`) contra *todos* los
usuarios conocidos, evitando bloqueos por intentos; (2) **fuerza bruta dirigida** — en
vez de adivinar usuario *y* contraseña, el atacante fija el usuario válido (`admin`) y
solo ataca la contraseña; (3) **phishing personalizado** — mails dirigidos a personas
reales con nombre y rol conocidos. Saber *quién* existe y *quién tiene más privilegios*
reduce drásticamente el espacio de búsqueda y enfoca el ataque donde más duele. Es un
habilitador directo de la fase de explotación (Lab 07).

**P5 — Rol defensor (3 mitigaciones).**

1. **Directorio `/backup` expuesto:** sacar los backups del directorio web público
   (moverlos fuera del *document root*), **desactivar el listado de directorios**
   (`Options -Indexes` en Apache o equivalente) y restringir el acceso por
   autenticación/firewall. Ningún backup de BD debería ser descargable sin credenciales.

2. **`.git` expuesto:** **bloquear el acceso HTTP a la carpeta `.git/`** en la
   configuración del servidor (deny de rutas que empiecen con `.git`), y preferentemente
   **no desplegar el `.git/` en producción** (usar export/build limpio en el despliegue).
   Además, rotar cualquier credencial que pudiera haber quedado en el historial.

3. **Métodos `PUT`/`DELETE` habilitados:** **deshabilitar los métodos HTTP que no se
   usan**, dejando solo `GET`, `POST`, `HEAD` y `OPTIONS`. En servidores de contenido
   estático, `PUT` y `DELETE` no tienen razón de existir y son una vía directa a subir
   web shells.

---

## 4. Bitácora de comandos

```bash
# R1 — Enumeración de directorios
dirb http://phantomcorp                       # encuentra /admin (403) y /backup (200)
curl -s http://phantomcorp/backup/            # listado del backup → FLAG R1

# R2 — Repositorio .git expuesto
curl -s http://phantomcorp/.git/config        # config del repo → FLAG R2

# R3 — Métodos HTTP peligrosos
curl -i -X OPTIONS http://phantomcorp/        # header Allow: PUT, DELETE → FLAG R3

# R4 — Enumeración de usuarios vía API
curl -s http://phantomcorp/api/users          # JSON de usuarios → FLAG R4

# R5 — Fingerprinting de tecnología
whatweb http://phantomcorp                    # identifica PhantomCMS 3.7
curl -s http://phantomcorp/phantomcms/VERSION # archivo default del CMS → FLAG R5

# Entrega de flags (desde /loot/ctf-home por el montaje read-only de /repo)
./ctf submit 06 R1 'FLAG{...}'
./ctf status 06
```

---
