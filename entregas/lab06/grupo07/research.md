# Mini-research — Laboratorio 06

**Grupo:** 07 · **Autora:** Guadalupe Gómez — @guadagomezgg8 · **Fecha:** 19/11/2026

**Tema elegido:** B

- [ ] **A.** Cómo un `.git` expuesto permite reconstruir el código (git-dumper) y
  casos reales de credenciales filtradas por esta vía.
- [x] **B.** Wordlists de enumeración: qué son SecLists, cómo se eligen, por qué
  una wordlist mala hace fallar la enumeración.
- [ ] **C.** El método HTTP `PUT` y el WebDAV: cómo se pasa de "método habilitado"
  a subir un webshell.
- [ ] **D.** Fingerprinting pasivo vs. activo: cómo `whatweb` deduce el stack.

> Se eligió B porque los temas A y C ya están desarrollados en P2 y P3 del informe,
> y porque nuestra propia operación del Lab 06 muestra el fenómeno con números.

## Desarrollo

### 1. Qué es una wordlist y para qué sirve en la enumeración

Un servidor web no publica la lista de todo lo que tiene: solo muestra lo que está enlazado. Para encontrar lo que no está enlazado se usa la **navegación forzada** (*forced browsing* o *dirbusting*). La herramienta pide al servidor una ruta tras otra y mira el código de respuesta: un 200 o un 403 indican que el recurso existe, y un 404 que no. OWASP lo describe como fuerza bruta con nombres conocidos de carpetas y archivos [1].

La **wordlist** es el archivo de donde salen esos nombres, uno por línea. `dirb`, `gobuster` o `ffuf` no "descubren" nada por sí mismos: solo prueban lo que dice la lista. **Si una ruta no está en la wordlist, la herramienta nunca la va a pedir**, por más que exista. La calidad de la enumeración depende casi por completo de la calidad de la lista.

### 2. SecLists y otras colecciones

**SecLists** es un repositorio público, mantenido por Daniel Miessler, Jason Haddix y otros colaboradores, que junta en un solo lugar listas de todo tipo usadas en evaluaciones de seguridad: usuarios, contraseñas, URLs, patrones de datos sensibles y payloads de fuzzing [2]. Para enumeración web, lo relevante está en `Discovery/Web-Content/`, con listas genéricas de distintos tamaños y listas específicas de cada tecnología (CMS, frameworks, servidores). En Kali se instala con `apt install seclists`.

`dirb` trae sus propias listas en `/usr/share/dirb/wordlists/`. La que usa por defecto es `common.txt`, que es la que corrimos en el lab [3].

Una alternativa más reciente son las listas de **Assetnote**, que se regeneran todos los meses a partir de datos reales de Internet (con Commonspeak2) en vez de mantenerse a mano [4]. Assetnote también plantea una crítica de fondo: las herramientas mejoraron sobre todo en velocidad y no en *qué* prueban. Para APIs propone el **descubrimiento contextual**, que arma las rutas a partir de especificaciones reales de APIs en lugar de probar palabras sueltas [5].

### 3. Cómo se elige una wordlist

No hay una "mejor" wordlist: se elige según lo que ya se sabe del objetivo. Los criterios principales son:

- **Tecnología identificada.** Es el criterio más importante. Cada CMS o framework tiene su propia estructura de carpetas y archivos default [1]. Si el fingerprinting dice qué producto corre, conviene una lista específica antes que una genérica.
- **Tipo de recurso.** No es lo mismo buscar directorios (`/backup`) que archivos (`VERSION`, `config.old`). Para archivos hay que sumar extensiones, y cada extensión multiplica la cantidad de pedidos.
- **Mayúsculas y minúsculas.** En la mayoría de los servidores, `/VERSION` y `/version` son rutas distintas. Una lista solo en minúsculas no encuentra la otra.
- **Tamaño contra costo.** Una lista grande cubre más pero tarda más, genera más ruido en los logs del defensor y puede activar bloqueos. Lo habitual es arrancar con una lista chica y genérica, y después usar listas dirigidas según lo que aparezca.
- **Idioma y contexto.** Un sitio en castellano puede usar `/respaldo` en vez de `/backup`. `dirb` trae una `spanish.txt` justamente por eso.

### 4. Por qué una wordlist mala hace fallar la enumeración: el caso del Lab 06

Nuestra operación muestra las tres situaciones posibles, con los conteos que registra cada salida de `dirb`:

| Ejecución | Wordlist | Pedidos | Hallazgos | Evidencia |
|---|---|---:|---|---|
| 1 | `common.txt` (genérica) | 4612 | `/admin` (403) y `/backup` (200) | `03-dirb.txt` |
| 2 | `common.txt` + extensiones `.txt`, `.html` | 9224 | **ninguno** | `12-dirb-archivos.txt` |
| 3 | Lista propia dirigida al CMS (`cms-wordlist.txt`) | 819 | `/phantomcms/VERSION` (200) | `14-dirb-cms.txt` |

- **La ejecución 1 funcionó** porque `backup` y `admin` son nombres genéricos que figuran en cualquier lista común.
- **La ejecución 2 duplicó el esfuerzo y no encontró nada.** El archivo que buscábamos estaba dentro de una carpeta con el nombre del producto (`/phantomcms/`) y se llamaba `VERSION`, sin extensión y en mayúsculas. Ninguna combinación de una lista genérica con extensiones iba a generar esa ruta. Más pedidos no significan mejor enumeración.
- **La ejecución 3 lo encontró con menos de una décima parte de los pedidos.** La diferencia fue usar lo que ya sabíamos: `whatweb` había identificado `PhantomCMS 3.7` (`08-whatweb.txt`), y con eso se armó una lista con nombres de archivos habituales (`readme`, `version`, `changelog`, en varias variantes de mayúsculas y extensiones) combinados con prefijos del producto.

La lección más importante es cómo se interpreta un resultado vacío. La ejecución 2 terminó con `FOUND: 0`, y eso **no significa que no haya nada**: significa que no hay nada *de lo que esa lista sabe pedir*. Es un falso negativo, el mismo tipo de error que la Parte B documentó con el script `http-git` de nmap. Un informe que diga "no se encontraron archivos" a partir de una lista genérica estaría afirmando más de lo que la evidencia sostiene.

## Fuentes (mín. 3, verificables)

Consultadas el 19/11/2026.

1. OWASP. *Web Security Testing Guide* — [WSTG-INFO-08: Fingerprint Web Application Framework](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework). Define el *dirbusting* y explica que cada producto tiene una estructura de archivos propia que permite identificarlo.
2. Miessler, D.; Haddix, J. y colaboradores. [SecLists](https://github.com/danielmiessler/SecLists) (repositorio GitHub, licencia MIT). Descripción del proyecto, tipos de listas e instalación.
3. Kali Linux. [Tool Documentation: dirb](https://www.kali.org/tools/dirb/). Uso de `dirb` con su lista por defecto `common.txt`.
4. Assetnote. [Assetnote Wordlists](https://wordlists.assetnote.io/). Listas generadas automáticamente cada mes con Commonspeak2.
5. Assetnote. [Contextual Content Discovery: You've forgotten about the API endpoints](https://www.assetnote.io/resources/research/contextual-content-discovery-youve-forgotten-about-the-api-endpoints) (2021). Crítica a la fuerza bruta genérica y descubrimiento contextual para APIs.

## Reflexión (3–5 líneas)

Antes de este lab pensaba que la enumeración era cuestión de herramienta y de tiempo: elegir `dirb` y dejarlo correr con la lista más grande. Nuestras propias salidas muestran lo contrario: 9224 pedidos no encontraron nada y 819 pedidos bien pensados sí. La wordlist es una hipótesis sobre el objetivo, y se arma con lo que dejaron las fases anteriores (en nuestro caso, el fingerprint de `whatweb`). Lo que más me llevo es no confiar en un resultado vacío: "no encontré" no es lo mismo que "no existe", y el informe tiene que decir con qué lista se buscó.
