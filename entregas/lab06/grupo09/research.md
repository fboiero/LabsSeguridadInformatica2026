# Mini-investigación — Laboratorio 06 · Enumeración

**Grupo:** 09
**Tema elegido:** A — Cómo un `.git` expuesto permite reconstruir el código (git-dumper) y casos reales de credenciales filtradas

---

## 1. Desarrollo

Durante la enumeración de PhantomCorp encontramos un `.git/config` accesible por HTTP
(`curl http://phantomcorp/.git/config`). Este apartado explica por qué ese hallazgo, que
parece menor, es en realidad uno de los más peligrosos del pentesting web.

**Por qué ocurre.** Cuando se programa con Git, en la raíz del proyecto vive la carpeta
oculta `.git/`, que contiene el repositorio completo: cada versión de cada archivo, el
historial de commits, autores y mensajes. El problema aparece en el **despliegue**:
muchos equipos suben su proyecto a producción copiando la carpeta entera (por ejemplo con
`git clone` o un `rsync` que incluye el `.git/`), y si el servidor web no bloquea las
rutas que empiezan con `.git`, esa carpeta queda servida públicamente. Es un error de
configuración, no una vulnerabilidad del software.

**Qué puede reconstruir un atacante.** El `.git/` no guarda solo la foto actual del
código: guarda **toda la historia**. A partir de los objetos de Git expuestos (los
"blobs", "trees" y "commits" bajo `.git/objects/`), un atacante puede reconstruir:
- El **código fuente íntegro** de la aplicación, pasando de un ataque de "caja negra" a
  uno de "caja blanca": ahora ve la lógica interna, las rutas, las validaciones y los
  posibles fallos.
- El **historial de commits**, que a menudo contiene **secretos que alguien subió y
  después "borró"** — pero borrar un archivo en un commit nuevo no lo elimina del
  historial: la contraseña, el token o la clave de API siguen recuperables en una versión
  anterior.
- **Información de infraestructura**: en nuestro caso, el `config` reveló
  `url = https://git.internal.phantomcorp/intranet.git`, delatando la existencia de un
  servidor Git interno y el nombre del repositorio (`intranet`).

**Cómo se automatiza (git-dumper).** No hace falta descargar archivo por archivo a mano.
Existen herramientas como **`git-dumper`** que, apuntando a un `.git/` expuesto, descargan
y reensamblan el repositorio completo de forma automática
(`git-dumper http://phantomcorp/.git/ ./botin`). El atacante queda con una copia local
funcional del repo, lista para analizar con `git log` y recuperar versiones viejas con
`git checkout`.

**La escala del problema (caso real).** No es un riesgo teórico. Un estudio publicado en
2026 por el equipo de investigación de Mysterium VPN relevó **cerca de 4,96 millones de
IPs** con directorios `.git` accesibles públicamente, de los cuales **más de 252.000**
tenían credenciales de despliegue activas dentro de su `.git/config` (aproximadamente un
5% del total). Aun ese 5% representa cientos de miles de secretos utilizables. Los países
más afectados fueron Estados Unidos, Alemania y Francia, concentrados en los grandes
proveedores de hosting. Esto confirma que un `.git` expuesto conduce habitualmente a robo
de código, abuso de credenciales, acceso a infraestructura cloud e incluso ataques a la
cadena de suministro mediante commits maliciosos.

---

## 2. Fuentes

- **Estudio sobre la escala del problema (Security Affairs, feb. 2026)** — cerca de 5
  millones de servidores con metadatos `.git` expuestos y 252.000+ con credenciales:
  https://securityaffairs.com/187674/security/nearly-5-million-web-servers-found-exposing-git-metadata-study-reveals-widespread-risk-of-code-and-credential-leaks.html
- **Explicación técnica del ataque a un `.git` expuesto:**
  https://techearl.com/exposed-git-directory-attack
- **Herramienta de extracción automática (gitjacker / familia de git-dumpers):**
  https://trickest.com/tools/gitjacker

---

## 3. Reflexión

Lo que nos llevamos es que un `.git/config` de 200 bytes puede ser la puerta a todo el
código fuente y a los secretos de una organización. Conecta directo con el laboratorio:
en el Lab 06 confirmamos la exposición, y en un ataque real el paso siguiente sería
`git-dumper` para reconstruir el repo y buscar credenciales en el historial — justo el
tipo de insumo que alimenta la fase de explotación del Lab 07. La lección defensiva es
simple y barata: bloquear el acceso a `.git` en el servidor y no desplegar la carpeta en
producción. Que un error tan fácil de evitar afecte a millones de servidores muestra
cuánto importa la enumeración: el atacante solo tiene que pedir un archivo que nunca
debió estar ahí.

---
