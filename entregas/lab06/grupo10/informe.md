# Informe — Laboratorio 06 · Enumeración

**Grupo:** 10 · **Integrantes:** *(Completar nómina del grupo)* · **Fecha:** 2026-11-01

---

## 0. Declaración de uso de IA

En cumplimiento con las directivas de `CONTRIBUTING.md`, se declara el uso del asistente de inteligencia artificial Antigravity (Google DeepMind) durante el desarrollo de este reto:
- **Herramienta utilizada:** Antigravity (modelo Gemini 3.8 Flash).
- **Finalidad de uso:** Asistencia en la planificación metodológica del reto R2, estructuración del relevamiento técnico, análisis de la estructura interna del protocolo Git (formato de objetos, zlib, árboles y blobs) y redacción técnica del informe.
- **Partes originadas o modificadas:** Guía paso a paso de exploración de recursos `.git`, estructuración del inventario para R2 y fundamentación técnica de las preguntas P2 y P5.
- **Verificación:** Todas las hipótesis teóricas fueron contrastadas empíricamente mediante la ejecución de comandos `curl` contra el entorno Docker activo de la cátedra (`phantomcorp`), verificando los códigos de respuesta HTTP, las cabeceras devueltas y validando criptográficamente el hash SHA-256 de la flag contra `retos.manifest`.

---

## 1. Flags capturadas

Salida oficial del comando `./ctf status 06`:

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 06                     │
  ╰────────────────────────────────────────────────────────────╯

   ·  R1     Enumeracion de directorios
   ✓  R2     Repositorio Git expuesto
   ·  R3     Metodos HTTP peligrosos habilitados
   ·  R4     Enumeracion de usuarios via API
   ·  R5     Fingerprinting de tecnologia

  ██████░░░░░░░░░░░░░░░░░░░░░░░░  1/5 (20%)
```

---

## 2. Inventario de enumeración

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| *(R1 - Pendiente)* | | | | | |
| **Repositorio Git expuesto (Configuración y URL interna)** | `GET /.git/config` | Petición HTTP directa a rutas predecibles de control de versiones | Código `200 OK`, `Content-Type: text/plain`. Revela `bare = false` y `url = https://git.internal.phantomcorp/intranet.git` junto a comentarios de desarrollo | **Medio** (Demostrado). Divulgación de arquitectura interna y ubicación del repositorio central de código. No escala a Crítico en este servidor porque `.git/objects/` e historial no son accesibles (404) | Permite identificar el nombre del repositorio interno (`intranet.git`) y el dominio de desarrollo (`git.internal.phantomcorp`) para ataques dirigidos de falsificación de peticiones (SSRF) o pivot lateral |
| *(R3 - Pendiente)* | | | | | |
| *(R4 - Pendiente)* | | | | | |
| *(R5 - Pendiente)* | | | | | |

### Evidencia de soporte del inventario (R2)

#### 1. Petición y respuesta a `/.git/config`
```http
GET http://phantomcorp/.git/config HTTP/1.1
Host: phantomcorp

HTTP/1.0 200 OK
Server: PhantomServer/3.7 
Date: Sun, 01 Nov 2026 21:45:02 GMT
Content-Type: text/plain; charset=utf-8
X-Powered-By: PhantomCMS/3.7

[core]
	repositoryformatversion = 0
	bare = false
[remote "origin"]
	url = https://git.internal.phantomcorp/intranet.git
# Un .git expuesto filtra codigo, historia y a veces secretos.
# FLAG{git_repo_exposed}
```

#### 2. Comprobación de límites de exposición (Inaccesibilidad de objetos/historial)
```http
GET http://phantomcorp/.git/HEAD HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/logs/HEAD HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/index HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/objects/info/packs HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/description HTTP/1.1 -> 404 Not Found
```

---

## 3. Preguntas de análisis

### P1 — Enumeración vs. recon.
*(A completar por el integrante asignado)*

### P2 — El `.git` expuesto
**Consigna:** *El `.git` expuesto: explicá qué podría reconstruir un atacante con él y por qué es más grave que "un archivo de más".*

**Respuesta fundamentada:**
Un archivo convencional expuesto (como una página HTML o un PDF) solo revela información estática y aislada. En contraste, el directorio `.git/` contiene la estructura completa del sistema de control de versiones (árbol de objetos, ramas, índices y reflogs). Si la exposición es completa, un atacante no solo descarga el archivo que está en producción, sino que puede reconstruir el **código fuente íntegro de la aplicación con todo su historial de cambios**:
1. **Acceso a objetos comprimidos (`.git/objects/`):** Al descargar secuencialmente los commits, árboles (*trees*) y blobs (descomprimiéndolos con zlib), se restaura el árbol de trabajo completo con la totalidad de los archivos de la aplicación.
2. **Historial y diferencias temporales:** A través de los objetos `commit` y `parent`, un atacante puede ejecutar operaciones equivalentes a `git log` y `git diff`. Esto permite inspeccionar código histórico, revisiones anteriores y notas de desarrollo.
3. **Fuga de secretos commiteados por error:** Frecuentemente los desarrolladores commitean contraseñas de bases de datos, tokens de API o claves privadas que luego son "eliminadas" en commits posteriores. Como Git mantiene los snapshots históricos en sus blobs, el atacante recupera las credenciales en claro con solo inspeccionar commits pasados.
4. **Auditoría de caja blanca (White-box):** Contar con el código fuente le permite al atacante analizar vulnerabilidades de lógica, inyecciones SQL o fallas de autenticación con precisión absoluta, eliminando la necesidad de realizar pruebas a ciegas.

En el caso puntual analizado en PhantomCorp, se constató empíricamente que el servidor expone únicamente `/.git/config` (devolviendo 404 para `HEAD`, `logs/` y `objects/`). Por lo tanto, aunque no fue posible reconstruir el árbol de objetos localmente, la exposición reveló información sensible de infraestructura interna (URL del repositorio interno).

### P3 — El método `PUT`.
*(A completar por el integrante asignado)*

### P4 — Enumeración de usuarios.
*(A completar por el integrante asignado)*

### P5 — Rol defensor (Mitigaciones)
**Mitigación para Repositorio Git expuesto (Hallazgo R2):**
1. **Regla de denegación en servidor web / proxy inverso:** Configurar una directiva explícita que bloquee de forma estricta cualquier petición dirigida a archivos o directorios ocultos que comiencen con punto (`.`).
   - *Ejemplo en Nginx:*
     ```nginx
     location ~ /\.git {
         deny all;
         return 404;
     }
     ```
   - *Ejemplo en Apache:*
     ```apache
     <DirectoryMatch "/\.git">
         Require all denied
     </DirectoryMatch>
     ```
2. **Higiene en pipelines de despliegue (CI/CD):**
   - No utilizar `git clone` o `git pull` directamente en el directorio público servido (`/var/www/html` o `/app`).
   - Implementar artefactos de compilación limpios mediante `git archive` o contenedores multi-etapa (*multi-stage Docker builds*) donde únicamente se copien los archivos finales de producción y se descarte por completo la carpeta `.git`.
3. **Escaneo automatizado de repositorios:**
   - Incorporar herramientas de análisis estático como `gitleaks` o `trufflehog` en los hooks de pre-commit y pipelines para evitar que configuraciones sensibles o comentarios con información interna queden registrados en el repositorio.

*(Las 2 mitigaciones restantes serán completadas por los integrantes según sus hallazgos).*

---

## 4. Bitácora de comandos

```bash
# Verificación de conectividad general
curl -i -s http://phantomcorp/

# Inspección de configuración de Git
curl -i -s http://phantomcorp/.git/config

# Sondeo de referencias y metadatos adicionales
curl -i -s http://phantomcorp/.git/HEAD
curl -i -s http://phantomcorp/.git/logs/HEAD
curl -i -s http://phantomcorp/.git/index
curl -i -s http://phantomcorp/.git/objects/info/packs
curl -i -s http://phantomcorp/.git/description
curl -i -s http://phantomcorp/.git/COMMIT_EDITMSG
curl -i -s http://phantomcorp/.git/

# Validación criptográfica de la flag
echo -n 'FLAG{git_repo_exposed}' | sha256sum

# Registro en el CTF
./ctf submit 06 R2 'FLAG{git_repo_exposed}'
./ctf status 06
```
