# Mini-research — Laboratorio 05

> Copiada a `entregas/lab05/grupo10/research.md`.
> Investigación técnica individual sobre técnica o vulnerabilidad del Laboratorio 05.

**Grupo:** 10  
**Autor:** Juan Pablo Saby (@JuanSaby)  
**Tema elegido:**

- [x] **A.** El CVE-2015-3306 de ProFTPD 1.3.5: qué es el `mod_copy`, cómo se explota el comando `SITE CPFR/CPTO`, y por qué un banner de versión alcanza para postular una hipótesis pero no para dar por confirmada la vulnerabilidad.
- [ ] **B.** Tipos de escaneo de `nmap` (`-sS` vs `-sT` vs `-sU` vs `-sV`): cómo funciona cada uno a nivel de paquetes TCP/IP y qué huella deja en el objetivo.
- [ ] **C.** OSINT y recon pasivo: qué información de una organización se puede reunir **sin tocar** sus sistemas (certificados, DNS, buscadores, filtraciones) y por qué es tan valiosa para un atacante.
- [ ] **D.** El estándar CVSS: cómo se arma un score (vector base), qué significan sus métricas, y por qué "criticidad" no es lo mismo que "score".

---

## 0. Declaración de uso de IA

Esta investigación individual se elaboró con la asistencia de un modelo de inteligencia artificial (asistente de ingeniería de software) para apoyar la búsqueda y contraste de referencias técnicas primarias, organizar la estructura del documento conforme a los criterios de la cátedra y pulir la redacción técnica.

- **Herramienta utilizada:** Asistente de IA (Gemini / Antigravity).
- **Alcance de la asistencia:** Estructuración de las secciones analíticas, síntesis de directivas de ProFTPD y formato de citas bibliográficas.
- **Partes originadas o modificadas con asistencia:** El borrador preliminar de las explicaciones conceptuales y el esquema comparativo entre banner grabbing y verificación activa.
- **Método de verificación humana:** Todos los aspectos técnicos, comandos de protocolo FTP (`SITE CPFR`, `SITE CPTO`), directivas de configuración (`CopyEngine`, `<Limit>`), puntuaciones CVSS 2.0 y vectores de ataque fueron cotejados manualmente contra las fuentes primarias oficiales ([NVD NIST](https://nvd.nist.gov/vuln/detail/CVE-2015-3306), [CVE.org](https://www.cve.org/CVERecord?id=CVE-2015-3306), [Documentación oficial de ProFTPD](http://ftp.proftpd.org/docs/contrib/mod_copy.html) y [Bugzilla #4169 de ProFTPD](http://bugs.proftpd.org/show_bug.cgi?id=4169)). Asimismo, se contrastó la realidad operativa contra la evidencia empírica recolectada por el Grupo 10 en `lab05-banner-ftp.txt` y contra el código del target en `server.py`, garantizando la veracidad de cada afirmación y evitando cualquier falso positivo.

---

## Desarrollo

### 1. ¿Qué es CVE-2015-3306 y qué componente de ProFTPD está involucrado?

El **CVE-2015-3306** es una vulnerabilidad crítica de seguridad que afecta al servidor FTP de código abierto **ProFTPD** en su versión 1.3.5 (y versiones previas que incluyan el módulo afectado). El fallo radica específicamente en el módulo de contribución **`mod_copy`**, encargado de permitir la copia de archivos y directorios en el servidor local.

La vulnerabilidad fue reportada formalmente en abril de 2015 (registrada en el bug tracker oficial del proyecto como [Bug #4169](http://bugs.proftpd.org/show_bug.cgi?id=4169)). La falla permite a atacantes remotos **no autenticados** ejecutar comandos arbitrarios de copia de archivos en el sistema de archivos del servidor anfitrión, utilizando los comandos propios del módulo a través de la interfaz de control TCP del protocolo FTP.

### 2. Función del módulo `mod_copy`

En el protocolo FTP estándar (RFC 959), la transferencia de un archivo entre dos ubicaciones del servidor normalmente requiere que el cliente descargue el archivo y luego lo vuelva a subir a la nueva ruta. Para optimizar operaciones administrativas y evitar el consumo innecesario de ancho de banda en la red, ProFTPD incorporó el módulo `mod_copy`.

De acuerdo con la [documentación oficial de ProFTPD sobre mod_copy](http://ftp.proftpd.org/docs/contrib/mod_copy.html), su propósito es brindar soporte para operaciones de copia local *server-side* sin requerir transferencia de datos sobre la conexión de datos FTP. El módulo introduce dos comandos personalizados bajo la extensión estándar `SITE`:
- `SITE CPFR` (*Copy From*): especifica la ruta de origen en el sistema de archivos.
- `SITE CPTO` (*Copy To*): especifica la ruta de destino donde se duplicará el recurso seleccionado.

### 3. Mecánica técnica de los comandos `SITE CPFR` y `SITE CPTO`

El flujo previsto por el módulo opera de la siguiente manera:
1. El cliente FTP establece la conexión de control al puerto 21.
2. El cliente emite `SITE CPFR <origen>`. Si la ruta existe y el proceso del servidor tiene permisos de lectura, ProFTPD responde con el código de estado `350 File or directory exists, ready for destination name`.
3. Inmediatamente después, el cliente envía `SITE CPTO <destino>`. Si la ubicación de destino es accesible para escritura por el proceso, el servidor efectúa la copia y responde con `250 Copy successful`.

**El defecto de diseño fundamental:** En ProFTPD versión 1.3.5 y anteriores, el despachador de comandos de `mod_copy` registraba los manejadores para `CPFR` y `CPTO` sin la bandera de control de acceso que exige autenticación previa. En consecuencia, cualquier cliente TCP que abra un socket al puerto 21 puede emitir directamente `SITE CPFR` y `SITE CPTO` **sin haber ejecutado previamente los comandos `USER` ni `PASS`**.

### 4. Riesgo de la copia de archivos no autenticada

La posibilidad de ejecutar copias en el sistema de archivos sin autenticación destruye el principio de mediación completa (*complete mediation*) y el control de accesos del servicio:
- **Exfiltración de información sensible (Pérdida de Confidencialidad):** Un atacante que no posee credenciales en el sistema puede copiar archivos de configuración sensibles, claves criptográficas, certificados TLS o archivos del sistema (como `/etc/passwd`) hacia un directorio público (por ejemplo, el directorio raíz de un servidor web que corra en el mismo host). Luego, basta con descargar el archivo vía HTTP.
- **Escalada a Ejecución Remota de Código - RCE (Pérdida de Integridad):** Si el servidor aloja conjuntamente un servicio web con soporte para lenguajes interpretados (como PHP), el atacante puede inyectar código malicioso en algún archivo al que tenga acceso o enviar un payload en un recurso temporal/log, y luego invocar `SITE CPTO /var/www/html/shell.php`. Al solicitar dicho archivo por HTTP, el intérprete web ejecuta el payload, otorgando acceso a nivel de shell al atacante con los privilegios del servidor web o del usuario bajo el que opera ProFTPD.

Debido a estas características, el National Vulnerability Database ([NVD NIST](https://nvd.nist.gov/vuln/detail/CVE-2015-3306)) asignó a CVE-2015-3306 un score **CVSS 2.0 Base de 10.0**, con vector `AV:N/AC:L/Au:N/C:C/I:C/A:C` (Acceso Remoto por Red, Complejidad Baja, Sin Autenticación, e Impacto Total en Confidencialidad, Integridad y Disponibilidad).

### 5. Condiciones de configuración para que la explotación sea posible

La sola presencia del binario no basta; deben cumplirse simultáneamente varias condiciones del entorno:
1. **Compilación del módulo:** Por diseño, `mod_copy` es un módulo de contribución (*contrib module*). En instalaciones compiladas desde código fuente, debe haberse incluido explícitamente durante la compilación (`./configure --with-modules=mod_copy`). En diversas distribuciones de Linux (como paquetes precompilados de Debian y Ubuntu de esa época), el módulo solía venir compilado e integrado por defecto.
2. **Directiva activa:** La directiva `CopyEngine` debe estar en `on` (valor por omisión cuando el módulo está cargado).
3. **Falta de restricciones de acceso:** La configuración en `proftpd.conf` no debe contener directivas `<Limit SITE_CPFR SITE_CPTO>` con reglas restrictivas (`DenyAll` o requerimiento explícito de usuario autenticado).
4. **Permisos a nivel de sistema operativo:** ProFTPD realiza las operaciones de copia con los privilegios de su proceso de trabajo (comúnmente el usuario `nobody` o `proftpd`). Para que `CPFR` y `CPTO` tengan éxito, dicho usuario debe poseer permisos de lectura sobre el archivo fuente y permisos de escritura en el directorio de destino.

### 6. Impacto y vectores de ataque reales

Históricamente, los exploits públicos para CVE-2015-3306 (por ejemplo, el módulo de Metasploit `exploit/unix/ftp/proftpd_modcopy_exec`) demuestran que el vector de explotación más común aprovecha servidores web concurrentes:
- Copia de `/proc/self/cmdline` o de logs de acceso del propio servidor (donde se ha introducido código PHP mediante un comando previo especialmente formateado) hacia un archivo `.php` dentro del DocumentRoot web.
- Sobrescritura de scripts o configuraciones locales si los permisos del filesystem lo permiten, derivando en alteración de servicio o denegación de servicio.

### 7. Medidas de mitigación y remediación

Para mitigar y subsanar esta vulnerabilidad de manera definitiva, se contemplan tres niveles de acción:
1. **Actualización del software (Solución Definitiva):** Actualizar a ProFTPD versión 1.3.5a, 1.3.6 o superior. En estas versiones, los desarrolladores corrigieron la falla restringiendo los comandos `SITE CPFR/CPTO` exclusivamente a sesiones formalmente autenticadas ([Bugzilla #4169](http://bugs.proftpd.org/show_bug.cgi?id=4169)).
2. **Desactivación del módulo en la configuración:** Si no es posible actualizar de inmediato, deshabilitar el motor de copia en `proftpd.conf`:
   ```apache
   <IfModule mod_copy.c>
       CopyEngine off
   </IfModule>
   ```
3. **Restricción mediante bloques `<Limit>`:** Bloquear el uso de los comandos mediante directivas de control en el archivo de configuración:
   ```apache
   <Limit SITE_CPFR SITE_CPTO>
       DenyAll
   </Limit>
   ```
4. **Recompilación:** En entornos donde se compila el software, excluir `mod_copy` del árbol de binarios si la funcionalidad de copia remota no es un requerimiento de negocio.

---

## Punto Metodológico: Banner Grabbing vs. Verificación de Explotabilidad

Un principio central en la práctica profesional de auditoría de seguridad y pentesting es que **un banner de servicio jamás prueba la existencia efectiva de una vulnerabilidad**. En el marco del Laboratorio 05, la evidencia obtenida por el Grupo 10 en `lab05-banner-ftp.txt` arrojó:

```text
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]
```

Es mandatorio distinguir analíticamente entre las tres fases del proceso metodológico:

1. **Identificación de versión (Banner Grabbing):** Es una técnica de reconocimiento activo superficial que se limita a leer la cadena de texto declarativa que el servicio transmite al conectarse. El banner puede ser inexacto, haber sido modificado por el administrador para engañar a atacantes (*banner obfuscation*), o mantenerse inalterado tras la aplicación de un parche de seguridad de la distribución (*backporting* común en distribuciones como Debian, Ubuntu o Red Hat, donde el paquete corrige el fallo pero conserva la nomenclatura de versión base).
2. **Inferencia de vulnerabilidad potencial (Candidato a CVE):** Al cruzar la cadena `ProFTPD 1.3.5` con registros de vulnerabilidades conocidas (NVD/CVE), surge de forma inmediata la correlación con **CVE-2015-3306**. Sin embargo, esto constituye únicamente una **hipótesis de trabajo**, no un hecho fáctico. El analista registra el CVE como candidato, estimando su riesgo potencial en caso de confirmarse.
3. **Verificación efectiva y demostración de explotabilidad:** Para demostrar que el servidor es verdaderamente vulnerable se requiere interactuar con el protocolo para comprobar el estado real de la funcionalidad. En el caso de `mod_copy`, esto exigiría enviar un comando `SITE CPFR /etc/passwd`. Si el servidor responde `350`, se confirma que el módulo está cargado, activo y escuchando sin autenticación; si en cambio devuelve `500 Unknown command` o `501 Operation not permitted`, la vulnerabilidad no existe en esa instancia, independientemente de lo que proclame el banner.

### El caso concreto del entorno de laboratorio (`phantomcorp`)

En el contexto del Laboratorio 05, este principio cobra una dimensión aún más clara:
Al analizar la arquitectura del objetivo `phantomcorp`, se observa que el puerto 21 no ejecuta un servidor ProFTPD genuino, sino un script mínimo en Python (`server.py`) que utiliza la biblioteca estándar `socket` para emitir una cadena simulada y entregar una flag de recon (`FLAG{banner_grab_proftpd_135}`):

```python
ftp_banner = (f"220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]\r\n"
              f"214 {FLAG_FTP}\r\n").encode()
```

Por lo tanto, en este laboratorio **no existe ningún binario de ProFTPD, no existe el módulo `mod_copy` ni existe posibilidad alguna de ejecutar `SITE CPFR/CPTO` o vulnerar el contenedor mediante este vector**. Afirmar en un informe que el host es vulnerable a CVE-2015-3306 basándose únicamente en el banner representaría un **falso positivo crítico** derivado de una práctica deficiente de reconocimiento. La clasificación rigurosa adoptada por el grupo —asentarlo como candidato provisional sin asumir explotación— es la única respuesta metodológicamente defendible.

---

## Fuentes

1. **NVD (National Vulnerability Database) — NIST:**  
   *CVE-2015-3306 Detail.*  
   Enlace: [https://nvd.nist.gov/vuln/detail/CVE-2015-3306](https://nvd.nist.gov/vuln/detail/CVE-2015-3306)  
   *Respaldo:* Métricas del vector de ataque CVSS v2 (Score 10.0), impacto sobre confidencialidad/integridad/disponibilidad y descripción de la ausencia de autenticación.
2. **CVE.org (The MITRE Corporation / CVE Program):**  
   *CVE Record CVE-2015-3306.*  
   Enlace: [https://www.cve.org/CVERecord?id=CVE-2015-3306](https://www.cve.org/CVERecord?id=CVE-2015-3306)  
   *Respaldo:* Registro formal de la vulnerabilidad, versiones de producto asignadas y referencias de divulgación originales.
3. **ProFTPD Project Official Documentation — TJ Saunders:**  
   *ProFTPD module mod_copy documentation.*  
   Enlace: [http://ftp.proftpd.org/docs/contrib/mod_copy.html](http://ftp.proftpd.org/docs/contrib/mod_copy.html)  
   *Respaldo:* Especificación de los comandos `SITE CPFR` y `SITE CPTO`, sintaxis de la directiva `CopyEngine`, funcionamiento del mecanismo de copia local y notas de compilación como módulo contrib.
4. **ProFTPD Bugzilla Tracker:**  
   *Bug #4169 — mod_copy unauthenticated file copying (CVE-2015-3306).*  
   Enlace: [http://bugs.proftpd.org/show_bug.cgi?id=4169](http://bugs.proftpd.org/show_bug.cgi?id=4169)  
   *Respaldo:* Reporte primario de la falla, parche oficial de mitigación que exige sesión autenticada y detalles de la corrección en el código fuente.

---

## Reflexión (3–5 líneas)

El análisis de CVE-2015-3306 demuestra que el reconocimiento activo inicial mediante banner grabbing solo aporta indicios circunstanciales sobre la superficie de ataque, pero no certezas. Asumir automáticamente que una versión coincide con un exploit sin verificar la habilitación del módulo (`mod_copy`), las directivas de configuración o la realidad subyacente del servicio induce a falsos positivos graves en una auditoría. El verdadero valor de un pentester no radica en listar CVEs a ciegas ante cada banner, sino en comprender las precondiciones técnicas que hacen viable la explotación y validar metódicamente cada hallazgo.

