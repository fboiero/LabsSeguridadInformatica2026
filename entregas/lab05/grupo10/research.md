# Mini-research — Laboratorio 05

**Grupo:** 10  
**Autor:** Juan Pablo Saby (@JuanSaby)  
**Tema elegido:** A — CVE-2015-3306 de ProFTPD: función de `mod_copy`, defecto de autenticación, riesgos, mitigaciones y límites del banner como evidencia.

---

## 0. Declaración de uso de IA

Esta investigación individual se elaboró con la asistencia de un modelo de inteligencia artificial (asistente de ingeniería de software) para organizar la estructura del documento conforme a los criterios de la cátedra y pulir la redacción técnica.

- **Herramienta utilizada:** Asistente de IA (Gemini / Antigravity).
- **Alcance de la asistencia:** Estructuración de las secciones analíticas, síntesis de directivas de ProFTPD y formato de citas bibliográficas.
- **Partes originadas o modificadas con asistencia:** El borrador preliminar de las explicaciones conceptuales y verificación activa.
- **Método de verificación humana:** Todos los aspectos técnicos, comandos de protocolo FTP (`SITE CPFR`, `SITE CPTO`), directivas de configuración (`CopyEngine`, `<Limit>`), puntuaciones CVSS 2.0 y vectores de ataque fueron cotejados manualmente contra las fuentes primarias oficiales ([NVD NIST](https://nvd.nist.gov/vuln/detail/CVE-2015-3306), [CVE.org](https://www.cve.org/CVERecord?id=CVE-2015-3306), [Documentación oficial de ProFTPD](http://ftp.proftpd.org/docs/contrib/mod_copy.html) y [Bugzilla #4169 de ProFTPD](http://bugs.proftpd.org/show_bug.cgi?id=4169)). Asimismo, se contrastó la realidad operativa contra la evidencia empírica recolectada por el Grupo 10 en `lab05-banner-ftp.txt` y contra el código del target en `server.py`, garantizando la veracidad de cada afirmación y evitando cualquier falso positivo.

---

## Desarrollo

### 1. Componente y defecto de seguridad

CVE-2015-3306 describe una falla de `mod_copy`, un módulo de ProFTPD que permite copiar archivos dentro del servidor sin transferir su contenido al cliente. `SITE CPFR` selecciona el origen y `SITE CPTO` el destino. El problema de seguridad es permitir operaciones de copia sin exigir autenticación, fuera de la autorización esperada para esa funcionalidad [1, 2, 4]. El registro CVE menciona ProFTPD 1.3.5; las versiones de paquetes afectadas deben contrastarse con el proveedor, no deducirse de una regla universal sobre cualquier versión anterior.

El impacto depende de los permisos efectivos del proceso y de los recursos accesibles: una copia no autorizada puede exponer información, alterar archivos o afectar servicios. El aviso de Debian también contempla posible ejecución de código [4]. Ese impacto requiere condiciones adicionales del entorno; no significa que todo servidor que anuncie ProFTPD permita ejecutar comandos del sistema.

### 2. Del banner a una hipótesis defendible

En `evidencia/lab05-banner-ftp.txt`, la respuesta declara `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)`. Esa cadena justifica relacionar el servicio con el CVE como candidato, pero no demuestra qué binario corre, qué módulos están cargados ni qué correcciones se aplicaron. La documentación indica que `mod_copy` no se compila por defecto [3]. Además, Debian publicó una corrección para el paquete `1.3.5-1.1+deb8u1`, que conserva la versión base 1.3.5 [4]: el número visible no basta para descartar un parche.

Nuestra conclusión se limita al reconocimiento documentado. No confirmamos la presencia ni la ausencia de `mod_copy`, ni realizamos explotación. Una evaluación posterior debería revisar, con autorización, el inventario de paquetes, los módulos y la configuración efectiva. Una respuesta aislada del protocolo tampoco alcanza para demostrar todas las condiciones de exposición. Por eso el mapa registra una hipótesis y separa los hechos observados de los impactos potenciales.

### 3. Severidad y mitigación

NVD publica una evaluación NIST CVSS 2.0 de **10.0**, vector `AV:N/AC:L/Au:N/C:C/I:C/A:C`. Al 05/11/2026, su API también incluye una evaluación secundaria CISA-ADP CVSS 3.1 de **10.0**, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` [1, 2]. No deben mezclarse versiones ni atribuir la segunda evaluación a NIST. Ningún score prueba que la instancia observada sea vulnerable: la criticidad contextual también considera exposición, privilegios y controles.

La medida principal es instalar una versión mantenida con la corrección del proveedor y comprobar su aplicación; las versiones históricas del aviso de Debian no son recomendaciones de despliegue actual [4]. Si la copia local no es necesaria, conviene retirar el módulo y limitar los permisos del servicio. Para configuraciones compatibles, la documentación agrupa sus restricciones bajo `SITE_COPY` y documenta `CopyEngine` desde **1.3.6rc1** [3]. No corresponde recomendar indiscriminadamente `CopyEngine off` para 1.3.5. Los controles deben verificarse en la versión instalada, junto con segmentación y mínimo privilegio.

---

## Fuentes

Fuentes primarias consultadas en la revisión del 05/11/2026:

1. National Institute of Standards and Technology. (s. f.). *CVE-2015-3306 detail*. National Vulnerability Database. https://nvd.nist.gov/vuln/detail/CVE-2015-3306 — Métricas y atribución verificadas también en la [API oficial de NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-3306).
2. CVE Program. (s. f.). *CVE-2015-3306*. https://www.cve.org/CVERecord?id=CVE-2015-3306 — [Registro JSON oficial](https://cveawg.mitre.org/api/cve/CVE-2015-3306), incluidos descripción y datos aportados por CISA-ADP.
3. Saunders, T. J. (s. f.). *ProFTPD module mod_copy*. ProFTPD Project. http://ftp.proftpd.org/docs/contrib/mod_copy.html — Función del módulo, instalación, restricciones `SITE_COPY` y compatibilidad de `CopyEngine`.
4. Delafond, S. (2015, 19 de mayo). *Debian Security Advisory DSA-3263-1: proftpd-dfsg — security update*. Debian Project. https://lists.debian.org/debian-security-announce/2015/msg00154.html — Impacto y versiones corregidas de los paquetes de Debian.

---

## Reflexión (3–5 líneas)

El banner nos permitió proponer un CVE candidato, no confirmar una vulnerabilidad.
Relacionar versión, módulo, configuración y parches evita presentar falsos positivos como hechos.
También aprendimos que una mitigación debe ser compatible con la versión realmente instalada.
El mapa es más defendible cuando explicita esos límites y conserva la evidencia de cada afirmación.

