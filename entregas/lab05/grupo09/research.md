# Mini-investigación — Laboratorio 05 · Reconocimiento

**Grupo:** 09
**Tema elegido:** A — CVE-2015-3306 en ProFTPD 1.3.5 (`mod_copy`)

---

## 1. Desarrollo

Durante el reconocimiento de PhantomCorp, el banner del puerto 21 reveló
`ProFTPD 1.3.5`. Esa versión concreta arrastra una vulnerabilidad crítica,
**CVE-2015-3306**, y este es el recorrido de por qué un simple banner de versión
alcanza para disparar la alarma.

**Qué es `mod_copy`.** ProFTPD es un servidor FTP modular: su funcionalidad se
amplía con módulos. `mod_copy` es uno de ellos, pensado para copiar archivos
*dentro del propio servidor* sin tener que descargarlos y volver a subirlos. Para
eso agrega dos comandos propios al protocolo FTP: `SITE CPFR` ("copy from", el
origen) y `SITE CPTO` ("copy to", el destino).

**El fallo.** En ProFTPD 1.3.5, `mod_copy` **no exige autenticación** para usar esos
comandos (la debilidad se clasifica como CWE-284, control de acceso inadecuado). Es
decir: un atacante **remoto y anónimo**, sin usuario ni contraseña, puede ordenarle al
servidor que copie archivos arbitrarios de un lado a otro del sistema de archivos.

**Cómo se explota (de copiar archivos a ejecutar código).** El salto de "copiar
archivos" a "ejecutar comandos" es ingenioso y vale la pena entenderlo:

1. El atacante abre una sesión FTP anónima y, en vez de subir un archivo normal, logra
   escribir contenido controlado por él (por ejemplo, una línea de código PHP) en una
   ruta del servidor.
2. Con `SITE CPFR` indica ese contenido como origen y con `SITE CPTO` lo copia a un
   directorio servido por el servidor web (por ejemplo, el *webroot* de Apache,
   `/var/www/html/shell.php`).
3. Ahora esa "web shell" es accesible desde el navegador: al visitarla, el servidor web
   ejecuta el PHP, y el atacante consigue **ejecución remota de comandos** en la máquina.

En otras palabras, `mod_copy` nunca "ejecuta" nada por sí mismo —solo copia—, pero esa
capacidad de escribir archivos arbitrarios sin autenticación, combinada con un servidor
web en la misma máquina, se convierte en una cadena de explotación hacia RCE. Existen
módulos públicos de Metasploit y exploits en Exploit-DB que automatizan toda la
secuencia.

**Severidad.** El impacto es máximo: **CVSS v2 = 10.0** y **CVSS v3.1 = 10.0 (CRÍTICO)**,
con vector de red (`AV:N`), baja complejidad (`AC:L`) y sin privilegios ni interacción
del usuario. Además, CISA lo incorporó a su catálogo **KEV** (Known Exploited
Vulnerabilities), lo que significa que no es teórico: hay explotación activa registrada
en el mundo real.

**Por qué el banner alcanza para sospechar.** Este es el punto que conecta con todo el
laboratorio. No hizo falta explotar nada para clasificar el hallazgo: bastó con que el
servicio se "presentara" (`220 ProFTPD 1.3.5 Server`). Con el producto y la versión
exactos, se consulta una base de CVE (NVD, Exploit-DB) y se descubre que esa versión
puntual carga una vulnerabilidad crítica conocida. Esa es, literalmente, la cadena del
recon: **descubrir → identificar (versión) → clasificar (CVE/CVSS) → priorizar**. Un
banner que "canta" la versión es, para el defensor, una fuga de información; para el
atacante, el atajo que convierte un escaneo en un plan de ataque.

---

## 2. Fuentes

- **Registro oficial de la vulnerabilidad** (CVSS, versiones afectadas, CWE, estado KEV):
  https://vulnerability.circl.lu/vuln/cve-2015-3306
- **Exploit público (Exploit-DB)** — ProFTPd 1.3.5 'mod_copy' Remote Command Execution:
  https://www.exploit-db.com/exploits/49908
- **Firma de detección (Juniper Threat Labs)** — perspectiva defensiva sobre el abuso de
  `SITE CPFR`/`CPTO` sin autenticación:
  https://www.juniper.net/us/en/threatlabs/ips-signatures/detail.FTP:PROFTP:REMOTE-FILE-COPY.html

---

## 3. Reflexión

Lo que nos llevamos es que una versión exacta en un banner no es un dato cosmético: es la
llave que transforma "hay un FTP corriendo" en "hay una vía de ejecución remota sin
autenticar". Conecta de lleno con el laboratorio, porque el hallazgo del puerto 21 pasó
de ser un simple "puerto abierto" a ser el hallazgo crítico del mapa de superficie solo
por identificar bien el producto y la versión. También nos deja una lección defensiva:
ocultar o minimizar los banners de versión y mantener el software actualizado no es
paranoia, es cerrarle al atacante el atajo que acabamos de recorrer.

---
