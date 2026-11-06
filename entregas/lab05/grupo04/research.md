# Mini-research — Laboratorio 05

**Grupo:** 04
**Tema elegido:**

- [x] **A.** El CVE-2015-3306 de ProFTPD 1.3.5: qué es el `mod_copy`, cómo se explota el comando `SITE CPFR/CPTO`, y por qué un banner de versión alcanza para saber que un servidor es vulnerable.
- [ ] **B.** Tipos de escaneo de `nmap` (`-sS` vs `-sT` vs `-sU` vs `-sV`)
- [ ] **C.** OSINT y recon pasivo
- [ ] **D.** El estándar CVSS

---

## Desarrollo

### 1. Qué es ProFTPD y qué es `mod_copy`

ProFTPD es un servidor FTP de código abierto para Linux y Unix. Tiene una arquitectura modular: funciones opcionales se agregan como módulos que se cargan en `proftpd.conf`. Uno de ellos es `mod_copy`, que agrega al protocolo FTP dos comandos no estándar, `SITE CPFR` (*copy from*, origen) y `SITE CPTO` (*copy to*, destino). Sirven para copiar archivos **dentro del servidor** sin tener que descargarlos y volver a subirlos.

### 2. La vulnerabilidad

El CVE-2015-3306 afecta a ProFTPD 1.3.5. La descripción oficial dice que el módulo permite a atacantes remotos leer y escribir archivos arbitrarios mediante esos dos comandos. El fallo de fondo es de **control de acceso**: OpenCVE clasifica el problema como CWE-284 (*Improper Access Control*). Los comandos estaban disponibles para clientes que **no habían iniciado sesión**, cuando deberían haber exigido autenticación.

Datos verificables sobre su historia:

- El problema fue descubierto por el investigador Vadim Melihow, a quien Debian le atribuye el hallazgo en su aviso DSA-3263-1.
- El CVE se publicó en la NVD el 18/05/2015.
- Debian emitió su aviso de seguridad el 19/05/2015 y corrigió `proftpd-dfsg` en `wheezy` (1.3.4a-5+deb7u3) y en `jessie` (1.3.5-1.1+deb8u1).
- Existe un módulo público de Metasploit para explotarlo, y la plataforma Nessus lo marca como explotable con exploits disponibles.

La corrección está en **ProFTPD 1.3.5a** y **1.3.6rc1** (o superior), según los avisos de SAINT y de openSUSE.

### 3. Cómo se explota

Los comandos se ejecutan con los privilegios del proceso de ProFTPD, que por defecto corre como el usuario `nobody`. La explotación típica tiene dos pasos:

1. **Lectura/copia:** con `SITE CPFR <origen>` se indica qué archivo copiar y con `SITE CPTO <destino>` dónde dejarlo. Un atacante puede copiar archivos legibles por ese usuario a un lugar accesible.
2. **Escritura:** se puede escribir contenido propio en el servidor. El caso más conocido es copiar un archivo con código PHP hacia el directorio de un servidor web. El módulo de Metasploit (descripto en Packet Storm) usa `/proc/self/cmdline` para meter el código del atacante en un archivo y lo copia al directorio web. Luego basta pedir esa URL por HTTP para ejecutar el código. Esto convierte una lectura/escritura de archivos en **ejecución remota de código**.

Ese último paso no es automático. Según SAINT, el exploit exige que `mod_copy` esté **habilitado** y que el servidor además ejecute un servidor web con PHP. Además, el usuario de ProFTPD tiene que poder dejar el archivo en el directorio web. Es decir que el CVE habilita lectura y escritura por sí solo, y el RCE depende del entorno.

### 4. Severidad

Los sitios consultados reportan un **CVSS v2 de 10.0** (el máximo), con vector `AV:N/AC:L/Au:N/C:C/I:C/A:C` según el plugin de Tenable: se llega por red, con complejidad baja, sin autenticación, y con impacto total en confidencialidad, integridad y disponibilidad. La página de la NVD consultada indica que el registro no está priorizado para enriquecimiento, así que conviene confirmar el puntaje vigente directamente en la ficha antes de citarlo.

### 5. ¿Por qué un banner de versión alcanza para saber que es vulnerable?

Alcanza **para identificar un candidato**, no para confirmar la explotación. El banner `220 ProFTPD 1.3.5 Server` nos da producto y versión exactos, y la base de datos de CVE asocia esa versión (con el identificador `cpe:2.3:a:proftpd:proftpd:1.3.5`) al CVE-2015-3306. Con eso se justifica clasificarlo como crítico en un recon sin tocar nada más.

Pero el banner **no dice** si `mod_copy` está cargado, ni si el mantenedor de la distribución aplicó el parche sin cambiar el número de versión (algunas distribuciones backportean correcciones). Por eso lo correcto es escribir "vulnerable por versión, no verificado": hay que probar el comando `SITE CPFR` para confirmarlo, y eso solo se hace con autorización. En el laboratorio no lo hicimos: nos limitamos a leer el banner con `ncat` y `nmap -sV`.

### 6. Mitigación

- Actualizar a ProFTPD 1.3.5a, 1.3.6rc1 o superior, o instalar el paquete corregido de la distribución. El Debian Security Tracker lista las versiones empaquetadas corregidas para cada release.
- Si no se usa la función, **no cargar** `mod_copy` en `proftpd.conf`.
- Reducir la exposición: filtrar el puerto 21 por firewall y evaluar reemplazar FTP por SFTP.
- Ejecutar el servicio con el mínimo privilegio y evitar que tenga escritura sobre directorios web.

---

## Fuentes

1. NIST — National Vulnerability Database, ficha de **CVE-2015-3306**: https://nvd.nist.gov/vuln/detail/CVE-2015-3306
2. Debian Security Tracker, **CVE-2015-3306** (versiones corregidas por release, referencia al DSA-3263-1): https://security-tracker.debian.org/tracker/CVE-2015-3306
3. Aviso **DSA-3263-1** de Debian (atribución del hallazgo y versiones corregidas), reproducido en LinuxSecurity: https://linuxsecurity.com/advisories/debian/debian-dsa-3263-1-proftpd-dfsg-security-update
4. SAINT Corporation, **ProFTPD mod_copy command execution** (descripción, limitaciones y resolución a 1.3.5a / 1.3.6rc1): https://my.saintcorporation.com/cgi-bin/exploit_info/proftpd_mod_copy
5. Packet Storm, **CVE-2015-3306** (descripción del módulo de Metasploit y del aviso de Debian): https://packetstormsecurity.com/files/cve/CVE-2015-3306
6. LWN.net, aviso **openSUSE-SU-2015:1031-1** (actualización a 1.3.5a): https://lwn.net/Articles/647899/
7. Tenable, plugin Nessus **83546** (vector y puntaje CVSS v2): https://www.tenablecloud.cn/plugins/nessus/83546
8. OpenCVE, ficha de **CVE-2015-3306** (clasificación CWE-284 y producto afectado): https://opencve.greenant.net/cve/CVE-2015-3306

---

## Reflexión

Este CVE resume la idea central del laboratorio: un puerto abierto no es un hallazgo, pero un puerto abierto con producto y versión identificados sí lo es. Con una sola línea de `nmap -sV` y un banner pudimos clasificar el puerto 21 como el servicio más crítico de PhantomCorp, sin enviar un solo comando adicional. Lo que más nos llevamos es la diferencia entre **lo que el banner prueba y lo que no**: nos dice la versión, pero no si `mod_copy` está cargado ni si hay un parche aplicado, por eso en el informe lo marcamos como vulnerable por versión y no como explotado. También vimos que el riesgo real del CVE depende del entorno: la lectura y escritura de archivos es directa, pero llegar a ejecutar código exige que se den otras condiciones. Para la defensa, la lección práctica es doble: mantener actualizado el software y desactivar los módulos que no se usan.