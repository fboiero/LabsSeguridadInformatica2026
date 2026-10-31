# Mini-research — Laboratorio 05

**Grupo:** 08
**Tema elegido:** **A.** El CVE-2015-3306 de ProFTPD 1.3.5: qué es el `mod_copy`, cómo se explota el comando `SITE CPFR/CPTO`, y por qué un banner de versión alcanza para saber que un servidor es vulnerable.

---

## Desarrollo

### Qué es `mod_copy`

`mod_copy` agrega a ProFTPD los comandos `SITE CPFR` (origen) y `SITE CPTO` (destino). Funcionan como `RNFR` y `RNTO`, pero copian archivos dentro del servidor sin que el cliente tenga que bajarlos y volver a subirlos [1]. Upstream no lo compila por defecto [1], aunque algunas distribuciones lo incluyeron en sus paquetes: Debian tuvo que publicar un aviso de seguridad por esta falla [5].

### La falla

Es un error de control de acceso (CWE-284 en NVD [2]). El título del reporte original lo resume: *"Unauthenticated copying of files via SITE CPFR/CPTO allowed by mod_copy"* [3]. El módulo atendía estos comandos antes del login, de modo que cualquier cliente que abriera una conexión podía copiar archivos con los permisos del proceso del servidor.

La prueba de concepto de Exploit-DB es una sesión FTP sin autenticar [4]:

```
site cpfr /etc/passwd
350 File or directory exists, ready for destination name
site cpto /tmp/passwd.copy
250 Copy successful
```

### Cómo se pasa de copiar a ejecutar

Esta parte nos pareció la más interesante. El atacante no puede subir contenido, solo copiar lo que ya existe. La salida es hacer que el servidor escriba texto controlado por el atacante en algún lugar y copiar ese lugar a un directorio web:

- La prueba de concepto de Exploit-DB intenta primero un `cpto` con código PHP como ruta. El servidor lo rechaza con `550`, pero la ruta queda escrita en una línea de log. Después copia `/proc/self/fd/3` a `/var/www/test.php`: el archivo final son líneas de log con la etiqueta PHP incrustada, y el intérprete ejecuta lo que está entre las etiquetas aunque el resto no sea PHP [4].
- El módulo de Metasploit `proftpd_modcopy_exec` usa `/proc/self/cmdline` como origen para el mismo fin [6].

De ahí sacamos un matiz importante: **la ejecución remota no es automática**. Según estos dos ejemplos, hace falta un directorio web donde el proceso FTP pueda escribir y un servidor que interprete lo copiado. Lo que la falla da siempre es la copia de archivos sin autenticación, como dice NVD: *"read and write to arbitrary files"* [2].

### El score, y por qué sigue importando

NVD publica 10.0 en CVSS v2 y 10.0 en CVSS v3.1, este último aportado por CISA-ADP con el vector `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` [2]. El vector explica el número: se ataca por red, con baja complejidad, sin privilegios y sin interacción de un usuario. CISA agregó la falla a su catálogo de vulnerabilidades explotadas el 8 de octubre de 2026 [7], más de once años después de publicada. Un CVE viejo no es un CVE resuelto.

### ¿Alcanza el banner?

La consigna pregunta por qué un banner de versión alcanza. Nuestra conclusión, después de investigarlo, es que **alcanza para priorizar, pero no para confirmar**.

Alcanza para priorizar porque leerlo no requiere credenciales y NVD asocia el CVE a la versión exacta `proftpd:1.3.5` [2]. Además, antes de 1.3.6rc3 el saludo por defecto incluía la versión [8]. Con una sola conexión ya se sabe qué probar primero.

No alcanza para confirmar, por cuatro motivos:

1. **El banner no dice qué módulos hay.** `mod_copy` no se compila por defecto upstream [1].
2. **Los parches se pueden aplicar sin cambiar de versión.** Debian corrigió jessie en `1.3.5-1.1+deb8u1` [5]: la versión upstream sigue siendo 1.3.5, de modo que, por lo que inferimos, un servidor parcheado puede seguir anunciándose como 1.3.5.
3. **El banner es configurable.** `ServerIdent` permite poner cualquier texto [8], o sea ocultar la versión o anunciar una falsa.
4. **También hay falsos negativos.** El reporte original se demostró contra un `ProFTPD 1.3.5rc3 Server (Debian)` [3], y Debian también parcheó la 1.3.4a de wheezy [5], mientras que el CPE de NVD solo lista 1.3.5 [2]. Comparar la cadena exacta se perdería esos casos.

La confirmación real es de comportamiento: enviar `site cpfr <ruta>` sin hacer login y observar si responde `350` [4]. Como el `cpto` no se envía, entendemos que no se copia nada, lo que la vuelve una prueba poco invasiva.

### Qué vimos en PhantomCorp

El puerto 21 anuncia `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)`, pero agrega una línea `214` que nadie pidió y cierra la conexión enseguida: `SYST` no obtuvo respuesta. Sin una sesión que atienda comandos no pudimos hacer esa prueba, así que en nuestro informe el CVE figura como aplicable por versión declarada, no como confirmado.

### Mitigación

Actualizar: el bug se resolvió en 1.3.5a y 1.3.6rc1 [3]. Desde 1.3.6rc1 la directiva `CopyEngine off` hace que el módulo ignore estos comandos [1], sin necesidad de recompilar.

## Fuentes

1. ProFTPD, documentación de `mod_copy`: http://www.proftpd.org/docs/contrib/mod_copy.html
2. NIST NVD, CVE-2015-3306: https://nvd.nist.gov/vuln/detail/CVE-2015-3306
3. ProFTPD Bugzilla, bug 4169: http://bugs.proftpd.org/show_bug.cgi?id=4169
4. Exploit-DB 36742, *ProFTPd 1.3.5 - File Copy*: https://www.exploit-db.com/exploits/36742
5. Debian, DSA-3263-1: https://lists.debian.org/debian-security-announce/2015/msg00154.html y tracker: https://security-tracker.debian.org/tracker/CVE-2015-3306
6. Rapid7, módulo `proftpd_modcopy_exec`: https://www.rapid7.com/db/modules/exploit/unix/ftp/proftpd_modcopy_exec/
7. CISA, Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2015-3306
8. ProFTPD, documentación de `mod_core`, directiva `ServerIdent`: http://www.proftpd.org/docs/modules/mod_core.html#ServerIdent

## Reflexión

Empezamos pensando que el lab se resolvía con cruzar versión contra CVE, y ahí aparece el límite: una versión es una afirmación del servidor, no un hecho. Nos pasó con el FTP de PhantomCorp, y también con el header de Werkzeug en el puerto 8080, que no coincidía con cómo respondía el servicio. Nos llevamos separar lo que un servicio declara de lo que pudimos comprobar, y dejarlo escrito. Decir "aplica por versión, sin confirmar" es menos vistoso que "es vulnerable", pero es lo que después sostiene las decisiones de un pentest.
