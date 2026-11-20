# Mini-research — Laboratorio 05

**Grupo:** 14
**Tema elegido:** **A.** CVE-2015-3306 de ProFTPD 1.3.5 — `mod_copy`,
`SITE CPFR/CPTO` y por qué el banner de versión alcanza.

---

## Desarrollo

### Qué es `mod_copy`

`mod_copy` es un módulo de ProFTPD que agrega dos comandos propietarios al
protocolo FTP, expuestos vía el comando `SITE`:

- `SITE CPFR <origen>` — *copy from*: marca el archivo de origen.
- `SITE CPTO <destino>` — *copy to*: lo copia al destino.

El objetivo legítimo es copiar archivos **dentro del servidor** sin tener que
descargarlos y volver a subirlos, algo útil para administrar grandes volúmenes.
El problema es cómo quedó implementado en las versiones afectadas.

### La vulnerabilidad (CVE-2015-3306)

En ProFTPD 1.3.5 (y 1.3.6 pre-parche), `mod_copy` **no exige autenticación** para
ejecutar `SITE CPFR`/`SITE CPTO`. Un usuario remoto anónimo puede, por lo tanto,
copiar archivos arbitrarios dentro del sistema de archivos del servidor con los
privilegios del proceso FTP. Reportada por Vadim Melihow en 2015.

El salto de "copiar archivos" a **ejecución remota de código (RCE)** es el truco
clásico del exploit: si el mismo host sirve contenido web desde un directorio
sobre el que el FTP puede escribir (por ejemplo un `DocumentRoot` compartido), el
atacante:

1. Hace que el servidor escriba un payload — típicamente combinando la carga de
   datos con un `SITE CPFR`/`CPTO` hacia la raíz web — por ejemplo un pequeño
   script PHP (`<?php system($_GET['c']); ?>`).
2. Luego **invoca ese archivo por HTTP**, y el intérprete web lo ejecuta.

Resultado: comandos arbitrarios en el servidor, **sin credenciales**. Existe un
módulo de Metasploit (`exploit/unix/ftp/proftpd_modcopy_exec`) que automatiza
exactamente esta cadena.

### Severidad

NVD clasifica CVE-2015-3306 con **CVSS v2 base 10.0 (HIGH)**, vector
`AV:N/AC:L/Au:N/C:C/I:C/A:C`: accesible por **red**, **baja complejidad**, **sin
autenticación** e impacto **total** en confidencialidad, integridad y
disponibilidad. NVD **no publicó un score CVSS v3.x** para este CVE (figura como
*N/A*), así que no citamos uno; el 10.0 de la v2 ya describe el peor perfil
posible: explotable de forma remota y no autenticada.

### Por qué el banner de versión alcanza

Acá está la conexión directa con el recon de este lab. No hace falta "probar" el
exploit para saber que el servidor es vulnerable: **el banner lo delata**. Al
conectarnos con `ncat phantomcorp 21` el servicio se presenta solo:

```
220 ProFTPD 1.3.5 Server (PhantomCorp FTP)
```

Con solo "ProFTPD 1.3.5" en la mano, cruzamos esa cadena contra una base de CVE
(NVD, Exploit-DB, `searchsploit`) y aparece CVE-2015-3306. El fingerprinting de
**versión exacta** convierte un "hay un FTP abierto" (dato sin valor) en "hay un
FTP con RCE no autenticado" (hallazgo accionable). Esa es, en una línea, la tesis
del laboratorio: un puerto abierto no es un hallazgo; un puerto abierto
**identificado y clasificado** sí lo es.

## Fuentes

- NVD — CVE-2015-3306: https://nvd.nist.gov/vuln/detail/CVE-2015-3306
- CVE Details — CVE-2015-3306: https://www.cvedetails.com/cve/CVE-2015-3306/
- Rapid7 / Metasploit — `proftpd_modcopy_exec`:
  https://www.rapid7.com/db/modules/exploit/unix/ftp/proftpd_modcopy_exec/
- ProFTPD — documentación de `mod_copy`: http://www.proftpd.org/docs/contrib/mod_copy.html

## Reflexión (3–5 líneas)

Nos llevamos que el recon no es "correr nmap": es cerrar el bucle hasta
**clasificar**. En este lab el banner del 21 nos dio la versión, y la versión nos
dio un CVE con CVSS v2 10.0. Sin ese último paso, el FTP era solo "un puerto más".
Entendimos también por qué publicar la versión en el banner (como hace
PhantomCorp) es un error del defensor: le entrega al atacante el trabajo de
identificación ya hecho.
