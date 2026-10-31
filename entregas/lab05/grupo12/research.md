# Mini-research — Laboratorio 05

**Grupo:** 12  
**Tema elegido:**
- [x] **A.** El CVE-2015-3306 de ProFTPD 1.3.5: qué es el `mod_copy`, cómo se
  explota el comando `SITE CPFR/CPTO`, y por qué un banner de versión alcanza
  para saber que un servidor es vulnerable.
- [ ] **B.** Tipos de escaneo de `nmap` (`-sS` vs `-sT` vs `-sU` vs `-sV`):
  cómo funciona cada uno a nivel de paquetes TCP/IP y qué huella deja en el
  objetivo.
- [ ] **C.** OSINT y recon pasivo: qué información de una organización se puede
  reunir **sin tocar** sus sistemas (certificados, DNS, buscadores, filtraciones)
  y por qué es tan valiosa para un atacante.
- [ ] **D.** El estándar CVSS: cómo se arma un score (vector base), qué
  significan sus métricas, y por qué "criticidad" no es lo mismo que "score".

---

## Desarrollo

### 1. El módulo `mod_copy` y su propósito original
**ProFTPD** es uno de los servidores FTP de código abierto más utilizados históricamente en entornos Unix/Linux. Dentro de su ecosistema de extensiones, el módulo `mod_copy` (`mod_copy.c`) fue diseñado para proporcionar una funcionalidad de copia local de archivos dentro del propio servidor.

En el protocolo FTP tradicional (RFC 959), si un cliente desea duplicar un archivo existente en el servidor hacia otra ruta del mismo host, debe descargarlo completamente a través de la red y volver a subirlo. El módulo `mod_copy` optimiza esta operación implementando los comandos de extensión `SITE CPFR` (*Copy From*) y `SITE CPTO` (*Copy To*), permitiendo indicar una ruta de origen y una de destino para que el servidor duplique el archivo localmente en disco de manera instantánea.

---

### 2. La vulnerabilidad crítica (CVE-2015-3306): Ausencia de autenticación
La vulnerabilidad catalogada como **CVE-2015-3306** (con puntaje CVSS v3 de **9.8 Crítico**) radica en un grave defecto de control de acceso (*CWE-284: Improper Access Control*):

- **Despacho sin sesión activa:** En el código fuente de ProFTPD 1.3.5, los comandos `SITE CPFR` y `SITE CPTO` fueron registrados en el despachador de directivas FTP permitiendo su ejecución por parte de cualquier cliente conectado al socket TCP (puerto 21), **antes de haber completado la autenticación** (es decir, sin necesidad de enviar credenciales válidas mediante `USER` ni `PASS`).
- **Privilegios del daemon:** Los comandos se ejecutan con los privilegios del usuario de sistema bajo el cual corre el proceso de ProFTPD (frecuentemente `nobody`, `proftpd` o en configuraciones erróneas, `root`). Esto otorga la capacidad de leer cualquier archivo legible por ese usuario y escribir en cualquier directorio donde el proceso posea permisos de escritura.

---

### 3. Mecanismo de explotación y Ejecución Remota de Código (RCE)
El impacto de esta vulnerabilidad trasciende la simple manipulación de archivos y permite alcanzar **Ejecución Remota de Código (RCE)** arbitrario. El vector de ataque más común combina `mod_copy` con la técnica de **inyección en archivos de registro (*Log Poisoning*)**:

```
[Atacante] -- (1) USER <?php system($_GET['cmd']); ?> --> [ProFTPD (Puerto 21)]
                                                                  |
                                              (Loguea payload)    v
                                                        [/var/log/proftpd.log]
                                                                  |
[Atacante] -- (2) SITE CPFR /var/log/proftpd.log -------------->  |
           -- (3) SITE CPTO /var/www/html/shell.php ----------->  |
                                                                  v
                                                        [/var/www/html/shell.php]
                                                                  |
[Atacante] -- (4) GET http://target/shell.php?cmd=id ----------> [Servidor Web (Puerto 80)]
```

1. **Inyección de código en logs:** El atacante inicia una conexión FTP y envía un intento de login con código ejecutable embebido, por ejemplo:  
   `USER <?php passthru($_GET['c']); ?>`  
   El servidor rechaza el usuario inválido pero registra la cadena literal dentro de su archivo de registro de autenticación (ej. `/var/log/proftpd/proftpd.log` o `/var/log/xferlog`).
2. **Copia no autenticada al Document Root web:** Sin autenticarse, el atacante emite:  
   `SITE CPFR /var/log/proftpd/proftpd.log`  
   `SITE CPTO /var/www/html/shell.php`  
   Dado que el usuario de FTP típicamente comparte grupo o permisos de escritura en la carpeta compartida o pública del servidor web, el archivo de log conteniendo el código PHP se copia dentro de la raíz servida por Apache/Nginx.
3. **Disparo de la webshell:** El atacante solicita vía HTTP `http://phantomcorp/shell.php?c=id`, logrando ejecución remota de comandos con los privilegios del servidor web.
4. **Exfiltración de información confidencial:** Alternativamente, el atacante puede copiar archivos sensibles del sistema (ej. `/etc/passwd`, backups locales de bases de datos o claves privadas) hacia `/var/www/html/` para descargarlos libremente por el navegador sin dejar rastros en los logs de transferencia FTP estándar.

---

### 4. ¿Por qué un banner de versión alcanza para determinar la vulnerabilidad?
Durante la fase de reconocimiento (como la realizada contra PhantomCorp en el Reto R2), una simple conexión TCP cruda mediante banner grabbing (`ncat phantomcorp 21`) devuelve la respuesta:
```text
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]
```

Este banner es suficiente para determinar que el host es vulnerable por las siguientes razones:

1. **Presencia universal del módulo por defecto:** En la versión oficial 1.3.5 distribuida por los repositorios binarios de múltiples distribuciones (Debian, Ubuntu, entre otras), el módulo `mod_copy` venía compilado e integrado de manera predeterminada (`--with-modules=mod_copy`).
2. **Falla estructural en el código base:** La vulnerabilidad no depende de una directiva exótica ni de un parámetro opcional; reside en el código intrínseco del despachador de `mod_copy.c`. A menos que el administrador haya recompilado manualmente el software excluyendo el módulo o haya establecido restricciones directas con `<Limit SITE_COP>`, la presencia confirmada de la versión 1.3.5 equivale a una alta certeza de explotabilidad.
3. **El riesgo de la divulgación de información (*Version Disclosure*):** Este escenario ilustra por qué los banners informativos son un vector de fuga crítico en la fase de reconocimiento: le ahorran al atacante la necesidad de realizar pruebas invasivas o ruidosas. Con una única petición no autenticada, el atacante correlaciona la versión expuesta contra bases de datos públicas de vulnerabilidades (NVD, Exploit-DB, CISA KEV) y selecciona el exploit exacto a utilizar.

---

## Fuentes

1. **National Institute of Standards and Technology (NIST) — NVD (2015).** *CVE-2015-3306 Detail — ProFTPD mod_copy Vulnerability*. U.S. Department of Commerce.  
   Disponible en: https://nvd.nist.gov/vuln/detail/CVE-2015-3306
2. **ProFTPD Bugzilla (2015).** *Bug 4169 — mod_copy: SITE CPFR and SITE CPTO allow unauthenticated file copying*. The ProFTPD Project.  
   Disponible en: http://bugs.proftpd.org/show_bug.cgi?id=4169
3. **Offensive Security — Exploit-DB (2015).** *ProFTPD 1.3.5 - 'mod_copy' Remote Command Execution*. Exploit Database Archive (EDB-ID: 36742).  
   Disponible en: https://www.exploit-db.com/exploits/36742
4. **Cybersecurity and Infrastructure Security Agency (CISA).** *Known Exploited Vulnerabilities Catalog (KEV) — CVE-2015-3306 ProFTPD mod_copy Command Execution*. U.S. Department of Homeland Security.  
   Disponible en: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

## Reflexión

El análisis del CVE-2015-3306 demuestra con claridad que **el reconocimiento no es una etapa preliminar decorativa, sino el pivote central que define el éxito de un ataque o de una auditoría defensiva**.

En el Laboratorio 05 bastó un comando de banner grabbing de un segundo (`ncat phantomcorp 21`) para identificar el software exacto (`ProFTPD 1.3.5`). Ese único dato bastó para clasificar inmediatamente el puerto 21 con criticidad 9.8 en nuestro mapa de superficie de ataque, revelando una vía directa hacia la toma de control del servidor (RCE) sin requerir contraseñas. Para el defensor, la lección es contundente: la higiene perimetral exige deshabilitar banners innecesarios (`ServerIdent off`) y desinstalar módulos superfluos; pero por sobre todo, entender que lo que un atacante puede leer en dos segundos de recon determina si la organización resiste o es vulnerada.
