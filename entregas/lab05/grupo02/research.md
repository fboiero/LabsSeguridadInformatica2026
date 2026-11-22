# Mini-research — Laboratorio 05

**Grupo:** 02
**Tema elegido:**

- [x] **A.** El CVE-2015-3306 de ProFTPD 1.3.5: qué es el `mod_copy`, cómo se
  explota el comando `SITE CPFR/CPTO`, y por qué un banner de versión alcanza
  para saber que un servidor es vulnerable.
- [ ] **B.** Tipos de escaneo de `nmap` (`-sS` vs `-sT` vs `-sU` vs `-sV`).
- [ ] **C.** OSINT y recon pasivo.
- [ ] **D.** El estándar CVSS.

---

## Desarrollo

### 1. De dónde sale este tema en nuestro lab
En el mapa de superficie (sección 2 del informe) el puerto 21 de `phantomcorp`
respondió con el banner `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)`. Esa única
línea de texto fue suficiente para marcar el servicio como "crítico
condicional" y asociarlo a CVE-2015-3306. Este research explica por qué ese
banner alcanza, qué es el módulo que lo hace explotable y cómo funciona el
ataque, sin ejecutarlo contra el target.

### 2. Qué es `mod_copy` y el comando `SITE CPFR/CPTO`
ProFTPD es un servidor FTP de código abierto muy usado en Linux. Trae módulos
opcionales; uno de ellos es `mod_copy`, que agrega los comandos no estándar
`SITE CPFR` ("copy from") y `SITE CPTO` ("copy to") para copiar archivos dentro
del servidor sin tener que descargarlos y volver a subirlos [1][2]. La idea era
una comodidad de administración.

El problema es que, en la versión 1.3.5, cuando `mod_copy` está cargado estos
comandos **se podían ejecutar sin autenticarse**: el servidor los aceptaba
antes del login [2][3]. Es decir, un usuario anónimo —o directamente sin
sesión— podía pedirle al servidor que copiara archivos.

### 3. Cómo se explota
El flujo del ataque es, conceptualmente, así [2][3]:

1. El atacante se conecta al puerto 21 sin credenciales.
2. Envía `SITE CPFR /ruta/origen` para fijar el archivo de origen.
3. Envía `SITE CPTO /ruta/destino` para copiarlo a donde él controla.

Con esas dos primitivas se consiguen dos cosas graves:

- **Lectura arbitraria:** copiar un archivo sensible (por ejemplo
  `/etc/passwd`) a una carpeta servida por FTP o por el servidor web del mismo
  host, y después descargarlo.
- **Escritura arbitraria → ejecución de código:** usar el esquema de URL
  `file:///` junto con un servicio HTTP/FTP controlado por el atacante para
  escribir un archivo con contenido elegido. Si ese archivo cae en una ruta
  interpretada por un servidor web (por ejemplo un `.php` dentro del webroot),
  el atacante logra ejecución remota de código [2][3]. Por eso Metasploit
  publicó un módulo de explotación (`proftpd_modcopy_exec`) que automatiza
  justamente este encadenamiento [3].

Esto explica la clasificación del informe: la falla es **remota, sin
autenticación y de alto impacto** (confidencialidad, integridad y
disponibilidad), lo que en CVSS v2 da el score máximo de 10.0 [1].

### 4. Por qué el banner de versión alcanza (y por qué igual quedó "condicional")
El reconocimiento de versión funciona porque muchos servicios se anuncian: el
banner de ProFTPD publica producto y número de versión exacto. Como el CVE está
atado a una versión concreta (1.3.5), basta leer `ProFTPD 1.3.5` en el banner
para saber que *esa build* figura como afectada en NVD [1]. No hace falta
atacar nada: la fuga de versión hace el trabajo.

Ahora bien, la vulnerabilidad depende de que `mod_copy` **esté cargado**. El
banner dice la versión, pero no dice qué módulos están habilitados. Por eso en
el informe la criticidad quedó como "crítica condicional": es una vulnerabilidad
*probable* según la versión, no *confirmada*, porque no verificamos (ni
teníamos que hacerlo en un recon) que el módulo estuviera activo. Esa distinción
entre "versión afectada" y "explotación confirmada" es justo lo que la rúbrica
pide no inventar.

### 5. La lección defensiva
Dos medidas concretas se desprenden del caso: **ocultar el banner de versión**
(directiva `ServerIdent off` en ProFTPD) para no regalar la versión en el recon,
y **no cargar módulos que no se usan** —si `mod_copy` no hace falta, no debería
estar—, además de actualizar a una versión corregida. La primera no arregla el
bug pero sube el costo del reconocimiento; la segunda elimina la superficie.

## Fuentes

[1] NVD (NIST) — *CVE-2015-3306 Detail*.
    https://nvd.nist.gov/vuln/detail/CVE-2015-3306
[2] MITRE — *CVE-2015-3306*.
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3306
[3] Rapid7 — *ProFTPD 1.3.5 Mod_Copy Command Execution* (módulo Metasploit
    `exploit/unix/ftp/proftpd_modcopy_exec`).
    https://www.rapid7.com/db/modules/exploit/unix/ftp/proftpd_modcopy_exec/

## Reflexión (3–5 líneas)

Lo que más nos quedó es que un dato aparentemente inofensivo —el número de
versión en un banner— es el puente entre el recon y la explotación: sin tocar
el servicio, la versión ya nos dice qué CVE buscar. También entendimos por qué
en el informe fuimos prudentes y pusimos "crítica condicional": la versión
afectada no garantiza que el módulo vulnerable esté cargado, y afirmar lo
contrario sería inventar. Conecta directo con la medida defensiva que
propusimos en la P5: apagar el banner y sacar `mod_copy` ataca el problema
desde los dos lados, el de la información que se filtra y el de la superficie
real.
