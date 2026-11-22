# Mini-research — Laboratorio 08 · Post-explotación

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149  
**Fecha:** 30 de Octubre de 2026

**Tema elegido:**
- [x] **A.** GTFOBins: qué es, cómo se usa un binario SUID/sudo para escalar, tres ejemplos concretos.
- [ ] **B.** Pivoting y túneles: cómo se pivotea de verdad (SSH tunneling, chisel, proxychains) más allá de un simple curl.
- [ ] **C.** Gestión de secretos: por qué los `.env` en el server son un problema y qué los reemplaza (vaults, variables de entorno efímeras, etc.).
- [ ] **D.** De scripts a agentes: qué agrega un agente de IA sobre un script de automatización, y qué NO debería decidir solo.

---

## Desarrollo

### 1. ¿Qué es GTFOBins y qué problemática aborda?
En sistemas tipo UNIX/Linux, una gran cantidad de programas estándar y utilidades legítimas del sistema operativo incorporan características diseñadas para interactuar con el entorno: lectura y escritura de archivos, ejecución de comandos del sistema, invocación de paginadores interactivos o escapes a la shell.

Cuando estos programas se configuran con privilegios especiales —específicamente a través del bit **SUID** (*Set User ID*) o mediante reglas delegadas en el archivo de configuración de **`sudo`** (`/etc/sudoers`) sin restricciones de comandos—, esas mismas funcionalidades legítimas pueden ser abusadas por un usuario local sin privilegios para evadir las restricciones de seguridad y obtener una shell interactiva como superusuario (`root`).

**GTFOBins** es un proyecto colaborativo de código abierto de referencia global en seguridad ofensiva y defensiva. Funciona como una base de conocimiento curada que cataloga binarios ejecutables legítimos de Linux y documenta de forma sistemática cómo pueden ser aprovechados para eludir restricciones locales de seguridad, romper shells restringidas (*jailbreak*), transferir archivos, escalar privilegios o mantener persistencia, sin necesidad de explotar vulnerabilidades de corrupción de memoria ni depender de exploits externos (*Living Off the Land* - LotL).

---

### 2. Mecanismo de escalada: El bit SUID y la delegación con Sudo

La escalada de privilegios a través de binarios legítimos explota dos mecanismos centrales del modelo de permisos de Linux:

1. **El bit SUID (SetUID):**  
   Identificado con el bit de modo octal `4000` (`-rwsr-xr-x`), instruye al kernel de Linux a ejecutar el archivo binario con los privilegios de su propietario (frecuentemente `root`), en lugar de los privilegios del usuario real que invoca el comando (`ruid`). Si el binario posee una funcionalidad que permita lanzar un comando arbitrario, spawnear un subproceso hijo o leer/escribir en cualquier ruta del disco, esa acción se ejecutará con el identificador efectivo `euid=0`, heredando los privilegios totales del administrador.
2. **Privilegios delegados en Sudo:**  
   Cuando un usuario o servicio posee una entrada en `/etc/sudoers` que le permite ejecutar un binario específico con `sudo` (incluso sin contraseña, `NOPASSWD`), si dicho comando no está estrictamente restringido en sus parámetros, el usuario puede invocar subcomandos o consolas que se ejecutan directamente en el espacio de usuario de `root`.

---

### 3. Tres ejemplos concretos de binarios y su técnica de escalada

A continuación se analizan tres herramientas esenciales documentadas en GTFOBins, detallando la funcionalidad abusada y el comando de explotación:

#### Ejemplo 1: `find` (Invocación de comandos vía parámetro `-exec`)
- **Funcionalidad legítima:** `find` es la herramienta estándar para buscar archivos en el árbol de directorios. Incluye el argumento `-exec`, diseñado para ejecutar una acción sobre cada archivo coincidente.
- **Abuso para escalada:** Si `find` tiene el bit SUID activo o puede ejecutarse con `sudo`, el parámetro `-exec` ejecuta comandos con privilegios elevados.
- **Comando de explotación:**
  ```bash
  # Con bit SUID root activo:
  find . -exec /bin/sh -p \; -quit

  # Con permisos de sudo:
  sudo find . -exec /bin/sh \; -quit
  ```
- **Mecánica interna:** `find` invoca la llamada al sistema `execve("/bin/sh", ...)` bajo su propio contexto de ejecución privilegiado. El parámetro `-p` preserva el Effective UID si se trata de SUID, y `-quit` finaliza inmediatamente tras el primer archivo, entregando una shell root limpia.

#### Ejemplo 2: `vim` / `vi` (Escape a shell desde el modo interactivo)
- **Funcionalidad legítima:** Los editores de texto interactivos basados en consola permiten al usuario ejecutar comandos de shell externos sin cerrar el editor mediante la sintaxis `:!comando` o la directiva `:shell`.
- **Abuso para escalada:** Si un administrador concede permisos para editar un archivo con `sudo vim /etc/hosts` o si el editor posee permisos SUID indebidos, el operador puede escapar del editor hacia una shell como root.
- **Comando de explotación:**
  ```bash
  # Ejecución mediante sudo:
  sudo vim -c ':!/bin/sh'
  ```
  O desde adentro de una sesión de vim ya abierta:
  ```vim
  :set shell=/bin/sh
  :shell
  ```
- **Mecánica interna:** Vim suspende su propia ejecución y spawnea el shell declarado en `:set shell`. Al haberse invocado con `sudo`, el proceso hijo `/bin/sh` nace como proceso hijo de un padre que corre como `uid=0`, otorgando acceso administrativo irrestricto.

#### Ejemplo 3: `bash` / `cp` (Copias de shell o manipulación de archivos críticos)
- **Funcionalidad legítima:** `cp` copia archivos en el sistema de archivos; una copia de `bash` permite ejecutar scripts.
- **Abuso con `cp` (SUID):** Un binario de copia con permisos SUID permite sobreescribir archivos críticos del sistema operativo que controlan la autenticación (como `/etc/passwd` o `/etc/shadow`), o escribir una llave pública en `/root/.ssh/authorized_keys`.
- **Comando de explotación:**
  ```bash
  # Generar una línea de usuario root con password conocido 'password':
  openssl passwd -1 -salt xyz password
  # Línea: hacker:$1$xyz$p5gK...:0:0:root:/root:/bin/bash

  # Utilizar 'cp' con SUID para sobreescribir /etc/passwd con el nuevo usuario:
  LFILE=/etc/passwd
  cp --attributes-only --preserve=all /etc/passwd /tmp/passwd.bak
  echo 'hacker:$1$xyz$p5gK...:0:0:root:/root:/bin/bash' >> /tmp/passwd
  cp /tmp/passwd /etc/passwd
  su hacker
  ```
- **Mecánica interna:** `cp` abre `/etc/passwd` en modo escritura con las credenciales efectivas de `root`. Al insertar una entrada con UID `0`, el atacante crea un superusuario alternativo y accede inmediatamente con `su hacker`.

---

## Fuentes

1. **GTFOBins Project (2024).** *Curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems*. Emilio Pinna & Andrea Cardaci.  
   Disponible en: https://gtfobins.github.io/
2. **NIST — National Institute of Standards and Technology (2020).** *Special Publication 800-53 Rev. 5: Security and Privacy Controls for Information Systems and Organizations — Control AC-6: Least Privilege*. U.S. Department of Commerce.  
   Disponible en: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
3. **MITRE ATT&CK (2023).** *Technique T1548.001: Abuse Elevation Control Mechanism: Setuid and Setgid*. The MITRE Corporation.  
   Disponible en: https://attack.mitre.org/techniques/T1548/001/
4. **Kerrisk, M. (2010).** *The Linux Programming Interface: A Linux and UNIX System Programming Handbook* (Capítulo 9: Process Credentials, SUID/SGID internals). No Starch Press.

---

## Reflexión

El estudio de GTFOBins transforma radicalmente la perspectiva del analista sobre la seguridad en sistemas Linux: demuestra de forma contundente que la escalada de privilegios no requiere necesariamente exploits de día cero ni vulnerabilidades de software complejas, sino que se nutre primordialmente de malas configuraciones operativas en utilidades estándar. El bit SUID y las reglas laxas de sudo convierten herramientas cotidianas de administración en puertas traseras legítimas. Como defensores, la lección fundamental es aplicar el principio de mínimo privilegio estricto, migrar hacia Linux Capabilities granulares, montar particiones con la bandera `nosuid` y auditar de forma continua los permisos de archivos en cada despliegue de infraestructura.
