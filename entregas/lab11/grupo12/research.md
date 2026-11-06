# Mini-research — Laboratorio 11

**Grupo:** 12  
**Tema elegido:**
- [ ] **A.** Volatility 3: cómo se captura un volcado de RAM (LiME, avml) y qué plugins se usan para procesos, red y credenciales.
- [x] **B.** Orden de volatilidad (RFC 3227) y por qué define el orden de captura *(articulado con ISO/IEC 27037 y Cadena de Custodia)*.
- [ ] **C.** Cadena de custodia: requisitos legales y por qué una evidencia mal manejada se cae en un juicio.
- [ ] **D.** IOCs y su ciclo de vida: cómo se comparten (STIX/TAXII, MISP) y cómo se usan para detectar el mismo ataque en otros sistemas.

---

## Desarrollo

### 1. El Orden de Volatilidad según IETF RFC 3227
En la respuesta a incidentes y forensia digital (*DFIR*), el **Principio de Intercambio de Locard** establece que todo contacto entre el atacante y el sistema deja un rastro. Sin embargo, en los sistemas computacionales modernos muchos de esos rastros residen en medios de almacenamiento transitorios cuya vida útil se mide en milisegundos o minutos.

El estándar **IETF RFC 3227** (*Guidelines for Evidence Collection and Archiving*, sección 2.1) formaliza el **Orden de Volatilidad**, exigiendo que la recolección de evidencia proceda estrictamente desde lo más volátil hacia lo menos volátil:

| Prioridad | Nivel de Volatilidad | Artefactos Técnicos | Vida útil típica / Riesgo de pérdida |
|:---:|---|---|---|
| **1°** | **Registros de CPU y Caché (L1/L2/L3)** | Registros de propósito general, punteros de instrucción (`RIP`/`EIP`), caché de procesador. | Nanosegundos / Ciclos de reloj (se sobrescriben con cada instrucción ejecutada). |
| **2°** | **Memoria Principal (RAM) y Tablas del Kernel** | Tabla de procesos activos (`task_struct`), sockets de red (`ESTABLISHED`/`TIME_WAIT`), tabla ARP, rutas, descriptores de archivos abiertos (`lsof`), buffers de heap (`bash_history` en RAM) y claves criptográficas en claro. | Segundos / Minutos; pérdida **total e irreversible** al apagar o reiniciar el equipo. |
| **3°** | **Sistemas de Archivos Temporales / Swap** | `/tmp`, `/dev/shm`, archivos de paginación o hibernación. | Minutos / Horas; `/tmp` (en `tmpfs`) se purga al reiniciar. |
| **4°** | **Almacenamiento Persistente Local (Disco)** | Sistema de archivos (`ext4`/`xfs`), binarios SUID (`/usr/local/bin/system-check`), webshells (`/var/www/uploads/shell.php`), `/etc/passwd`, `/etc/cron.d/`, bloques no asignados (*unallocated space*). | Persistente ante apagados; vulnerable a sobrescritura o borrado deliberado (`rm`, `shred`). |
| **5°** | **Logs Remotos y Monitoreo de Red** | Servidores SIEM/Syslog centralizados, capturas PCAP en sensores de red, NetFlow. | Persistente fuera del host comprometido (inmune a `root` local si está bien aislado). |
| **6°** | **Medios de Respaldo y Archivo (Backups)** | Snapshots de volúmenes, cintas o copias de seguridad en frío (*cold storage*). | Meses / Años. |

---

### 2. Por qué el Orden de Volatilidad define la estrategia de captura (Aplicación al caso PhantomCorp)
El dilema fundamental del perito forense al llegar a un sistema comprometido en vivo (*Live Forensics*) es la **Paradoja del Observador Forense**:
- Si el administrador apaga el servidor inmediatamente ("tira del cable") para preservar el disco, **destruye el 100% de la evidencia de los niveles 1 y 2 (RAM)**. En el incidente de `phantomcorp-web`, tirar del cable habría borrado la conexión activa al C2 (`45.13.37.7:4444`, `PID 1490`), el proceso SUID en ejecución (`PID 1477`) y los comandos en memoria (`memoria/bash_history.txt`) que el atacante ya había eliminado del disco con `history -c`.
- Por otro lado, si el investigador ejecuta decenas de comandos pesados dentro del sistema comprometido antes de volcar la RAM, los nuevos procesos creados por el propio investigador sobrescriben páginas de memoria libre y contaminan el estado del sistema.

Por esta razón, el protocolo dictado por **RFC 3227** e **ISO/IEC 27037** establece:
1. **Primero adquirir la memoria RAM completa** hacia un medio externo o de red utilizando herramientas de huella mínima como **AVML** (*Acquire Volatile Memory for Linux*, desarrollada en Rust por Microsoft y estáticamente enlazada) o **LiME** (*Linux Memory Extractor* vía módulo de kernel).
2. **Luego adquirir el estado de red y procesos volátiles** (o extraerlos *offline* desde el dump de RAM usando **Volatility 3** con los plugins `linux.pslist`, `linux.sockstat`, `linux.lsof` y `linux.bash`).
3. **Recién después realizar la imagen bit a bit (*bit-stream image*) del disco** con `dd` / `dc3dd` y calcular los hashes criptográficos SHA-256 de cada artefacto.

---

### 3. Preservación y Cadena de Custodia bajo ISO/IEC 27037
La norma internacional **ISO/IEC 27037:2012** (*Guidelines for identification, collection, acquisition, and preservation of digital evidence*) complementa a la RFC 3227 estableciendo los pilares que otorgan validez legal y pericial a la evidencia recolectada:

1. **Principio de Mismidad e Integridad Criptográfica:**
   Al momento exacto de la adquisición se calcula el resumen criptográfico (SHA-256) de cada archivo o imagen forense (`evidencia.sha256`). Cualquier análisis posterior debe realizarse **exclusivamente sobre copias de trabajo**, verificando antes y después con `shasum -a 256 -c` que el hash permanezca idéntico. Como se demostró en el reto **R5** con `logs/auth.log` (`FAILED`), la función hash actúa como un sello matemático inquebrantable que expone de inmediato cualquier alteración post-captura.
2. **Auditabilidad y Trazabilidad (Acta de Cadena de Custodia):**
   Todo traslado o acceso a la evidencia debe quedar registrado cronológicamente detallando: *quién* recolectó el artefacto, *cuándo* (timestamp UTC), *cómo* (herramienta y versión), *dónde* se resguardó y *qué hash SHA-256* arrojó.
3. **Reproducibilidad Científica:**
   Los métodos y herramientas utilizados (como el script `src/timeline.py` o los comandos de Volatility 3) deben estar documentados de modo que otro perito independiente, aplicando el mismo procedimiento sobre una copia de la evidencia original, obtenga exactamente los mismos resultados y conclusiones.

---

## Fuentes

1. **IETF — Brezinski, D., & Killalea, T. (2002).** *RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55)*. Internet Engineering Task Force.  
   Disponible en: https://datatracker.ietf.org/doc/html/rfc3227
2. **ISO/IEC (2012).** *ISO/IEC 27037:2012 — Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence*. International Organization for Standardization.  
   Disponible en: https://www.iso.org/standard/44381.html
3. **NIST — Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006).** *NIST Special Publication 800-86: Guide to Integrating Forensic Techniques into Incident Response*. National Institute of Standards and Technology.  
   Disponible en: https://csrc.nist.gov/publications/detail/sp/800-86/final
4. **The Volatility Foundation (2024).** *Volatility 3 Framework Documentation — Linux Memory Forensics Plugins (`linux.pslist`, `linux.sockstat`, `linux.lsof`, `linux.bash`)*.  
   Disponible en: https://volatility3.readthedocs.io/en/latest/

---

## Reflexión

El estudio conjunto de la RFC 3227 y la norma ISO/IEC 27037 deja una enseñanza fundamental para el cierre de la materia: en respuesta a incidentes, la velocidad técnica sin rigor metodológico destruye las pruebas. Un equipo que apaga un servidor por pánico pierde la memoria RAM donde residían las únicas pruebas de la exfiltración tras un `history -c`; y un equipo que analiza archivos originales sin verificar ni preservar su cadena de custodia SHA-256 convierte un hallazgo técnico brillante en una prueba nula ante un tribunal. La excelencia en ciberseguridad exige dominar tanto el arte ofensivo de encontrar la vulnerabilidad como la disciplina forense de reconstruir y preservar la verdad con rigor científico.
