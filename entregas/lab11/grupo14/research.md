# Mini-research — Laboratorio 11

**Tema elegido:** B. Orden de volatilidad (RFC 3227) y por qué define el orden de captura.

## Desarrollo

La RFC 3227 (*Guidelines for Evidence Collection and Archiving*) es una guía para quien recolecta evidencia digital tras un incidente. Su idea central es el **orden de volatilidad**: se captura primero lo que antes se pierde. El orden que propone, de más a menos volátil, es: registros y caché del procesador; tabla de ruteo, caché ARP, tabla de procesos, estadísticas del kernel y memoria; sistemas de archivos temporales; disco; logs y datos de monitoreo remotos; configuración física y topología de red; medios de archivo.

Por qué importa: capturar en el orden equivocado destruye evidencia. Apagar el equipo para sacar una imagen de disco borra la RAM, y con ella los procesos, conexiones y comandos. Además, la propia recolección altera el sistema, así que conviene minimizar la actividad sobre la máquina y empezar por lo más frágil. La RFC también pide documentar cada paso, hashear la evidencia, trabajar sobre copias y mantener la cadena de custodia, y recomienda ser transparente y no hacer suposiciones sobre lo que no se verificó.

Aplicado a este lab: la memoria (`pslist`, `netstat`, `lsof`, `bash_history`) se capturó a las 02:30 y aportó lo que el disco ya no tenía: el `nc` hacia 45.13.37.7:4444 y los comandos del atacante, que había hecho `history -c` y borrado el historial del disco. El disco aportó los archivos dejados (webshell, SUID, cron) y los logs la secuencia de pedidos HTTP. Los hashes de `evidencia.sha256` permitieron detectar que `auth.log` fue alterado después de la captura.

Límite: el orden es una guía, no un dogma. La propia RFC admite adaptarlo según el caso, y la captura de RAM tiene un costo (altera el sistema y puede no ser posible).

## Fuentes (mín. 3)

1. Brezinski, D. y Killalea, T. (2002). *RFC 3227: Guidelines for Evidence Collection and Archiving* (BCP 55). IETF. https://www.rfc-editor.org/rfc/rfc3227
2. Kent, K., Chevalier, S., Grance, T. y Dang, H. (2006). *NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response*. NIST.
3. Ligh, M. H., Case, A., Levy, J. y Walters, A. (2014). *The Art of Memory Forensics*. Wiley.
4. The Volatility Foundation. *Volatility 3* (documentación oficial). https://volatility3.readthedocs.io

**Nota:** estas fuentes se citan de memoria, por ser obras que se conocen con certeza; **no fueron abiertas ni consultadas durante esta sesión**. Hay que verificar año, ediciones y enlaces antes de la entrega.

## Reflexión

Lo que más me sorprendió es que el orden de captura es una decisión que se toma una sola vez y no se puede deshacer: si se apaga la máquina, la memoria no vuelve. El caso del lab lo muestra bien, porque sin la RAM no habríamos sabido del C2 activo ni de los comandos de exfiltración. También me quedó claro que seguir un orden no alcanza si no se documenta: el `auth.log` alterado demuestra que la integridad (hashes) y la custodia valen tanto como la técnica. Como grupo, usamos IA para trabajar el informe; por eso verificamos cada resultado contra la salida real de los comandos y la evidencia.
