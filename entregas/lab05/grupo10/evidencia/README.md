# Evidencia del Laboratorio 05 — Grupo 10

## Procedencia y alcance

Las once capturas originales documentan respuestas obtenidas del contenedor de
la cátedra `phantomcorp` el 10/10/2026 (fechas UTC dentro de los archivos).
Se conservaron sin modificar. No se usaron sistemas de terceros para la práctica.

El 05/11/2026 se registraron las cinco flags ya presentes en esas capturas con
el verificador oficial del curso.

| Reto | Técnica documentada | Captura original |
|---|---|---|
| R1 | Barridos TCP y banner del puerto 31337 | [Barrido completo](lab05-nmap-all-ports.txt), [banner TCP](lab05-banner-31337.txt) |
| R2 | Banner FTP | [Banner FTP](lab05-banner-ftp.txt) |
| R3 | Cabeceras HTTP | [Respuesta HTTP](lab05-http-root.txt) |
| R4 | Ruta publicada en robots.txt y respuesta del panel | [robots.txt](lab05-robots.txt), [panel](lab05-hidden-panel.txt) |
| R5 | Información del endpoint de estado de desarrollo | [Respuesta de estado](lab05-http-8080-status.txt), [captura adicional](lab05-r5-status.txt) |

El escaneo por defecto también encontró 31337 en esta ejecución. La asociación
con R1 no implica que ese puerto haya sido descubierto exclusivamente con `-p-`.
El informe explica la discrepancia con el resultado anticipado por la guía.

## Registro de los retos

- [Transcripción del registro](lab05-ctf-registro.txt): relaciona cada envío con
  la captura que contiene la flag y conserva la respuesta del verificador.
- [Estado final](lab05-ctf-status.txt): salida de `./ctf status 05`, con R1–R5
  registrados, 5/5 (100 %) y código de salida 0.

En Windows, el checkout tenía finales CRLF en los scripts Bash. Se ejecutó el
contenido versionado del verificador en una copia temporal con finales LF,
utilizando Git Bash. No se cambiaron `ctf`, `bin/`, `labs/` ni los hashes del
manifiesto en el repositorio. El progreso quedó guardado en `.progreso/05.done`,
archivo generado e ignorado por Git.

En un checkout Linux con finales LF, `./ctf status 05` puede ejecutarse desde la
raíz del repositorio. El progreso es local: un clon nuevo comienza sin retos
registrados hasta que se envían las flags obtenidas; las capturas adjuntas son
la evidencia de esta entrega, no un archivo de progreso que deba versionarse.

## Límites de interpretación

- Los banners y headers muestran lo que el servicio declara, no certifican el
  binario instalado, sus módulos, sus parches ni su configuración efectiva.
- La respuesta `debug:true` no prueba que exista un depurador interactivo.
- No se confirmó la aplicabilidad de CVE-2015-3306 ni se realizó explotación.
- Las conclusiones sobre el alcance y duración de los barridos de Nmap se
  apoyan en las capturas conservadas del 10/10/2026.
