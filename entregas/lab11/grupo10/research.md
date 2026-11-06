# Mini-research — Laboratorio 11

**Grupo:** 10
**Tema elegido:** B. Orden de volatilidad (RFC 3227) y por qué define el orden de captura.

## Desarrollo

El orden de volatilidad ayuda a priorizar la adquisición de evidencia que puede desaparecer o cambiar mientras el sistema sigue funcionando. La RFC 3227 recomienda recolectar primero los datos más volátiles y avanzar hacia los más persistentes; no es una secuencia mecánica universal, porque el impacto de cada acción debe evaluarse y documentarse para el sistema investigado.

En PhantomCorp, el paquete incluye una captura de memoria fechada el 05/09/2026 a las 02:30 UTC (`caso/memoria/pslist.txt:1`). En esa fotografía aparecen una shell, `system-check` con `euid=0` y `nc` ejecutándose como root (`pslist.txt:7-9`); `netstat.txt:4` muestra una conexión `ESTABLISHED` con `45.13.37.7:4444`. Estos datos volátiles complementan los artefactos persistentes del disco, como el binario SUID, la webshell y el archivo cron (`caso/disco/listado.txt:4-6`). Los logs, por su parte, proporcionan marcas temporales precisas de las peticiones HTTP (`caso/logs/access.log:6-22`). Correlacionar las fuentes permite reconstruir más que cualquiera de ellas por separado.

La recomendación práctica es planificar la adquisición en orden de volatilidad, preservar primero el estado vivo que se perdería al apagar o reiniciar, registrar las acciones que puedan modificar el sistema y luego obtener imágenes de almacenamiento y registros persistentes. Se deben calcular hashes, conservar los originales y analizar copias de trabajo. En este laboratorio la memoria ya fue extraída por la cátedra: no afirmamos haber adquirido RAM real ni ejecutado Volatility sobre un volcado.

La cadena de custodia complementa esta prioridad: identificar quién recolectó cada elemento, cuándo y con qué herramienta; documentar su traslado y almacenamiento; y verificar su integridad. En el caso, ocho archivos coinciden con el manifiesto y `logs/auth.log` presenta un mismatch. Se conserva tal como fue recibido y se documenta la discrepancia, sin corregir el original ni atribuir causa o momento del cambio únicamente a partir del hash.

## Fuentes

1. Brezinski, D. y Killalea, T. (2002). [RFC 3227: Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227).
2. NIST (2006). [SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final).
3. NIST (2012). [SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final).
4. Cátedra, Laboratorio 11: `README.md`, `docs/rubrica.md` y evidencias del directorio `caso/`.

## Reflexión

El caso muestra que apagar un equipo antes de adquirir evidencia volátil podría hacer perder los procesos y la conexión C2 observados en la captura de memoria. También muestra que la preservación no elimina la necesidad de evaluar confiabilidad: `auth.log` no coincide con el hash del manifiesto, por lo que sus afirmaciones requieren cautela. Un análisis sólido explica qué se observó, cómo se correlacionó y cuáles son los límites de lo que puede concluirse.
