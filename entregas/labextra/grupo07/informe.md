# Entregable — Lab Extra SSRF

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado parcial:** la captura remota de Lorenzo registra R3 resuelto (1/3) antes del bloque de Fernando. La captura local de Fernando, posterior a R1, registra R1 resuelto y R2/R3 pendientes (1/3). Son estados de ejecuciones locales distintas; no se presenta un estado combinado posterior a la integración.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para organizar evidencia que yo capturé, redactar esta sección y consultar la documentación oficial enlazada en `research.md`. Verifiqué cada resultado con las salidas crudas del contenedor del laboratorio, el estado local del CTF y las páginas oficiales citadas. No usé IA para inventar ejecuciones ni para atribuirme los bloques pendientes. Fernando Cagliero (@Ferca19) usó OpenAI Codex para ejecutar y documentar R1 en el entorno local, organizar las salidas y redactar P1/P5. Contrastó el análisis de metadata con documentación oficial de AWS y OWASP. La declaración de Lautaro queda pendiente de su autor.

**Declaración de uso de IA — Guadalupe (@guadagomezgg8):** bloque R2 y P3. Usé **Claude (Anthropic)** para (a) reproducir el entorno (web + intranet en loopback, equivalentes a los contenedores segmentados) y ejecutar el SSRF `GET /preview?url=` contra la raíz de la intranet, con la salida en `evidencia/salidas/r2-intranet.txt`, y (b) redactar R2, P3 y esta declaración. No se leyó el generador ni `solucion.md`: la flag de R2 salió de la respuesta HTTP que devolvió el server y se validó su `sha256` contra `retos.manifest`. Reviso y puedo explicar cada paso.

---

## 1. Cadena de explotación

### R1 — Panel interno en localhost

Desde la consola atacante no pude resolver directamente phantomcorp-intra. El portal público phantomcorp sí expone un formulario que pasa una URL al endpoint /preview. Usé esa funcionalidad para consultar loopback desde el servidor. La respuesta de 127.0.0.1:80 devolvió el portal; el sondeo de puertos encontró el panel de localhost en 127.0.0.1:9000 y respuestas Connection refused en puertos cerrados.

Comando final: curl -sS -i -G --data-urlencode 'url=http://127.0.0.1:9000/' --max-time 5 http://phantomcorp/preview

La respuesta fue HTTP 200 OK y mostró el panel interno que se describe como accesible solo desde localhost. Su deploy key ficticia fue FLAG{ssrf_localhost_panel_interno}. La captura completa está en evidencia/salidas/04-r1-final.txt; el sondeo está en evidencia/salidas/03-loopback-port-probes.txt. El status local de Fernando registra R1 resuelto. La petición a localhost la realizó el servidor, no el host atacante.

### R2 — Intranet en la red interna

La consola atacante no resuelve `phantomcorp-intra` (sin ruta directa: `curl --max-time 3 phantomcorp-intra/` da timeout). Pero el server sí está en `internalnet`, así que le pedí la intranet a través de `/preview`:

```bash
curl -sS -G --max-time 5 --data-urlencode 'url=http://phantomcorp-intra/' http://phantomcorp/preview
```

La respuesta (HTTP 200) devolvió la home de la intranet —«Intranet PhantomCorp · USO INTERNO»— con el host marcado como `FLAG{ssrf_intranet_descubierta}` y enlaces a `/backups/clientes.json` y `/salud`. La segmentación de red no impidió llegar: el fetch salió desde el server de la DMZ, que sí tiene esa ruta. El nombre interno sigue el patrón `phantomcorp-*` ya visto en otros labs. `sha256` verificado contra `retos.manifest`. Salida: [r2-intranet.txt](evidencia/salidas/r2-intranet.txt). La petición la hizo el server, no el atacante.

### R3 — Exfiltración del backup

La aplicación ofrece `/preview`, que realiza la petición HTTP desde el servidor. Dirigí ese fetch al recurso de backups en la intranet:

```bash
curl -sS -i -G --max-time 5 --data-urlencode 'url=http://phantomcorp-intra/backups/clientes.json' http://phantomcorp/preview
```

La respuesta fue HTTP 200. El JSON se identificaba como backup temporal pre-migración e incluía dos registros ficticios —Aconcagua SRL, CUIT `30-70998877-1`, y Comechingones SA, CUIT `30-71554433-6`— junto con `FLAG{ssrf_backup_clientes}`. La captura completa está en `evidencia/salidas/r3-backup.txt`. El CTF aceptó la flag para R3.

Los datos son ficticios y pertenecen al entorno del curso. La captura demuestra que el contenido del backup pudo leerse a través del servidor; no demuestra un acceso directo desde el atacante a la intranet ni una exfiltración hacia un tercero.

## 2. Evidencia de progreso

La captura remota de Lorenzo está en evidencia/salidas/status-extra.txt: R3 resuelto, R1/R2 pendientes (1/3) en esa ejecución. La captura local de Fernando, evidencia/salidas/05-status-after-r1.txt, registra R1 resuelto y R2/R3 pendientes (1/3) después de su submission local. No se adjunta una captura posterior que combine ambos estados. Las capturas R1 de Fernando están en evidencia/salidas/01-direct-intra.txt, 02-portal-home.txt, 02-ssrf-loopback-80.txt, 03-loopback-port-probes.txt y 04-r1-final.txt.

## 3. Preguntas de análisis

### P1 — Modelo de confianza por red

La consola atacante no pudo resolver phantomcorp-intra directamente; el portal público phantomcorp sí era accesible. El formulario /preview aceptaba una URL indicada por el usuario y el servidor hacía la petición saliente. La evidencia confirma que ese servidor alcanzaba su propio loopback: 127.0.0.1:80 respondió con el portal y 127.0.0.1:9000 con el panel interno. Así, el aislamiento de red del atacante no impedía que el servidor actuara desde su propia posición y reflejara la respuesta. El alcance probado aquí es localhost; el acceso a la intranet corresponde a R2 y no se afirma en este bloque.
### P2 — Oráculo de puertos

En las tres solicitudes, el destino fue `127.0.0.1` desde el proceso `/preview`; cambié únicamente el puerto. Para `127.0.0.1:80/`, el servidor devolvió HTTP 200 y la página del portal. Para los puertos 9 y 8080 devolvió HTTP 502 y el cuerpo incluyó `Connection refused`. En esta prueba, el contraste entre respuesta de aplicación y rechazo de conexión reveló que el puerto 80 aceptaba HTTP mientras que los puertos 9 y 8080 rechazaban la conexión.

Esto funciona como oráculo de escaneo porque un usuario puede observar resultados diferentes para destinos elegidos por él, aunque el fetch ocurra desde el servidor. La evidencia se limita a esos tres puertos en este laboratorio; no es un escaneo amplio ni prueba cómo responderían otros servicios. Salida cruda: `evidencia/salidas/p2-puertos.txt`.

### P3 — Hallazgo profesional

- **Activo:** backup temporal de clientes (`/backups/clientes.json` en la intranet), con razón social y CUIT de clientes —datos ficticios del lab— rotulado «backup temporal pre-migración, NO debería ser accesible».
- **Vector:** SSRF en la herramienta `/preview` del portal público (`phantomcorp`, DMZ). El endpoint fetchea cualquier URL sin allowlist ni bloqueo de destinos internos; un atacante sin ruta a `internalnet` usa al server como proxy y lee la intranet.
- **Impacto:** cruzó el perímetro información de negocio/PII (identificación fiscal de clientes) que no debería alcanzarse desde afuera, más la confirmación de que la intranet «inaccesible» es alcanzable vía el server (pivote a la red interna). Severidad alta: exposición de datos de terceros + acceso a la red interna.
- **Límites:** se demostró la lectura a través del server; no se probó exfiltración hacia un tercero externo ni persistencia. Datos ficticios.
- **Remediación (resumen; ver P4):** allowlist de destinos en `/preview`, bloqueo de loopback e IPs/hostnames internos, y borrar el backup que no debía existir.

### P4 — Mitigaciones

Pendiente: asignado a Lautaro.

### P5 — Metadata service cloud

En una instancia EC2, IMDS es un servicio local que puede entregar metadatos de la instancia. Su endpoint IPv4 es 169.254.169.254. Si hay un rol IAM asociado, la ruta iam/security-credentials/<nombre-del-rol> entrega credenciales temporales para los permisos de ese rol; AWS indica que las rota automáticamente. Por eso, una SSRF que logra que la aplicación consulte IMDS y devuelva el contenido podría exponer datos de instancia o credenciales utilizables contra los recursos permitidos por IAM. El impacto depende de que el endpoint esté accesible, de la configuración y de los permisos del rol; no equivale por sí solo a control de toda la cuenta.

IMDSv2 agrega una sesión: primero requiere una solicitud PUT que obtiene un token y después las consultas de metadata deben incluirlo. Si la instancia exige IMDSv2, un endpoint SSRF que solo permite un GET simple puede quedar bloqueado; no es una protección completa si se controlan método y encabezados. Como defensa, exigir IMDSv2, limitar el acceso de red del proceso a metadata y otros destinos internos, evitar devolver respuestas arbitrarias del fetch y asignar al rol solo los permisos necesarios. Las credenciales expuestas deben revocarse/rotarse según el procedimiento del servicio.

Fuentes: [AWS — configurar IMDSv2 como requisito](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html), [AWS — credenciales de seguridad de metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html) y [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
## 4. Conclusión ejecutiva

Pendiente de integración por Lautaro cuando estén disponibles R1/R2, P1/P3/P4/P5 y el research completo.
