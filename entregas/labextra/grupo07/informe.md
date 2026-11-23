# Entregable — Lab Extra SSRF

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado:** cadena SSRF completa. Fernando resolvió R1 (panel en localhost), Guadalupe R2 (intranet en la red interna) y Lorenzo R3 (exfiltración del backup); Lautaro integró el informe, respondió P4, cerró el research y consolidó el estado. Enviadas las tres flags, el estado combinado es **3/3** (`evidencia/salidas/status-extra-consolidado.txt`). Las flags se validaron por `sha256` contra `retos.manifest`.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para organizar evidencia que yo capturé, redactar esta sección y consultar la documentación oficial enlazada en `research.md`. Verifiqué cada resultado con las salidas crudas del contenedor del laboratorio, el estado local del CTF y las páginas oficiales citadas. No usé IA para inventar ejecuciones ni para atribuirme los bloques pendientes. Fernando Cagliero (@Ferca19) usó OpenAI Codex para ejecutar y documentar R1 en el entorno local, organizar las salidas y redactar P1/P5. Contrastó el análisis de metadata con documentación oficial de AWS y OWASP. **Declaración de uso de IA — Lautaro Mariño (@lautaromarino0):** integración del informe, P4 (mitigaciones), cierre del `research.md` y consolidación del estado. Usé **Claude (Anthropic)** para redactar P4 y la conclusión ejecutiva, escribir el cierre comparativo del research (SSRF vs. inyección de comandos) y unificar el informe a partir de los bloques de los compañeros, que revisé antes de commitear. Consolidé el estado 3/3 enviando las tres flags ya recuperadas por el grupo y verificando su `sha256` contra `retos.manifest`. No se leyó el generador ni `solucion.md`.

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

Durante el desarrollo cada integrante capturó su estado por separado (Lorenzo 1/3 con R3, Fernando 1/3 con R1, en `status-extra.txt` y `05-status-after-r1.txt`). En la integración se enviaron las tres flags y se capturó el estado combinado **3/3** en `evidencia/salidas/status-extra-consolidado.txt`. Las capturas R1 de Fernando están en `evidencia/salidas/01-direct-intra.txt`, `02-portal-home.txt`, `02-ssrf-loopback-80.txt`, `03-loopback-port-probes.txt` y `04-r1-final.txt`; R2 en `r2-intranet.txt` y R3 en `r3-backup.txt`.

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

El patrón a cerrar es: `/preview` deja que una entrada del usuario decida a qué URL pide el servidor. Las defensas, de la más importante a la de apoyo:

1. **Allowlist de destinos (modelo positivo).** `/preview` sólo debería contactar los destinos que la función realmente necesita (si es una vista previa de enlaces públicos, una lista de dominios/servicios permitidos; si no necesita salir a ningún lado, no hacer la petición). Una **blocklist** de strings (`127.0.0.1`, `localhost`, `internal`) es frágil: se evade con otras representaciones (`127.1`, `0`, decimal/octal/IPv6, `localtest.me`), con DNS que resuelve a una IP interna, o con redirecciones. La allowlist se define sobre lo permitido, no sobre lo prohibido.
2. **Validar la IP resuelta, no el texto de la URL.** Resolver el hostname y **rechazar** si la IP cae en loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16` — el metadata de nube de P5), privadas (`10/8`, `172.16/12`, `192.168/16`) o el segmento interno del lab. Para evitar **DNS rebinding** (resolver dos veces y conectar a una IP distinta de la validada), conectar a la **misma IP** que se validó, no volver a resolver.
3. **No seguir redirecciones** (o re-validar cada salto con las reglas 1 y 2): un destino permitido puede responder un `302` hacia `169.254.169.254` o hacia la intranet.
4. **Restringir esquemas:** permitir sólo `http`/`https`; bloquear `file://`, `gopher://`, `ftp://`, etc., que amplían el abuso.
5. **No reflejar la respuesta cruda** al usuario, o limitar tamaño/tipo. Devolver el cuerpo entero convirtió a `/preview` en un **oráculo** (P2: distinguir puerto abierto de cerrado) y en un canal de exfiltración (R3).
6. **Defensa en profundidad de red:** el server de la DMZ **no debería tener ruta** a `internalnet` ni al endpoint de metadata si no lo necesita. La segmentación existía pero `/preview` la sorteó desde adentro; cortar el egress del proceso a destinos internos habría contenido R2/R3 aun con la SSRF presente.
7. **Remediar el dato, no sólo el vector:** borrar el `backups/clientes.json` que «no debería ser accesible» (nunca debió estar ahí) y rotar cualquier credencial o clave que haya quedado expuesta por la cadena.

La regla de fondo es la misma que en toda inyección: **no construir la operación sensible —acá, la URL de salida— a partir de entrada no confiable**; si hay que hacerlo, encuadrarla con una allowlist y mínimo privilegio de red.

### P5 — Metadata service cloud

En una instancia EC2, IMDS es un servicio local que puede entregar metadatos de la instancia. Su endpoint IPv4 es 169.254.169.254. Si hay un rol IAM asociado, la ruta iam/security-credentials/<nombre-del-rol> entrega credenciales temporales para los permisos de ese rol; AWS indica que las rota automáticamente. Por eso, una SSRF que logra que la aplicación consulte IMDS y devuelva el contenido podría exponer datos de instancia o credenciales utilizables contra los recursos permitidos por IAM. El impacto depende de que el endpoint esté accesible, de la configuración y de los permisos del rol; no equivale por sí solo a control de toda la cuenta.

IMDSv2 agrega una sesión: primero requiere una solicitud PUT que obtiene un token y después las consultas de metadata deben incluirlo. Si la instancia exige IMDSv2, un endpoint SSRF que solo permite un GET simple puede quedar bloqueado; no es una protección completa si se controlan método y encabezados. Como defensa, exigir IMDSv2, limitar el acceso de red del proceso a metadata y otros destinos internos, evitar devolver respuestas arbitrarias del fetch y asignar al rol solo los permisos necesarios. Las credenciales expuestas deben revocarse/rotarse según el procedimiento del servicio.

Fuentes: [AWS — configurar IMDSv2 como requisito](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html), [AWS — credenciales de seguridad de metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html) y [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
## 4. Conclusión ejecutiva

**Qué pasó.** El portal público de PhantomCorp tiene una función de vista previa (`/preview`) que pide, desde el propio servidor, cualquier dirección que le indique el usuario. Un atacante sin acceso a la red interna usó esa función para que el servidor actuara en su nombre: primero alcanzó un panel de administración que se creía accesible «sólo desde la misma máquina» (R1), después llegó a la intranet que la red separada debía mantener aislada (R2) y, por último, leyó un backup de clientes con identificación fiscal —datos de terceros— que no debería existir ni ser accesible (R3). Los datos son ficticios, del laboratorio.

**Qué tan grave es.** Alto. La separación de redes **no** contuvo el ataque, porque la petición maliciosa salió desde dentro del perímetro, desde un servidor que sí tenía alcance a la red interna. Se cruzaron información de negocio y datos personales de clientes hacia afuera, y se confirmó que la red «inaccesible» es alcanzable. Una falla equivalente en la nube puede exponer credenciales de la instancia (ver P5).

**Qué hacer, en orden.** (1) Encuadrar `/preview` con una lista de destinos permitidos y validar la dirección efectiva, bloqueando loopback e internos (P4); (2) cortar el acceso de red del servidor público a la red interna y al metadata, como segunda barrera; (3) borrar el backup de clientes y rotar cualquier credencial expuesta; (4) revisar logs para estimar si alguien más ya lo usó. La lección transversal del curso se repite: no construir una operación sensible —un comando (Lab 07) o una URL de salida (acá)— a partir de entrada no confiable.
