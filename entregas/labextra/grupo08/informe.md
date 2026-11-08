# Informe — Laboratorio Extra · SSRF (Server-Side Request Forgery)

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 08/11/2026

> **Nota de armado.** La entrega se construye por partes:
> - **Parte 1** (teoría — "el servidor como cómplice involuntario" + P1 del modelo de confianza por red) — *completa en este commit.*
> - **Parte 2** (práctica R1–R2 + P2) — *pendiente: requiere el entorno Docker arriba.*
> - **Parte 3** (R3 + P3–P5 + conclusión + `research.md`) — *pendiente.*
>
> Esta división es honesta a propósito: la práctica (R1–R3) exige levantar los
> contenedores (`./ctf lab extra`) y observar la salida **real** del servidor.
> Al momento de redactar la Parte 1 el daemon de Docker no estaba corriendo, así
> que no se pegan flags ni evidencias que no se hayan ejecutado. La rúbrica es
> explícita: *inventar evidencia es causal de rechazo*. Las secciones 1, 2 y las
> preguntas empíricas quedan marcadas como **[PENDIENTE — entorno]** y se
> completan al correr el lab.

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en la **Parte 1**: redacción de la base teórica de SSRF (el servidor como cómplice involuntario), el análisis del modelo de confianza por red a partir del diagrama del lab y la respuesta a **P1**. | `informe.md`: secciones 3 (teoría), 4.1 (P1) y la "Nota de armado". | El grupo revisó el diagrama de red real del lab (`entorno/target.compose.yml`: `phantomcorp` en `labnet`+`internalnet`, `phantomcorp-intra` solo en `internalnet`) y confirmó que la explicación se corresponde con esa topología. Ninguna flag ni salida de comando se dio por válida sin ejecutar el entorno; esas secciones quedan marcadas como pendientes. |

El grupo declara que comprende el contenido de lo entregado hasta acá y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Cadena de explotación

### R1 — Panel interno en localhost
**[PENDIENTE — entorno]** · Requiere `./ctf lab extra` + `make shell`. Se
documentará: descubrimiento de `/preview`, sondeo de puertos de `127.0.0.1` vía
el fetcher del servidor (usando los mensajes de error como oráculo), comando y
salida con la flag.

### R2 — Intranet en la red interna
**[PENDIENTE — entorno]** · Deducción del hostname interno (`phantomcorp-intra`,
mismo patrón de nombres de los labs previos), pedido a través del SSRF, comando
y salida con la flag.

### R3 — Exfiltración del backup
**[PENDIENTE — entorno]** · Recorrido dentro de la intranet, lectura del backup
que "había que borrar", comando y salida con la flag, y qué datos sensibles la
acompañaban.

## 2. Evidencia de progreso
**[PENDIENTE — entorno]** · Salida de `./ctf status extra` con los 3 retos en ✓.

---

## 3. Parte 1 (teoría) — el servidor como cómplice involuntario

### 3.1 Qué es un SSRF

Un **Server-Side Request Forgery** ocurre cuando una aplicación recibe una URL
(o un host) y **la fetchea desde el servidor**, estando esa URL bajo control del
atacante. La consecuencia clave es *quién* hace el pedido: no sale desde la
máquina del atacante, sino **desde el servidor**, con la **identidad de red y la
posición de red del servidor**. El atacante no toca la red interna — la toca el
servidor por él:

```
   vos ──> web: "fetcheame http://intranet/backups"
              │
              └── el server (que SÍ está en la red interna) la fetchea
                  y te devuelve el contenido
```

SSRF es la vulnerabilidad que mejor desnuda un supuesto de la arquitectura
moderna: la **confianza por ubicación de red** — *"si el pedido viene de
adentro, es de confianza"*. Figura como **A10:2021** en el OWASP Top 10.

### 3.2 Los tres destinos clásicos

| Destino | Qué hay | Por qué importa |
|---|---|---|
| `http://127.0.0.1:PUERTO` | Servicios que escuchan **solo en localhost** (paneles de admin, métricas, endpoints de debug) | "Solo localhost" deja de ser defensa: para el SSRF, el servidor *es* localhost. Es exactamente el **R1** de este lab. |
| `http://host-interno` | Intranets, APIs internas, bases de administración | La segmentación de red se anula si un host de la DMZ puede fetchear arbitrariamente. Es el **R2/R3**. |
| `http://169.254.169.254` | Metadata service de la nube (AWS/GCP/Azure) | Credenciales temporales de la instancia → compromiso de toda la cuenta cloud (Capital One, 2019: 100M de registros). Se amplía en P5. |

### 3.3 Cómo se detecta un SSRF candidato

Cualquier funcionalidad que **reciba una URL o un host y la contacte** por el
usuario: "previsualizar link", "importar desde URL", "avatar por URL",
webhooks, "probar conexión", generadores de PDF o de thumbnails server-side. En
este lab, el candidato es la **herramienta de previsualización de URLs** del
portal de PhantomCorp: el servidor fetchea la URL que le pasás y te devuelve el
contenido, **sin validación ni allowlist**.

### 3.4 La idea central

> **El perímetro ya no es el límite.** Si el servidor puede pedir, el atacante
> puede pedir a través del servidor. La confianza por ubicación de red es una
> defensa ilusoria cuando un servicio fetchea URLs arbitrarias.

---

## 4. Preguntas de análisis

### 4.1 P1 — ¿Por qué dejó de ser cierto que "la intranet no es alcanzable desde afuera"?

El diagrama de red del lab es:

```
   atacante ──labnet──>  phantomcorp (web :80)  ──internalnet──>  phantomcorp-intra
        │                        │                                        ▲
        └─────────── ✗ NO hay ruta directa ──────────────────────────────┘
```

Según `target.compose.yml`, la topología real es:

- `phantomcorp` (web pública) está conectada a **dos** redes: `labnet` (donde
  vive la consola atacante) **e** `internalnet`.
- `phantomcorp-intra` (la intranet) está **solo** en `internalnet`, que además
  está declarada `internal: true` (sin ruta hacia afuera).
- La consola atacante está **solo** en `labnet`.

A nivel de capa de red, la afirmación *"la intranet no es alcanzable desde
afuera"* es **verdadera**: no existe ninguna ruta IP directa desde `labnet`
hacia `phantomcorp-intra`. Un `curl --max-time 3 phantomcorp-intra/` desde la
consola atacante da **timeout**, porque no hay camino.

**Lo que la hace alcanzable es el servidor web `phantomcorp`.** Al estar con un
pie en cada red (*dual-homed*), funciona como un puente. Y su herramienta de
`/preview` acepta una URL arbitraria y la fetchea **desde su propia posición de
red** — es decir, desde dentro de `internalnet`. El atacante nunca envía un
paquete a la intranet; le pide al servidor que lo haga por él. El componente que
rompe la segmentación no es una falla de red: es la **funcionalidad de la
aplicación** (`/preview` sin allowlist) corriendo sobre un host que sí tiene
visibilidad interna. La segmentación de red seguía intacta; lo que falló fue
confiar en que **nadie con acceso a ambos lados haría de proxy**.

### 4.2 P2 — Oráculo de escaneo de puertos (errores de conexión)
**[PENDIENTE — entorno]** · Se completa tras R1, comparando el mensaje de error
de un puerto cerrado (connection refused inmediato) contra uno abierto
(respuesta HTTP / cuelgue), que es lo que convierte al `/preview` en un oráculo.

### 4.3 P3 — Hallazgo profesional (activo, vector, impacto, evidencia)
**[PENDIENTE — entorno]** · Se redacta tras R3.

### 4.4 P4 — Tres mitigaciones ordenadas
**[PENDIENTE]** · Se completa junto a la Parte 3 (incluye por qué filtrar
strings como "localhost" no alcanza: `http://2130706433/`, `http://127.1/`, un
dominio que resuelve a 127.0.0.1, DNS rebinding).

### 4.5 P5 — Conexión con la nube (metadata service)
**[PENDIENTE]** · Se completa junto al `research.md`.

---

## 5. Conclusión
**[PENDIENTE]** · Resumen ejecutivo para el CTO de PhantomCorp, al cerrar la
Parte 3.
