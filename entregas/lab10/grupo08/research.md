# Mini-research — Laboratorio 10

**Tema elegido:** **C.** SIEM y correlación de logs: cómo se detecta lo que ninguna firma ve.

## Desarrollo

### El problema concreto que vimos en el lab

El R5 de este lab fue la demostración más barata del problema: la intrusión real
(`185.220.101.42 - GET /admin/../../etc/passwd 200 ALERT[path-traversal]`) **ya
estaba detectada** —la firma `path-traversal` la marcó y la etiquetó en el log—,
pero quedó sepultada entre ~120 líneas de tráfico benigno esperando a que un
humano abriera `/soc` y la encontrara. Peor: el request devolvió `200`, es decir
se detectó **y aun así se sirvió**. La lección es que *una alerta que nadie lee
equivale a no tener alerta*. El salto de "tengo logs" a "detecto y respondo" es,
precisamente, lo que hace un **SIEM** (*Security Information and Event
Management*): centraliza los eventos de todas las fuentes, los **correlaciona** y
dispara alertas accionables [1].

### Qué es un SIEM y qué resuelve

Un SIEM agrega y unifica logs de fuentes heterogéneas —firewalls, IDS/IPS,
servidores web, endpoints, identidad— en un único lugar donde se los normaliza,
indexa y analiza en conjunto [1]. Resuelve tres carencias que el R5 dejó a la
vista:

1. **Centralización.** El evento no vive aislado en el log de un solo host donde
   nadie lo mira; converge con todo lo demás en una consola única. El analista no
   tiene que saber de antemano *dónde* buscar.
2. **Correlación.** Es la capacidad central: cruzar eventos de distintas fuentes y
   en el tiempo para reconstruir una historia que ninguna línea suelta cuenta. Un
   `ALERT[path-traversal]` aislado es un dato; ese mismo evento *más* un origen en
   un nodo de salida de Tor *más* un acceso posterior a un archivo sensible es una
   **intrusión en curso**. La correlación detecta el patrón que la firma, mirando
   un request a la vez, no puede ver [2].
3. **Alertado y respuesta.** En vez de esperar una revisión manual, el SIEM
   dispara la alerta (ticket, mail, webhook) y alimenta flujos de respuesta
   (SOAR), cerrando el lazo detección → acción.

### Cómo se detecta lo que ninguna firma ve

La firma reconoce lo **conocido** (un patrón catalogado); por diseño no ve ni el
*zero-day* ni la variante no catalogada (lo discutimos en P1 del informe). El SIEM
ataca justamente ese hueco con técnicas que no dependen de un catálogo de payloads:

- **Detección por anomalía / UEBA.** En lugar de "¿esto coincide con algo malo
  conocido?", pregunta "¿esto se **desvía** de la línea base de lo normal?". Se
  construye un *baseline* del comportamiento habitual de usuarios y entidades
  (*User and Entity Behavior Analytics*) y se marcan las desviaciones: un usuario
  que de golpe baja 10 GB, un login a las 3 AM desde otro país, un host interno
  que empieza a escanear la red [3]. Ninguna de esas acciones tiene "firma" —son
  sospechosas por *contexto*, no por contenido.
- **Reglas de correlación.** Condiciones lógicas sobre múltiples eventos y
  ventanas temporales: "N fallos de login seguidos de un éxito desde la misma IP"
  (fuerza bruta exitosa), o "recon → explotación → conexión saliente a IP nueva"
  (la *kill chain* completa). Cada evento por separado puede ser benigno; la
  **secuencia** es el ataque.
- **Enriquecimiento con threat intelligence.** Cruzar los indicadores (IPs,
  dominios, hashes) contra fuentes de reputación. En el R5, cotejar
  `185.220.101.42` contra una lista de nodos Tor habría subido la severidad del
  evento automáticamente, sin intervención humana.
- **Agregación/umbral.** Reglas simples que el R5 pedía a gritos: "cualquier
  `ALERT[...]` desde una IP fuera del rango interno `10.0.x.x` → severidad alta"
  habría separado la intrusión del ruido sola.

Un detalle importante que también trae el SIEM es **retención y búsqueda
histórica**: permite la *threat hunting* y el análisis forense *después* del
incidente, correlacionando hacia atrás en semanas de logs —algo imposible si cada
fuente guarda su log por separado y lo rota a los pocos días [1].

### Mitigación aplicada a nuestro caso

Si PhantomCorp hubiera enviado el log de su IDS a un SIEM, el R5 no habría
dependido de que alguien leyera `/soc` a ojo: una regla de correlación ("evento
`ALERT[path-traversal]` + origen externo/Tor + respuesta `200`") habría generado
una alerta de severidad alta en el momento, con la IP ya enriquecida como nodo
Tor. El analista no busca la aguja en el pajar; el SIEM se la pone sobre el
escritorio. Y combinado con bloqueo inline (IPS) y threat intel, el `200` que
sirvió `/etc/passwd` se habría convertido en un `403` registrado y escalado.

## Fuentes (mín. 3)

1. **IBM — What is SIEM?** (agregación, normalización, correlación, alertado y
   retención como funciones centrales de un SIEM).
   https://www.ibm.com/think/topics/siem
2. **MITRE ATT&CK — Data Sources / Detection** (por qué la detección efectiva se
   apoya en correlacionar fuentes de datos y comportamiento, no en un único
   evento). https://attack.mitre.org/datasources/
3. **Gartner — User and Entity Behavior Analytics (UEBA)** (detección por línea
   base de comportamiento y desviaciones, complementaria a las firmas).
   https://www.gartner.com/en/information-technology/glossary/user-and-entity-behavior-analytics-ueba
4. **Microsoft — What is SIEM?** (correlación de eventos de múltiples fuentes y
   threat intelligence para detectar amenazas que una regla aislada no ve).
   https://www.microsoft.com/en-us/security/business/security-101/what-is-siem

## Reflexión

Lo que nos ordenó el tema es entender que la detección no termina en la firma:
termina en alguien (o algo) que **lee** la alerta y responde. El R5 fue el
contraejemplo perfecto —la firma hizo su trabajo y no sirvió de nada porque la
alerta quedó en un log que nadie miraba—, y el SIEM es exactamente la pieza que
faltaba: centraliza, correlaciona y empuja la alerta en vez de esperar a que la
descubran. La idea que nos queda es que firmas y SIEM no compiten: la firma atrapa
barato lo conocido y el SIEM, con correlación y anomalía, atrapa lo que ninguna
firma tenía catalogado. Un ataque moderno casi nunca es una sola línea obvia; es
un patrón repartido entre fuentes, y solo se ve cuando las juntás.
