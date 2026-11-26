# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 09
**Integrantes:**
- Santiago Cocchi (legajo 15271) — @santicocchi
- Franco Ferraro (legajo 14973) — @francovalentin08
- Francisco Mossello (legajo 15339) — @FranMossello
- Tomas Spat (legajo 15055) — @TomiSpat
- Santiago Torres (legajo 15059) — @santy500

**Fecha:** 2026-11-20

---

## 0. Declaración de uso de IA

Se usó un asistente de IA (Claude Code) para levantar el entorno Docker, ejecutar
los `curl` de ataque/defensa y redactar el informe. **Las 5 flags se obtuvieron
operando el servicio real** (`phantomcorp` monitoreado): se leyó el ruleset
publicado por el propio SOC en `/soc/reglas` y se construyó el payload de evasión
a partir de esa información, no del código fuente del target.

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 10                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Acceso a la vista del SOC
   ✓  R2     Disparar una deteccion (te vieron)
   ✓  R3     Conocer el ruleset del IDS
   ✓  R4     Evadir una firma de deteccion
   ✓  R5     Encontrar la intrusion en el ruido

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 10 COMPLETO!
```

---

## 2. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| `scanner-ua` (`sqlmap\|nikto\|nmap\|dirb` en el User-Agent) | Cambiando el header `User-Agent` a cualquier valor que no matchee esas palabras (p. ej. el de un navegador real: `Mozilla/5.0 ...`). El ataque en sí no cambia en nada; solo cambia cómo se *presenta*. | No depender de un campo que el cliente controla 100% y puede falsificar sin costo. En vez de "quién dice ser", mirar **qué hace**: tasa de requests por IP/sesión en poco tiempo, patrones de rutas (escaneo secuencial de endpoints inexistentes), ausencia de recursos estáticos (un navegador real pide CSS/JS/imágenes; un scanner no). Esas señales de comportamiento no dependen de un header auto-declarado. |
| `sqli-union` (regex `union\s+select`, exige un espacio literal) | Reemplazando el espacio obligatorio entre `union` y `select` por algo que cumpla la misma función en SQL pero no sea un espacio para el regex: un comentario SQL en línea `/**/` (`union/**/select`), un salto de línea, un tab, o paréntesis según el motor. El SQL sigue siendo válido para la base de datos; el string ya no matchea `\s+`. | La regex de la firma mira la sintaxis literal, no la semántica. Dos mejoras concretas: (1) **normalizar** el input antes de inspeccionarlo (colapsar comentarios SQL, espacios en blanco variados, y codificaciones alternativas a un formato canónico, y *recién después* aplicar la firma); (2) complementar la detección por firma con un **WAF que entienda SQL** (parsea el query como un tokenizer SQL real, no como texto plano con regex) o, mejor todavía, resolver el problema de raíz con consultas parametrizadas en el backend — ninguna firma hace falta si la inyección es imposible desde el origen. |

---

## 3. Preguntas de análisis

**P1 — por qué la detección por firmas es evadible por diseño, y qué la complementa.**
Una firma describe un patrón **exacto y conocido de antemano**: una cadena, una
regex, un valor de header. Por construcción, solo puede reconocer lo que ya fue
anticipado y codificado en la regla. Cualquier variación sintáctica del mismo
ataque que el autor de la firma no previó —un espacio distinto, un encoding
alternativo, una técnica de ofuscación nueva— cae fuera del patrón y pasa sin
alertar, aunque el efecto malicioso sea idéntico. Es una limitación estructural,
no un bug puntual: toda detección basada en coincidencia de patrones conocidos
tiene este techo. Lo que la complementa es exactamente lo que vimos en el R5: el
**análisis humano de logs** (y, a mayor escala, la detección por **anomalías** o
**comportamiento**, que no busca un patrón fijo sino una desviación de lo normal).
Ninguna de las dos reemplaza a la otra: las firmas atrapan lo conocido al
instante y barato; el analista (o el modelo de anomalías) encuentra lo que la
firma nunca iba a anticipar.

**P2 — reescribir la firma `sqli-union` para que no se evada con `/**/`, y si existe una firma "perfecta".**
Una versión más robusta normalizaría el query **antes** de aplicar la regex, por
ejemplo colapsando cualquier secuencia de espacios en blanco **y** comentarios
SQL (`/*...*/`, `--`, `#`) a un único separador canónico antes de buscar
`union\s*select`. Algo así en pseudocódigo: `normalizado =
re.sub(r"(/\*.*?\*/|\s)+", " ", query); if re.search(r"union\s+select",
normalizado): bloquear`. Eso cierra específicamente el truco del comentario que
usamos en el R4.

Pero **no existe una firma perfecta**, y esta misma regla mejorada lo demuestra:
quedan otras formas de separar `UNION` de `SELECT` que un motor SQL acepta y que
esta regex normalizada todavía no contempla (paréntesis, saltos de línea
codificados en otro charset, concatenación de palabras clave partidas con
comentarios intercalados dentro de las palabras mismas en algunos dialectos,
doble URL-encoding antes de llegar al parser). Cada mejora cierra el agujero
conocido y potencialmente abre —o deja sin cerrar— el siguiente que todavía no
se probó. Por eso la defensa real contra SQLi nunca es "la firma perfecta": es
eliminar la clase de vulnerabilidad en el origen (consultas parametrizadas, como
vimos en el Lab 07), dejando la firma como una capa adicional de alerta temprana,
no como el control principal.

**P3 — por qué detectar por User-Agent es débil, y qué mirar en su lugar.**
El User-Agent es un valor que **el cliente envía y declara sobre sí mismo**: no
hay ninguna verificación del lado del servidor de que sea veraz. Confiar en él
para una decisión de seguridad es confiar en la palabra del propio atacante
sobre quién es — literalmente lo opuesto al principio de "nunca confiar en el
input del cliente" que atraviesa todo este curso (Lab 07, P5 sobre IDOR). Cambiar
un header es gratis y no requiere ninguna sofisticación técnica. En lugar de
"quién dice ser", conviene mirar **patrones de comportamiento** que el atacante
no puede simplemente declarar distinto: volumen y cadencia de requests desde un
mismo origen en una ventana de tiempo corta, secuencias de rutas que no siguen
un flujo de navegación humano normal (probar decenas de endpoints en segundos),
tasa de respuestas 404 (un escaneo genera muchas más que un usuario real), y
ausencia de los recursos que un navegador real siempre pide junto con el HTML
(CSS, JS, favicon).

**P4 — qué habría hecho que el R5 se detecte automáticamente, sin depender de que alguien lo mirara.**
La intrusión del R5 (`GET /admin/../../etc/passwd`) **sí** matchea la firma
`path-traversal` que el propio ruleset ya tiene definida (`"../" in path`) — y de
hecho el log la marca como `ALERT[path-traversal]`. El problema no es que faltara
una firma: es que **la alerta se generó y quedó enterrada entre 120 líneas de
tráfico benigno**, sin que nada la sacara a la superficie. Lo que haría que se
detecte automáticamente, sin depender de que un analista la encuentre leyendo,
es un paso más allá de generar el log: un **sistema de alertado activo** (un
SIEM con reglas de correlación que dispare una notificación — email, Slack,
ticket— apenas se registra un evento con severidad `ALERT`, en vez de solo
anotarlo en un archivo que alguien tiene que abrir y filtrar manualmente). La
detección ya existía; lo que faltaba era que **empujara** la alerta hacia un
humano en vez de esperar pasivamente a que alguien la fuera a buscar.

**P5 — por qué un buen atacante tiene que entender al defensor, y viceversa.**
Los dos lados operan sobre el **mismo terreno técnico** mirado desde ángulos
opuestos: el atacante necesita saber qué firmas existen y cómo razona un IDS/WAF
para poder anticipar qué lo va a delatar y diseñar su payload en consecuencia
(literalmente lo que hicimos en el R3→R4 de este lab: leímos el ruleset antes de
evadirlo). El defensor, simétricamente, necesita pensar como atacante para
anticipar **qué variantes** de un ataque conocido alguien va a intentar, y
escribir firmas (o reglas de correlación) que cubran esas variantes en vez de
solo el caso exacto que ya vio una vez. Un analista que nunca pensó como
atacante escribe firmas ingenuas, fáciles de evadir (como `sqli-union` tal cual
viene en este lab); un atacante que nunca pensó como defensor no entiende por
qué su ataque fue detectado ni cómo adaptarlo. Es el mismo conocimiento aplicado
en direcciones opuestas — y es la razón por la que este curso recorrió primero
ataque (05–09) antes de dar vuelta la perspectiva en este lab.

---

## 4. Bitácora de comandos

```bash
# Preparación
make setup
./ctf lab 10
make shell

# R1 — vista del SOC
curl -s http://phantomcorp/soc
# -> FLAG{soc_log_access}

# R2 — disparar una deteccion (User-Agent de scanner)
curl -s -A sqlmap http://phantomcorp/
# -> 🚨 ALERTA IDS · firma 'scanner-ua' disparada. FLAG{detection_triggered}

# R3 — leer el ruleset publicado
curl -s http://phantomcorp/soc/reglas
# -> FLAG{signature_ruleset} + revela que sqli-union exige un ESPACIO literal

# R4 — evadir sqli-union con un comentario SQL en vez del espacio
curl -s -G http://phantomcorp/api --data-urlencode "q=xx union/**/select yy"
# -> 200 OK (procesado como benigno). FLAG{signature_evaded}

# R5 — encontrar la intrusion real entre el ruido
curl -s http://phantomcorp/soc | grep ALERT
# -> 185.220.101.42 ... ALERT[path-traversal] ... FLAG{intrusion_in_the_noise}

# Entrega
./ctf submit 10 R1 'FLAG{soc_log_access}'
./ctf submit 10 R2 'FLAG{detection_triggered}'
./ctf submit 10 R3 'FLAG{signature_ruleset}'
./ctf submit 10 R4 'FLAG{signature_evaded}'
./ctf submit 10 R5 'FLAG{intrusion_in_the_noise}'
./ctf status 10
```
