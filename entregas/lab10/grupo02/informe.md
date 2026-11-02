# Laboratorio 10 — Detección y evasión: la vista del defensor

**Unidad 10** · Detección, respuesta y evasión (Blue vs Red) sobre PhantomCorp
**Grupo:** 02

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Milanesio Hebe Del Lourdes | 15343 | @hebemilanesio1 |
| Romero Jimena Soledad | 15377 | @Jimena-Romero |
| Toranzo Juan Cruz | 15308 | @JuanToranzo |
| Torres Damaris | 14563 | @damaris412 |

**Entorno:** Docker — portal `phantomcorp` monitoreado por un IDS/SOC por firmas

> Cierre del curso: después de cinco labs como atacante, nos damos vuelta. Este lab
> mira el ataque desde el **defensor** (leer logs y firmas) y desde el **atacante que
> evade** (ofuscar el payload para no matchear ninguna firma).

---

## 1. Tabla de firmas

| Firma | Qué detecta | Cómo la evadimos (o cómo se evade) | Cómo la mejoraríamos |
|---|---|---|---|
| **scanner-ua** | User-Agent que contiene `sqlmap\|nikto\|nmap\|dirb` | Cambiar la User-Agent por la de un navegador real: la misma herramienta pasa desapercibida porque la firma mira *quién decís ser*, no *qué hacés* | No detectar por identidad declarada (trivial de falsificar). Mirar **comportamiento**: tasa de requests, recorrido secuencial de rutas, ratio de 404, patrones de fuzzing |
| **sqli-union** | Query que matchea `/union\s+select/` (exige un **espacio** entre las dos palabras) | Reemplazar el espacio por un comentario SQL inline: `UNION/**/SELECT`. Mismo efecto en la DB, pero no hay whitespace que matchee `\s+`, así que la firma no dispara | Normalizar el input antes de evaluar la firma (colapsar comentarios `/**/`, decodificar, bajar a minúsculas) y recién ahí aplicar la regla. Mejor aún: no depender de patrones sintácticos — usar consultas parametrizadas del lado de la app |

---

## 2. Flags obtenidas (5/5)

| Reto | Cara | Flag | Cómo |
|---|---|---|---|
| R1 | Blue | `FLAG{soc_log_access}` | `curl http://phantomcorp/soc` — acceso a la vista del SOC |
| R2 | Red | `FLAG{detection_triggered}` | `curl -A sqlmap http://phantomcorp/` — disparó la firma `scanner-ua` |
| R3 | Blue | `FLAG{signature_ruleset}` | `curl http://phantomcorp/soc/reglas` — ruleset del IDS |
| R4 | Red | `FLAG{signature_evaded}` | `curl "http://phantomcorp/api?q=UNION/**/SELECT"` — evadió `sqli-union` |
| R5 | Blue | `FLAG{intrusion_in_the_noise}` | En `/soc`, la única línea `ALERT` no disparada por nosotros: `185.220.101.42 - GET /admin/../../etc/passwd ... ALERT[path-traversal]`, escondida entre 120 líneas benignas |

---

## 3. Preguntas de análisis

### P1 · ¿Por qué la detección por firmas es evadible por diseño? ¿Qué la complementa?

Una firma describe un **patrón exacto** de un ataque conocido. Detecta al instante lo
que *ya conoce*, pero **solo** eso: cualquier variante que no matchee la cadena literal
pasa. Es evadible por diseño porque reconoce la *forma* del ataque, no su *efecto* —
y la misma acción maliciosa admite infinitas formas (ofuscar, codificar, cambiar la
User-Agent, partir el payload). Lo complementa el **análisis humano de logs** (el
analista del SOC que correlaciona y encuentra lo que ninguna firma describe) y la
**detección por comportamiento/anomalías**, que mira desvíos del patrón normal en vez
de firmas puntuales. Firmas + analistas: las dos cosas, porque cubren huecos opuestos.

### P2 · La firma `sqli-union` exigía un espacio. Reescribí la regla para que NO se evada con `/**/`. ¿Se puede hacer una firma "perfecta"?

La regla original era `/union\s+select/`. Se evade con `UNION/**/SELECT` porque el
comentario no es whitespace. Una versión más robusta normaliza y contempla el
comentario:

```
# 1) normalizar antes de evaluar: colapsar comentarios y espacios, bajar a minúsculas
normalizado = lower(regex_replace(query, "/\*.*?\*/", " "))
normalizado = regex_replace(normalizado, "\s+", " ")
# 2) recién ahí aplicar la firma
match: /union\s+select/   sobre `normalizado`
```

O, directo sobre el crudo, aceptar comentario o whitespace entre las palabras:
`/union(\s|\/\*.*?\*\/)+select/i`.

**No se puede hacer una firma "perfecta".** Siempre queda otra codificación
(hex, `CHAR()`, URL-encoding doble, `UNiOn`, saltos de línea, concatenación) que
produce el mismo efecto con otra cadena. Endurecer la firma sube el costo de evadirla,
pero no lo elimina: la detección por patrones persigue un blanco infinito. La defensa
real es no depender del patrón — **consultas parametrizadas** que hacen que el payload
nunca se interprete como SQL.

### P3 · Detectar por User-Agent: ¿por qué es débil? ¿Qué mirarías en lugar de "quién dice ser"?

La User-Agent es un header que el cliente **elige libremente**: cambiarla es una línea
(`curl -A "Mozilla/5.0 ..."`). Detectar por ella es detectar *identidad declarada*, y
un atacante no va a declararse. Es señal de ruido bajo (un escáner descuidado), nunca
de ataque real.

En lugar de "quién dice ser" miraría **qué hace**: volumen y velocidad de requests
desde una IP, recorrido secuencial o exhaustivo de rutas (fuerza bruta de
directorios), proporción alta de 404, payloads con metacaracteres (`../`, `'`, `UNION`),
accesos a rutas que ningún link legítimo referencia, horarios y correlación entre
eventos. El comportamiento es mucho más caro de falsificar que un header.

### P4 · El R5: la intrusión estaba en el log. ¿Qué habría hecho que se detecte automáticamente?

La línea maliciosa (`GET /admin/../../etc/passwd`) **ya matcheaba** la firma
`path-traversal` (la ruta contiene `../`): estaba marcada `ALERT` en el log. Lo que
faltó no fue la detección sino la **respuesta/correlación**: nadie miró la alerta
entre 120 líneas benignas. Para que no dependiera de un humano haría falta:

- **Alertamiento activo**: que una línea `ALERT` dispare una notificación (mail, ticket,
  SIEM) en vez de quedar escrita en un log que alguien tiene que leer.
- **Correlación/priorización automática**: separar `ALERT` de `BENIGN` y elevar las
  de IPs externas o fuentes reputadas maliciosas (la IP `185.220.101.42` es de un rango
  de salida de Tor, señal extra de sospecha).
- **Umbrales y dashboards** que hagan visible la señal sin depender de lectura manual.

### P5 · Cierre del curso: ¿por qué un buen atacante tiene que entender al defensor, y viceversa?

Son el mismo conocimiento visto de los dos lados. El **atacante** que entiende cómo
detecta el defensor sabe exactamente qué tiene que ofuscar: leer la firma `sqli-union`
fue lo que nos permitió evadirla con `/**/`. Y el **defensor** que piensa como atacante
escribe mejores reglas: sabe que la User-Agent se falsifica, que `\s+` se esquiva con
comentarios, que una alerta sin respuesta es inútil. Diseñar una defensa sin saber cómo
se la ataca produce firmas frágiles; atacar sin saber cómo se detecta produce ruido que
te delata. Durante cinco labs atacamos; entender la vista del SOC es lo que convierte
esa experiencia en capacidad de **defender** — y al revés.

---

## 4. Captura de `./ctf status 10`

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 10                        │
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

## 5. Conclusión

El mismo request puede ser invisible o ruidoso según cómo esté escrito, y la misma
firma que detecta un ataque conocido deja pasar su variante ofuscada. La detección por
firmas es potente pero frágil: reconoce lo que ya conoce. Por eso el SOC necesita las
dos patas —reglas *y* analistas— y la defensa sólida no vive en el patrón (siempre
evadible) sino en la raíz: input parametrizado, detección por comportamiento y alertas
que efectivamente se miran. Cerrar el curso desde la vista del defensor resignifica
todo lo que atacamos antes: cada técnica ofensiva es, del otro lado, una firma que
escribir y una alerta que responder.
