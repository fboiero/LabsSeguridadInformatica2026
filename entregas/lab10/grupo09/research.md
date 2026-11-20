# Mini-research — Laboratorio 10

**Grupo:** 09
**Tema elegido:** **A.** IDS/IPS por firmas vs. por anomalía (Snort/Suricata):
fortalezas y límites.

---

## Desarrollo

### Dos filosofías de detección

Un **IDS/IPS por firmas** (el modelo que implementa, de forma simplificada,
el target de este lab) compara cada evento contra una base de patrones
conocidos de ataque: una cadena en el payload, un valor de header, una secuencia
de bytes. Herramientas como **Snort** y su sucesor **Suricata** trabajan
mayormente así: un *ruleset* de firmas (las reglas de Snort tienen una sintaxis
estandarizada que incluye el patrón a buscar, el protocolo, el puerto y la
acción a tomar) que se actualiza constantemente a medida que aparecen nuevas
amenazas conocidas.

Un **IDS/IPS por anomalía**, en cambio, no busca un patrón fijo: construye un
perfil de lo que es **tráfico/comportamiento normal** para un sistema dado
(volumen de requests, rutas habituales, horarios de actividad, protocolos
esperados) y alerta cuando algo se desvía de ese perfil, **sin necesidad de
haber visto antes ese ataque específico**. El NIST, en su *SP 800-94: Guide to
Intrusion Detection and Prevention Systems (IDPS)*, describe ambos enfoques como
metodologías complementarias dentro de un mismo sistema IDPS, señalando que la
detección basada en firmas es "muy efectiva para detectar amenazas conocidas
pero en gran medida ineficaz para detectar amenazas nunca vistas antes" (NIST,
2007).

### Fortalezas y límites de cada enfoque

La detección por firmas tiene una fortaleza clara: **precisión y bajo costo
computacional** para lo que ya conoce. Si una firma matchea, hay una certeza
razonablemente alta de que el patrón exacto de un ataque conocido está presente,
con pocos falsos positivos (si la firma está bien escrita). El límite es
exactamente el que explotamos en el R4 de este lab: la firma `sqli-union`
exigía un espacio literal entre `union` y `select`; un comentario SQL (`/**/`)
en su lugar produjo el mismo efecto para la base de datos pero no matchea la
regex. Este es el patrón general: **cualquier variación sintáctica no
anticipada evade la firma**, aunque el ataque subyacente sea idéntico en
efecto.

La detección por anomalía tiene la fortaleza inversa: puede señalar **ataques
de día cero** o variantes nunca vistas, porque no depende de conocer el patrón
de antemano, sino de que el comportamiento se aleje de lo normal. El límite es
que necesita un período de "entrenamiento" o calibración para establecer qué es
"normal" en un entorno dado, y tiende a generar **más falsos positivos**: un
pico legítimo de tráfico (una promoción, un evento) puede verse idéntico a un
ataque de denegación de servicio desde la perspectiva de "esto es distinto de
lo usual". Suricata, en su documentación de motor de detección, de hecho
combina reglas de firma tradicionales con capacidades de detección basada en
protocolo y comportamiento (*protocol anomaly detection*), reconociendo que
ninguno de los dos enfoques solo alcanza en producción.

### El enfoque híbrido es la norma real

En la práctica, ningún IDS/IPS serio de producción usa un solo enfoque. El
propio NIST SP 800-94 recomienda una arquitectura con **múltiples tipos de
tecnología IDPS** (basada en firmas, en anomalía estadística, y análisis de
protocolo con estado) operando en conjunto, porque cada una cubre el punto
ciego de las otras. Esto conecta directamente con lo que vimos en el R5 de
este lab: la intrusión real quedó correctamente **marcada** por una firma
(`path-traversal`), pero sin un sistema de correlación/alertado que la sacara
del ruido, de nada sirvió que la firma funcionara. La tecnología de detección
(firma o anomalía) es solo una parte del sistema completo; la otra parte —no
menos importante— es qué pasa con la alerta una vez generada.

---

## Fuentes (mín. 3)

1. National Institute of Standards and Technology. (2007). *SP 800-94: Guide
   to Intrusion Detection and Prevention Systems (IDPS)*.
   https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf
2. MITRE. (s.f.). *ATT&CK Tactic TA0005 — Defense Evasion*.
   https://attack.mitre.org/tactics/TA0005/
3. Suricata (OISF). (s.f.). *Suricata User Guide — Rules Format*.
   https://docs.suricata.io/en/latest/rules/intro.html
4. Snort Project (Cisco Talos). (s.f.). *Snort 3 Rule Writing Guide*.
   https://docs.snort.org/

---

## Reflexión

Antes de este lab, "firma de detección" era un concepto abstracto. Después de
evadir `sqli-union` cambiando literalmente un carácter (un espacio por un
comentario), queda mucho más claro por qué ningún sistema de seguridad serio
confía en un solo mecanismo: la firma hace exactamente lo que se le pidió —
buscar un patrón exacto— y por diseño no puede generalizar a variantes que no
se le enseñaron. La detección por anomalía cubre parte de ese punto ciego, pero
trae el suyo (falsos positivos, necesidad de calibración). La lección real no
es "cuál enfoque es mejor", sino que la seguridad efectiva se construye en
capas que se compensan entre sí — firmas rápidas y precisas para lo conocido,
anomalía para lo desconocido, y un analista humano (o una correlación
automatizada) para lo que ninguna de las dos técnicas logró enganchar a tiempo.
