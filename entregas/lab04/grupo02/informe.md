# Informe — Laboratorio 04 · Marcos normativos y gestión de la seguridad

**Grupo:** 02

**Integrantes:**

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Romero Jimena Soledad | 15377 | @Jimena-Romero |
| Milanesio Hebe Del Lourdes | 15343 | @hebemilanesio1 |
| Toranzo Juan Cruz | 15308 | @JuanToranzo |
| Torres Damaris | 14563 | @damaris412 |

---

## 0. Declaración de uso de IA

Se utilizó Gemini (Google) como asistente conversacional para:
- Guiar la estructuración del flujo de trabajo en Git (gestión de ramas `lab04-grupo02` y sincronización remota).
- Asistir en la implementación de las funciones cuantitativas de `src/riesgo.py` (`ale`, `roi_control`, `priorizar`).
- Estructurar el archivo de datos `riesgos.json` adaptado al escenario de PhantomCorp.
- Colaborar en la redacción técnica y análisis del informe.

Se utilizó Claude (Anthropic) para:
- Revisión del código entregado: detección de un import incorrecto en verificar.py (import entregas.lab04.grupo02.src.riesgo) que impedía ejecutar la autoevaluación, y su corrección.
- Explicación del problema de codificación de caracteres en la consola de Windows.
- Borradores de redacción de las secciones A.1, A.2, A.3, B.2 y B.3 del informe, con el mapeo de debilidades a categorías de NIST CSF 2.0.

Todo el código fue probado de manera local ejecutando `src/verificar.py` y los resultados del script fueron validados por el equipo. Los textos generados por IA fueron leídos, adaptados y son responsabilidad del grupo.

---

## 1. Parte A — Marco aplicado

### A.1 — Marco elegido y justificación

Elegimos el **NIST Cybersecurity Framework (CSF) 2.0** como marco de referencia para PhantomCorp porque ofrece un enfoque flexible, práctico y adaptable a las necesidades de la organización. Este marco fue desarrollado por el Instituto Nacional de Estándares y Tecnología de Estados Unidos (NIST) con el objetivo de ayudar a las organizaciones a comprender, evaluar, gestionar y reducir los riesgos relacionados con la ciberseguridad.

Una de sus principales ventajas es que se encuentra organizado en seis funciones fundamentales: **Govern (Gobernar)**, **Identify (Identificar), Protect (Proteger), Detect (Detectar), Respond (Responder) y Recover (Recuperar)**. Cada una aborda un aspecto específico de la seguridad informática y permite estructurar las acciones necesarias para proteger los sistemas, la información y los recursos de la organización. De esta manera, es posible analizar la situación actual de PhantomCorp, identificar sus principales debilidades y establecer prioridades para mejorar progresivamente su nivel de seguridad.

Otro motivo importante para elegir NIST CSF 2.0 es su **flexibilidad**. A diferencia de otros estándares y modelos más orientados a la implementación de un sistema de gestión formal, este marco permite adaptar las recomendaciones al tamaño, los recursos disponibles, los objetivos y los riesgos particulares de cada organización. Además, su utilización no exige obtener una certificación para poder aplicarlo, lo que representa una ventaja para PhantomCorp, ya que permite comenzar a trabajar en ciberseguridad sin asumir desde el principio los costos y la complejidad que podría implicar un proceso formal de certificación, como el asociado a ISO/IEC 27001.

En el caso específico de PhantomCorp, la elección resulta especialmente adecuada porque se trata de una organización pequeña que actualmente no cuenta con un programa de seguridad informática establecido. Por esta razón, implementar de inmediato un sistema de gestión de seguridad de la información completo podría resultar complejo, tanto por la falta de procedimientos definidos como por las posibles limitaciones de personal, presupuesto y conocimientos técnicos. NIST CSF 2.0 permite abordar esta situación de manera gradual, comenzando por comprender el contexto de la organización, reconocer los activos críticos, evaluar las amenazas y vulnerabilidades, y definir medidas de protección acordes con los riesgos identificados.

Asimismo, las seis funciones del marco permiten desarrollar una estrategia integral. La función **Govern** ayuda a establecer responsabilidades, políticas y criterios para tomar decisiones sobre ciberseguridad; **Identify** permite reconocer los activos, los sistemas y los riesgos que deben gestionarse; **Protect** se centra en implementar medidas preventivas; **Detect** busca identificar posibles incidentes de seguridad; **Respond** establece cómo actuar ante un incidente; y **Recover** contempla las acciones necesarias para restaurar los servicios y las operaciones afectadas. 

En conjunto, estas funciones permiten que PhantomCorp no se concentre únicamente en prevenir ataques, sino que también esté preparada para detectar problemas, responder de manera organizada y recuperarse ante posibles interrupciones.

### A.2 — Mapeo de cinco debilidades a controles/funciones del marco

| # | Debilidad de PhantomCorp | Función | Categoría CSF 2.0 | Control concreto |
|---|---|---|---|---|
| 1 | Sin MFA para el acceso remoto | Protect | PR.AA (Gestión de identidades, autenticación y control de acceso) | MFA en VPN y correo |
| 2 | Sin política de contraseñas | Govern / Protect | GV.PO (Política) y PR.AA | Política de longitud mínima, gestor de contraseñas y bloqueo por intentos fallidos |
| 3 | Servidor web público con datos de clientes (DNI, tarjetas) | Protect / Detect | PR.DS (Seguridad de los datos), PR.PS (Seguridad de la plataforma) y DE.CM (Monitoreo continuo) | WAF, cifrado de datos, parcheo y monitoreo de logs |
| 4 | Backups en un único disco dentro de la oficina | Protect / Recover | PR.DS y RC.RP (Ejecución del plan de recuperación) | Copia cifrada fuera de sitio y pruebas periódicas de restauración |
| 5 | Sin plan de respuesta a incidentes | Respond | RS.MA (Gestión de incidentes) y RS.CO (Comunicación de la respuesta) | Plan escrito, roles y contactos definidos, simulacro anual |

#### Justificación de cada mapeo

1. **Sin MFA → PR.AA.** La categoría PR.AA cubre cómo se verifica quién accede a los sistemas. Con solo usuario y contraseña, una credencial robada alcanza para entrar por acceso remoto; el MFA agrega un segundo factor que corta ese ataque.

2. **Sin política de contraseñas → GV.PO y PR.AA.** La falta de reglas es un problema de gobierno (GV.PO: no hay política definida) y también de autenticación (PR.AA: contraseñas débiles facilitan fuerza bruta y credential stuffing). Se corrige primero la política y después se aplica técnicamente.

3. **Servidor web público → PR.DS, PR.PS y DE.CM.** Es el activo más expuesto y el que guarda los datos más sensibles. PR.DS protege los datos (cifrado), PR.PS endurece la plataforma (parches, WAF) y DE.CM permite detectar ataques en curso a través de logs y alertas.

4. **Backups en la oficina → PR.DS y RC.RP.** Si el disco se pierde o se daña junto con los equipos (robo, incendio, ransomware), no hay forma de recuperar la información. PR.DS exige proteger los respaldos y RC.RP exige poder restaurar la operación, lo que implica copias fuera de sitio y pruebas de restauración.

5. **Sin plan de incidentes → RS.MA y RS.CO.** Sin plan, cada incidente se improvisa y aumenta su impacto (SLE) y el tiempo de exposición. RS.MA define cómo se gestiona el incidente y RS.CO cómo se comunica a la dirección, a los clientes y a las autoridades.

### A.3 — Respuestas al riesgo elegidas (mitigar/transferir/aceptar/evitar) con justificación

La decisión de cada respuesta se basó en el ALE calculado en la Parte B, en el costo y la dificultad del control, y en el impacto que tendría el incidente sobre PhantomCorp (datos de clientes, DNI y tarjetas).

| # | Debilidad | ALE | Respuesta | Justificación |
|---|---|---:|---|---|
| 1 | Sin MFA en acceso remoto | $20.000 | **Mitigar** | El ALE es alto y el control es barato, estándar y de rápida implementación (MFA en VPN y correo). Una sola credencial robada da acceso a la red interna, por lo que reducir la probabilidad tiene un retorno claro. No tiene sentido aceptarlo ni transferirlo: un seguro no devuelve la confianza de los clientes. |
| 2 | Sin política de contraseñas | $15.000 | **Mitigar** | Es la medida de menor costo del escenario: se resuelve con una política escrita y configuración técnica (longitud mínima, bloqueo por intentos, gestor de contraseñas). Ataca un ARO alto (0.6), que es lo que más pesa en su ALE. |
| 3 | Servidor web público con datos de tarjetas y DNI | $30.000 | **Mitigar y evitar** | Es el riesgo de mayor ALE. Se mitiga con WAF, cifrado, parcheo y monitoreo. Además se **evita** en origen dejando de almacenar números de tarjeta y delegando el cobro a un procesador de pagos certificado: lo que no se guarda no se puede filtrar. También conviene reducir los datos personales que se conservan. |
| 4 | Backups en un disco dentro de la oficina | $3.000 | **Aceptar (parcial) y transferir** | El ALE es el más bajo y un control costoso costaría más de lo que evita. Se aplica solo una mejora de bajo costo (copia cifrada fuera de sitio), se acepta el riesgo residual y se transfiere parte del impacto con la cobertura del seguro de la oficina. Ver B.3. |
| 5 | Sin plan de respuesta a incidentes | No se estimó de forma individual | **Mitigar** | No genera una pérdida propia, pero **aumenta el SLE de todos los demás riesgos**: sin plan, cada incidente dura más, se contiene peor y se comunica tarde. Documentar roles, contactos y pasos tiene un costo bajo frente a su efecto sobre el resto. |

**Nota sobre el riesgo #5.** Aunque no se le asignó un ALE propio, su efecto se puede analizar de forma indirecta: la falta de un plan de respuesta funciona como un multiplicador del impacto de los otros cuatro riesgos. Sin roles ni pasos definidos, la detección y la contención se demoran, el tiempo de exposición crece y la comunicación a clientes y autoridades llega tarde, lo que eleva el SLE de cada incidente. Por eso, aunque no aparezca en el ranking por ALE, mitigarlo mejora la postura de seguridad de todo el escenario con un esfuerzo bajo (documentar el plan, definir responsables y realizar un simulacro anual).

**Cierre:** no se eligió "mitigar todo". Se combinaron cuatro estrategias: mitigar (1, 2, 5), evitar (3, parte de los datos de tarjeta), aceptar (4) y transferir (4, mediante seguro), según el ALE y el costo de cada control.

---

## 2. Parte B — Riesgo cuantitativo

### B.1 — El ranking por ALE. ¿Coincide con tu intuición? ¿Dónde no?

Se ejecutó el script `src/riesgo.py priorizar --archivo riesgos.json` utilizando los datos cuantitativos del escenario PhantomCorp. El resultado obtenido fue:

```text
  ALE ($)     Riesgo / Incidente
  -----------------------------------------------------------------------------------
  30000.00    Filtración de datos de tarjetas/DNI por Servidor Web público
  20000.00    Acceso no autorizado por falta de MFA en empleados remotos
  15000.00    Falta de política de contraseñas (fuerza bruta / credential stuffing)
   3000.00    Pérdida de backups físicos por daño o robo en la oficina
```
¿Dónde coincide con la intuición? Coincide ampliamente al situar la filtración de datos en el servidor web público ($30.000,00) y el acceso no autorizado por falta de MFA ($20.000,00) en el tope de las prioridades. Dado que son activos expuestos hacia internet con información crítica de clientes (tarjetas, DNI), la intuición sugiere atacarlos primero.

¿Dónde NO coincide con la intuición? A primera vista, la pérdida de backups en la oficina suena como una catástrofe operativa grave que requeriría atención urgente. Sin embargo, al calcular cuantitativamente con el ARO (frecuencia estimada de 0.2 veces/año), su ALE resulta ser el más bajo de la lista ($3.000,00). Por el contrario, la falta de política de contraseñas parece un problema menor a nivel intuitivo, pero su alta probabilidad de ocurrencia continua (ARO: 0.6) genera un costo esperado anual considerablemente mayor ($15.000,00).

### B.2 — Para el riesgo #1, proponé un control, estimá su costo y el ALE resultante, y calculá el ROI. ¿Conviene?

**Riesgo #1 según el ranking:** filtración de datos de tarjetas/DNI por el servidor web público.

**ALE antes del control**

- SLE = $100.000 (pérdida por evento: multas, notificación a clientes, investigación forense, daño reputacional y reposición de tarjetas).
- ARO = 0.3 (un evento cada tres años aproximadamente).
- ALE = 100.000 × 0.3 = **$30.000 por año**.

**Control propuesto** (paquete de cuatro medidas, alineadas con PR.DS, PR.PS y DE.CM de NIST CSF 2.0):

| Medida | Qué hace | Costo anual estimado |
|---|---|---:|
| WAF (firewall de aplicaciones web) | Filtra ataques comunes como inyección SQL y XSS antes de que lleguen al servidor | $3.000 |
| Cifrado o tokenización de datos de tarjeta y DNI | Si hay una filtración, los datos robados no son utilizables | $2.500 |
| Pentest anual con corrección de hallazgos | Detecta vulnerabilidades antes que un atacante | $1.500 |
| Monitoreo de logs y alertas del servidor web (SIEM básico o servicio gestionado) | Detecta intentos de intrusión y comportamientos anómalos para actuar a tiempo | $2.000 |
| **Total** | | **$9.000** |

**ALE después del control**

- El SLE se mantiene en $100.000, pero el ARO baja a 0.15: el WAF y el pentest reducen la probabilidad de intrusión, el monitoreo permite detectar y cortar un ataque antes de que se concrete, y el cifrado limita el daño de la que ocurra. No se asume una reducción total, porque ningún control elimina el riesgo por completo.
- ALE = 100.000 × 0.15 = **$15.000 por año**.

Verificación con el script:

```text
$ python riesgo.py ale --sle 100000 --aro 0.15
15000.00
```

**Cálculo del ROI**

- Pérdida evitada = 30.000 − 15.000 = **$15.000 por año**.
- ROI = (pérdida evitada − costo) / costo = (15.000 − 9.000) / 9.000 = **0.667**.

Verificación con el script:

```text
$ python riesgo.py roi --antes 30000 --despues 15000 --costo 9000
0.667
```

**¿Conviene?** Sí. El control evita $15.000 de pérdida esperada por año y cuesta $9.000, es decir, cada peso invertido devuelve $0,67 netos además de recuperar lo gastado. El ROI es positivo, por lo que el control se paga solo.

**Sensibilidad (¿qué pasa si nuestras estimaciones son optimistas?):**

- El control es rentable mientras evite más de $9.000 por año (punto de equilibrio, ROI = 0), es decir, mientras el ALE después sea menor a $21.000.
- Si el ARO solo bajara a 0.2 (ALE después = $20.000), la pérdida evitada sería $10.000 y el ROI sería (10.000 − 9.000) / 9.000 = **0.111**, todavía positivo pero con un margen muy chico.
- Si el ARO solo bajara a 0.25 (ALE después = $25.000), la pérdida evitada sería $5.000 y el ROI sería (5.000 − 9.000) / 9.000 = **−0.444**: el control dejaría de convenir.
- Por lo tanto, la decisión de implementarlo es sólida mientras el control reduzca el ARO al menos a 0.2. Cuanto menos efectivo sea, menor es el beneficio, y de ahí la importancia de medir su efectividad después de implementarlo.

**Limitación:** el SLE, el ARO y los costos son estimaciones del grupo, no datos medidos en una empresa real. El ROI muestra el orden de magnitud y permite comparar opciones, no es una predicción exacta.

---

### B.3 — Un riesgo donde la respuesta correcta sea aceptar o transferir (no mitigar), y por qué

**Riesgo elegido:** pérdida de backups físicos por daño o robo en la oficina.

**Datos del riesgo**

- SLE = $15.000
- ARO = 0.2
- ALE = 15.000 × 0.2 = **$3.000 por año** (el más bajo del ranking).

**Por qué no conviene mitigarlo con un control costoso**

Una mitigación completa, como un sitio secundario con replicación o una solución de backup empresarial, costaría por ejemplo $6.000 por año. Aun si redujera el ALE a $500:

- Pérdida evitada = 3.000 − 500 = $2.500.
- ROI = (2.500 − 6.000) / 6.000 = **−0.58**.

El ROI es negativo: se gastaría más de lo que se intenta proteger. Aplicar ese control no se justifica económicamente.

**Respuesta elegida: aceptar el riesgo residual y transferir parte del impacto**

- **Aceptar:** al ser el riesgo de menor ALE, la dirección acepta formalmente el riesgo residual, dejando constancia de la decisión y revisándola una vez por año.
- **Transferir:** se contrata o se verifica una cobertura del seguro de la oficina que contemple robo, incendio o daño de equipos y soportes de datos, de modo que parte del SLE de $15.000 lo absorba la aseguradora.
- **Medida complementaria de bajo costo:** una copia cifrada fuera de sitio (por ejemplo, un servicio de nube de bajo costo) con una prueba de restauración periódica. Su costo es muy inferior al de un sitio secundario y mejora la recuperación (RC.RP) sin comprometer la decisión de no invertir en una solución cara.

**Conclusión:** la gestión de riesgos no consiste en eliminar todos los riesgos, sino en decidir con números cuáles se reducen, cuáles se transfieren y cuáles se aceptan. Gastar más que el ALE para protegerse de este riesgo sería una mala decisión de gestión.

---

## 3. Anexo — riesgos.json

```json
[
  {
    "nombre": "Acceso no autorizado por falta de MFA en empleados remotos",
    "sle": 40000,
    "aro": 0.5
  },
  {
    "nombre": "Filtración de datos de tarjetas/DNI por Servidor Web público",
    "sle": 100000,
    "aro": 0.3
  },
  {
    "nombre": "Pérdida de backups físicos por daño o robo en la oficina",
    "sle": 15000,
    "aro": 0.2
  },
  {
    "nombre": "Falta de política de contraseñas (fuerza bruta / credential stuffing)",
    "sle": 25000,
    "aro": 0.6
  }
]
```