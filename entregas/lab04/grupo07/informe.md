# Informe — Laboratorio 04 · Marcos normativos y gestión

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc — @LoloBlanc · Fernando Cagliero — @Ferca19 · Guadalupe Gómez — @guadagomezgg8 · Lautaro Mariño — @lautaromarino0

## 0. Declaración de uso de IA

Se utilizó el asistente de IA **Claude (Anthropic)**. Siguiendo lo que pide el `CONTRIBUTING.md`:

- **Qué herramienta:** Claude (Anthropic).
- **Qué partes:** Parte A (marco NIST CSF aplicado al escenario).
- **Para qué:** explicación de las funciones del marco y corrección de redacción del análisis.
- **Cómo se verificó:** el grupo revisó las correcciones y sugerencias de la IA, las aceptó y comprendió el mapeo.
- **Lautaro Mariño — Parte B (`src/riesgo.py`, `riesgos.json`, B.1, B.2 y Anexo):** usó Claude (Anthropic) para implementar las tres funciones de `riesgo.py`, buscar fuentes para las cifras de SLE, ARO y costos, y redactar un primer borrador del análisis. **Cómo lo verificó:** corrió `verificar.py` (3/3 en verde) y los ejemplos del enunciado (`20000.00` y `0.875`); recalculó cada ALE y ROI con la CLI de `riesgo.py`; contrastó cada cifra con la fuente citada; y marcó como *supuesto* todo número que no proviene de una fuente.
- **Lorenzo Blanc — B.3:** usó ChatGPT para organizar y redactar la justificación de transferir el riesgo físico R4 mediante un seguro. Verificó que los valores de SLE, ARO y ALE coincidan con `riesgos.json`, revisó que la respuesta no afirme que el seguro elimina el riesgo y comprobó que la sección incluya las limitaciones de la transferencia.
- **Fernando Cagliero (@Ferca19) — Mini-research y armado final:** utilizó
  **OpenAI Codex** para investigar y redactar `research.md` (tema D), revisar
  la consistencia del conjunto y precisar en B.1 que los respaldos reducen
  el riesgo y en Parte B que el ROSI expresa una pérdida evitada esperada,
  recuperar los datos de `INTEGRANTES.md` de
  la entrega del Lab 03 y preparar el PR. Durante esta sesión se consultaron
  las fuentes primarias de NIST y ENISA; se ejecutaron `src/verificar.py`,
  los ejemplos del enunciado y los cálculos del informe y del mini-research.
  Los resultados se contrastaron con `decimal.Decimal`, el ranking con
  `riesgos.json` y el anexo con el archivo original. Se probaron además la
  ausencia de modificaciones a la entrada de `priorizar`, empates, lista vacía,
  ROI negativo, punto de equilibrio, costo no positivo y salidas de la CLI.
  Los detalles de verificación del armado final figuran en la sección 4.

## 1. Parte A — Marco aplicado

### A.1 — Marco elegido y por qué

Para analizar la situación de PhantomCorp, elegimos el **NIST Cybersecurity Framework (CSF) 2.0**, ya que permite identificar las principales debilidades de seguridad de una organización y definir qué aspectos debería mejorar.

Este marco se organiza en seis funciones: **Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS) y Recover (RC)**. En conjunto, permiten abordar la seguridad desde la gestión de riesgos y la prevención hasta la detección de incidentes y la recuperación. La versión 2.0, publicada en 2024, incorporó la función Govern, que se suma a las cinco funciones que tenía la versión anterior.

En el caso de PhantomCorp, el problema principal es que la organización todavía no cuenta con controles básicos de seguridad ni con un programa de seguridad suficientemente desarrollado. Por eso, el NIST CSF resulta útil para evaluar qué medidas faltan y establecer prioridades sin tener que implementar desde el principio un sistema de gestión completo.

Por otro lado, ISO/IEC 27001 también es una alternativa válida, pero está más orientada a establecer y mantener un sistema de gestión de seguridad de la información (SGSI), que puede incluir la posibilidad de obtener una certificación. Esto implica definir su alcance, documentar los controles aplicables y realizar auditorías, entre otras actividades.

En resumen, mientras que ISO 27001 permite organizar la gestión de la seguridad dentro de la empresa, el NIST CSF ayuda a identificar qué resultados de seguridad se necesitan y cuáles deberían ser las prioridades. Considerando la situación actual de PhantomCorp, nos parece más conveniente comenzar por esta última opción.

### A.2 — Cinco debilidades relacionadas con el marco

A partir del escenario planteado, identificamos cinco debilidades y las relacionamos con las funciones y categorías correspondientes del NIST CSF 2.0.

| N.º | Debilidad identificada | Función o categoría del CSF 2.0 | Medida que se debería implementar |
|---|---|---|---|
| 1 | El acceso remoto y la aplicación web no utilizan MFA. | PR.AA — Gestión de identidades, autenticación y control de acceso. | Incorporar un segundo factor de autenticación para reducir el riesgo de accesos no autorizados. |
| 2 | No existe una política de contraseñas. | PR.AA, PR.AT — Concientización y capacitación, y GV.PO — Política organizacional. | Definir reglas para el uso y almacenamiento de contraseñas, documentarlas y capacitar al personal. |
| 3 | Las copias de seguridad se guardan en un único disco dentro de la oficina. | PR.DS — Seguridad de los datos, y RC.RP — Ejecución del plan de recuperación. | Mantener copias adicionales, almacenar al menos una fuera de las instalaciones y probar periódicamente su restauración. |
| 4 | No hay un plan de respuesta ante incidentes. | RS.MA — Gestión de incidentes, y RC.RP — Ejecución del plan de recuperación. | Establecer un procedimiento de actuación, definir responsables y determinar cómo detectar, contener y resolver incidentes. |
| 5 | Los datos de tarjetas se almacenan en infraestructura propia expuesta a través de un servidor público. | PR.DS — Seguridad de los datos, DE.CM — Monitoreo continuo, y GV.OC — Contexto organizacional. | Proteger y monitorear la información sensible, y evaluar si es necesario mantener esos datos o si conviene delegar su procesamiento. |

Estas relaciones permiten ver qué aspectos de la seguridad están más comprometidos en PhantomCorp. Las primeras dos debilidades se relacionan principalmente con la protección de las identidades y los accesos. La tercera afecta tanto a la protección de la información como a la posibilidad de recuperarla si ocurre una falla.

La falta de un plan de respuesta también es importante, porque la empresa no tiene definido cómo actuar frente a un incidente. Finalmente, el almacenamiento de datos de tarjetas requiere una atención especial: además de implementar medidas técnicas, es necesario evaluar las responsabilidades y los requisitos de seguridad asociados a ese tipo de información.

De esta manera, el NIST CSF permite relacionar los problemas detectados con medidas concretas y organizar las mejoras según las necesidades de la organización.

### A.3 — Respuesta al riesgo para cada debilidad

Una vez identificados los problemas, se puede definir cómo actuar frente a cada uno de ellos. Las respuestas posibles incluyen mitigar, evitar, transferir o aceptar el riesgo, según las características de cada situación.

**1. Falta de MFA — Mitigar.**

La ausencia de un segundo factor de autenticación aumenta el riesgo de que una persona acceda al sistema utilizando credenciales robadas. Para reducirlo, proponemos implementar MFA mediante una aplicación de autenticación con TOTP, como la utilizada en el Laboratorio 03. Es una medida relativamente sencilla de incorporar y agrega una barrera adicional frente al acceso no autorizado.

**2. Falta de una política de contraseñas — Mitigar.**

En este caso, proponemos establecer una política que defina cómo deben gestionarse las contraseñas, junto con mecanismos seguros para almacenar sus hashes. Se puede utilizar PBKDF2, como se trabajó en el Laboratorio 03, y complementar la implementación con capacitación para los empleados. De esta manera, se reducen los riesgos asociados tanto a las contraseñas débiles como a su almacenamiento incorrecto.

**3. Copias de seguridad en un único disco — Mitigar.**

Guardar todas las copias de seguridad en un solo disco dentro de la oficina representa un riesgo importante. Si el disco falla, es robado o se ve afectado por un ransomware, la empresa podría perder la posibilidad de recuperar su información.

Para evitar esta situación, proponemos implementar la estrategia de respaldo **3-2-1**: mantener tres copias de los datos, utilizar dos tipos de medios de almacenamiento y conservar al menos una copia fuera de las instalaciones. También sería conveniente contar con una copia inmutable y realizar pruebas de restauración periódicas.

Además, el riesgo residual asociado a una pérdida física total de las instalaciones podría transferirse parcialmente mediante un seguro, aunque esto no reemplaza la necesidad de contar con copias de seguridad adecuadas.

**4. Ausencia de un plan de respuesta a incidentes — Mitigar.**

La falta de un procedimiento definido puede hacer que la empresa tarde más en responder ante un ataque y que sus consecuencias sean mayores. Por eso, proponemos elaborar un plan que establezca las acciones que se deben seguir, los responsables de cada tarea y los mecanismos de comunicación.

No alcanza con redactarlo: también es necesario realizar pruebas o simulaciones para comprobar que el personal sepa cómo actuar. Esto permitiría mejorar la capacidad de respuesta y reducir el impacto de posibles incidentes.

**5. Almacenamiento de datos de tarjetas en infraestructura propia — Evitar.**

En este caso, consideramos que una alternativa conveniente es dejar de almacenar los datos completos de las tarjetas en la infraestructura de PhantomCorp y delegar el procesamiento de los pagos a un proveedor especializado, como Mercado Pago o Stripe, según las condiciones del servicio.

Esta decisión permite reducir la cantidad de información sensible que la empresa necesita proteger y puede disminuir el alcance de las obligaciones relacionadas con PCI DSS. Sin embargo, no significa que desaparezcan todas las responsabilidades de seguridad o de cumplimiento: estas dependerán de cómo se integre el servicio y de las actividades que PhantomCorp continúe realizando.

Por eso, antes de implementar esta alternativa, sería necesario revisar el flujo de pagos y asegurarse de que los datos de las tarjetas no queden almacenados en los sistemas propios.

### Cierre

A partir del análisis, podemos observar que la mayoría de los problemas de PhantomCorp se deben a la falta de controles básicos de seguridad. Por este motivo, en los primeros cuatro casos proponemos mitigar los riesgos mediante medidas concretas, como incorporar MFA, definir una política de contraseñas, mejorar las copias de seguridad y establecer un plan de respuesta a incidentes.

En el caso de los datos de tarjetas, en cambio, consideramos que conviene evaluar si realmente es necesario que la empresa los almacene. Delegar el procesamiento de los pagos permitiría reducir la exposición a este tipo de información y simplificar parte de las obligaciones asociadas a su protección.

Por último, la aceptación del riesgo también puede ser una respuesta válida cuando el nivel de riesgo residual es conocido y la organización considera que puede asumirlo. Sin embargo, esa decisión debería estar justificada y no utilizarse simplemente porque implementar una medida de seguridad tiene un costo. Este criterio se puede profundizar en el análisis de riesgos de la Parte B.3.

### Fuentes consultadas

1. National Institute of Standards and Technology (NIST). *The NIST Cybersecurity Framework (CSF) 2.0*, NIST CSWP 29, 2024. Disponible en: https://www.nist.gov/cyberframework

2. PCI Security Standards Council. *Payment Card Industry Data Security Standard (PCI DSS)*. Disponible en: https://www.pcisecuritystandards.org

## 2. Parte B — Riesgo cuantitativo (ranking por ALE; ROI del control #1; un riesgo a aceptar/transferir)

### Implementación (`src/riesgo.py`)

| Función | Implementación |
|---|---|
| `ale(sle, aro)` | `sle * aro` |
| `roi_control(ale_antes, ale_despues, costo_anual)` | `(ale_antes - ale_despues - costo_anual) / costo_anual`; rechaza un costo ≤ 0 con `ValueError` |
| `priorizar(riesgos)` | Agrega el `ale` a una copia de cada riesgo y los ordena por `ale` descendente. No modifica la lista original. |

```text
$ python3 src/verificar.py
== Lab 04 · Riesgo cuantitativo ==
  ✓ ale()
  ✓ roi_control()
  ✓ priorizar() ordena por ALE

3 OK · 0 a revisar · 0 sin implementar

$ python3 src/riesgo.py ale --sle 50000 --aro 0.4
20000.00
$ python3 src/riesgo.py roi --antes 20000 --despues 5000 --costo 8000
0.875
```

El ROI que calcula `roi_control` es el **ROSI** (*Return on Security Investment*) descripto por ENISA: la reducción de la pérdida esperada (ALE sin el control − ALE con el control) menos el costo de la solución, dividido por ese costo [6]. Si el resultado es mayor a 0, la reducción estimada de pérdidas supera el costo anual; esto no garantiza un ahorro efectivo en un año particular.

### Supuestos y origen de las cifras

Las cifras son **estimaciones del grupo apoyadas en fuentes públicas**. El mismo documento de ENISA advierte que el cálculo del ROSI "es el resultado de muchas aproximaciones" y que sus resultados deben tomarse con cuidado [6]. Por eso indicamos de dónde sale cada número y marcamos como **supuesto** lo que no proviene directamente de una fuente. Cifras verificadas el 22/10/2026.

**Perfil supuesto de PhantomCorp:** pyme de unos 40 empleados (todos con acceso remoto), unos 20.000 clientes con nombre, DNI y tarjeta guardados, y una facturación de ≈ USD 2,5 M/año (≈ USD 10.000 por día hábil). Todos los valores están en dólares estadounidenses.

| Riesgo | SLE (USD) | Cómo se estimó el SLE | ARO | Cómo se estimó el ARO |
|---|---:|---|---:|---|
| **R1** — Intrusión por el acceso remoto sin MFA (credenciales robadas) y robo de la base de clientes | 250.000 | Costo promedio de un incidente en pymes (empresas con menos de USD 2.000 M de facturación): **USD 246.000** según NetDiligence 2025 [3], redondeado. Es un valor conservador: IBM informa un promedio de USD 4,99 M a nivel global (2026) y de USD 2,51 M en Latinoamérica (2025) [4][5], pero esos promedios corresponden a organizaciones más grandes. | 0,3 | El abuso de credenciales es el vector de acceso inicial más frecuente (**22 %**) [1], y en pymes el uso de credenciales robadas es la variante de *hacking* más común (**33 %**) [2]. PhantomCorp no tiene MFA ni política de contraseñas, y la MFA reduce el riesgo de compromiso en un **99,22 %** [7]. **Supuesto:** un incidente cada 3 o 4 años. |
| **R2** — *Ransomware* que cifra los servidores y el único backup (disco en la oficina) | 180.000 | **Supuesto** construido por componentes: 10 días hábiles sin operar (100.000) + respuesta al incidente y reinstalación (50.000) + reconstrucción de datos (30.000), porque el disco de backup está en la misma red y también se cifra. No incluye el pago de un rescate (mediana pagada: **USD 115.000** [1]). | 0,2 | El *ransomware* aparece en el **44 %** de las brechas [1] y en el **88 %** de las brechas de pymes [2]. **Supuesto:** un incidente cada 5 años. |
| **R3** — Explotación de una vulnerabilidad del servidor web público (filtración parcial) | 150.000 | **Supuesto:** filtración de parte de la base + caída del sitio + aplicación de parches y análisis forense. Es menor que R1 porque el atacante obtiene lo que expone la aplicación, no un acceso completo a la red interna. | 0,1 | La explotación de vulnerabilidades representa el **20 %** de los accesos iniciales y sigue en aumento [1]. El escenario no indica que el servidor esté sin parches, por eso el ARO es menor que el de R1. **Supuesto:** un incidente cada 10 años. |
| **R4** — Siniestro físico en la oficina (incendio, inundación o robo) que destruye a la vez el servidor y el backup | 400.000 | **Supuesto:** reposición de equipos (40.000) + 20 días sin operar, porque se pierden juntos el servidor y el backup (200.000) + reconstrucción de datos y pérdida de clientes (160.000). | 0,01 | En EE. UU. se registran **3.340 incendios por año** en oficinas (promedio 2007–2011) [9] sobre unos **970.000** edificios de oficinas [10]. Esto da ≈ 0,34 % anual solo por incendio (orden de magnitud). Si sumamos inundación y robo, lo redondeamos a 1 % anual. |
| **R5** — Falla de hardware del disco de backup (sin redundancia) | 2.000 | **Supuesto:** disco nuevo + unas 20 h técnicas para rehacer los respaldos completos + días sin backup. | 0,0136 | Tasa anual de fallas (AFR) de discos en 2025: **1,36 %** (Backblaze) [8]. |

### B.1 — Ranking por ALE

```text
$ python3 src/riesgo.py priorizar --archivo riesgos.json
      75000.00  R1 - Intrusion por acceso remoto sin MFA (credenciales robadas) y robo de la base de clientes
      36000.00  R2 - Ransomware que cifra servidores y el unico backup (disco en la oficina)
      15000.00  R3 - Explotacion de una vulnerabilidad del servidor web publico (filtracion parcial)
       4000.00  R4 - Siniestro fisico en la oficina (incendio/inundacion/robo) que destruye servidor y backup
         27.20  R5 - Falla de hardware del disco de backup (sin redundancia)
```

| # | Riesgo | SLE (USD) | ARO | ALE (USD/año) | Debilidad de la Parte A |
|---:|---|---:|---:|---:|---|
| 1 | R1 — Acceso remoto sin MFA → robo de la base | 250.000 | 0,3 | **75.000** | 1 y 2 (sin MFA ni política de contraseñas) |
| 2 | R2 — *Ransomware* + backup único | 180.000 | 0,2 | **36.000** | 3 y 4 (backup único, sin plan de respuesta) |
| 3 | R3 — Explotación del servidor web | 150.000 | 0,1 | **15.000** | 5 (datos sensibles detrás de un servidor público) |
| 4 | R4 — Siniestro físico en la oficina | 400.000 | 0,01 | **4.000** | 3 (backup dentro de la misma oficina) |
| 5 | R5 — Falla del disco de backup | 2.000 | 0,0136 | **27,20** | 3 |

**¿Coincide con nuestra intuición?** En parte. Estos son los puntos donde coincide y donde no:

- **Coincide en el primer puesto.** El acceso remoto sin MFA es la vía más barata para un atacante: no necesita explotar ninguna falla, le alcanza con una contraseña filtrada o fácil de adivinar. R1 representa por sí solo el **58 %** del ALE total (75.000 de 130.027 USD/año).
- **No coincide en el *ransomware* (2.º).** Esperábamos que encabezara la lista, porque es la amenaza más mencionada. Queda segundo porque tanto su SLE como su ARO son menores que los de R1. Además, R1 y R2 **no son independientes**: una de las formas típicas en que entra un *ransomware* es justamente el acceso remoto con credenciales robadas. Como el ranking evalúa cada riesgo por separado, **subestima el beneficio de cerrar R1**. Para que el *ransomware* pasara al primer lugar, la relación ARO(R1)/ARO(R2) tendría que bajar de 1,5 a menos de 0,72. Es decir, tendríamos que haber sobrestimado el ARO de R1 en más del doble.
- **No coincide en el servidor web (3.º).** Intuitivamente, lo más visible (el sitio público) parece lo más peligroso. Sin embargo, para atacarlo hace falta que exista una vulnerabilidad explotable. En cambio, el acceso remoto sin MFA solo requiere una contraseña válida. El ALE da más peso a lo que es fácil y frecuente que a lo que más preocupa.
- **La mayor diferencia aparece en el siniestro físico (4.º).** Tiene el **SLE más alto de la tabla** (400.000, ≈ 16 % de la facturación anual), pero un ALE de solo 4.000 porque su ARO es de 0,01. Esto muestra una limitación del ALE: como es un promedio, trata igual una pérdida de 400.000 cada 100 años que una de 4.000 todos los años. Para una pyme, la primera puede significar el cierre. Por eso, el ALE sirve para **ordenar** los riesgos, pero no alcanza para **decidir** sobre los de baja probabilidad y alto impacto.
- **Coincide en que R5 queda último.** Una falla de disco no parece grave, y los números lo confirman (27 USD/año). Su peligro real aparece si se combina con otro evento: que el disco falle justo cuando hay que restaurar. La regla 3-2-1 propuesta en la Parte A reduce la dependencia de ese único disco; también hay que probar las restauraciones, porque no elimina toda posibilidad de fallo.

**¿Qué tan firme es el ranking?** Los ARO son estimaciones, así que los valores absolutos son aproximados. Aun así, los **órdenes de magnitud** se mantienen: R1 a R3 están entre 15.000 y 75.000 USD/año, R4 está en el orden de los miles y R5 en el de las decenas. Para que R4 superara a R3, el ARO del siniestro físico tendría que ser casi 4 veces mayor (0,0375 en lugar de 0,01).

### B.2 — Control para el riesgo n.º 1 (R1) y ROI

**Control propuesto:** MFA obligatoria en el acceso remoto (VPN o escritorio remoto) y en los paneles de administración. Puede implementarse con una aplicación TOTP, como la del Lab 03, o con notificaciones *push* con verificación por número. Corresponde a la categoría **PR.AA** del NIST CSF (debilidad 1 de la Parte A).

**Costo anual estimado:**

| Concepto | Cálculo | USD/año |
|---|---|---:|
| Licencias de Duo Essentials | USD 3 por usuario/mes × 40 usuarios × 12 meses [11] | 1.440 |
| Implementación, enrolamiento y soporte | **Supuesto:** unas 60 h técnicas × USD 50/h | 3.000 |
| **Total** | | **4.440** |

La edición gratuita de Duo cubre como máximo 10 usuarios [11], por lo que no alcanza para los 40 empleados.

**ALE resultante:** según Microsoft Research, la MFA reduce el riesgo de compromiso un **99,22 %** en general y un **98,56 %** cuando las credenciales ya fueron filtradas [7]. Para no sobrestimar el beneficio, usamos una eficacia del **90 %**, porque la MFA no cubre todos los casos (*phishing* con proxy intermedio, fatiga de notificaciones *push*, vulnerabilidades del propio equipo VPN):

- ARO: 0,3 → **0,03**
- ALE después del control = 250.000 × 0,03 = **USD 7.500/año**

```text
$ python3 src/riesgo.py roi --antes 75000 --despues 7500 --costo 4440
14.203
```

**ROI = (75.000 − 7.500 − 4.440) / 4.440 ≈ 14,2.** Cada dólar invertido en MFA evita en promedio unos USD 15,20 de pérdida esperada. Descontado el costo del control, quedan USD 14,20 de beneficio neto por cada dólar.

**¿Qué pasa si nos equivocamos con los números?**

| Escenario | ALE antes | ALE después | Costo | ROI (`riesgo.py roi`) |
|---|---:|---:|---:|---:|
| Base (eficacia del 90 %) | 75.000 | 7.500 | 4.440 | **14,203** |
| Eficacia medida por Microsoft (98,56 %) | 75.000 | 1.080 | 4.440 | **15,649** |
| Pesimista: ARO real de 0,05 en lugar de 0,3, con 90 % de eficacia | 12.500 | 1.250 | 4.440 | **1,534** |

**Punto de equilibrio:** el control se paga si reduce el ALE en al menos USD 4.440 por año. Con nuestros números, eso equivale a una eficacia de apenas **5,9 %**. Visto desde el otro lado, con una eficacia del 90 % alcanza con que R1 tenga un ARO de al menos **0,02** (un incidente cada 50 años).

**Decisión: conviene, con mucho margen.** Además, el ROI calculado es **conservador**, porque no incluye la reducción del ARO de R2: el *ransomware* suele entrar por el mismo acceso remoto. Recomendamos aplicar la MFA primero a los administradores y al acceso remoto, y después extenderla a todo el personal. Para las cuentas con privilegios conviene usar MFA resistente a *phishing* (llaves FIDO2).

### B.3 — Un riesgo a aceptar o transferir

**Transferir R4 — siniestro físico en la oficina.** El escenario estima para este riesgo un SLE de **USD 400.000**, un ARO de **0,01** y, por lo tanto, un ALE de **USD 4.000 por año**. Como la pérdida potencial podría comprometer la continuidad de PhantomCorp, no sería prudente aceptar el riesgo completo. Proponemos transferir parte de su impacto financiero mediante un seguro de propiedad e interrupción del negocio que cubra incendio, inundación o robo y los costos de recuperación de los activos afectados.

La transferencia no evita que ocurra el siniestro ni reemplaza los controles preventivos y los respaldos fuera de la oficina. Además, una póliza puede tener límites, deducibles y exclusiones, y no compensa completamente el tiempo de inactividad, el daño reputacional ni todas las consecuencias de una pérdida de datos. Por eso, la empresa debe revisar que la cobertura y sus condiciones correspondan al escenario; el costo de la prima debe compararse con la pérdida cubierta esperada. Así se transfiere una parte de la carga financiera del riesgo catastrófico mientras se conserva la responsabilidad de reducir su probabilidad y asegurar la recuperación.

### Fuentes de la Parte B

1. Verizon. *2025 Data Breach Investigations Report* (comunicado del 23/04/2025): abuso de credenciales 22 %, explotación de vulnerabilidades 20 %, *ransomware* en el 44 % de las brechas, mediana del rescate pagado USD 115.000. https://www.verizon.com/about/news/2025-data-breach-investigations-report
2. Verizon. *2025 DBIR — SMB Snapshot*: *ransomware* en el 88 % de las brechas de pymes; uso de credenciales robadas, 33 %. https://www.verizon.com/business/resources/infographics/2025-dbir-smb-snapshot.pdf
3. NetDiligence. *Cyber Claims Study 2025* (vía Mondaq): costo promedio por incidente en pymes de USD 246.000 (período 2020–2024). https://www.mondaq.com/canada/security/1686464/netdiligence-releases-2025-cyber-claims-study-report
4. IBM. *Cost of a Data Breach Report 2026* (resumen de eSecurity Planet): costo promedio global de USD 4,99 M. https://www.esecurityplanet.com/cybersecurity/ibm-2026-cost-of-a-data-breach-report-key-findings/
5. IBM. *Cost of a Data Breach Report 2025*, datos de Latinoamérica (vía ComputerWeekly en español): USD 2,51 M. https://www.computerweekly.com/es/noticias/366633372/Uso-de-IA-y-automatizacion-reduce-el-costo-de-brechas-de-datos-en-LATAM
6. ENISA. *Introduction to Return on Security Investment*, diciembre de 2012. https://www.enisa.europa.eu/sites/default/files/publications/Return%20On%20Security%20Investment.pdf
7. Meyer, L. A. *et al.* *How effective is multifactor authentication at deterring cyberattacks?* Microsoft Research, mayo de 2023. https://www.microsoft.com/research/publication/how-effective-is-multifactor-authentication-at-deterring-cyberattacks/
8. Backblaze. *Backblaze Drive Stats for 2025* (12/02/2026): AFR 2025 de 1,36 %. https://www.backblaze.com/blog/backblaze-drive-stats-for-2025/
9. NFPA Journal, septiembre/octubre de 2013: 3.340 incendios por año en oficinas (promedio 2007–2011). https://nxtbook.com/nxtbooks/nfpa/journal_20130910/index.php?startid=72
10. U.S. EIA. *Commercial Buildings Energy Consumption Survey (CBECS) 2018*, tabla B4: 970.000 edificios de oficinas. https://www.eia.gov/consumption/commercial/data/2018/bc/html/b4.php
11. Cisco Duo. *Editions and Pricing*: Free (hasta 10 usuarios), Essentials USD 3, Advantage USD 6 y Premier USD 9 por usuario/mes. https://duo.com/editions-and-pricing

## 3. Anexo — `riesgos.json`

Archivo: [`riesgos.json`](riesgos.json). Los nombres van sin tildes a propósito: `riesgo.py` lo abre con `open()` sin indicar el *encoding*, y en Windows eso usa cp1252, por lo que los caracteres acentuados en UTF-8 saldrían mal.

```json
[
  {"nombre": "R1 - Intrusion por acceso remoto sin MFA (credenciales robadas) y robo de la base de clientes", "sle": 250000, "aro": 0.3},
  {"nombre": "R2 - Ransomware que cifra servidores y el unico backup (disco en la oficina)", "sle": 180000, "aro": 0.2},
  {"nombre": "R3 - Explotacion de una vulnerabilidad del servidor web publico (filtracion parcial)", "sle": 150000, "aro": 0.1},
  {"nombre": "R4 - Siniestro fisico en la oficina (incendio/inundacion/robo) que destruye servidor y backup", "sle": 400000, "aro": 0.01},
  {"nombre": "R5 - Falla de hardware del disco de backup (sin redundancia)", "sle": 2000, "aro": 0.0136}
]
```

## 4. Verificación del armado final — Fernando (@Ferca19)

Entorno: Python 3.12.2 en Windows, únicamente biblioteca estándar. Se utilizó
`python -B` para evitar generar `__pycache__` en la entrega. En Linux se puede
usar `python3 -B`.

```text
$ python -B src/verificar.py
3 OK · 0 a revisar · 0 sin implementar

$ python -B src/riesgo.py ale --sle 50000 --aro 0.4
20000.00

$ python -B src/riesgo.py roi --antes 20000 --despues 5000 --costo 8000
0.875

$ python -B src/riesgo.py priorizar --archivo riesgos.json
```

El último comando devuelve los cinco riesgos en el orden de B.1, con ALE de
75.000, 36.000, 15.000, 4.000 y 27,20 USD/año. El anexo JSON coincide con el
archivo entregado. Los tres ROI de B.2 se reprodujeron con la CLI:
`14.203`, `15.649` y `1.534`. El caso adicional del mini-research devuelve
`-0.493` y muestra la dependencia de la decisión respecto de los supuestos.

Las comprobaciones adicionales contrastaron ALE y ROI con `decimal.Decimal`,
incluidos valores cero, ARO mayor que uno, punto de equilibrio y ROI negativo.
Se comprobó que `roi_control` rechaza costos cero o negativos, y que
`priorizar` conserva la entrada, devuelve nuevas filas y resuelve listas
vacías y empates. Se revisaron compilación, importaciones de stdlib,
salidas y códigos de retorno de los tres subcomandos y la ayuda.

Estos resultados verifican las operaciones del modelo. Las frecuencias,
impactos y eficacia del control son estimaciones del ejercicio: que el
código y sus cuentas sean correctos no los convierte en mediciones reales
de PhantomCorp. El mini-research desarrolla esa distinción y sus fuentes.

Desde la raíz del repositorio, `git diff --check` y
`bash bin/validar-repo.sh` pasaron. En Git Bash se usó una función `python3`
que delega en Python 3.12.2, con `PYTHONPYCACHEPREFIX` dirigido a una carpeta
temporal externa al repositorio. Se verificaron compilación, shell,
manifiestos y enlaces internos.

Las cuatro fuentes del mini-research se consultaron directamente. En la
comprobación de enlaces del informe, la referencia NFPA [9] devolvió
HTTP 403 y no se pudo reconfirmar su cifra en esta sesión. El ARO de R4
se considera un supuesto orientativo del grupo, no una tasa medida para
PhantomCorp: combina referencias de EE. UU. de períodos diferentes y una
estimación adicional de inundación y robo. Esto no afecta la comprobación
aritmética de `400000 × 0,01 = 4000`.
