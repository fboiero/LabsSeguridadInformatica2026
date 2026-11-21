# Evidencia del recorrido A → B → C

## Corrida integrada defensiva con Juice Shop real

El 21/11/2026 a las 14:39 (UTC−03:00) se ejecutaron los tres componentes en
una sola corrida sobre evidencia obtenida de un contenedor efímero de Juice
Shop, con red `none` y sin puertos publicados. No se usaron observaciones
sintéticas para el traspaso de A a B.

| Etapa | Tope | Resultado observado |
|---|---:|---|
| **A — Reconocimiento (`run_loop`)** | 3 rondas | Dos consultas de disponibilidad al loopback del contenedor devolvieron `HTTP 200`. El grafo se estabilizó en la segunda ronda (`graph_stabilized`) y su digest pasó a B. |
| **B — Análisis (`detection_loop`)** | 3 rondas | La primera ronda recibió el digest de A; la segunda no agregó evidencia. B se detuvo por `no_progress` con resultado `inconclusive`, sin enviar tráfico al laboratorio. |
| **C — Revisión (`review`)** | 1 ronda | Un adaptador documental de la corrida tradujo el resultado inconcluso de B en una solicitud de revisión humana (`agent_escalated`). El control devolvió `PENDING_HITL`, con `started: false`. |

- **Digest del grafo compartido por A y B:** `c3b2752eb3e84e4420ae64312e35de2005aec7f4e76d452a2dfe58fa58257c3e`.
- **Auditoría de A:** cuatro eventos con integridad estructural verificada, sin anclaje externo.
- **Informe:** cero hallazgos registrados, publicación `PENDING_HITL`, SHA-256 `8cd87845ad9078d86a6ec41af42ec39830bbb1838f1f64eaff377f5c1a47d6b5`. Se verificó que sin aprobación se rechaza publicar. El contenedor se retiró al terminar.

La corrida acredita el traspaso de evidencia real **A → B → C** hasta el
control humano. El enlace B → C pertenece al adaptador de esta corrida, no
al orquestador de producción. No se ejecutaron comprobaciones de explotación
ni se observó escalado independiente en A o B.

El contenedor aislado de Juice Shop se inició **antes de A**. Es distinto
del sandbox que valida el recibo **después de C**. Para el recibo real se usa
`runtime.validate_abc`, no el validador de casos sintéticos. El nuevo sandbox
no tiene red ni vuelve a consultar Juice Shop: verifica la consistencia de
los registros de A y B, el estado de C y los hashes del informe. No certifica
por sí mismo el origen de las observaciones ni publica el informe.

Después de revisar el recibo, desde `ptaas-app` se pasa el SHA-256 exacto
aprobado por la revisora (no el hash interno del informe):

```powershell
python -m runtime.validate_abc <ruta-al-recibo-real.json> --approve-sha256 <sha256-aprobado-del-archivo>
```

El recibo original queda fuera del repositorio. Su SHA-256 es
`d866fcb9c07689c987e6f606e879b3b848735238318e2ad269a1c8a8795ea313`.
Se verificó que la falta de aprobación o un hash incorrecto bloquean el
arranque. Tras la autorización de Carolina para validar ese recibo, el
sandbox devolvió `DOCUMENT_CHECKED`, `network_isolated: true` y
`container_removed: true`. Los hashes del recibo, del informe y del grafo
coincidieron con los registrados arriba. La autorización se limitó a esta
validación documental: no se publicó el informe ni se registró aprobación
docente.

## Comprobación previa de disponibilidad y aislamiento

El 21/11/2026 a las 14:36 (hora local, UTC−03:00) se levantó una instancia
efímera de Juice Shop. La comprobación fue de disponibilidad y configuración,
sin escanear vulnerabilidades ni probar exploits.

| Etapa | Evidencia observada |
|---|---|
| **A — Inventario** | El contenedor estaba en ejecución. La página inicial respondió `HTTP 200` desde el loopback del propio contenedor. |
| **B — Contraste con la política de aislamiento** | Dos lecturas consecutivas de Docker coincidieron: modo de red `none` y cero puertos publicados. |
| **C — Revisión documental** | Se confirmó el retiro del contenedor y se dejó el registro para revisión humana. No se declaró ningún hallazgo de vulnerabilidad. |

**Registro de Docker:** `true|none|{}|sha256:634032bbcc50e4d2096734bc6a984265973c966db13933354dc85a9218d54836`.
El SHA-256 de esa línea (UTF-8, sin salto final) es
`57beceab2304901c7c5011162f8514803b1af189524f7bc11c47843af47f91c7`.

Esta comprobación previa acredita la disponibilidad y el aislamiento de la
instancia, no el traspaso entre los componentes.

## Prueba de integración automatizada

Una sola prueba conecta las tres etapas **offline**, con datos sintéticos y sin
modelos externos. El recorrido termina en revisión humana, sin iniciar un
sandbox, enviar tráfico ni confirmar hallazgos.

Desde `ptaas-app`, con las dependencias de desarrollo instaladas:

```powershell
python -m pytest -q -s tests/test_recon_correlation_reporting.py::test_offline_a_b_c_stops_at_human_review
```

| Etapa | Qué recibe y qué le pasa a la siguiente |
|---|---|
| **A — Reconocimiento** | Genera un grafo sintético y se detiene al estabilizarse en dos rondas (`graph_stabilized`). Entrega el digest del grafo como referencia de evidencia. |
| **B — Correlación y análisis** | Conserva el digest de A al correlacionar la observación sintética. Al repetirse la evidencia, termina sin progreso (`no_progress`) y devuelve un resultado `inconclusive`. |
| **C — Revisión documental** | El proveedor de prueba toma la decisión de B y solicita revisión humana (`agent_escalated`). C queda en `PENDING_HITL`; sin aprobación, el sandbox no arranca. |

Salida observada (digest abreviado):

```text
A: graph_stabilized (2 rondas), digest=87c0bc8f…
B: no_progress, inconclusive, referencia=87c0bc8f…
C: agent_escalated, PENDING_HITL, sandbox iniciado=False
1 passed
```

Las pruebas complementarias en `tests/test_recon_correlation_reporting.py` y
`tests/test_review_loop.py` cubren topes de rondas, paradas y el control de
aprobación de C. Esta prueba con fixtures permite repetir el recorrido sin
levantar el laboratorio. La [validación local de DefectDojo](entrega-defensiva.md)
acredita por separado el formato de exportación.
