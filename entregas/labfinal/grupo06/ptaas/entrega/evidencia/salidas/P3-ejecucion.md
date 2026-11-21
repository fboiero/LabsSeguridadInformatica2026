# Ejecución P3 — 2026-11-13

Se leyó el adjunto original PLAN_LABFINAL_PTAAS(2).md, las reglas locales y los contratos de P1/P2. Se trabajó sobre la rama local labfinal-ptaas-grupo06, sin fetch, pull, push ni acceso al remoto.

## Secuencia ejecutada

- 38212f8: diseño y deltas.
- 58a5b3b: 53 tests rojos por interfaces todavía ausentes; recolección correcta. Esta evidencia inicial no acredita por sí sola regresiones de comportamiento.
- ae4a575, 9dbf1a5 y aa02c5e: pruebas rojas de comportamiento antes de corregir siete defectos concretos. Salidas P3-red-behavior.txt, P3-red-review.txt y P3-red-frontier.txt.
- Implementación de adaptadores, grafo persistido, loop A y módulo de informe P3; suite completa de 230 tests aprobados.
- Revisión independiente de código: detectó errores de gate reanudado, semillas omitidas, cambio de tasa, Location malformada y frontera no persistida. La segunda revisión no encontró defectos nuevos concretos.
- Seis mutaciones en memoria detectadas por tests: tasa, CVSS, EPSS, conservación de HITL, exclusión previa al sondeo y tope al recargar. P3-mutaciones.txt contiene las salidas; no se alteró producción para mutar.

## Alcance comprobado

Los fixtures son sintéticos y están identificados en tests/fixtures/p3/README.md. Docker respondió que el daemon no estaba iniciado. No se ejecutó reconocimiento real ni se acreditó audit verify sobre una corrida real. Subfinder devuelve local_source_required sin runner local; no se habilitaron sus proveedores de Internet.

El informe de 007 2.3/2.4 se invoca desde harness.reporting_p3.render_report y conserva el gate existente. reporting.py, contracts.py, engagement.py, policy.yaml, Docker, los loops B/C y tests ajenos no fueron modificados.

La revisión automática rechazó un instalador por lotes por riesgo de sobrescribir lógica ajena; no se ejecutó. Se inspeccionó el diff y se aplicaron reemplazos exactos con aserciones, conservando íntegro el prefijo original de loops.py.

## Correcciones de la IA verificadas

| Error detectado | Evidencia | Corrección |
|---|---|---|
| HTTP vacío tratado como éxito | test_http_empty_output_is_not_convergence en rojo | error explícito empty_output |
| Reanudar STOPPED o PENDING_HITL ejecutaba nuevas acciones | tests de checkpoint terminal y schema HITL en rojo | preservar estados |
| Reducir tasa no imponía el nuevo intervalo | test_rate_lowered_between_calls en rojo | respetar tasas actual y anterior |
| Location inválida lanzaba excepción sin finalizar | test_malformed_redirect_cannot_crash_loop en rojo | registrar host invalid sin propagar error |
| Enumeración vacía omitía la semilla y se perdía la frontera | tests de semilla y frontier en rojo | incluir semilla y persistir frontier |

Registro P3 separado para no editar documentos consolidados de otros dueños.
