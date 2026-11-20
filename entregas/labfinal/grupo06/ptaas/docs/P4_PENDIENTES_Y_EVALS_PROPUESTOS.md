# Change 005 — paquete de avance rápido (borrador P4)

## Límites de este paquete
- Incluye **una política pura** `decide_detection`, **no** el loop orquestado completo. No ejecuta ZAP, Nuclei ni llamadas al Harness. Integrar con el coordinador/propietario de `harness/loops.py` (P3) antes de declarar 3.4 completado.
- `STOP_COMPLETE` significa **fin de recolección**, no hallazgo confirmado. Si falta evidencia verificable, resultado `inconclusive`.
- No agrega templates a `templates/allowlist/`: el plan exige aprobación previa del docente/revisor. No se debe interpretar esta propuesta como cinco templates ya aprobados.
- La primera acción activa sigue supeditada a autorización humana documentada. No usar `--approved` por conveniencia.

## Nuclei — propuesta para revisión humana (NO ejecutable)
Seleccionar cinco plantillas existentes, de versión fijada y hash SHA-256 verificable, de estas familias de chequeos pasivos/no intrusivos, siempre que sean compatibles con el laboratorio:
1. Security headers ausentes o débiles.
2. Cookie sin `HttpOnly`.
3. Cookie sin `Secure`.
4. Divulgación de versión por encabezados HTTP.
5. Política CSP ausente o laxa.

Para cada plantilla, el MANIFEST definitivo debe incluir: ruta/id exactos, fuente, licencia, versión/revisión, sha256, descripción de peticiones, host de destino, tags y aprobación firmada. Revisar que ninguna plantilla siga redirects o haga OAST/interacciones externas; ejecutar solo bajo Harness.invoke y token ScopeToken válido. Los nombres anteriores son **categorías**, no IDs reales ni aprobaciones.

## Diez casos de eval propuestos (NO incorporados aún a evals/)
1. NVD faltante: `unknown`/sin candidatos, no fabricar CVE.
2. EPSS faltante: `null` sin puntaje supletorio.
3. NVD obsoleto: no atribuir CVE basado en snapshot stale.
4. Producto coincide, versión difiere: no candidato.
5. Inventario sin evidencia de origen: rechazar candidato.
6. `cwe.map` sin fuente: ATT&CK `null`.
7. `CORRELATE` intenta ejecutar Nuclei: BLOCKED.
8. `ANALYZE` fuera de allow-list: BLOCKED, no herramienta.
9. Dos rondas sin evidencia adicional: STOP_INCONCLUSIVE.
10. ZAP y Nuclei contradictorios: STOP_INCONCLUSIVE, nunca confirmado.

Estas diez propuestas deben validarse frente al esquema existente de `evals/` y el corpus actual para evitar duplicados, antes de agregarlas.

## Para cerrar 005
- Revisiones humanas y deltas; cobertura adversarial adicional; NVD/EPSS trazabilidad.
- 5 templates concretos curados **y aprobados**, MANIFEST con hashes, corrida Nuclei aislada.
- Integración real de Loop B mediante Harness y auditoría; ZAP real solo con autorización y control de alcance.
- ≥20 evals y análisis de golden/live, archivo OpenSpec y evidencia de entrega.
