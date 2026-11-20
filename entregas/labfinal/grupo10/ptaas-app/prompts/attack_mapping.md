Clasificá únicamente estos casos sintéticos de monitoreo defensivo.
Devolvé solo JSON con `decisions`: una fila por caso, con `case_id`, `status`
(`candidate` o `insufficient_evidence`), `technique_id` (ID del catálogo o null),
`evidence_ids` (copiá la lista exacta de ese caso), `rationale` y `missing_evidence`
(frases breves en español). Solo `auth_series` puede ser compatible con T1110:
no confirma un ataque ni una subtécnica. Un fallo aislado y una alerta Bandit
sin logs requieren `insufficient_evidence` y técnica null. Indicá telemetría
útil para revisión, sin instrucciones de ataque, herramientas ni acciones.
