# Diseño

El informe conserva referencias y hashes de evidencia, distingue `validated` de
`not_validated` y queda en `PENDING_HITL`. La exportación local solo ocurre si
el hash del Reviewer coincide; no se envían secretos ni cuerpos HTTP crudos.
