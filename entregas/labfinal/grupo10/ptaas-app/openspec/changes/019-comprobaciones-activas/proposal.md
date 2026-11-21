# Change 019 — Comprobaciones activas autorizadas por sesión

## Por qué

El catálogo solo ejecutaba comprobaciones inertes (`GET`). Las propuestas de
comprobación activa existían en `harness/poc/proposals.yaml` como visibles y **no
ejecutables**, pendientes de revisión docente. Este change habilita una de ellas
con un contrato explícito y deja las demás declaradas, sin adaptador.

## Qué cambia

- Nuevo `harness/poc/active.yaml`: cinco propuestas derivadas del catálogo de
  propuestas. **Ninguna registra aprobación docente**: todas conservan
  `review_status: pending_teacher_review`.
- `PROPOSAL-AUTH-SQLI-001` queda implementable con un **POST fijo** a
  `/rest/user/login`, carga fija y evaluación binaria de emisión de sesión. No
  extrae datos ni modifica estado fuera del login del laboratorio.
- `PROPOSAL-SQLI-SEARCH-001` queda implementable con un **GET fijo** a
  `/rest/products/search?q='`, que solo evalúa si la respuesta expone una firma de
  error del motor SQL. No extrae datos.
- El panel ofrece **Profundizar** para encolar la próxima comprobación activa sin
  depender de que el modelo la proponga; el gate por intento se mantiene.
- `PROPOSAL-DOM-XSS-001`, `PROPOSAL-UPLOAD-001`, `PROPOSAL-ADMIN-AUTHZ-001` y
  `PROPOSAL-CAPTCHA-001` quedan declaradas sin ejecución: requieren navegador,
  adaptador multipart o ya están cubiertas por comprobaciones inertes.
- `POC-FTP-001` ahora describe los nombres de archivo que el propio índice ya
  expone. No descarga ni abre archivos.
- Relevo exige una casilla explícita **Comprobaciones activas** al iniciar la
  sesión, registra una autorización de la persona que opera y mantiene la
  aprobación por intento incluso con catálogo automático.

## Límites que se preservan

- Solo objetivo `juice-shop`, red interna efímera, sin puertos publicados.
- Carga fija en código; el modelo no puede aportar cuerpo, método ni ruta.
- Una propuesta no implementable nunca envía tráfico.
- `run_active` falla sin autorización de sesión.
- El recibo y la bitácora distinguen autorización de operador de revisión
  docente. No se inventan firmas ni aprobaciones.

## Pendiente

- Revisión docente de las propuestas activas (estado real: pendiente).
- Adaptador de navegador para XSS DOM y adaptador multipart para carga de archivos.
- Revisión independiente del diff antes de archivar el change.
