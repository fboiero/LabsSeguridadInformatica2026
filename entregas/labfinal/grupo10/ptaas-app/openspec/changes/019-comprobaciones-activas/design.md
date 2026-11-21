# Design — 019 Comprobaciones activas

## Separación de conceptos

| Concepto | Dónde vive | Qué garantiza |
|---|---|---|
| Propuesta visible | `proposals.yaml` | El agente puede recomendarla, pero no ejecutarla |
| Comprobación activa | `active.yaml` | Carga fija, método y ruta definidos |
| Autorización de sesión | `fresh_reviews.active` + evento | La persona habilita el modo activo para ese laboratorio |
| Aprobación por intento | gate existente (`AWAITING_CHECK`) | Nadie ejecuta sin decisión explícita |
| Revisión docente | `review_status` | Sigue pendiente; no se deriva de la autorización local |

## Flujo

1. La persona inicia la sesión y marca **Comprobaciones activas**.
2. Se registra un evento `autorización de sesión` que aclara que no equivale a
   aprobación docente.
3. Validación solo recibe los IDs activos implementables en `catalogo_disponible`
   cuando `active` es verdadero. Las no implementables aparecen como declaradas.
4. Toda propuesta activa exige `AWAITING_CHECK`; el catálogo automático no la
   saltea.
5. `run_active` exige `authorized=True` y una carga de `PAYLOADS`; no acepta
   cuerpos del modelo.
6. El recibo conserva `review_status: pending_teacher_review`.

## Evaluación de SQLi

Se evalúa únicamente si la respuesta es `200`, contiene un bloque
`authentication` y un `token`. Es una observación de bypass de autenticación en
el laboratorio; no se enumeran usuarios, no se vuelcan datos y no se reutiliza el
token.

## FTP

`ftp_index_entries` extrae hasta 20 nombres de los enlaces del índice ya
recibido. El recibo los muestra junto con la aclaración de que no se descargó
ningún archivo.

## Riesgos

- Un cambio futuro en Juice Shop puede hacer que la carga fija deje de ser
  válida. Se registra `not_validated`, no un falso positivo.
- La autorización de operador no reemplaza la revisión docente; el texto de UI y
  los eventos deben mantener esa distinción.
