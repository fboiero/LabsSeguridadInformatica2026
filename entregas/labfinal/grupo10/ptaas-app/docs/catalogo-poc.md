# Catálogo curado de verificaciones

`harness/poc/catalog.yaml` contiene quince entradas limitadas a `dvwa` y
`juice-shop`. Todas son `inert_check`, tienen aprobación registrada y observan
respuestas HTTP de solo lectura: headers ausentes, flags de cookies, listado
visible, reflexión de un canario inerte, errores detallados, listado `/ftp`,
configuración administrativa, métricas, Swagger, CAPTCHA, productos, reseñas,
autorización de rutas administrativas y catálogo de retos. No ejecutan código,
no extraen datos y no cambian el estado del objetivo.

El agente solo puede elegir un ID y completar exactamente sus parámetros.
`run_parametrized` rechaza IDs inexistentes, parámetros extra, valores inseguros
y cualquier ejecución sin aprobación del Reviewer. La aprobación ocurre antes
del sender y queda asociada al hallazgo.

Las comprobaciones de Juice Shop usan rutas conocidas por defecto, pero
Validación puede proponer una `ruta` distinta. `validate_target_path` solo acepta
rutas relativas que empiezan con `/`, sin `//`, `..`, barra invertida, CRLF ni
escapes `%2e`; el host sigue fijo en `juice-shop.lab.test:3000`. El gate humano
muestra la URL exacta antes de ejecutar. Una ruta fuera del dominio bloquea la
sesión sin enviar tráfico.

Estas comprobaciones evidencian controles o debilidades observables; no deben
presentarse como explotación confirmada. Ampliar el catálogo exige otro change,
revisión de seguridad y aprobación humana.

## Corrida real acreditada

El `Sender` se ejecutó mediante `Harness.invoke` dentro de un contenedor
efímero, con la imagen real `bkimminich/juice-shop` y red Docker interna. La
entrada `POC-CSP-001` fue aprobada explícitamente y consultó `GET /` en
`juice-shop.lab.test:3000`; obtuvo HTTP 200 y validó la ausencia de CSP. El
recibo es `runs/juice-poc-real-20261118-204806-csp.json`.

La bitácora contiene dos eventos y su hash de cadena. Se verificó la eliminación
del contenedor y de la red. `validated` significa que la comprobación
declarativa encontró la condición observada; no significa ejecución de código ni
explotación confirmada. Por eso el recibo conserva `confirmed_findings: []`.
