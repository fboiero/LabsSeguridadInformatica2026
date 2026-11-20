# 021 — Catálogo dinámico de rutas autorizadas

El catálogo incorpora comprobaciones de solo lectura sobre rutas conocidas de
Juice Shop (listado `/ftp`, configuración administrativa, métricas, Swagger,
CAPTCHA, productos, reseñas, catálogo de retos y autorización de rutas
administrativas). Validación puede proponer una ruta nueva dentro de
`juice-shop.lab.test`; Python valida la ruta, el gate humano muestra la URL
exacta y cada ejecución conserva su aprobación individual. No se añaden métodos
de escritura ni shell libre.
