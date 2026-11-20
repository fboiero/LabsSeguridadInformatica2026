# Diseño 013

El operador levanta el contenedor y expone solo `127.0.0.1:18080`. El CLI recibe
esa URL, pero la permite únicamente si el host es `phantomcorp`, `phantomcorp.test`
o loopback con puerto explícito. El adaptador tiene un catálogo fijo por código:
R1 `GET /portal-rrhh`; R2 `POST /portal/login` con el fixture de autenticación
del laboratorio; R3 `GET /backup/rrhh.conf`; R4 `GET /api/reporte` con el token
obtenido en R3 y el único comando de impacto aprobado por el catálogo.

El token de R3 vive solo en memoria y no aparece en `result.json` ni en la
bitácora. Se detiene ante cualquier marcador faltante. La imagen usada se
construye desde `entorno/phantomcorp/Dockerfile`, no desde una imagen ambigua.
El resultado queda `PENDING_HITL`; ver un marcador no equivale a confirmar un
hallazgo ni a aprobar una entrega.
