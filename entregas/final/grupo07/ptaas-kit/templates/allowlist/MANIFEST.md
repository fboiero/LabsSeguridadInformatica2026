# Allow-list de Nuclei · Grupo 07

El adaptador ejecuta exclusivamente los cinco archivos registrados en `manifest.json` y verifica su SHA-256 (texto UTF-8 normalizado a LF) antes de invocar Nuclei. Cada template usa solicitudes HTTP `GET` sin parámetros de explotación, autenticación, fuzzing, JavaScript, headless ni OAST. Los dos endpoints de riesgo bajo solo registran exposición si responden con el contenido esperado; los otros tres informan presencia de recursos públicos y no prueban credenciales. Nuclei corre con `-disable-redirects` para no seguir una respuesta a otro host.

| Archivo | Método | Propósito | Severidad declarada |
|---|---|---|---|
| `robots-txt.yaml` | GET | Presencia de `robots.txt` | info |
| `security-txt.yaml` | GET | Presencia de `/.well-known/security.txt` | info |
| `phpinfo-exposure.yaml` | GET | `phpinfo()` público con respuesta coincidente | low |
| `apache-server-status.yaml` | GET | `server-status` público con versión Apache | low |
| `admin-panel-presence.yaml` | GET | Presencia de `/admin/`; no intenta autenticación | info |

Los hashes fuente de verdad están en `manifest.json`. Ante cualquier cambio de contenido, el hash anterior deja de coincidir y el adapter rechaza la ejecución hasta revisar y actualizar el manifiesto.

**Revisión de seguridad:** cada template se inspeccionó en este change para confirmar método GET único, ausencia de cuerpo y ausencia de funcionalidades activas de Nuclei. Su uso real requiere aún la corrida dentro del laboratorio aislado.

| Archivo | SHA-256 (texto UTF-8, LF) |
|---|---|
| `robots-txt.yaml` | `0c333fe55f758a03915a128681dfe1677789d51bd4a1f9bdaf5d7c832571927b` |
| `security-txt.yaml` | `a437fc99df9222e7f49ff66e91da3abd0c241a13e380378d00d1fdb3abef499a` |
| `phpinfo-exposure.yaml` | `a18cf8617a22bb1aef1745eca92e16f75ac8959e58e1ed8f2608f6895700560b` |
| `apache-server-status.yaml` | `c8267832ca0f92ef4809c6b54230b74a989d1894d856a2d0284af44499fee690` |
| `admin-panel-presence.yaml` | `460343f458e4bd1a31873bd37a989c92b852ec9c59f2a84022dcd8de4c7ed6be` |
