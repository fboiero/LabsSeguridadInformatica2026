# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 10 · **Integrantes:** Belén Rocío Ramello — @belramello · Carolina Paula Corazza — @carocor1 · Chiara Agustina Kordek — @chiarakordek · Juan Pablo Saby — @JuanSaby · **Fecha:**
**Proveedor usado:** mock

## 0. Declaración de uso de IA

## 1. Flags capturadas

## 2. Tu agente

## 3. Auditoría crítica del agente

### 3.1 Transcript

### 3.2 Aciertos y errores

### 3.3 El guardrail (R4)

### 3.4 Otros guardrails que agregaríamos

Además del control de alcance existente, proponemos agregar estas capas en `herramientas.py`:

1. **Validación estricta de destinos y redirecciones.** Parsear URLs con una biblioteca de URL, normalizar el hostname y validar direcciones resueltas. En `http_get` y `http_post`, revisar cada redirección y bloquear cualquier salto fuera de `phantomcorp`; la comprobación actual del host inicial no alcanza si una respuesta redirige a otro servidor.
2. **Allowlist de operaciones y rutas.** Separar los GET de los POST, limitar rutas y parámetros aceptados, y exigir aprobación humana para operaciones que cambien estado o envíen datos. El modelo no debería convertir una instrucción recibida en una página en autorización para hacer un POST.
3. **Límites por ejecución y auditoría.** Además de `MAX_PASOS`, fijar un máximo global y por herramienta de solicitudes, una tasa permitida, tamaños de respuesta y registro con objetivo, método, herramienta y resultado. Esto reduce loops, consumo excesivo y facilita reconstruir qué ocurrió.
4. **Marcar resultados externos como no confiables.** Encapsular las respuestas de `http_get` como datos, filtrar secretos antes de devolverlas al LLM y comprobar la acción propuesta con reglas deterministas. Delimitar el contenido ayuda, pero no sustituye la autorización de las herramientas (OWASP GenAI Security Project, 2025; OpenAI, 2026).

## 4. Preguntas de análisis

### P1 — el loop de tool-use

### P2 — LLM vs. script fijo

### P3 — ventaja del diseño agnóstico

El agente no necesita conocer el formato particular de la API de Claude o de OpenAI. `crear_cliente(system, tools)` selecciona una implementación según `LLM_PROVIDER`; cada adaptador transforma el esquema genérico de herramientas al formato de su proveedor y `paso(resultados)` devuelve una acción común (`tool` con nombre y argumentos, o `final` con texto). Así, el loop de `agente_esqueleto.py` y el despachador de herramientas pueden mantenerse iguales al cambiar de proveedor. El mock permite recorrer el flujo sin claves ni conexión externa y de forma determinista, lo que sirve para depurar el loop; no demuestra que un LLM real vaya a elegir las mismas acciones ni que los proveedores tengan igual calidad o seguridad.

El agente queda acoplado a esa interfaz (`crear_cliente(...).paso()`), al formato de acción normalizada y al contrato de nombres y argumentos de `TOOLS`. Los detalles de autenticación, endpoint y formato de function calling quedan dentro de `llm.py`. La abstracción facilita sustituir proveedores, aunque solo cubre el conjunto común de funciones; capacidades particulares de una API pueden requerir cambios en su adaptador (ver `llm.py`).

### P4 — dos riesgos y su guardrail

1. **Que una instrucción del objetivo desvíe al agente fuera del alcance.** Una respuesta de `phantomcorp` podría pedirle que escanee `8.8.8.8`. Si el modelo la obedece, se produciría tráfico no autorizado y la auditoría podría afectar a un tercero. El control actual es que cada herramienta verifica el objetivo contra `ALCANCE = {"phantomcorp"}` mediante `_verificar_alcance()` y bloquea el host directo que no coincide. La validación del host y las redirecciones debe endurecerse como se propone en 3.4; no alcanza con confiar en el prompt (OWASP GenAI Security Project, 2025).
2. **Acciones excesivas o con efectos no previstos.** Un proveedor podría repetir llamadas, consumir recursos del entorno o intentar usar `http_post` cuando bastaba con leer una respuesta. `MAX_PASOS = 12` limita la cantidad de iteraciones de esta ejecución; además, `nmap_scan` y las llamadas HTTP tienen tiempos de espera. Como defensa complementaria, limitar solicitudes por herramienta y exigir confirmación antes de POST reduce el impacto de una selección equivocada o manipulada (OpenAI, 2026).

### P5 — por qué los labs 05–08 eran requisito

## Cierre

### Dificultades encontradas

### Distribución del trabajo

### Fuentes consultadas
