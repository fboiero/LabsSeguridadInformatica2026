# Diseño — Change 004: recon y loop A

## Modelo del grafo

`AssetGraph` se persiste como JSON versionado (`schema_version: 1`). Cada nodo conserva el `Asset` validado, el conjunto de herramientas que lo observaron, las relaciones de descubrimiento y la clasificación de alcance. El ID se deriva de la dirección normalizada; repetir un nodo fusiona tecnologías y fuentes sin duplicarlo. La escritura usa reemplazo atómico del archivo para no dejar una mitad de serialización si el proceso se interrumpe.

Los descubrimientos fuera de scope quedan como nodos `in_scope: false`, con herramienta de origen y padre. No cuentan como activos nuevos del loop y nunca llegan a un adaptador activo. Antes de una invocación, `Harness.invoke` vuelve a aplicar el Guard determinista sobre el target exacto.

## Adaptadores y errores

Subfinder consume únicamente JSONL, con tiempo máximo, límite de resultados y rate limit explícitos; no se usa `-all` ni configuración de proveedor con credenciales. HTTPX recibe un hostname individual, emite JSONL y limita threads, tasa, timeout y reintentos. Ambos usan argv fijo sin shell; una salida malformada se rechaza como error de schema y no se agrega parcialmente al grafo.

Los adapters reciben un runner inyectable. El desarrollo y CI usan fixtures sintéticas; las herramientas reales solo se ejecutan desde el runner aislado del compose y a través de `Harness.invoke`. El adapter conserva errores de herramienta como salida `status: error` sin fingir un resultado satisfactorio.

## Loop A

En cada iteración se hace enumeración pasiva y luego se sondean solo los dominios nuevos que el Guard permite. Si no aparecen nodos dentro del alcance, `decide_recon` detiene el loop por grafo estabilizado; el tope se toma de `policy.yaml`. El target semilla no se expande ni se interpreta desde parámetros de shell.

## Límites

Las pruebas no contactan internet ni targets. La corrida real y la verificación de la bitácora con `audit verify` dependen de levantar el laboratorio aislado y de la implementación 002; no se declararán hechas si esa evidencia no existe.
