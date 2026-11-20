# Diseño

`AssetGraph` deduplica por `host:port` y conserva un digest estable. El loop A
termina cuando el digest no cambia o al alcanzar tres rondas. `SubfinderAdapter`
solo construye la invocación declarada y filtra resultados al allowlist; el
sondeo HTTP de Juice Shop usa `HttpxAdapter` y nunca recibe comandos del modelo.
