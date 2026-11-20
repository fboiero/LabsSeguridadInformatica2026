# 013 — Recorrido activo acotado de PhantomCorp

El PTaaS incorpora un adaptador HTTP específico para el laboratorio de la
cátedra. Ejecuta solo cuatro operaciones fijas, encadenadas y no destructivas:
localizar el portal, comprobar el foothold del fixture, recuperar el artefacto
de configuración y leer únicamente el resumen de impacto previsto. No acepta
comandos ni URLs del modelo. Cada paso pasa por `Harness.invoke`, token de fase,
bitácora y un único gate humano de inicio. La evidencia persistida contiene
marcadores y hashes de respuesta, nunca tokens, flags ni cuerpos crudos.
