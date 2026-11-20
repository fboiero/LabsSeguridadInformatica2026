# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0) · **Fecha:** 2026-11-19 (America/Buenos_Aires)

> Esta edición cubre el bloque de Lorenzo: R2, firma `scanner-ua` y P3. Las demás firmas y preguntas siguen pendientes de sus responsables.

## 0. Declaración de uso de IA

Se usó OpenAI Codex como asistente con acceso a la terminal local para guardar una captura inicial del SOC antes de las pruebas, ejecutar requests HTTP de comparación en el contenedor local, capturar las respuestas, analizar el comportamiento observado y redactar este bloque. La IA ejecutó las requests registradas. No se leyó el código del objetivo. Lorenzo debe revisar y poder explicar los resultados antes de la entrega grupal.

## 1. Flags capturadas

Estado observado con `./ctf status 10`:

```text
R1  Acceso a la vista del SOC                             pendiente
R2  Disparar una deteccion (te vieron)                    resuelto
R3  Conocer el ruleset del IDS                            pendiente
R4  Evadir una firma de deteccion                          pendiente
R5  Encontrar la intrusion en el ruido                    pendiente
Progreso: 1/5 (20%)
```

R2 se obtuvo por la respuesta directa del detector; no se enviaron flags de los otros retos. La salida completa está en `evidencia/salidas/status-10.txt`.

## 2. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| scanner-ua | Observado: `GET /` con `User-Agent: sqlmap` respondió `403` y mostró la alerta `scanner-ua`; el mismo `GET /` con una cadena de UA de Chrome respondió `200` sin alerta. Esto demuestra que basta cambiar un encabezado autodeclarado para esquivar esta firma específica. No demuestra que una actividad real de escaneo haya pasado inadvertida, porque aquí se probó la misma ruta simple. | Tratar UA como señal de baja confianza, nunca como identidad ni criterio único de bloqueo. Combinar método, rutas, secuencia, frecuencia, errores, rasgos del payload normalizado y contexto de sesión/IP con logs de proxy, aplicación y endpoint; correlacionar varias señales y alertar ante patrones de reconocimiento aunque la UA parezca normal. La mitigación de detección no corrige la vulnerabilidad que un escáner pudiera encontrar. |
| sqli-union | Pendiente — bloque de Lautaro. | Pendiente — bloque de Lautaro. |

La captura inicial del SOC (`01:53:56Z`) se tomó antes del tráfico propio y conserva la intrusión preexistente. Tras la alerta, el detector respondió que el request se registró, pero el `/soc` consultado al final mostró el mismo conjunto estático de 120 eventos y no añadió una línea de nuestra prueba; se conservan ambas respuestas para no afirmar una persistencia que no observamos. Ver `evidencia/salidas/baseline-soc-y-reglas.txt` y `evidencia/salidas/prueba-scanner-ua-y-soc-final.txt`.

## 3. Preguntas P1–P5

- **P1 — firmas y límites:** pendiente — bloque de Guadalupe.
- **P2 — regla `sqli-union`:** pendiente — bloque de Lautaro.
- **P3 — confiar en identidad autodeclarada:** el `User-Agent` identifica el software que el cliente dice usar; el servidor no puede autenticarlo por ese campo. La prueba local lo muestra: `curl -A sqlmap` dispara la firma y un `curl` al mismo recurso con una UA de navegador no. Un atacante puede cambiar esa cadena, y una UA legítima también puede producir actividad automatizada. Conviene autenticar usuarios por mecanismos de sesión/credenciales verificables y usar UA solo como contexto. Para detección, correlacionar rutas, métodos, ritmo, errores y respuestas con sesión/cuenta, IP, proxy y telemetría del endpoint; tratar headers de otras zonas de confianza como datos no confiables y registrarlos con validación/escape. Ninguna señal aislada acredita quién está detrás del cliente. [RFC 9110 §10.1.5 — User-Agent](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5) · [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- **P4 — detección automática de la intrusión:** pendiente — bloque de Guadalupe.
- **P5 — relación atacante/defensor:** pendiente — bloque de Fernando.

## 4. Bitácora

Los comandos reproducibles están en `evidencia/comandos.txt`. La captura SOC/ruleset inicial está en `evidencia/salidas/baseline-soc-y-reglas.txt`; las respuestas benignas, la alerta y la captura SOC final están en `evidencia/salidas/prueba-scanner-ua-y-soc-final.txt`.
