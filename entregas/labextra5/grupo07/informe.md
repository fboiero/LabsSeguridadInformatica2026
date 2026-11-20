# Entregable — Lab Extra 5: JWT inseguro

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0), Fernando Cagliero (@Ferca19)

**Estado parcial:** Lorenzo implementó y verificó las cuatro funciones de `jwt_tool.py` con datos sintéticos. R1–R3, control de sanidad y status son de Guadalupe; P1/P2/P4 de Lautaro; P3/P5 e integración de Fernando. Esos bloques siguen pendientes. No se levantó el portal, no se presentó ninguna flag y el CTF observado es 0/3.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para revisar el diseño del código y preparar pruebas sintéticas. Verifiqué el resultado con assertions locales para firma, alteración, diccionario sintético, errores de formato y CLI. No utilicé IA para afirmar aceptación del servidor ni para inventar hallazgos del caso. Declaraciones de los otros integrantes: pendientes.

---

## 1. Anatomía del token real

Pendiente: asignada a Guadalupe. No se solicitó un token del portal en este aporte.

## 2. Crack offline del secreto

La implementación de `firma_es_valida()` calcula HMAC-SHA256 sobre los segmentos codificados exactos `header.payload` y compara la firma decodificada usando `hmac.compare_digest`. Con un token y un candidato, la validación ocurre localmente; no hace una solicitud al servidor. La prueba sintética confirmó un secreto correcto, un secreto incorrecto y una firma alterada. No se probó el secreto del caso ni se reporta cantidad/tiempo de candidatos reales; eso corresponde a Guadalupe.

## 3. Las dos forjas

### R2 — Escalada vertical (role=admin)

Pendiente: ejecución y evidencia asignadas a Guadalupe. `forjar()` está implementada, pero aún no se afirma que el portal acepte un token de esta copia.

### R3 — Suplantación horizontal (sub=maria)

Pendiente: ejecución y evidencia asignadas a Guadalupe.

## 4. Control de sanidad

Pendiente: asignado a Guadalupe. Las pruebas sintéticas comprueban firma incorrecta en la función local, pero no sustituyen los requisitos del servidor: token regular de Diego rechazado en `/admin` y token forjado modificado rechazado con 401.

## 5. Preguntas P1–P5

- **P1 — Integridad vs. confidencialidad:** pendiente, asignada a Lautaro.
- **P2 — Crack offline vs. login online:** pendiente, asignada a Lautaro.
- **P3 — IDOR en el claim y autorización:** pendiente, asignada a Fernando.
- **P4 — `alg:none`:** pendiente; Lautaro debe medir el comportamiento de este servidor.
- **P5 — Defensas priorizadas:** pendiente, asignada a Fernando.

## 6. Evidencia de progreso

`evidencia/salidas/` contiene ayuda CLI, salida de las pruebas sintéticas y estado del CTF. El estado completo observado es 0/3. La cadena de explotación y las capturas del servidor se agregan cuando Guadalupe complete su bloque.
