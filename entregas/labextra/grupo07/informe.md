# Entregable — Lab Extra SSRF

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado parcial:** solo se documentan R3 y P2, asignados a Lorenzo. R1/P1/P5 (Fernando), R2/P3 (Guadalupe) y P4/cierre/integración (Lautaro) todavía no están incluidos. El estado observado del CTF es 1/3.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para organizar evidencia que yo capturé, redactar esta sección y consultar la documentación oficial enlazada en `research.md`. Verifiqué cada resultado con las salidas crudas del contenedor del laboratorio, el estado local del CTF y las páginas oficiales citadas. No usé IA para inventar ejecuciones ni para atribuirme los bloques pendientes. Declaraciones de los otros integrantes: pendientes de sus aportes.

---

## 1. Cadena de explotación

### R1 — Panel interno en localhost

Pendiente: asignado a Fernando.

### R2 — Intranet en la red interna

Pendiente: asignado a Guadalupe. El resultado de R3 y sus datos ficticios ya fue compartido como insumo para su P3.

### R3 — Exfiltración del backup

La aplicación ofrece `/preview`, que realiza la petición HTTP desde el servidor. Dirigí ese fetch al recurso de backups en la intranet:

```bash
curl -sS -i -G --max-time 5 --data-urlencode 'url=http://phantomcorp-intra/backups/clientes.json' http://phantomcorp/preview
```

La respuesta fue HTTP 200. El JSON se identificaba como backup temporal pre-migración e incluía dos registros ficticios —Aconcagua SRL, CUIT `30-70998877-1`, y Comechingones SA, CUIT `30-71554433-6`— junto con `FLAG{ssrf_backup_clientes}`. La captura completa está en `evidencia/salidas/r3-backup.txt`. El CTF aceptó la flag para R3.

Los datos son ficticios y pertenecen al entorno del curso. La captura demuestra que el contenido del backup pudo leerse a través del servidor; no demuestra un acceso directo desde el atacante a la intranet ni una exfiltración hacia un tercero.

## 2. Evidencia de progreso

La salida completa está en `evidencia/salidas/status-extra.txt`: R3 ✓; R1 y R2 pendientes; total 1/3. Los comandos y sus capturas crudas se encuentran bajo `evidencia/`.

## 3. Preguntas de análisis

### P1 — Modelo de confianza por red

Pendiente: asignado a Fernando.

### P2 — Oráculo de puertos

En las tres solicitudes, el destino fue `127.0.0.1` desde el proceso `/preview`; cambié únicamente el puerto. Para `127.0.0.1:80/`, el servidor devolvió HTTP 200 y la página del portal. Para los puertos 9 y 8080 devolvió HTTP 502 y el cuerpo incluyó `Connection refused`. En esta prueba, el contraste entre respuesta de aplicación y rechazo de conexión reveló que el puerto 80 aceptaba HTTP mientras que los puertos 9 y 8080 rechazaban la conexión.

Esto funciona como oráculo de escaneo porque un usuario puede observar resultados diferentes para destinos elegidos por él, aunque el fetch ocurra desde el servidor. La evidencia se limita a esos tres puertos en este laboratorio; no es un escaneo amplio ni prueba cómo responderían otros servicios. Salida cruda: `evidencia/salidas/p2-puertos.txt`.

### P3 — Hallazgo profesional

Pendiente: asignado a Guadalupe. R3 y el inventario ficticio recuperado quedan como evidencia de apoyo para que describa el activo, vector e impacto.

### P4 — Mitigaciones

Pendiente: asignado a Lautaro.

### P5 — Metadata service cloud

Pendiente: asignado a Fernando. El análisis documental de metadata asignado a Lorenzo está en `research.md`.

## 4. Conclusión ejecutiva

Pendiente de integración por Lautaro cuando estén disponibles R1/R2, P1/P3/P4/P5 y el research completo.
