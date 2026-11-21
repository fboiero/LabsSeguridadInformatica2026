# Verificación real P3 — 2026-11-13

Se ejecutó el loop A contra DVWA y Juice Shop del kit, únicamente dentro de una red Docker interna. Se descargaron imágenes y dependencias antes de la ejecución. No se consultó ni modificó Git remoto ni se hizo push.

## Resultado observado

- Engagement `p3-real-20261113T161919Z` (el identificador exacto está en el manifiesto de P3-real-04).
- Dos activos, dos iteraciones, estado STOPPED, motivo «grafo estabilizado».
- DVWA: respuesta HTTP 302, tecnologías Apache HTTP Server 2.4.25, Debian y PHP.
- Juice Shop: respuesta HTTP 200 en puerto 3000; sin atribuir tecnologías no informadas por la herramienta.
- Cuatro sondeos HTTP reales y cuatro invocaciones de subfinder con estado de enumeración no disponible.
- Bitácora original verificada; una copia alterada falló por hash y otra con una fila eliminada falló por conteo.
- Suite dentro del runner: 245 passed; evals golden: 10/10.
- Progress: 004 13/15; 007 4/15 global, incluidas las dos tareas asignadas a P3.

## Evidencia y alcance

La evidencia definitiva está en `entrega/evidencia/salidas/P3-real-04/`: manifest.json, graph.json, audit.json y ocho archivos de salida de herramienta. Los stdout de subfinder son vacíos reales, no fixtures fabricados. Subfinder v2.17.0 devuelve código 1 y «No sources selected for this search» al excluir todos sus proveedores. Ese caso exacto se registra UNAVAILABLE; los demás errores abortan. No hubo descubrimiento pasivo efectivo: se sondearon las semillas del alcance autorizado con httpx v1.12.0.

El verificador `python -m harness.recon_lab audit verify` delega en `harness.audit.verificar_cadena` de P1. Verifica integridad interna del snapshot exportado y su conteo/head; no sustituye SQLite ni proporciona un anclaje externo contra reescritura completa.

Se verificó red `ptaas-p3_lab`, internal=true, 10.99.0.0/24, sin gateway ni ruta por defecto. No se publicaron puertos. El archivo original lab/docker-compose.yml de P5 permanece intacto; la preparación reproducible de P3 está en tools/p3_lab/.

## Correcciones verificadas durante la ejecución

El binario httpx requería musl: se usó Python 3.12 Alpine con stages fijados por digest. El test de Juice Shop falló antes de corregir su puerto a 3000. La revisión independiente detectó una Location relativa que perdía ese puerto; se corrigió después de reproducir la falla. La enumeración sin fuentes se distinguió de éxito mediante dos tests rojos. Un test rojo adicional comprobó que la evidencia activa reemplaza la procedencia inicial scope.seed por httpx.probe.

Se conserva únicamente P3-real-04 como evidencia definitiva de la corrida. La revisión independiente final no informó nuevos defectos concretos.

Se actualizaron únicamente archivos de P3 y su task 3.5. Los contratos, la auditoría de P1, el reporte de P5, policy.yaml y los loops B/C permanecen intactos.
