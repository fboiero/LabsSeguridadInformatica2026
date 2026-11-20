# Subfinder: fixtures simulados, sin red

Estos JSONL fueron escritos para tests; no son capturas ni descubrimientos reales.

- `subfinder-authorized.jsonl`: subdominios de dvwa.lab.test, normalización y duplicados.
- `subfinder-mixed.jsonl`: activo autorizado, subdominio excluido y referencias fuera de alcance, incluido un sufijo engañoso.
- `subfinder-empty.jsonl`: stdout vacío de una ejecución simulada exitosa.

Los casos usan el adaptador SubfinderEnum, Harness, Guard y loop A existentes. El runner, la resolución y los sondeos HTTP son simulados; cualquier intento de abrir procesos o resolver mediante socket.getaddrinfo hace fallar estos tests. No se modifican los perfiles ni el alcance real.

La evidencia real se conserva en `entrega/evidencia/salidas/P3-real-04/` y `tests/fixtures/p3/real/`. Allí subfinder respondió «No sources selected for this search» (exit 1, UNAVAILABLE). Eso es distinto de una ejecución simulada exitosa sin resultados (OK, assets=[]). Estas simulaciones validan procesamiento y controles; no demuestran descubrimiento pasivo efectivo en el laboratorio.

Pruebas: `tests/test_recon_loop_a.py`, casos `test_subfinder_simulated_*`.

Verificación local: 6 casos nuevos aprobados; suite completa de 251 tests aprobados; progress finalizó correctamente. Los hashes SHA256 de P3-real-04 permanecieron idénticos. Salida guardada en entrega/evidencia/salidas/P3-subfinder-simulacion.txt.
