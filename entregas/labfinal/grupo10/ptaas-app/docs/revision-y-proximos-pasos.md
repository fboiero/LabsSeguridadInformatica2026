# Revisión preliminar y próximos pasos

La primera demo usó cuatro roles de IA real en cinco llamadas, una consulta
simulada y ningún escaneo. El borrador quedó en `PENDING_HITL / before_deliver`.
La ejecución original está en `runs/opencode-compatible/`, una carpeta local
ignorada por Git. Desde la raíz del repositorio, abrila con PowerShell:

```powershell
explorer.exe .\entregas\final\grupo10\ptaas\runs\opencode-compatible
```

`result.json` contiene decisiones, `draft.json` el borrador y `audit.db` la
bitácora. Para repetir la demo, ver [instrucciones](../README.md#ejecutar-en-windows).

## Propuesta: primer análisis defensivo

1. **Bandit:** análisis estático local del código Python propio. Empezar por
   `harness/` y `runtime/`. Sus alertas requieren revisión, no se confirman solas.
2. **pip-audit:** revisar las versiones instaladas en el entorno virtual propio
   contra avisos públicos. Se ejecuta por separado del sandbox; consulta un
   servicio de avisos y no se usaría con actualización automática.
3. **Análisis:** importar los informes JSON de una corrida iniciada por una
   persona. Normalizar referencias, distinguir posible hallazgo, falso positivo
   y resultado inconcluso, y sugerir remediaciones. El agente no lanza herramientas
   ni decide a qué sistema conectarse; si no hay evidencia suficiente, lo dice.
4. **Validación aislada:** verificar un control concreto, por ejemplo que un
   adaptador simulado no se invoca si falla el registro previo. Usar un contenedor
   desechable sin red, sin secretos, sin socket de Docker y con entradas de solo
   lectura. Ejecutar únicamente pruebas predefinidas y guardar el resultado
   con una referencia al test y al artefacto. No equivale a validar la
   explotabilidad de una vulnerabilidad ni a un pentest contra DVWA.

## Revisión preliminar del asistente (no independiente)

- **Trazabilidad:** `runtime/demo.py:72–98` registra salidas aceptadas y la segunda
  inválida, pero no la primera inválida ni un error del proveedor. Registrar
  metadatos mínimos por intento, sin prompts ni respuestas crudas.
- **Diagnóstico de fallos:** `runtime/demo.py:196–210` escribe `result.json` solo
  si el flujo retorna sin excepción. Conservar un resumen parcial saneado cuando
  falle el proveedor, sin presentarlo como una ejecución exitosa.
- **Historial:** `harness/audit.py:94–96` comprueba que existan los nombres de los
  triggers; no demuestra quién los creó ni certifica que el historial esté
  completo. Mantener esa garantía fuera de las promesas del verificador.

## Revisión independiente (pendiente)

Otro integrante que no haya escrito el cambio revisa el diff en el PR y corre
los tests. En particular, verifica que no haya herramientas directas para el
modelo, que los fallos de bitácora impidan ejecutar, que los errores no
expongan secretos y que las referencias de evidencia sean verificables. Cada
hallazgo debe quedar en el PR con archivo, impacto y resolución o justificación.
Una segunda opinión de IA o un informe de Bandit no reemplazan esa aprobación.

En la iteración siguiente se incorporaron Bandit, el rol de análisis preliminar
y las dos correcciones de trazabilidad del proveedor y las respuestas inválidas.
Ver [cómo ejecutarlo](../README.md#analizar-nuestro-código-con-bandit). Sandbox,
pip-audit y revisión independiente siguen pendientes.
