# Extensión: análisis defensivo de código propio

- Un operador ejecuta Bandit fuera del modelo sobre `harness/` y `runtime/`; el agente solo importa resultados JSON. No puede invocar herramientas.
- El contexto del modelo solo incluye identificador de evidencia, regla, severidad y confianza; no rutas, mensajes, fragmentos, secretos ni URLs del informe.
- Cada alerta importada requiere exactamente una clasificación preliminar (revisar, posible falso positivo o inconclusa). No se aceptan referencias ajenas ni se declaran vulnerabilidades confirmadas.
- Si el proveedor falla, el resumen conserva los pasos aceptados y un código de error fijo. Cada respuesta inválida queda registrada sin copiar contenido; tras dos consecutivas se pide revisión humana.
- La ruta de modelos es explícita por rol. El modo fixture no llama a ningún modelo y no hay sustitución automática ante errores del proveedor.
