# 018 — Agente de validación con GPT-5.6 Luna

Separar el rol de Validación del rol de Análisis y asignarle el modelo
`openai/gpt-5.6-luna`. Validación propone comprobaciones del catálogo; el
coordinador conserva la ejecución mediante `Harness.invoke` y el gate humano.
