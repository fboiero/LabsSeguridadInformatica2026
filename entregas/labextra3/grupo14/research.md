# Research — Lab Extra 3: Hardening (defensa en profundidad)

**Grupo:** 14 · **Declaración de uso de IA:** usamos IA para redactar y
contrastar con OWASP (Top 10, cheat sheets de SQLi y de File Path).

## Seguridad por oscuridad vs. defensa en profundidad
Ocultar versiones/rutas (D1, robots de D3) reduce la información gratuita al
atacante pero **no** corrige vulnerabilidades: es una capa, no un control. La
defensa en profundidad combina capas reales (parametrización, control de acceso,
validación de entrada, mínimos privilegios) de modo que la falla de una no
derrumbe todo.

## Lista negra vs. diseño seguro (D4)
Filtrar caracteres (`replace("'","")`) es lista negra: incompleta por definición.
El patrón correcto es **parametrización/prepared statements** (separar código de
datos), equivalente en espíritu a la codificación contextual para XSS. Mismo
principio en D5: en vez de "sacar los `..`", canonicalizar la ruta
(`realpath`) y verificar que caiga **dentro** del directorio permitido.

## Cierre
El hardening efectivo prioriza por impacto (acá: SQLi y traversal primero) y
elige fixes **estructurales** sobre parches cosméticos, manteniendo la
funcionalidad legítima verificada por regresión.
