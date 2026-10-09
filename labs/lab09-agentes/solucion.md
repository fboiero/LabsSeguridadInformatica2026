# Solución — Laboratorio 09 (SOLO DOCENTE)

> No compartir con alumnos.

## Correr
```bash
make lab N=09
export LLM_PROVIDER=mock          # o claude/openai con su key
make shell
cd /repo/labs/lab09-agentes/src && python3 agente_pentest.py
```
Con `mock` el agente encuentra las 5 flags sin gastar API. Con claude/openai, el
LLM real las encuentra razonando (puede variar el orden/los pasos).

## Flags

| Reto | Flag | De dónde sale |
|---|---|---|
| R1 | `FLAG{agente_primer_recon}` | header `X-Recon-Flag` en `GET /` |
| R2 | `FLAG{agente_ruta_oculta}` | `GET /vault-interno-x7` (vía robots.txt) |
| R3 | `FLAG{agente_api_expuesta}` | `GET /api/debug` |
| R4 | `FLAG{guardrail_fuera_de_alcance}` | el guardrail bloquea `8.8.8.8` en `herramientas.py` |
| R5 | `FLAG{agente_esqueleto_completo}` | `GET /api/token` → `POST /api/vault` (encadenado) |

## Solución del esqueleto (los 3 TODO)
```python
if accion["tipo"] == "final":
    print(f"\n[agente] Fin: {accion['texto']}"); break
salida = ejecutar_tool(accion["nombre"], accion["argumentos"])
print("\n".join("    " + l for l in salida.splitlines()[:12]))
# ...
resultados = [{"id": accion["id"], "output": salida}]
```

## Notas de corrección
- El guardrail (R4) es lo más importante conceptualmente: verificar que lo
  entienden, no solo que lo corrieron.
- Con proveedor real, el LLM podría NO probar 8.8.8.8 solo. Para R4 el alumno
  puede forzar el caso llamando la tool con un host fuera de alcance, o el docente
  acepta la demostración con mock.
- Verificar que NO haya ninguna API key en el repo del grupo (revisar el history).
