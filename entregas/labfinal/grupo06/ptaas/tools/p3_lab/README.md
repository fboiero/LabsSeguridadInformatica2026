# Ejecución real de recon P3

La imagen instala herramientas antes de entrar a la red interna, sin modificar el compose de P5. Python 3.12 Alpine resuelve la dependencia musl del binario oficial httpx. Los tres stages se fijan por digest.

Comandos usados (raíz del PTaaS, proyecto Docker propio ptaas-p3):

```sh
docker build -t ptaas-p3-runner:20261113 tools/p3_lab
docker compose -p ptaas-p3 -f lab/docker-compose.yml -f tools/p3_lab/compose.override.yaml up -d
docker network inspect ptaas-p3_lab
docker exec ptaas-p3-runner-1 cat /proc/net/route
```

La red verificada es internal=true, 10.99.0.0/24, sin gateway ni ruta por defecto. No se publican puertos. Los objetivos son DVWA:80 y JuiceShop:3000.

La autorización consumida por el comando contiene actor, reference, quote, expires_at y approved_targets. La ventana máxima aceptada es una hora; la usada fue 30 minutos. El archivo de autorización se suministra al contenedor y no se reutiliza tras vencer.

```sh
docker exec ptaas-p3-runner-1 python -m harness.recon_lab run --approval /tmp/approval.json --output entrega/evidencia/salidas/NUEVA-CORRIDA
docker exec ptaas-p3-runner-1 python -m harness.recon_lab audit verify entrega/evidencia/salidas/NUEVA-CORRIDA/audit.json
```

En la corrida guardada, el archivo de autorización se montó desde una carpeta temporal de esta sesión, en /p3-runtime/approval.json. El directorio de salida debe ser nuevo para no sobrescribir evidencia.

Subfinder excluye todos sus proveedores externos. Su respuesta nativa sin fuentes queda UNAVAILABLE y no se disfraza de éxito: no se descubrieron subdominios pasivamente. El loop registra esa limitación y sondea las semillas autorizadas mediante httpx. Toda acción pasa por Harness.invoke.

El comando audit verify usa el verificador existente de P1 sobre un snapshot de AuditLog con conteo y hash final. Detecta alteración/borrado de la copia; no proporciona anclaje externo ni sustituye la persistencia SQLite del change002.
