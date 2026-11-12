# copia a FS nativo del contenedor (el bind mount de Windows hace lento el arranque)
mkdir -p /w/labs /w/entregas/labextra3 && cp -r /lab/labs/labextra3-hardening /w/labs/ && cp -r /lab/entregas/labextra3/grupo08 /w/entregas/labextra3/ && cd /w
G=entregas/labextra3/grupo08; S=/lab/$G/evidencia/salidas
levantar() { PORT=8080 python3 "$1" >/dev/null 2>&1 & until curl -s -o /dev/null http://127.0.0.1:8080/; do sleep 0.2; done; }
