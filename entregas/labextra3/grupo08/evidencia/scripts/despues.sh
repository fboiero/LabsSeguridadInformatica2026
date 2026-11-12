. /s/run.sh
P=8081; PORT=$P python3 $G/objetivo/server.py >/dev/null 2>&1 & PID=$!
until curl -s -o /dev/null http://127.0.0.1:$P/; do sleep 0.2; done
U=http://127.0.0.1:$P
{ curl -si $U/; echo; echo ----; curl -si $U/no-existe; echo; echo ----; curl -sI $U/ | head -3; } > $S/11-D1-despues.txt
{ curl -si $U/api/status; echo; echo ----; curl -si $U/ruta-que-nunca-existio; } > $S/12-D2-despues.txt
{ curl -si $U/robots.txt; echo; echo ----; curl -si $U/backup; } > $S/13-D3-despues-sin-credenciales.txt
kill $PID
P=8082; PHANTOM_BACKUP_USER=ops PHANTOM_BACKUP_PASS=prueba-local-123 PORT=$P python3 $G/objetivo/server.py >/dev/null 2>&1 & PID=$!
until curl -s -o /dev/null http://127.0.0.1:$P/; do sleep 0.2; done
U=http://127.0.0.1:$P
{ echo "## sin Authorization"; curl -si $U/backup; echo; echo "## password incorrecta"; curl -si -u ops:adivinando $U/backup; echo; echo "## header malformado"; curl -si -H "Authorization: Basic %%%" $U/backup; echo; echo "## credenciales de operador correctas"; curl -si -u ops:prueba-local-123 $U/backup; } > $S/14-D3-despues-con-auth.txt
{ echo "## GET /"; curl -si $U/; echo; echo "## login legitimo"; curl -si "$U/login?user=admin&pass=sup3r-s3cr3t0"; echo; echo "## login incorrecto"; curl -si "$U/login?user=admin&pass=mala"; echo; echo "## descarga legitima"; curl -si "$U/descargar?archivo=manual.txt"; } > $S/15-regresion-parte1.txt
kill $PID
