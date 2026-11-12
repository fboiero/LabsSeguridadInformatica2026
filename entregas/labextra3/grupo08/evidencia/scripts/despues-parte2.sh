# Part 2 "after": functional regression on the fully patched copy + final verifier.
# Usage inside the container:  sh /s/despues-parte2.sh
. /s/run.sh
P=8091; PORT=$P python3 $G/objetivo/server.py >/dev/null 2>&1 & PID=$!
n=0; until curl -s -o /dev/null http://127.0.0.1:$P/; do
  n=$((n+1)); [ $n -lt 50 ] || { echo "server did not start" >&2; exit 1; }; sleep 0.2
done
U=http://127.0.0.1:$P
{
  echo "## GET /";                 curl -sSi $U/; echo
  echo "## login legitimo";        curl -sSi "$U/login?user=admin&pass=sup3r-s3cr3t0"; echo
  echo "## login incorrecto";      curl -sSi "$U/login?user=admin&pass=mala"; echo
  echo "## descarga legitima";     curl -sSi "$U/descargar?archivo=manual.txt"; echo
  echo "## descarga inexistente";  curl -sSi "$U/descargar?archivo=no-existe.txt"; echo
  echo "## ruta inexistente";      curl -sSi $U/no-existe; echo
} > $S/42-regresion-final.txt
kill $PID
python3 labs/labextra3-hardening/verificar-defensa.py --dir $G/objetivo > $S/50-verificador-final.txt 2>&1
python3 /s/p4_replace_demo.py > $S/43-P4-replace-vs-parametrizada.txt 2>&1
