# Part 2 attack battery (D4 SQLi, D5 path traversal).
# Usage inside the container:  sh /s/ataques-parte2.sh <server.py> <out-prefix>
# (executed with sh, not sourced: POSIX "." does not pass arguments)
# Runs the SAME battery against whichever server is given, so "before" and
# "after" outputs are directly comparable line by line.
SRV=$1; OUT=$2
[ -n "$SRV" ] && [ -n "$OUT" ] || { echo "usage: sh ataques-parte2.sh <server.py> <out-prefix>" >&2; exit 2; }
. /s/run.sh
P=8090; PORT=$P python3 "$SRV" >/dev/null 2>&1 & PID=$!
n=0; until curl -s -o /dev/null http://127.0.0.1:$P/; do
  n=$((n+1)); [ $n -lt 50 ] || { echo "server did not start: $SRV" >&2; exit 1; }; sleep 0.2
done
U=http://127.0.0.1:$P

# Fixtures for two extra D5 variants (created after startup, outside the web root):
#  - a sibling directory whose name starts with the web root's name
#    (defeats a naive startswith(DESCARGAS) check)
#  - a symlink planted inside the web root pointing outside of it
mkdir -p /tmp/phantom_descargas_secreto
echo "clave-interna-no-publica" > /tmp/phantom_descargas_secreto/clave.txt
ln -sf /etc/passwd /tmp/phantom_descargas/enlace.txt

login() { echo "## user=[$1] pass=[$2]"; curl -sSi --get --data-urlencode "user=$1" --data-urlencode "pass=$2" "$U/login" 2>&1; echo; echo; }
descargar() { echo "## archivo=$1"; curl -sSi --path-as-is "$U/descargar?archivo=$1" 2>&1 | head -12; echo; echo; }

{
  login "admin'--" "x"                                  # verifier variant 1: comment out the password check
  login "x" "' OR 1=1 --"                               # verifier variant 2: tautology
  login "' OR '1'='1" "' OR '1'='1"                     # tautology without comments
  login "' UNION SELECT 'inyectado' --" "x"             # UNION: attacker controls the returned row
  login "'" "x"                                         # lone quote: breaks the SQL syntax
  login "O'Brien" "x"                                   # legitimate input with a quote (must not crash)
} > "$S/${OUT}-D4.txt"

{
  echo "## server process runs as: $(id -un) (uid $(id -u))"; echo
  descargar "../../../../etc/passwd"                                   # verifier variant
  descargar "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"         # URL-encoded dots and slashes
  descargar "..%2f..%2f..%2f..%2fetc%2fpasswd"                         # only the slash encoded
  descargar "%252e%252e%252f%252e%252e%252fetc%252fpasswd"             # double encoding
  descargar "....//....//....//....//etc/passwd"                       # defeats a single replace('../','')
  descargar "/etc/passwd"                                              # absolute path
  descargar "../../../../etc/passwd%00.txt"                            # null byte
  descargar "../phantom_descargas_secreto/clave.txt"                   # sibling dir sharing the prefix
  descargar "enlace.txt"                                               # symlink inside the web root
  descargar "../phantom_hardening.db"                                  # D2->D5 chain: DB path leaked by /api/status
  descargar "../../../../etc/shadow"                                   # readable only if the process runs as root
  descargar "manual.txt"                                               # legitimate download (must keep working)
} > "$S/${OUT}-D5.txt"

kill $PID
