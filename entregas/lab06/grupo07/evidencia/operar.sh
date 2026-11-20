#!/usr/bin/env bash
set -euo pipefail
mkdir -p /loot/lab06
date -Is | tee /loot/lab06/01-fecha-contenedor.txt
ping -c1 phantomcorp | tee /loot/lab06/02-conectividad.txt
dirb http://phantomcorp/ /usr/share/dirb/wordlists/common.txt -r -S -o /loot/lab06/03-dirb.txt
curl -sS -i http://phantomcorp/backup/ | tee /loot/lab06/04-backup.txt
curl -sS -i http://phantomcorp/.git/config | tee /loot/lab06/05-git-config.txt
curl -sS -X OPTIONS -i http://phantomcorp/ | tee /loot/lab06/06-options.txt
curl -sS -i http://phantomcorp/api/users | tee /loot/lab06/07-api-users.txt
whatweb --color=never http://phantomcorp | tee /loot/lab06/08-whatweb.txt
curl -sS -i http://phantomcorp/ | tee /loot/lab06/09-index.txt
