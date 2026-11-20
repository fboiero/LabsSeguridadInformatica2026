#!/usr/bin/env bash
set -euo pipefail
cd /loot/lab06/validador
for pair in R1:04-backup.txt R2:05-git-config.txt R3:06-options.txt R4:07-api-users.txt R5:15-cms-version.txt; do
  id=${pair%%:*}
  file=${pair#*:}
  flag=$(grep -oE 'FLAG\{[^}]+\}' "/loot/lab06/$file" | head -1)
  ./ctf submit 06 "$id" "$flag" | tee "/loot/lab06/submit-$id.txt"
done
./ctf status 06 | tee /loot/lab06/16-status-final.txt
