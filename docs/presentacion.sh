#!/usr/bin/env bash
# presentacion.sh — CyberLab UTN, presentación de terminal (bien hacker).
# Uso:  ./docs/presentacion.sh          navegación interactiva (← → · q sale)
#       ./docs/presentacion.sh --all    imprime todas las slides de corrido
#       NO_COLOR=1 ./docs/presentacion.sh   sin colores
set -uo pipefail

# ── colores ──────────────────────────────────────────────────────────────
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  R=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'
  G=$'\033[38;5;48m'; C=$'\033[38;5;45m'; A=$'\033[38;5;214m'
  V=$'\033[38;5;141m'; RED=$'\033[38;5;203m'; W=$'\033[38;5;252m'; GR=$'\033[38;5;240m'
else R= B= D= G= C= A= V= RED= W= GR=; fi

FIG="$(command -v figlet || true)"          # usa figlet si está; si no, fallback
banner(){ if [ -n "$FIG" ]; then printf '%s' "$G$B"; figlet -w 100 -f standard "$1" 2>/dev/null || figlet -w 100 "$1"; printf '%s' "$R";
  else printf '%s\n' "$G$B  ═══  $1  ═══$R"; fi; }
rule(){ printf '%s' "$GR"; printf '─%.0s' $(seq 1 "${1:-72}"); printf '%s\n' "$R"; }
kick(){ printf '\n%s// %s%s\n\n' "$G$B" "$1" "$R"; }
type_out(){ local s="$1"; local i; for ((i=0;i<${#s};i++)); do printf '%s' "${s:$i:1}"; sleep 0.006; done; printf '\n'; }

TOTAL=14

# ── slides ───────────────────────────────────────────────────────────────
s01(){ cat <<EOF

$G$B   ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██╗      █████╗ ██████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██║     ██╔══██╗██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██║     ███████║██████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██║     ██╔══██║██╔══██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ███████╗██║  ██║██████╔╝
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═════╝$R

$W   Práctico de Seguridad Informática — de la tríada CIA a los agentes
   autónomos y de vuelta a la defensa. Diez labs + un engagement final.$R

$GR   UTN · FRVM  /  Seguridad Informática  /  2026  /  $G Ing. Fernando Boiero$R
EOF
}
s02(){ kick "Qué es"; banner "Se aprende haciendo"
cat <<EOF
$W   No se aprende leyendo. Se opera con herramientas reales contra objetivos
   deliberadamente vulnerables que se levantan solos en Docker.$R

   $G▸$R $B Hands-on$R      todo con código, tool por tool, clasificando cada escenario
   $C▸$R $B Autodescubrible$R  un comando ./ctf y el entorno arranca; cero instalar
   $A▸$R $B Progresivo$R    de la tríada CIA a agentes de IA y defensa
EOF
}
s03(){ kick "Filosofía · 4 reglas"; banner "Sin atajos"
cat <<EOF
   $G[01]$R $B Conceptos antes que código$R   primero el porqué, después la tool
   $G[02]$R $B A mano antes que automático$R  los agentes recién al final
   $G[03]$R $B La IA es una herramienta$R     el humano dirige, la máquina ejecuta
   $G[04]$R $B Sin atajos$R                   nadie se hace pentester en dos horas
EOF
}
s04(){ kick "El programa · 10 labs + final"
cat <<EOF
   $G$B FUNDAMENTOS · CÓDIGO (Python)$R          $C$B OFENSIVA · Docker$R
   ┌───────────────────────────────┐    ┌───────────────────────────────┐
   │ 01  Introducción (CIA, hash)  │    │ 05  Reconocimiento            │
   │ 02  Criptografía              │    │ 06  Enumeración               │
   │ 03  Autenticación (2FA)       │    │ 07  Explotación               │
   │ 04  Marcos normativos         │    │ 08  Post-explotación          │
   │                               │    │ 09  Agentes de IA             │
   │                               │    │ 10  Detección y evasión       │
   └───────────────────────────────┘    └───────────────────────────────┘

   $A★$R  …y todo desemboca en el $A$B Práctico Final$R: engagement + informe de pentest.
EOF
}
s05(){ kick "Unidades 05–10 · la cadena"; banner "El engagement"
cat <<EOF
   $G[05]$R──▶$G[06]$R──▶$G[07]$R──▶$G[08]$R──▶$V[09]$R──▶$A[10]$R══▶ $A$B★ FINAL$R
   recon   enum  exploit  post  agentes defensa      informe

   $D Un hilo narrativo —la auditoría de PhantomCorp— atraviesa las seis unidades.$R
   $D Manual (05–08) · Agentes (09) · Defensa (10). Cada lab avanza el ataque.$R
EOF
}
s06(){ kick "Cómo se juega"; cat <<EOF
   $GR┌─ operador@cyberlab ──────────────────────────────┐$R
   $GR│$R $G\$ ./ctf lab 05$R                                    $GR│$R
   $GR│$R $D  >> entorno arriba. entrá: make shell$R           $GR│$R
   $GR│$R $G\$ make shell$R                                      $GR│$R
   $GR│$R $W attacker:~\$ nmap -Pn phantomcorp$R                 $GR│$R
   $GR│$R $D  21/tcp open ftp  ProFTPD 1.3.5$R                  $GR│$R
   $GR│$R $D  80/tcp open http PhantomServer$R                  $GR│$R
   $GR│$R $G\$ ./ctf submit 05 R1 'FLAG{...}'$R                  $GR│$R
   $GR│$R $A  ★ FLAG CAPTURADA · +1 al score$R                  $GR│$R
   $GR└──────────────────────────────────────────────────┘$R

   $W Las flags te enganchan. $G$B El informe es lo que evalúa la rúbrica.$R
EOF
}
s07(){ kick "05–08 · a mano, siempre primero"; cat <<EOF
   $G 05 Reconocimiento$R   nmap, banners, headers, robots — mapear y clasificar
   $G 06 Enumeración$R      dirb, whatweb, .git expuesto, métodos HTTP, APIs
   $G 07 Explotación$R      SQLi real (sqlite+sqlmap), cmdi, path traversal, IDOR
   $G 08 Post-explotación$R escalada por SUID, pivoting, automatización

   $D Cuatro fases, tool por tool, entendiendo cada salida. Recién después, la IA.$R
EOF
}
s08(){ kick "Pivoting · redes segmentadas (lab 08)"; cat <<EOF
   $D labnet ...............................  internalnet ............$R
   ┌────────────┐   HTTP    ┌────────────┐   pivot   ┌────────────┐
   │ $W ATACANTE$R   │─────────▶│ $G VÍCTIMA$R    │─────────▶│ $W DB INTERNA$R │
   │ $D tu consola$R │          │ $D 2 redes$R    │          │ $D crown$R      │
   └─────┬──────┘           └────────────┘           └──────▲─────┘
         $RED╎$R                                                  $RED│$R
         $RED└╌╌╌╌╌╌╌╌  ✗ sin ruta directa — segmentado  ╌╌╌╌╌╌┘$R

   $D El atacante no llega a la DB. La víctima vive en las dos redes: es el trampolín.$R
EOF
}
s09(){ kick "Unidad 09 · Agentes de pentest"; cat <<EOF
   ┌───────────┐ propone ┌────────────┐  ok  ┌───────────┐
   │ $W LLM razona$R│────────▶│ $V GUARDRAIL$R  │─────▶│ $W TOOL$R      │
   │ $D ¿qué tool?$R│         │ $D ¿alcance?$R  │      │ $D nmap/curl$R │
   └─────▲─────┘         └──────┬─────┘      └─────┬─────┘
         $G│$R  resultado ↺       $A│$R ✗ fuera         $G│$R
         $G└────────────────────┼──────────────────┘$R
                          $A▼$R
                    $A[ ✗ BLOQUEA ]$R

   $D El LLM razona; tu código pone las manos (tools) y los límites (guardrails).$R
   $D Agnóstico: Claude · OpenAI · mock offline (corre sin API key).$R
EOF
}
s10(){ kick "Unidad 10 · Detección y evasión"; cat <<EOF
   ?q=UNION SELECT      ──▶ ┌───────────┐ ──match──▶  $RED🚫 ALERTA$R
                           │ $C IDS·firma$R │
   ?q=UNION/**/SELECT   ──▶ │ $D \\s+select$R │ ─no match▶ $A✓ evadido$R
                           └───────────┘

   $W Del otro lado siempre hubo alguien mirando. Blue vs Red.$R
   $D Mismo ataque: el espacio dispara la firma; un comentario /**/ la esquiva.$R
   $D Ninguna firma es perfecta — lo que ella no ve, lo caza el analista de logs.$R
EOF
}
s11(){ kick "★ Práctico Final · el engagement completo"; cat <<EOF
   $G[RECON]$R─▶$G[FOOTHOLD]$R─▶$G[LOOT]$R─▶$G[RCE]$R─▶ $A$B[CROWN JEWELS]$R
    05·06     SQLi 07    token 08  cmd inj    datos de clientes

   $W Un solo objetivo que exige encadenar TODO el curso. Caja negra, 4 hitos.$R
   $A El entregable estrella:$R informe de pentest profesional
   $D (resumen ejecutivo + hallazgos con CVSS, evidencia y remediación).$R
EOF
}
s12(){ kick "El hilo narrativo · PhantomCorp S.A."; cat <<EOF
   $GR engagement.log$R
   $D [05]$R perímetro mapeado ....... $G 4 servicios$R
   $D [06]$R intranet enumerada ...... $G .git expuesto$R
   $D [07]$R portal comprometido ..... $G RCE + SQLi$R
   $D [08]$R root + red interna ...... $G pivot ok$R
   $D [09]$R auditoría autónoma ...... $G agente$R
   $D [10]$R visto por el SOC ........ $G firma evadida$R
   $D [★ ]$R engagement final ........ $A informe entregado$R
EOF
}
s13(){ kick "Cómo se entrega y se corrige"; cat <<EOF
   $G FLUJO$R                              $A EVALUACIÓN$R
   ▸ fork + Pull Request (flujo real)   ▸ rúbrica de 100 pts
   ▸ grupos 4–5 en entregas/labNN/      ▸ flags: pudiste · informe: entendiste
   ▸ los commits de todos cuentan       ▸ uso de IA declarado (obligatorio)

   $A ⚠ Uso responsable.$R $D Solo contra los contenedores de la cátedra. Ley 26.388.$R
EOF
}
s14(){ cat <<EOF

$G$B   ███████╗██╗███╗   ██╗
   ██╔════╝██║████╗  ██║
   █████╗  ██║██╔██╗ ██║
   ██╔══╝  ██║██║╚██╗██║
   ██║     ██║██║ ╚████║
   ╚═╝     ╚═╝╚═╝  ╚═══╝$R

$W   El humano $G$B dirige$R$W. La máquina ejecuta.$R
$D   La diferencia entre un pentester y un delincuente es la autorización,
   el alcance y la ética. Nunca lo olvides.$R

$G   git clone$R  $D·  hacé el fork  ·  ponete las pilas$R
EOF
}

render(){ "s$(printf '%02d' "$1")"; }

# ── modo --all (no interactivo) ──────────────────────────────────────────
if [ "${1:-}" = "--all" ]; then
  for i in $(seq 1 $TOTAL); do render "$i"; echo; rule; done; exit 0
fi

# ── navegación interactiva ───────────────────────────────────────────────
i=1
draw(){ clear 2>/dev/null || printf '\033[2J\033[H'; render "$i"
  echo; rule
  printf '%s  [%02d/%02d]  %s← →/espacio$R%s avanzar · %sp$R atrás · %sg$R ir · %sq$R salir%s\n' \
    "$GR" "$i" "$TOTAL" "$G" "$GR" "$G" "$G" "$RED" "$GR" "$R"; }
draw
while true; do
  IFS= read -rsn1 key
  case "$key" in
    ''|' '|'n'|'j') ((i<TOTAL)) && ((i++)); draw ;;
    $'\033') read -rsn2 -t 0.05 rest || rest=""    # flechas
      case "$rest" in '[C'|'[B') ((i<TOTAL)) && ((i++));; '[D'|'[A') ((i>1)) && ((i--));; esac; draw ;;
    'p'|'b'|'k') ((i>1)) && ((i--)); draw ;;
    'g') printf '\nir a slide #: '; read -r n; [[ "$n" =~ ^[0-9]+$ ]] && ((n>=1&&n<=TOTAL)) && i=$n; draw ;;
    'q'|'Q') clear 2>/dev/null; printf '%s  root@cyberlab:~# %s./fin.sh — hasta la próxima, loco.%s\n\n' "$G" "$D" "$R"; break ;;
  esac
done
