#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
PY="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"

function ensure_venv_and_deps() {
  if [ ! -d "$VENV_DIR" ]; then
    echo "Création d'un virtualenv dans $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
  fi
  source "$VENV_DIR/bin/activate"
  echo "Installation des dépendances..."
  "$PIP" install --upgrade pip >/dev/null
  "$PIP" install cryptography pycryptodome >/dev/null
}

function usage() {
  cat <<EOF
Usage: $0 <command> [options]

Commands:
  setup
      Crée le venv et installe les dépendances.

  generate-shares [--k K] [--n N] [--out OUT]

  encrypt --path PATH --shares S1 S2 ... [--algo ALGO] [--pubkey PUBKEY] [--no-delete]

  encrypt --path PATH --shares-file FILE [--algo ALGO] [--pubkey PUBKEY] [--no-delete]

  decrypt --path PATH --shares S1 S2 ... [--algo ALGO] [--privkey PRIVKEY]

  decrypt --path PATH --shares-file FILE [--algo ALGO] [--privkey PRIVKEY] [--privkey-password PW]

Examples:
  $0 setup
  $0 generate-shares --k 4 --n 6 --out shares.json
  $0 encrypt --path ./secrets --shares-file shares.json --algo xchacha20-poly1305
  $0 decrypt --path ./secrets --shares-file shares.json

EOF
  exit 1
}

if [ $# -lt 1 ]; then usage; fi

cmd="$1"; shift

case "$cmd" in
  setup)
    ensure_venv_and_deps
    echo "Environnement prêt."
    exit 0
    ;;

  generate-shares)
    ensure_venv_and_deps
    K=4; N=6; OUT=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --k) K="$2"; shift 2;;
        --n) N="$2"; shift 2;;
        --out) OUT="$2"; shift 2;;
        *) echo "Option inconnue: $1"; usage;;
      esac
    done
    if [ -n "$OUT" ]; then
      "$PY" "$SCRIPT_DIR/quadlock_encrypt.py" generate-shares --k "$K" --n "$N" --out "$OUT"
    else
      "$PY" "$SCRIPT_DIR/quadlock_encrypt.py" generate-shares --k "$K" --n "$N"
    fi
    ;;

  encrypt|decrypt)
    ensure_venv_and_deps
    MODE="$cmd"
    TARGET_PATH=""
    SHARES_FILE=""
    SHARES_ARRAY=()
    ALGO="aes-gcm"
    PUBKEY=""
    PRIVKEY=""
    PRIVKEY_PASSWORD=""
    NODELETE=""

    while [ $# -gt 0 ]; do
      case "$1" in
        --path) TARGET_PATH="$2"; shift 2;;
        --shares-file) SHARES_FILE="$2"; shift 2;;
        --shares)
          shift
          while [ $# -gt 0 ]; do
            SHARES_ARRAY+=("$1"); shift
          done
          ;;
        --algo) ALGO="$2"; shift 2;;
        --pubkey) PUBKEY="$2"; shift 2;;
        --privkey) PRIVKEY="$2"; shift 2;;
        --privkey-password) PRIVKEY_PASSWORD="$2"; shift 2;;
        --no-delete) NODELETE=1; shift;;
        *) echo "Option inconnue: $1"; usage;;
      esac
    done

    if [ -z "$TARGET_PATH" ]; then echo "--path requis"; exit 1; fi

    if [ -n "$SHARES_FILE" ]; then
      if [ ! -f "$SHARES_FILE" ]; then echo "Fichier de parts introuvable: $SHARES_FILE"; exit 1; fi
      mapfile -t SHARES_ARRAY < <(
        "$PY" - "$SHARES_FILE" <<'PY'
import sys, json
p=sys.argv[1]
try:
    obj=json.load(open(p))
    if isinstance(obj, dict) and 'shares' in obj:
        for s in obj['shares']:
            print(s)
    else:
        for line in open(p):
            line=line.strip()
            if line:
                print(line)
except Exception as e:
    for line in open(p):
        line=line.strip()
        if line:
            print(line)
PY
      )
    fi

    if [ ${#SHARES_ARRAY[@]} -eq 0 ]; then echo "Aucune part fournie"; exit 1; fi

    CMD=( "$PY" "$SCRIPT_DIR/quadlock_encrypt.py" "$MODE" --path "$TARGET_PATH" --shares )
    for s in "${SHARES_ARRAY[@]}"; do CMD+=("$s"); done
    CMD+=( --algo "$ALGO" )
    if [ -n "$PUBKEY" ]; then CMD+=( --pubkey "$PUBKEY" ); fi
    if [ -n "$PRIVKEY" ]; then CMD+=( --privkey "$PRIVKEY" ); fi
    if [ -n "$PRIVKEY_PASSWORD" ]; then CMD+=( --privkey-password "$PRIVKEY_PASSWORD" ); fi
    if [ -n "$NODELETE" ]; then CMD+=( --no-delete ); fi

    "${CMD[@]}"
    ;;

  *) echo "Commande inconnue: $cmd"; usage;;
esac
