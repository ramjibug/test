#!/usr/bin/env bash
# Runs the PoC for every API mode x payload length 0..12, plus valid-address controls and the
# fuzz-artifact replay. Every run is its own process, so an abort does not stop the matrix.
#
# Usage: ./run_matrix.sh [path/to/poc]        (default: ../poc; SKIP_BUILD=1 skips `cargo build --release`)
# Output: ../logs/05-matrix.log        raw stderr + exit status for every run
#         ../logs/05-matrix-table.md   markdown summary (also printed)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
POC="${1:-$HERE/../poc}"
LOGDIR="$HERE/../logs"
ARTIFACT="$HERE/../fuzzing/crash-0b94ee470ea1beccfb38b3709e5550b664db9c1e"
VALID='qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'

mkdir -p "$LOGDIR"
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  ( cd "$POC" && cargo build --release ) || { echo "build failed" >&2; exit 1; }
fi
BIN="$POC/target/release/bch_repro"
[ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }

ulimit -c 0   # no core dumps
RAW="$LOGDIR/05-matrix.log"
TABLE="$LOGDIR/05-matrix-table.md"
: > "$RAW"
printf '%s\n' '| mode | input | payload symbols | exit | result |' '|---|---|---|---|---|' > "$TABLE"

# run <mode> <input> <label> [display]
run() {
  local mode="$1" input="$2" label="$3" disp="${4-$2}" rc res
  [ -z "$disp" ] && disp='(empty)'
  { echo "=== mode=$mode input=[$input] ==="; } >> "$RAW"
  "$BIN" "$mode" "$input" 2>> "$RAW" >/dev/null
  rc=$?
  { echo "EXIT=$rc"; echo; } >> "$RAW"
  case "$rc" in
    0)   res="returned normally" ;;
    134) res="**abort (SIGABRT)**" ;;
    101) res="panic (unwound)" ;;
    *)   res="other" ;;
  esac
  printf '| %s | `%s` | %s | %s | %s |\n' "$mode" "$disp" "$label" "$rc" "$res" >> "$TABLE"
}

for mode in parser is_valid with_string with_string_unchecked; do
  for n in $(seq 0 12); do
    run "$mode" "$(head -c "$n" /dev/zero | tr '\0' 'q')" "$n"
  done
  run "$mode" "$VALID" "valid control"
  run "$mode" "bitcoincash:$VALID" "valid control (prefixed)"
done
run replay "$ARTIFACT" "fuzz artifact" "crash-0b94ee47..."

cat "$TABLE"
