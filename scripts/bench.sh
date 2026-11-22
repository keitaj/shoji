#!/usr/bin/env bash
# Measures wall time and peak memory of witness generation, proving and
# verification for the adult mock fixture. Run via `make bench`.
# Uses BSD time (-l) on macOS and GNU time (-v) on Linux.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:$HOME/.nargo/bin:$HOME/.bb"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go run ./cmd/genfixtures -out "$work/fixtures.nr" -prover-toml "$work/Prover.toml" 2>/dev/null

art=circuits/target/shoji.json
vk=circuits/target/vk/vk
t=noir-recursive

measure() { # label, command...
  local label=$1; shift
  local log="$work/time.log"
  if [[ "$(uname)" == "Darwin" ]]; then
    /usr/bin/time -l "$@" >/dev/null 2>"$log"
    local secs=$(awk '/ real /{print $1}' "$log")
    local mem=$(awk '/maximum resident set size/{printf "%.0f", $1/1048576}' "$log")
  else
    /usr/bin/time -v "$@" >/dev/null 2>"$log"
    local secs=$(awk -F': ' '/Elapsed/{print $2}' "$log")
    local mem=$(awk -F': ' '/Maximum resident set size/{printf "%.0f", $2/1024}' "$log")
  fi
  printf '| %s | %s | %s |\n' "$label" "$secs" "$mem"
}

echo "nargo $(nargo --version | head -1 | awk '{print $4}'), bb $(bb --version)"
bb gates -b "$art" -t "$t" 2>/dev/null | grep -E 'acir_opcodes|circuit_size'
echo
echo '| step | wall time (s) | peak RSS (MiB) |'
echo '|---|---|---|'
measure 'witness (noir-execute)' noir-execute execute --artifact-path "$art" --prover-file "$work/Prover.toml" --output-dir "$work" --witness-name witness
for i in 1 2 3; do
  measure "prove (bb prove) #$i" bb prove -b "$art" -w "$work/witness.gz" -k "$vk" -o "$work/out" -t "$t"
done
measure 'verify (bb verify)' bb verify -k "$vk" -p "$work/out/proof" -i "$work/out/public_inputs" -t "$t"
echo
echo "proof size: $(wc -c < "$work/out/proof" | tr -d ' ') bytes"
