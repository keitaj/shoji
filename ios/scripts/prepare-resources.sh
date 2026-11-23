#!/usr/bin/env bash
# Collects what the app needs to prove on the device into App/ProverResources/
# (ignored by git): the compiled circuit, its verification key, the structured
# reference string, and mock inputs for the on-device benchmark.
#
# Run `make circuit` first. The reference string is the file bb downloaded from
# Aztec's CRS server on its first run (~/.bb-crs/bn254_g1.dat).
set -euo pipefail
cd "$(dirname "$0")/../.."
out=ios/App/ProverResources
srs="$HOME/.bb-crs/bn254_g1.dat"
[[ -f circuits/target/shoji.json && -f circuits/target/vk/vk ]] || { echo "run 'make circuit' first" >&2; exit 1; }
[[ -f "$srs" ]] || { echo "$srs not found: run 'make circuit' (bb downloads it)" >&2; exit 1; }
mkdir -p "$out"
cp circuits/target/shoji.json "$out/shoji.json"
cp circuits/target/vk/vk "$out/vk"
cp "$srs" "$out/g1.dat"
go run ./cmd/genfixtures -inputs-json "$out/bench_inputs.json" 2>/dev/null
ls -l "$out" | awk 'NR>1{print $5, $9}'
