#!/usr/bin/env bash
# Downloads Aztec's official Barretenberg static libraries (the ones
# barretenberg-rs links) for the Apple targets, verifies their SHA-256 against
# the digests published with the v6.0.0 release, and unpacks them to
# prover/vendor/bb/<target>/libbb-external.a. Nothing is linked unverified.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=v6.0.0
fetch() { # <rust target> <release asset> <sha256>
  local dir="vendor/bb/$1"
  [[ -f "$dir/libbb-external.a" ]] && return
  mkdir -p "$dir"
  curl -sSfL -o "$dir/bb.tar.gz" "https://github.com/AztecProtocol/aztec-packages/releases/download/$VERSION/$2"
  echo "$3  $dir/bb.tar.gz" | shasum -a 256 -c
  tar -xzf "$dir/bb.tar.gz" -C "$dir"
  rm "$dir/bb.tar.gz"
}
fetch aarch64-apple-darwin  barretenberg-static-arm64-darwin.tar.gz  310b2baaee0f8c8a96725d9cc246ffd41243ed8606965ad0c87f99428288d964
fetch aarch64-apple-ios     barretenberg-static-arm64-ios.tar.gz     c7350fb21963da64d59d1b94835dfcdf71a78ea05752ed56af7004e5fa7f671d
fetch aarch64-apple-ios-sim barretenberg-static-arm64-ios-sim.tar.gz 5ca108540b0cf88731cb6e6c3017eb630efbcfa3091c234971b78f0fb012f494
