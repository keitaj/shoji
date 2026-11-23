#!/usr/bin/env bash
# Builds the prover library for iPhone, the iOS simulator and macOS and packs
# the three into ios/ShojiProverKit/ShojiProverFFI.xcframework.
#
# Requires Xcode and a Rust toolchain with the aarch64-apple-ios and
# aarch64-apple-ios-sim targets.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/fetch-bb.sh

export IPHONEOS_DEPLOYMENT_TARGET=16.0
export MACOSX_DEPLOYMENT_TARGET=13.0
libs=()
for target in aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin; do
  BB_LIB_DIR="$PWD/vendor/bb/$target" cargo build --release --lib --target "$target"
  libs+=(-library "target/$target/release/libshoji_prover.a" -headers include)
done

out=../ios/ShojiProverKit/ShojiProverFFI.xcframework
rm -rf "$out"
xcodebuild -create-xcframework "${libs[@]}" -output "$out"
