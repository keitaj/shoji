# shoji-prover

Generates shoji proofs in-process, so that a phone can prove without handing the
certificate to another machine. It does what `noir-execute` followed by
`bb prove -t noir-recursive` does on a PC, and its proofs verify with the same
`bb verify` and verification key.

- Witness generation: the Noir crates (`acvm`, `nargo`, `noirc_abi`) at v1.0.0.
- Proving: `barretenberg-rs` 6.0.0, Aztec's official bindings, linked against
  Aztec's official static library. `scripts/fetch-bb.sh` downloads that library
  and checks it against the SHA-256 digests published with the release.
- Zero-knowledge is always on, and nothing here uses the network or the file
  system: the circuit, inputs, reference string and verification key are passed in.

No other proving wrapper or prebuilt binary is used.

## Entry points

- `prove(circuit, inputs, srs, vk)`: inputs given as JSON keyed by parameter name.
- `prove_card(circuit, certificate, ca_certificate, signature, request, srs, vk)`:
  assembles the inputs from what a phone holds after talking to the card
  (`src/inputs.rs`, kept in step with `internal/witness` on the Go side).
- The same two through C (`include/shoji_prover.h`), used by `ios/ShojiProverKit`.

Error messages never contain input values.

## Build and test

Requires a Rust toolchain (and Xcode with the `aarch64-apple-ios` and
`aarch64-apple-ios-sim` Rust targets for the Apple build).

```sh
./scripts/fetch-bb.sh
export BB_LIB_DIR=$PWD/vendor/bb/aarch64-apple-darwin

# Unit tests; with the fixture they also compare the inputs with the Go implementation.
(cd .. && go run ./cmd/genfixtures -card-fixture /tmp/shoji-card-fixture)
SHOJI_CARD_FIXTURE=/tmp/shoji-card-fixture cargo test --release --lib

# Prove on this machine and check with bb (after `make circuit` in the repository root).
cargo build --release
(cd .. && go run ./cmd/genfixtures -inputs-json /tmp/shoji-inputs.json)
target/release/shoji-prove ../circuits/target/shoji.json /tmp/shoji-inputs.json \
    ~/.bb-crs/bn254_g1.dat ../circuits/target/vk/vk /tmp/shoji-out
bb verify -k ../circuits/target/vk/vk -p /tmp/shoji-out/proof -i /tmp/shoji-out/public_inputs -t noir-recursive

# iPhone, simulator and macOS libraries packed as an xcframework for ios/ShojiProverKit.
./scripts/build-apple.sh
```
