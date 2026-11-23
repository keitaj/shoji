# shoji

[![CI](https://github.com/keitaj/shoji/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/keitaj/shoji/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/keitaj/shoji)](go.mod)
[![Noir 1.0.0](https://img.shields.io/badge/Noir-1.0.0-black)](circuits/Nargo.toml)
[![Status: proof of concept](https://img.shields.io/badge/status-proof%20of%20concept-orange)](docs/threat-model.md#out-of-scope-and-known-limitations)

**English** | [日本語](README.ja.md)

> Like a *shoji* screen: it shows the outline of a person, but not who they are.

shoji is an open-source verification layer that uses Japan's My Number Card
(the JPKI signing certificate) as its root of trust. A user proves, in zero
knowledge, that they are **a real person over a given age** and derives a
**per-application anonymous ID (nullifier)**, without the certificate or any
personal data ever leaving their device.

> [!WARNING]
> **Status: proof of concept. Not for production.**
> It has been run end to end with one real card and one iPhone: the card was read
> and signed a challenge, the proof was generated on the phone, and a verifier
> trusting only the real signing CA accepted it. Only the proof and the nullifier
> left the phone. This was done with a development tool, not an app for end
> users. Day-to-day development uses a mock CA. The circuit and its dependencies
> are unaudited, and certificate expiry and revocation are not checked (see
> [open questions](docs/open-questions.md)).

## What it proves

The server learns only a proof and these public values:

| Public inputs (chosen by the server) | Public outputs |
|---|---|
| `ca_pubkey_hash`, `nonce`, `app_id`, `current_date`, `age_threshold` | `nullifier`, `is_over_threshold` |

The circuit ([`circuits/src`](circuits/src)) enforces:

1. **Issued by the CA.** The RSA-2048 / SHA-256 signature over the
   TBSCertificate verifies under the CA key committed to by `ca_pubkey_hash`.
   The server compares that hash with its own trusted list.
2. **Card possession.** The holder's key, taken from the signed certificate,
   signed a message containing the server's `nonce` and `app_id`. A copy of
   someone's certificate is not enough.
3. **Age.** The date of birth in the certificate, `current_date` and
   `age_threshold` determine `is_over_threshold`.
4. **Nullifier.** `nullifier = Poseidon(Poseidon(holder public key), app_id)`:
   the same for one person in one app, unrelated across apps.

The positions of the public key and the date of birth are not supplied by the
prover. The circuit walks the certificate's DER structure from the root, so
bytes that merely look like a date of birth elsewhere in the certificate are
never used.

## How it works

```
holder (device)                               verifier (server)
     │  POST /challenge {app}                       │
     │ ────────────────────────────────────────────▶│ issue and store a nonce
     │  {nonce, app_id, current_date, age_threshold}│ (short-lived, single-use)
     │ ◀────────────────────────────────────────────│
 the card signs "shoji-v1-nonce::" ‖ app_id ‖ nonce
 a proof is generated from the certificate and signature
     │  POST /verify {nonce, ca_pubkey_hash,        │
     │               nullifier, proof}              │
     │ ────────────────────────────────────────────▶│ consume the nonce
     │                                              │ check the CA hash against the trusted list
     │                                              │ rebuild the public inputs, run `bb verify`
     │  {ok, nullifier, new}                        │ record the nullifier, check the ban flag
     │ ◀────────────────────────────────────────────│
```

The server builds every public input except the nullifier from its own state
(`is_over_threshold` is fixed to 1). It stores only outstanding nonces and
per-app nullifiers with a ban flag.

## Quick start

### Requirements (pinned)

| Tool | Version | Notes |
|---|---|---|
| [nargo](https://github.com/noir-lang/noir) (Noir) | 1.0.0 | the bundled `noir-execute` is used too |
| [bb](https://github.com/AztecProtocol/aztec-packages) (Barretenberg) | 6.0.0 | UltraHonk, verifier target `noir-recursive` (zero-knowledge) |
| Go | 1.27.4 | |

Noir libraries are pinned by tag in [`circuits/Nargo.toml`](circuits/Nargo.toml)
(noir_rsa v0.12.1, noir-bignum v0.11.0-1, sha256 v0.3.0, poseidon v0.4.0); Go
modules are pinned in `go.mod` / `go.sum`.

Install the pinned binaries (macOS arm64 shown; for other platforms take the
matching archive from the same release and check it against the SHA-256 digest
on the release page):

```sh
curl -sSLO https://github.com/noir-lang/noir/releases/download/v1.0.0/noir-aarch64-apple-darwin.tar.gz
echo "ac2166fc06fe289fd2524f9eb9da228550159c976e88c1013bfc6d0e0b4a2309  noir-aarch64-apple-darwin.tar.gz" | shasum -a 256 -c
mkdir -p ~/.nargo/bin && tar -xzf noir-aarch64-apple-darwin.tar.gz -C ~/.nargo/bin

curl -sSLO https://github.com/AztecProtocol/aztec-packages/releases/download/v6.0.0/barretenberg-arm64-darwin.tar.gz
echo "48bd18a7d53781a2820e7538dfd89584ca5b4d76c7908e8be4910ce994e7c35e  barretenberg-arm64-darwin.tar.gz" | shasum -a 256 -c
mkdir -p ~/.bb && tar -xzf barretenberg-arm64-darwin.tar.gz -C ~/.bb
```

The Makefile and the Go code look in `~/.nargo/bin` and `~/.bb` when the tools
are not on `PATH`.

The on-device prover and the iOS tool additionally need Xcode and a Rust
toolchain; see [`ios/README.md`](ios/README.md). They are not needed for the
circuit, the verifier or the tests above.

### Build and test

```sh
make circuit   # generate mock fixtures, compile the circuit, write the verification key
make test      # circuit tests (nargo test) and Go tests (which generate and verify real proofs)
make bench     # proving time and memory
```

### Run it locally

```sh
go run ./cmd/verifier -trusted-ca testdata/ca.pem -apps demo &

go run ./cmd/mockclient                                                    # adult  -> accepted
go run ./cmd/mockclient -cert testdata/minor.pem -key testdata/minor.key   # minor  -> rejected
```

`mockclient` plays the holder: a mock key on disk stands in for the card.

### Mock data

The mock CA, the mock certificates in `testdata/` and the derived Noir fixtures
(`circuits/src/fixtures.nr`) are **not in the repository**. `make` generates
them on first use and reuses them afterwards. All of it is synthetic.

The mock CA is for tests only: whoever holds its key can issue a certificate
with any date of birth. Never expose a verifier that trusts `testdata/ca.pem`.

## Performance

About 222k gates and 14.7 KB proofs. Proving takes **~0.8 s** on an Apple M5
laptop (585 MiB peak) and **~1.8 s** on an iPhone 15 Pro (506 MiB peak);
verifying takes ~10 ms. Details: [docs/bench.md](docs/bench.md).

## Repository layout

```
circuits/           Noir circuit and its tests
cmd/mockca/         mock CA (init / issue / hash)
cmd/genfixtures/    generates testdata/ and the circuit test fixtures
cmd/certinspect/    prints a certificate's structure without its contents; checks it against the circuit
cmd/verifier/       verification server (/challenge, /verify, `ban` subcommand)
cmd/mockclient/     stand-in for the holder: signs with a mock key instead of a card
cmd/cardclient/     holder for a real card: gets a challenge, then proves with the card's signature
internal/proto/     values the circuit and Go must agree on (message format, hashes, field encoding)
internal/mockjpki/  mock certificate issuance
internal/witness/   circuit inputs (Prover.toml)
internal/prover/    runs noir-execute and bb prove
internal/verifier/  server and SQLite store
internal/client/    holder side of the protocol
docs/               threat model, open questions, benchmarks
prover/             Rust library that generates proofs in-process, for phones (official Noir and Barretenberg crates only)
ios/                development tool that reads a real card and proves on the device (iPhone)
```

## Documentation

- [Threat model](docs/threat-model.md): what is protected, attacks and the tests covering them, known limitations
- [Open questions](docs/open-questions.md): everything not yet confirmed against a real card, and open design decisions
- [Benchmarks](docs/bench.md)

Japanese versions of the first two are in [`docs/ja/`](docs/ja). The English
documents are authoritative.

## Roadmap

Working today: the circuit, a mock CA, the verification server, negative tests
and PC benchmarks. With one real card, a full proof has been made on an iPhone
(card reading, signing and proving all on the device) and accepted.

Not implemented yet:

- A reader app for end users. `ios/` is a development tool: it has no network
  code, and the proof is relayed to the verifier by a Mac over the cable.
- Computing the CA key hash on the phone (the verifier's list is relayed to it),
  which matters once more than one CA key is trusted.
- Android, and phones with less memory than the one tested.
- Checking certificate expiry.

Revocation checking falls under Japan's accreditation scheme for public personal
authentication and is out of scope for the proof of concept.

## Contributing

Contributions and reviews are welcome, especially of the circuit's constraints.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) first; the most important rule is
that **no real person's certificate or personal data** may appear in code, test
data, logs, issues or commits. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## Disclaimer

shoji is an independent project. It is not affiliated with or endorsed by
J-LIS, the Digital Agency or any other government body.

## License

[Apache License 2.0](LICENSE)
