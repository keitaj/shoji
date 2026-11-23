# shoji

A verification layer that, like a shoji screen, "shows the outline of a person, but not who they are".

shoji is an open-source verification layer that uses Japan's My Number Card (the JPKI signing
certificate) as its root of trust and proves in zero knowledge, without handing raw data to a server,
that the user is "a real person aged 18 or over", together with a "per-application anonymous ID (nullifier)".

## Goals and principles

- Raw personal data (name, address, date of birth, the certificate itself) never leaves the device.
  Only the proof and the public inputs reach the server.
- The server stores no personal data. It stores only state that is not tied to an identity:
  nullifiers, ban flags, nonces.
- Users cannot be linked across applications (the nullifier differs per application).
- Everything on the client side (circuit, proof generation, card reading) is open source.

## Tech stack

- ZK circuit: Noir (nargo 1.0.0). Proving system: Barretenberg (bb 6.0.0, UltraHonk, verifier target
  `noir-recursive`, which is zero-knowledge)
- Verification server: Go 1.27. For now proofs are verified by calling `bb verify` as a subprocess.
  Storage is SQLite
- Test certificate generation: Go (crypto/x509)
- On-device proving: `prover/` (Rust) runs Noir witness generation and Barretenberg proving in-process. It
  depends only on the official crates (acvm/nargo/noirc_abi at Noir v1.0.0, barretenberg-rs 6.0.0); do not
  add third-party proving wrappers or prebuilt binaries from other sources
- iOS app (`ios/`, Swift, CoreNFC): opened from a service's QR code, it reads the card, has it sign the
  challenge, proves on the device and sends the proof to the verifier. Its only network code is
  `App/VerifierClient.swift` (two requests, to the origin named by the link). Developer tools for
  inspecting a card are behind a button in the same app

The authoritative versions are in README.md, `circuits/Nargo.toml` and `go.mod`.

## Common commands

```sh
make circuit   # generate fixtures + compile the circuit + write the verification key
make test      # nargo test and go test (which generate and verify real proofs)
make bench     # measure proving time and memory (record results in docs/bench.md)
gofmt -l . && go vet ./...
```

Run `make fixtures` before using `nargo` directly (`circuits/src/fixtures.nr` is generated and not in git).

## What the circuit must prove (security invariants, most important)

Public inputs: `ca_pubkey_hash`, `nonce`, `app_id`, `current_date`, `age_threshold`
Public outputs: `nullifier`, `is_over_threshold`

1. The RSA-2048 signature over the SHA-256 of the certificate's TBSCertificate verifies under the public
   key of the J-LIS CA (a mock CA in tests). The hash of the CA public key is exposed as a public input,
   and **the server compares it with its own trusted list** (it does not trust a value received from the user).
2. **Proof of card possession**: a signature over the server-issued `nonce` verifies under the holder's
   public key contained in the certificate. Without this, anyone could build a proof from a copy of a
   certificate that is in circulation. Never omit it.
3. Whether the holder is at least `age_threshold` is decided from the date of birth extracted from the
   certificate and `current_date`. The extraction position must be constrained by the certificate's
   actual data (do not trust a position the witness can choose freely).
4. `nullifier = Poseidon(a value uniquely determined by the certificate, app_id)`. The same person in
   the same application always gets the same value; in a different application, an unrelated value.
   Never let the inputs of the nullifier be freely chosen by the witness (non-determinism).

Under-constrained circuits are the most common vulnerability in ZK. For every constraint, confirm with a
negative test that a proof cannot be produced when the value is falsified.

## Repository layout

```
circuits/           Noir circuit (src/main.nr, cert.nr, der.nr, tests.nr)
cmd/mockca/         test CA and tool that issues certificates shaped like JPKI signing certificates
cmd/genfixtures/    generates testdata/ and the circuit test fixtures (circuits/src/fixtures.nr)
cmd/certinspect/    prints a certificate's structure without its contents; checks it against the circuit
cmd/verifier/       verification server (nonce issuance, proof verification, nullifier storage, `ban` subcommand)
cmd/mockclient/     stand-in for the holder (signs with a mock key instead of a card)
cmd/cardclient/     holder for a real card (gets a challenge, then proves with the card's signature)
internal/proto/     values the circuit and Go must agree on (message format, hashes, field encoding)
internal/           the other Go packages (mockjpki, witness, prover, verifier, client)
testdata/           mock certificates and keys (generated, not in git; never put real personal data here)
docs/               threat model, open questions, benchmarks (English is authoritative; Japanese in docs/ja/)
prover/             Rust library that generates proofs in-process, for phones
ios/                iOS app (verification from a QR code, proving on the device) and developer tools
```

## What is implemented (without a real card)

1. Development environment: nargo and bb versions are pinned in the README.
2. `cmd/mockca`: a mock CA issues RSA-2048 / SHA-256 certificates. As in a JPKI signing certificate, the
   four basic attributes are stored as otherName entries in subjectAltName. The OIDs and the nine-digit
   date of birth (era digit + YYYYMMDD) follow what was observed on one real card (docs/open-questions.md).
3. `circuits`: implements invariants 1-4 above. RSA, SHA-256 and Poseidon come from existing libraries;
   there is no hand-rolled cryptography. The circuit determines the positions of the public key and the
   date of birth by walking the DER of the TBS from the root.
4. Negative tests: a certificate signed by another CA, a nonce mismatch, a tampered date of birth, a
   substituted nullifier input and others are confirmed not to prove (`circuits/src/tests.nr`,
   `internal/verifier/server_test.go`; the mapping to attacks is in docs/threat-model.md).
5. `cmd/verifier`: `POST /challenge` (nonce issuance, short-lived and single-use) and `POST /verify`
   (proof verification, CA key hash check, nonce consumption, nullifier duplicate check). Storage is
   SQLite. Every public input except the nullifier is built from the server's own values.
6. Benchmarks: proving time and memory on a PC are recorded in docs/bench.md.

Open decisions are in docs/open-questions.md. The main ones: what the nullifier is derived from (it
changes when the certificate is reissued), checking the validity period (the circuit does not look at
it), linkage by third parties who hold the certificate, and checking against the structure of a real
card's certificate.

## Rules for making changes

- When adding or changing a circuit constraint, always add a negative test showing that a proof cannot
  be produced when the value is falsified. Make each negative test a passing case with exactly one
  thing changed.
- Do not take positions, offsets or selectors as witness inputs. Do not write `unconstrained` code of our own.
- When changing a public input, a public output, the signed message or a hash, update `internal/proto`
  and the verification server to match, and regenerate the verification key. The inputs are also
  assembled in `prover/src/inputs.rs`; keep it in step with `internal/witness` (a test compares them).
- Update docs/threat-model.md when the set of attacks or guarantees changes. When changing an English
  document under docs/, update docs/ja/ as well.
- The phone, not the server, decides which application a proof is for: `app_id` is derived from the origin
  the phone talks to (`VerificationLink.appID`, same value as `proto.AppID(origin)`). Do not add a path
  where the server chooses `app_id`, the date or the CA hash without the phone checking it.
- The rules for external contributors are in CONTRIBUTING.md.

## Not implemented yet (notes)

- A reader app that selects the JPKI AP, reads the signing certificate and, after PIN entry, has the
  card sign the nonce. Confirm APDUs and the file layout from existing open-source implementations and
  official documentation before implementing (do not write them from guesses).
- The whole user flow has run with one real card on a local network: scan the service's QR code, tap the
  card, proof generated on the phone and accepted. What remains is deployment (TLS, a public origin,
  app distribution) and a defined way for a separate service to embed it.
- On-device proving on other phones: measured only on an iPhone 15 Pro (about 1.8 s, 506 MiB). Low-memory
  phones and Android are untested (time and memory decide whether this is viable as a business).
- Revocation checking falls under the accreditation scheme for public personal authentication and is
  not handled in the PoC.

## Things to observe

- Never include a real person's certificate, name, address or PIN in code, test data, logs or commits.
- Never log a proof's witness or the contents of a certificate.
- Do not settle unconfirmed specifications (OIDs, APDUs, certificate field positions) by guessing;
  record them in docs/open-questions.md.
- Pin the versions of dependencies.
- Do not commit the mock CA's keys and certificates (testdata/) or `circuits/src/fixtures.nr`.
