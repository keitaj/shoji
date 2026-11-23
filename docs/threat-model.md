# Threat model

**English** | [日本語](ja/threat-model.md)

## What we protect

- The user's name, address, date of birth, certificate and signatures never
  leave the device.
- The verifier accepts only someone who, right now, holds a card whose
  certificate was issued by a trusted CA and who is over the age threshold.
- One person cannot hold several anonymous IDs in the same application, and IDs
  in different applications cannot be linked to each other.

## What reaches the server, and what it keeps

| Data | Sent to server | Stored |
|---|---|---|
| Proof (about 14.7 KB, zero-knowledge) | yes | no |
| nonce, app, current_date, age_threshold | issued by the server | until the nonce is consumed or expires |
| ca_pubkey_hash | yes (reveals which CA) | no |
| nullifier | yes | yes (per app, with a ban flag) |
| Certificate, four basic attributes, signatures, public key | no | no |

Logs record only that a verification was accepted or rejected and the kind of
reason. Proofs, nullifiers and witnesses are never logged. Output of the proving
tools is discarded; Prover.toml and the witness are written to a temporary
directory that is removed when proving ends.

## Attacks and countermeasures

| Attack | Countermeasure | Tests |
|---|---|---|
| Issue a certificate from a home-made CA | The CA key hash is a public input; the server compares it with its own trusted list | `fail_certificate_from_other_ca`, `fail_other_ca_key_with_trusted_hash`, `TestUntrustedCA` |
| Prove with a copy of someone's certificate | The circuit verifies a signature over the nonce made with the key in the certificate | `fail_certificate_copy_without_card` |
| Replay an old proof or signature | Nonces are issued by the server, short-lived and single-use, and are consumed before verification | `fail_nonce_mismatch`, `TestNonceIsSingleUse`, `TestNonceExpires`, `TestNonceNotIssuedByServer` |
| Reuse a signature or proof made for another app | `app_id` is part of the signed message and a public input | `fail_app_id_mismatch`, `TestProofBoundToApp` |
| Alter the date of birth | The whole TBSCertificate is covered by the CA signature | `fail_tampered_date_of_birth` |
| Plant date-of-birth-looking bytes in another attribute, or lie about where the date is | Positions are not witness values; the circuit derives them by walking the DER from the root | `decoy_date_of_birth_in_address_is_ignored`, `TestDecoyDateOfBirthIsRejected` |
| Prove against a convenient date or threshold | The server rebuilds the public inputs from the values it stored | `TestMinorIsRejected` |
| A minor submits a proof with `is_over_threshold = 0` | The server fixes that public input to 1 | `TestMinorIsRejected` |
| Substitute the nullifier or the public key | The nullifier depends only on the public key inside the signed TBS and on `app_id` | `fail_substituted_public_key`, `TestNullifierCannotBeSubstituted` |
| A banned person registers again | Per-app ban flag on the nullifier | `TestBannedNullifier` |

Each negative test is a passing case with exactly one thing changed.
`tampered_date_of_birth_parses` and `substituted_public_key_parses` confirm that
the tampered certificates are still well-formed, i.e. that it is the signature
check that stops them.

## About the circuit's constraints

- The only inputs the prover can choose freely, bound by neither a signature nor
  a hash, are `ca_redc` and `user_redc` (Barrett reduction helpers). They are
  hints for noir-bignum's unconstrained computation; a wrong value only makes
  proving fail (`fail_bogus_redc_hint`).
- RSA, SHA-256, Poseidon and big-integer arithmetic come from existing libraries.
  Only the DER reader and the byte packing are our own, and all of that code is
  constrained.
- The public exponent is fixed to 65537. For the holder key, the whole
  SubjectPublicKeyInfo is compared against a fixed pattern, which forces
  RSA-2048 with e = 65537.
- We have not audited the dependencies ourselves, in particular how
  noir-bignum's unconstrained hints are tied to its constraints.

## Out of scope and known limitations

- Certificate expiry and revocation are not checked. An expired or revoked card
  is accepted.
- Reissuing the certificate changes the nullifier, and a third party holding the
  certificate can compute the nullifier ([open questions](open-questions.md)).
- A borrowed or stolen card together with its PIN is not defended against.
- The server has no rate limiting, no authentication of calling applications and
  no TLS (proof of concept). Anyone can call `/challenge` for a configured app.
- Whoever can read the nullifier table learns how many users an app has.
- If the proving software on the device is tampered with, leakage of personal
  data cannot be prevented (to be addressed by open source and reproducible
  builds). The on-device prover (`prover/`) is built from source and depends only
  on the official Noir and Barretenberg crates, but it links Aztec's prebuilt
  Barretenberg static library (checksum-pinned), which we have not built or
  audited ourselves.
- The certificate structure was checked against a single real card. A card whose
  structure differs (for example a TBSCertificate longer than the buffer) is
  rejected by the circuit; it is not wrongly accepted.
