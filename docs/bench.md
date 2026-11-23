# Benchmarks

Output of `make bench` (`scripts/bench.sh`): wall time and peak memory (maximum
resident set size reported by `/usr/bin/time`) for one proof with the adult mock
certificate (about 800-byte TBSCertificate).

## 2026-11-23 — Apple M5 (10 cores, 32 GB RAM), macOS, nargo 1.0.0, bb 6.0.0

Circuit size: 35,439 ACIR opcodes, 222,339 UltraHonk gates (fits in 2^18).
Proof size: 14,656 bytes.

| Step | Time (s) | Peak RSS (MiB) |
|---|---|---|
| Witness generation (noir-execute) | 0.17 | 52 |
| Proving (bb prove), run 1 | 0.96 | 585 |
| Proving (bb prove), run 2 | 1.65 | 583 |
| Proving (bb prove), run 3 | 1.24 | 548 |
| Verification (bb verify) | 0.01 | 9 |

bb ran with 10 threads and a precomputed verification key (`-k`). This run was
taken after the date-of-birth format change, with other applications open, which
is the likely reason for the spread between proving runs; an earlier run of the
previous circuit (222,256 gates) on an idle machine took 0.80-0.92 s.

## 2026-11-23 — iPhone 15 Pro (iPhone16,1; 6 cores, 8 GB RAM), iOS 27.2.1

Proving inside the development app (`ios/`) with the in-process prover
(`prover/`, Barretenberg 6.0.0 static library), same circuit and the same mock
inputs. Time is wall time of witness generation plus proving; memory is the
app's peak physical footprint, the figure iOS memory limits apply to.

| Run | Time (s) | Peak footprint (MiB) |
|---|---|---|
| 1 | 1.77 | 506 |
| 2 | 1.74 | 506 |
| 3 | 1.81 | 506 |

The proof made on the phone (14,656 bytes) verifies with `bb verify` and the same
verification key on a PC. For comparison, the same library on the M5 laptop
takes about 1.2 s with a 660 MiB peak resident set.

A proof was also made on this phone from a real card (reading, signing and
proving on the device) and accepted by the verifier; its timing was shown on the
phone but not recorded.

## How to read this

- The phone measured is a high-end model. Phones with 4 GB of RAM or less may
  not be allowed a 500 MiB footprint; that has not been tested, and neither has
  Android.
- The circuit's TBS buffer is fixed at 2048 bytes, so the gate count does not
  change with the length of the certificate (a real one was 1552 bytes).
- No breakdown has been measured. Apart from the two RSA verifications (about
  27k gates each according to the library), we expect most of the cost to be
  SHA-256 (up to 32 blocks) and the array accesses of the DER reader, but have
  not confirmed it.
