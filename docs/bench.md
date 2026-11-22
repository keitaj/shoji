# Benchmarks

Output of `make bench` (`scripts/bench.sh`): wall time and peak memory (maximum
resident set size reported by `/usr/bin/time`) for one proof with the adult mock
certificate (783-byte TBSCertificate).

## 2026-11-23 — Apple M5 (10 cores, 32 GB RAM), macOS, nargo 1.0.0, bb 6.0.0

Circuit size: 35,369 ACIR opcodes, 222,256 UltraHonk gates (fits in 2^18).
Proof size: 14,656 bytes.

| Step | Time (s) | Peak RSS (MiB) |
|---|---|---|
| Witness generation (noir-execute) | 0.15 | 52 |
| Proving (bb prove), run 1 | 0.92 | 585 |
| Proving (bb prove), run 2 | 0.80 | 585 |
| Proving (bb prove), run 3 | 0.82 | 585 |
| Verification (bb verify) | 0.01 | 9 |

bb ran with 10 threads and a precomputed verification key (`-k`).

## How to read this

- These are native PC numbers. On-device proving, which is what matters in the
  end, has not been measured. Phones have fewer threads and less memory, so
  these numbers cannot simply be scaled.
- The circuit's TBS buffer is fixed at 2048 bytes, so the gate count does not
  change with the length of the certificate.
- No breakdown has been measured. Apart from the two RSA verifications (about
  27k gates each according to the library), we expect most of the cost to be
  SHA-256 (up to 32 blocks) and the array accesses of the DER reader, but have
  not confirmed it.
