# Security policy

## Status

shoji is a proof of concept. It has not been audited and must not be
used to protect anything real. Known limitations are listed in the
[threat model](docs/threat-model.md); those are not vulnerabilities to report,
though ideas for addressing them are welcome as regular issues.

## Reporting a vulnerability

Please report privately, not in a public issue: use **"Report a vulnerability"**
under the repository's *Security* tab (GitHub private vulnerability reporting).

Reports we are especially interested in:

- Under-constrained logic: any way to obtain an accepted proof without a
  certificate from a trusted CA, without the card's key, with a falsified date
  of birth, or with a nullifier that is not the one determined by the
  certificate and the app.
- Ways for the server, or an observer, to learn personal data or to link
  nullifiers across applications beyond what the threat model already states.
- Nonce replay, or bypasses of the checks in the verifier.

Please include the affected commit, a description, and if possible a failing
test or reproduction steps. **Never include a real certificate or real personal
data in a report**; reproduce with the mock CA.

We will acknowledge a report, keep you informed while we work on it, and credit
you in the fix unless you prefer otherwise. As a volunteer project we cannot
promise response times.
