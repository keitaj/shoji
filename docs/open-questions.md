# Open questions

**English** | [日本語](ja/open-questions.md)

Things we do not settle by guessing. Update an entry, with its source, once it
has been confirmed against a real card, official documentation or an existing
open-source implementation.

## Confirmed from documents and open-source implementations

From the official *Operating Rules of the Signing CA* (署名用認証局 運用規程, v2.1, 2021-09-01; read from the
copy published by Shizuoka Prefecture):

- The CA key and the holder key are both RSA-2048 (§6.1.5).
- The card holds the holder's private key, the signing certificate and the signing CA's **self-signed**
  certificate (§4.3.1.1, §4.4.1.1), which supports the single-level assumption. The CA's self-signed
  certificate is valid for 10 years and link certificates exist for CA key rollover (§6.3.2.1, §7.1), so a
  verifier must expect to trust more than one CA key at a time.
- subjectAltName carries `commonName`, `dateOfBirth`, `gender`, `address`,
  `substituteCharacterOfCommonName` and `substituteCharacterOfAddress` (§3.1.2, §4.3.1.1). The mock uses the
  same six entries.
- The certificate profile itself (OIDs, string types, the date format, the extension list) is delegated to
  a "technical specification" (§7.1) that we have not found in public. Those points were checked on a real
  card instead (see the table below).
- The holder CRL is access-restricted (§2.4).

From open-source implementations ([jpki/myna](https://github.com/jpki/myna) at `55a90c2`, and
[tex2e's write-up](https://tex2e.github.io/blog/protocol/jpki-mynumbercard-with-apdu)), which agree with each
other but are **not official**:

- JPKI application AID `D3 92 F0 00 26 01 00 00 00 01`.
- Files: signing certificate `00 01` (readable only after the signing PIN is verified), signing CA
  certificate `00 02`, signing key `00 1A`, signing PIN `00 1B`.
- Signing: `80 2A 00 80` with a SHA-256 **DigestInfo** as data; the card applies PKCS#1 v1.5 padding and
  returns the RSA signature. This matches what the circuit verifies.
- The remaining PIN attempts can be read without spending one (status `63 Cx`). myna upper-cases the signing
  password before verifying it.

## Certificate structure: checked against a real card

Checked on 2026-11-23 against **one** real card, with `ios/` (card probe) and `cmd/certinspect`, which reports
structure only. Cards issued at other times may differ; additional reports are welcome (structure only, never
contents — use the "Certificate structure" issue template).

| Item | Observed on the real card | In the code |
|---|---|---|
| OIDs of the otherName entries | `1.2.392.200149.8.5.5.{1 name, 2 substitute characters for name, 3 gender, 4 date of birth, 5 address, 6 substitute characters for address}`, in the order 1, 4, 3, 5, 2, 6 | matches (`internal/mockjpki`, `OID_DATE_OF_BIRTH` in `circuits/src/cert.nr`); the circuit does not depend on the order |
| Wrapping of the otherName value | one UTF8String inside `[0] EXPLICIT` | matches; the circuit accepts UTF8String only |
| Date-of-birth format | **nine digits**: one leading digit, then Gregorian `YYYYMMDD`. On the card checked, the leading digit equals the Japanese era code of the date (1 Meiji, 2 Taisho, 3 Showa, 4 Heisei, 5 Reiwa) | the circuit requires nine digits and ignores the first; the mock CA writes the era code |
| Gender | one digit | not read by the circuit; the mock's `"1"` / `"2"` values are placeholders |
| Substitute-character entries | name: five digits; address: a longer string | not read by the circuit; mock values are placeholders |
| Extensions | seven: keyUsage (critical), subjectAltName, certificatePolicies (critical, policy `1.2.392.200149.8.5.1.1.20`), issuerAltName, cRLDistributionPoints, authorityKeyIdentifier, subjectKeyIdentifier | the circuit finds subjectAltName by OID and allows up to 12 (`MAX_EXTENSIONS`) |
| subjectAltName entries | six, all otherName | the circuit allows up to 10 (`MAX_GENERAL_NAMES`) |
| issuerUniqueID / subjectUniqueID | absent | the circuit rejects a certificate that has them |
| Subject | C, two L attributes, CN | not read by the circuit |
| TBSCertificate length | 1552 bytes on the card checked. It varies with the length of the name and address | the circuit accepts up to 2032 bytes (`MAX_TBS_LEN` minus headroom). **Whether the longest possible name and address fit is not established** |
| Keys and signature algorithm | holder and CA keys RSA-2048 with e = 65537; sha256WithRSAEncryption | matches |
| CA hierarchy | the CA certificate on the card is self-signed and directly verifies the holder certificate | matches the single-level assumption |

With that card, a full proof was made and accepted by a verifier that trusts only the card's signing CA
(2026-11-23; reading and signing on an iPhone with `ios/`, proving on a PC with `cmd/cardclient`).

## Card signing behaviour (needed for the card reader app)

- The commands for selecting the application, reading the certificates, reading the PIN retry counter,
  verifying the PIN and signing (SHA-256 DigestInfo in, PKCS#1 v1.5 signature out) all worked on a real
  card as the open-source implementations describe, and the resulting signature verifies in the circuit.
  There is still no official specification to check them against.
- A signature made with the signing certificate can carry legal effect. Whether
  it is appropriate to have users sign a nonce for identity verification, and
  what wording or domain separation the signed message needs, requires a
  legal and regulatory review.

## Open design decisions

- **What the nullifier is derived from.** Currently the holder's public key. The
  signing certificate is reissued on renewal and whenever the holder's name or
  address changes, and the nullifier changes with it, which allows ban evasion
  and duplicate registration. The only values stable across reissuance are the
  four basic attributes, but they have low entropy: a nullifier derived from them
  could be brute-forced back to a person. Undecided.
- **Linkage by parties who hold the certificate.** Anyone can compute the
  nullifier from the certificate and `app_id`. Relying parties the user has
  signed for, and the issuer, hold the certificate and can therefore link a
  nullifier to a person. Mixing a deterministic card signature into the nullifier
  as a secret would prevent this at the cost of one more RSA verification in the
  circuit.
- **Validity period.** The circuit does not look at notBefore / notAfter.
- **Revocation.** Falls under the accreditation scheme for public personal
  authentication; out of scope for the proof of concept.
- **Age arithmetic.** `date_of_birth + threshold × 10000 <= current_date` on
  `YYYYMMDD` integers. The threshold is met from the birthday itself, one day
  later than the legal rule in Japan (age is gained at the end of the day before
  the birthday), so the check errs on the strict side. Someone born on
  29 February meets it from 1 March in non-leap years.
- **Reference for `current_date`.** The server fixes the date in Japan Standard
  Time when it issues the challenge.
