# Open questions

**English** | [日本語](ja/open-questions.md)

Things we do not settle by guessing. Update an entry, with its source, once it
has been confirmed against a real card, official documentation or an existing
open-source implementation.

## Certificate structure (to be checked against a real card)

| Item | Current placeholder | Where it matters |
|---|---|---|
| OIDs of the otherName entries for the four basic attributes | `1.2.392.200149.8.5.5.{1 name, 2 substitute characters for name, 3 gender, 4 date of birth, 5 address, 6 substitute characters for address}` | `internal/mockjpki`, `OID_DATE_OF_BIRTH` in `circuits/src/cert.nr` |
| Date-of-birth format | Eight digits, Gregorian `YYYYMMDD`. Whether a real card adds something such as an era prefix is unconfirmed | `cert.nr` (requires length 8, digits only) |
| Date-of-birth string type | UTF8String (the circuit also accepts PrintableString) | `cert.nr` |
| Wrapping of the otherName value | One string inside `[0] EXPLICIT` | `cert.nr` |
| Gender encoding | `"1"` / `"2"` (not read by the circuit) | `internal/mockjpki` |
| Which extensions, how many, in what order | The mock has keyUsage, authorityKeyIdentifier, certificatePolicies, subjectAltName. The circuit finds subjectAltName by OID, so order does not matter, but it allows at most 12 extensions | `MAX_EXTENSIONS` in `cert.nr` |
| Number of subjectAltName entries | At most 10 | `MAX_GENERAL_NAMES` in `cert.nr` |
| issuerUniqueID / subjectUniqueID | Assumed absent (the circuit rejects a certificate that has them) | `cert.nr` |
| Subject / issuer contents | Arbitrary in the mock; not read by the circuit | `internal/mockjpki` |
| TBSCertificate length | The circuit accepts up to 2032 bytes (2048-byte buffer minus 16 bytes of headroom). The mock is about 800 bytes | `MAX_TBS_LEN` in `cert.nr` |
| Keys and signature algorithm | Holder and CA keys are RSA-2048 with e = 65537; sha256WithRSAEncryption (PKCS#1 v1.5) | the whole circuit |
| CA hierarchy | The CA key is assumed to sign holder certificates directly. An intermediate CA would require extending the circuit | `main.nr` |

## Card signing behaviour (needed for the card reader app)

- The format of the data handed to the signing application. Our understanding
  that the host passes a DigestInfo and the card applies PKCS#1 v1.5 padding is
  unconfirmed.
- APDUs, file layout and PIN handling. To be confirmed from existing open-source
  implementations and official documentation before any implementation.
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
