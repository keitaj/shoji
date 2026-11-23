# Passports: what was checked

**English** | [日本語](ja/passport.md)

shoji proves from the My Number Card. This note records an investigation into
doing the same from a Japanese electronic passport. **No passport circuit exists.**
What exists is a reader (developer tool in `ios/`) and `cmd/sodinspect`, which
reports how a passport is signed without printing its contents.

## Checked on a real passport

One recently issued Japanese passport, read on 2026-11-23 over NFC with Basic
Access Control. Only the security object, the chip's public key, the security
infos and one chip signature were read; the photo and the data group with the
name were not.

| Item | Observed |
|---|---|
| Issuer of the Document Signer certificate (the CSCA) | `CN=e-passportCSCA, OU=The Ministry of Foreign Affairs, O=Japanese Government, C=JP` |
| Document Signer certificate | signed by the CSCA with ecdsa-with-SHA384; key EC P-384, given with explicit curve parameters; valid for about 11 years |
| Signature over the security object | ecdsa-with-SHA384 |
| Hash of the data groups | SHA-384 |
| Data groups covered by the signature | DG1, DG2, DG13, DG14, DG15 |
| Active Authentication | supported: ECDSA P-384, plain `r \| s` signature over SHA-384 of the 8-byte nonce; the chip key (DG15) is covered by the security object |
| Access control | BAC worked; DG14 also announces PACE (ECDH generic mapping, AES-256) |
| Chip Authentication | not announced |

Every check passed: the hash chain from the data groups to the signed
attributes, the signature under the Document Signer key, and the chip's signature
over a fresh nonce. The Document Signer certificate could not be checked against
the CSCA key, because the CSCA certificate is not on the chip.

Older passports may use other algorithms. An expired passport could not be
read: its chip is destroyed when the passport is invalidated.

## From documents

- The protection profile for Japanese passport chips (Passport Division of the
  Ministry of Foreign Affairs, certified by JISEC) covers BAC, PACE and Active
  Authentication; a 2020 chip product certified against it implements Active
  Authentication with ECDSA, 256 bits with SHA-256 or 384 bits with SHA-384.
- The reader follows ICAO Doc 9303, eighth edition (Parts 3, 10 and 11). Its
  tests replay the worked examples of Part 11, Appendix D.

## What a passport circuit would need

The same statement as for the My Number Card is available: the data is signed by
the state, the prover holds the chip (Active Authentication plays the role of the
card's signature over the nonce), and conditions are evaluated on signed data,
here including nationality.

It would be considerably heavier than the current circuit:

- three ECDSA P-384 verifications (CSCA to Document Signer, Document Signer to
  security object, chip to nonce). Noir has a built-in verifier only for 256-bit
  curves, so P-384 has to be done with big-integer arithmetic;
- SHA-384 several times, for the hash chain;
- the Active Authentication nonce is only 8 bytes, so the verifier's challenge
  and `app_id` would have to be compressed into it (64 bits of binding instead of
  the full hash the card signs today);
- the CSCA certificate has to come from outside the chip (published master lists).

Whether that fits on a phone has not been measured.

## Related work

[zkPassport](https://github.com/zkpassport/circuits) has open-source Noir circuits
for passports (Apache-2.0) and lists Japanese passports as supported. Its circuits
did not appear to use Active Authentication when we looked (2026-11). Its code also
reserves a verification method for "Japan's My Number card, JPKI chain"; no such
circuit was in the public repository at that time.

## Sources

- [Protection profile for ePassport IC with SAC (BAC+PACE) and Active Authentication, v2.10](https://www.ipa.go.jp/security/jisec/pps/certified-pps/c0738_pp.pdf)
- [eTravel Essential for Japan 1.0, security target](https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/anssi-cible-2020_88en.pdf)
- [ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303)
