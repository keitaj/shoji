// Positive and negative tests for the security invariants in AGENTS.md.
//
// Every negative test is the passing case `prove(ADULT, ...)` with exactly one
// thing changed, so a failure can only be caused by that change.
// Fixtures come from `go run ./cmd/genfixtures` (synthetic data only).

use crate::cert::parse_tbs;
use crate::fixtures::{
    ADULT, ADULT2, APP_ID, APP_ID_2, CA, CA_OTHER, CaFixture, CertFixture, DECOY, MINOR, NONCE,
    NONCE_2, OTHER_CA_ADULT,
};
use crate::main;

global TODAY: u32 = 20261123;
global THRESHOLD: u8 = 18;

fn prove(
    c: CertFixture,
    ca: CaFixture,
    ca_hash: Field,
    nonce: Field,
    app_id: Field,
    date: u32,
    nonce_sig: [u8; 256],
) -> (Field, bool) {
    main(
        ca_hash, nonce, app_id, date, THRESHOLD, c.tbs, c.tbs_len, ca.modulus, ca.redc, c.cert_sig,
        c.user_redc, nonce_sig,
    )
}

fn prove_default(c: CertFixture) -> (Field, bool) {
    prove(c, CA, CA.hash, NONCE, APP_ID, TODAY, c.nonce_sig)
}

// ---------------------------------------------------------------- positive

#[test]
fn adult_is_accepted() {
    let (nullifier, over) = prove_default(ADULT);
    assert(over);
    // The nullifier matches the value computed independently in Go.
    assert_eq(nullifier, ADULT.nullifier);
}

#[test]
fn minor_proves_but_is_not_over_threshold() {
    let (nullifier, over) = prove_default(MINOR);
    assert(!over);
    assert_eq(nullifier, MINOR.nullifier);
}

#[test]
fn age_boundary_is_the_birthday() {
    // ADULT was born 1990-01-15 and turns 18 on 2008-01-15.
    let (_, day_before) = prove(ADULT, CA, CA.hash, NONCE, APP_ID, 20080114, ADULT.nonce_sig);
    assert(!day_before);
    let (_, birthday) = prove(ADULT, CA, CA.hash, NONCE, APP_ID, 20080115, ADULT.nonce_sig);
    assert(birthday);
}

#[test]
fn bytes_after_tbs_len_are_ignored() {
    let mut c = ADULT;
    for i in c.tbs_len..2048 {
        c.tbs[i] = 0xff;
    }
    let (nullifier, over) = prove_default(c);
    assert(over);
    assert_eq(nullifier, ADULT.nullifier);
}

// ------------------------------------------------- (1) certificate / CA

// A certificate issued by another CA does not verify under the trusted CA's key.
#[test(should_fail)]
fn fail_certificate_from_other_ca() {
    let _ = prove_default(OTHER_CA_ADULT);
}

// Supplying the other CA's key while claiming the trusted CA's hash is rejected.
#[test(should_fail_with = "CA key does not match ca_pubkey_hash")]
fn fail_other_ca_key_with_trusted_hash() {
    let c = OTHER_CA_ADULT;
    let _ = prove(c, CA_OTHER, CA.hash, NONCE, APP_ID, TODAY, c.nonce_sig);
}

// With the other CA's key AND hash the circuit is satisfied: the circuit cannot know
// which CAs are trusted. The public `ca_pubkey_hash` then differs from the trusted
// one, and rejecting it is the verifier's job (see internal/verifier tests).
#[test]
fn other_ca_is_only_distinguished_by_public_hash() {
    let c = OTHER_CA_ADULT;
    let (_, over) = prove(c, CA_OTHER, CA_OTHER.hash, NONCE, APP_ID, TODAY, c.nonce_sig);
    assert(over);
    assert(CA_OTHER.hash != CA.hash);
}

#[test(should_fail)]
fn fail_corrupted_certificate_signature() {
    let mut c = ADULT;
    c.cert_sig[255] ^= 1;
    let _ = prove_default(c);
}

#[test(should_fail)]
fn fail_truncated_tbs() {
    let mut c = ADULT;
    c.tbs_len -= 1;
    let _ = prove_default(c);
}

// ------------------------------------------------- (2) card possession

#[test(should_fail)]
fn fail_nonce_mismatch() {
    // The signature is over NONCE; the verifier issued NONCE_2.
    let _ = prove(ADULT, CA, CA.hash, NONCE_2, APP_ID, TODAY, ADULT.nonce_sig);
}

#[test(should_fail)]
fn fail_app_id_mismatch() {
    // A signature made for APP_ID cannot be replayed to APP_ID_2.
    let _ = prove(ADULT, CA, CA.hash, NONCE, APP_ID_2, TODAY, ADULT.nonce_sig);
}

#[test(should_fail)]
fn fail_certificate_copy_without_card() {
    // Someone holding a copy of ADULT's certificate signs with their own key.
    let _ = prove(ADULT, CA, CA.hash, NONCE, APP_ID, TODAY, ADULT2.nonce_sig);
}

#[test(should_fail)]
fn fail_corrupted_nonce_signature() {
    let mut sig = ADULT.nonce_sig;
    sig[0] ^= 1;
    let _ = prove(ADULT, CA, CA.hash, NONCE, APP_ID, TODAY, sig);
}

// ------------------------------------------------- (3) date of birth

#[test(should_fail)]
fn fail_tampered_date_of_birth() {
    // 2015-04-01 -> 1915-04-01 in the real date-of-birth field.
    let mut c = MINOR;
    assert_eq(c.tbs[c.dob_offset], 0x32);
    assert_eq(c.tbs[c.dob_offset + 1], 0x30);
    c.tbs[c.dob_offset] = 0x31;
    c.tbs[c.dob_offset + 1] = 0x39;
    let _ = prove_default(c);
}

// The tampered TBS above is well-formed: only the signature stops it.
#[test]
fn tampered_date_of_birth_parses() {
    let mut c = MINOR;
    c.tbs[c.dob_offset] = 0x31;
    c.tbs[c.dob_offset + 1] = 0x39;
    assert_eq(parse_tbs(c.tbs, c.tbs_len).date_of_birth, 19150401);
}

// DECOY is a validly signed minor whose address attribute contains the bytes of a
// complete date-of-birth otherName claiming 1970-01-01. The parser must not use it.
#[test]
fn decoy_date_of_birth_in_address_is_ignored() {
    let (_, over) = prove_default(DECOY);
    assert(!over);
    assert_eq(parse_tbs(DECOY.tbs, DECOY.tbs_len).date_of_birth, 20150401);
}

#[test]
fn parser_extracts_fixture_fields() {
    let f = parse_tbs(ADULT.tbs, ADULT.tbs_len);
    assert_eq(f.date_of_birth, 19900115);
    assert_eq(f.modulus, ADULT.modulus);
}

#[test(should_fail_with = "date of birth: not a digit")]
fn fail_parser_non_digit_date() {
    let mut c = ADULT;
    c.tbs[c.dob_offset + 3] = 0x41;
    let _ = parse_tbs(c.tbs, c.tbs_len);
}

// The leading era digit is not part of the date: changing it leaves the parsed date
// unchanged (and, like any change to the TBS, breaks the CA signature).
#[test]
fn era_digit_is_not_part_of_the_date() {
    let mut c = ADULT;
    assert_eq(c.tbs[c.dob_offset - 1], 0x34); // Heisei
    c.tbs[c.dob_offset - 1] = 0x33;
    assert_eq(parse_tbs(c.tbs, c.tbs_len).date_of_birth, 19900115);
}

#[test(should_fail_with = "date of birth: not a digit")]
fn fail_parser_non_digit_era() {
    let mut c = ADULT;
    c.tbs[c.dob_offset - 1] = 0x41;
    let _ = parse_tbs(c.tbs, c.tbs_len);
}

#[test(should_fail)]
fn fail_tampered_era_digit() {
    let mut c = ADULT;
    c.tbs[c.dob_offset - 1] = 0x33;
    let _ = prove_default(c);
}

#[test(should_fail)]
fn fail_parser_length_does_not_match_tbs_len() {
    let _ = parse_tbs(ADULT.tbs, ADULT.tbs_len + 1);
}

// ------------------------------------------------- (4) nullifier

#[test]
fn nullifier_is_stable_per_person_and_app() {
    let (a, _) = prove_default(ADULT);
    // Same person, same app, different nonce: identical.
    let (b, _) = prove(ADULT, CA, CA.hash, NONCE_2, APP_ID, TODAY, ADULT.nonce_sig_nonce2);
    assert_eq(a, b);
    // Same person, different app: different (and equal to the independent Go value).
    let (c, _) = prove(ADULT, CA, CA.hash, NONCE, APP_ID_2, TODAY, ADULT.nonce_sig_app2);
    assert_eq(c, ADULT.nullifier_app2);
    assert(a != c);
    // Different person, same app: different.
    let (d, _) = prove_default(ADULT2);
    assert(a != d);
}

// Nullifier-input substitution: put another key into the victim's certificate
// (to obtain a fresh nullifier, or to sign with a key one controls).
#[test(should_fail)]
fn fail_substituted_public_key() {
    let mut c = ADULT;
    for i in 0..256 {
        assert_eq(c.tbs[c.modulus_offset + i], ADULT.modulus[i]);
        c.tbs[c.modulus_offset + i] = ADULT2.modulus[i];
    }
    c.user_redc = ADULT2.user_redc;
    // ADULT2's signature is valid for the substituted key; the CA signature is not.
    let _ = prove(c, CA, CA.hash, NONCE, APP_ID, TODAY, ADULT2.nonce_sig);
}

// The substituted TBS above is well-formed and yields ADULT2's key: again only the
// CA signature prevents the substitution.
#[test]
fn substituted_public_key_parses() {
    let mut c = ADULT;
    for i in 0..256 {
        c.tbs[c.modulus_offset + i] = ADULT2.modulus[i];
    }
    assert_eq(parse_tbs(c.tbs, c.tbs_len).modulus, ADULT2.modulus);
}

// A wrong Barrett hint cannot be used to forge anything: the honest inputs with a
// bogus hint simply fail.
#[test(should_fail)]
fn fail_bogus_redc_hint() {
    let mut c = ADULT;
    c.user_redc = ADULT2.user_redc;
    let _ = prove_default(c);
}
