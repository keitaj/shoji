// Positive and negative tests of the delegated circuit.
//
// Every negative test is the passing case `prove_default(ADULT)` with exactly
// one thing changed. The certificate parsing and CA checks are shared with the
// card-present circuit and tested in depth in ../../src/tests.nr; here they get
// one test each to show they are wired in.
//
// A bad RSA signature fails inside the RSA library, before our own message, so
// those tests cannot name the reason; the others do.

use crate::fixtures::{
    ADULT, ADULT2, APP_ID, APP_ID_2, CA, CA_OTHER, CaFixture, CertFixture, DELEGATION_EXPIRY,
    DELEGATION_SECRET, MINOR, NONCE, NONCE_2, OTHER_CA_ADULT,
};
use crate::main;

global TODAY: u32 = 20261123;
global THRESHOLD: u8 = 18;
// What a verifier passes on TODAY: 30 days later.
global LATEST: u32 = 20261223;

fn prove(
    c: CertFixture,
    ca: CaFixture,
    ca_hash: Field,
    app_id: Field,
    date: u32,
    latest: u32,
    sig: [u8; 256],
    secret: Field,
    expiry: u32,
) -> (Field, bool) {
    main(
        ca_hash, NONCE, app_id, date, THRESHOLD, latest, c.tbs, c.tbs_len, ca.modulus, ca.redc,
        c.cert_sig, c.user_redc, sig, secret, expiry,
    )
}

fn prove_default(c: CertFixture) -> (Field, bool) {
    prove(
        c, CA, CA.hash, APP_ID, TODAY, LATEST, c.delegation_sig, DELEGATION_SECRET,
        DELEGATION_EXPIRY,
    )
}

// ---------------------------------------------------------------- positive

// The nullifier is the one the card-present circuit gives the same person.
#[test]
fn adult_is_accepted_with_the_card_present_nullifier() {
    let (nullifier, over) = prove_default(ADULT);
    assert(over);
    assert_eq(nullifier, ADULT.nullifier);
}

#[test]
fn minor_proves_but_is_not_over_threshold() {
    let (nullifier, over) = prove_default(MINOR);
    assert(!over);
    assert_eq(nullifier, MINOR.nullifier);
}

// One delegation serves every application and every nonce, each with its own nullifier.
#[test]
fn one_delegation_serves_any_application_and_nonce() {
    let (a, _) = prove_default(ADULT);
    let (b, _) = main(
        CA.hash, NONCE_2, APP_ID_2, TODAY, THRESHOLD, LATEST, ADULT.tbs, ADULT.tbs_len,
        CA.modulus, CA.redc, ADULT.cert_sig, ADULT.user_redc, ADULT.delegation_sig,
        DELEGATION_SECRET, DELEGATION_EXPIRY,
    );
    assert_eq(b, ADULT.nullifier_app2);
    assert(a != b);
}

#[test]
fn delegation_is_valid_through_its_last_day() {
    // On the expiry day the verifier's limit is 30 days later still.
    let (_, over) = prove(
        ADULT, CA, CA.hash, APP_ID, DELEGATION_EXPIRY, 20270122, ADULT.delegation_sig,
        DELEGATION_SECRET, DELEGATION_EXPIRY,
    );
    assert(over);
}

// ------------------------------------------------- (2) delegated possession

#[test(should_fail)]
fn fail_wrong_secret() {
    // Certificate and signature are in hand, the secret is not.
    let _ = prove(
        ADULT, CA, CA.hash, APP_ID, TODAY, LATEST, ADULT.delegation_sig, DELEGATION_SECRET + 1,
        DELEGATION_EXPIRY,
    );
}

#[test(should_fail_with = "delegation has expired")]
fn fail_expired() {
    let _ = prove(
        ADULT, CA, CA.hash, APP_ID, 20261224, 20270123, ADULT.delegation_sig, DELEGATION_SECRET,
        DELEGATION_EXPIRY,
    );
}

#[test(should_fail)]
fn fail_claiming_a_later_expiry_than_signed() {
    // The same day as fail_expired, now claiming the delegation runs a month longer.
    let _ = prove(
        ADULT, CA, CA.hash, APP_ID, 20261224, 20270123, ADULT.delegation_sig, DELEGATION_SECRET,
        20270123,
    );
}

#[test(should_fail_with = "delegation runs longer than allowed")]
fn fail_longer_than_the_verifier_allows() {
    // A delegation signed for 30 days, presented where the limit is one day earlier.
    let _ = prove(
        ADULT, CA, CA.hash, APP_ID, TODAY, 20261222, ADULT.delegation_sig, DELEGATION_SECRET,
        DELEGATION_EXPIRY,
    );
}

#[test(should_fail)]
fn fail_delegation_signed_by_another_key() {
    // Someone holding a copy of ADULT's certificate delegates with their own card.
    let _ = prove(
        ADULT, CA, CA.hash, APP_ID, TODAY, LATEST, ADULT2.delegation_sig, DELEGATION_SECRET,
        DELEGATION_EXPIRY,
    );
}

#[test(should_fail)]
fn fail_card_present_signature_is_not_a_delegation() {
    // A signature the card made for the card-present circuit (over a nonce).
    let _ = prove(
        ADULT, CA, CA.hash, APP_ID, TODAY, LATEST, ADULT.nonce_sig, DELEGATION_SECRET,
        DELEGATION_EXPIRY,
    );
}

#[test(should_fail)]
fn fail_corrupted_delegation_signature() {
    let mut sig = ADULT.delegation_sig;
    sig[0] ^= 1;
    let _ = prove(
        ADULT, CA, CA.hash, APP_ID, TODAY, LATEST, sig, DELEGATION_SECRET, DELEGATION_EXPIRY,
    );
}

// ------------------------------------------------- (1), (3), (4): wired in

#[test(should_fail)]
fn fail_certificate_from_other_ca() {
    let _ = prove_default(OTHER_CA_ADULT);
}

#[test(should_fail_with = "CA key does not match ca_pubkey_hash")]
fn fail_other_ca_key_with_trusted_hash() {
    let c = OTHER_CA_ADULT;
    let _ = prove(
        c, CA_OTHER, CA.hash, APP_ID, TODAY, LATEST, c.delegation_sig, DELEGATION_SECRET,
        DELEGATION_EXPIRY,
    );
}

#[test(should_fail)]
fn fail_tampered_date_of_birth() {
    // 2015-04-01 -> 1915-04-01.
    let mut c = MINOR;
    assert_eq(c.tbs[c.dob_offset], 0x32);
    c.tbs[c.dob_offset] = 0x31;
    c.tbs[c.dob_offset + 1] = 0x39;
    let _ = prove_default(c);
}

#[test(should_fail)]
fn fail_substituted_public_key() {
    // Put ADULT2's key into ADULT's certificate and delegate with ADULT2's card.
    let mut c = ADULT;
    for i in 0..256 {
        c.tbs[c.modulus_offset + i] = ADULT2.modulus[i];
    }
    c.user_redc = ADULT2.user_redc;
    c.delegation_sig = ADULT2.delegation_sig;
    let _ = prove_default(c);
}
