// shoji, delegated: the same statement as ../../src/main.nr ("a real person over
// the age threshold", with the same per-application nullifier), proved without
// the card being present.
//
// The card signs once: a commitment to a secret that the holder's own device
// chose, and the last day the delegation is valid. Until that day, knowing the
// secret stands in for holding the card. This is what lets software acting for
// the holder (an AI agent, through the holder's device) be told apart from
// software acting for nobody, without a card tap per request and without the
// certificate leaving the device.
//
// Invariants (see AGENTS.md); 1, 3 and 4 are exactly those of the card-present
// circuit:
//   1. The TBSCertificate is signed by the CA whose key hashes to `ca_pubkey_hash`.
//   2. Delegated possession: the holder's key, taken from the signed TBS, signed
//      DELEGATION_DOMAIN || Poseidon(delegation_secret) || delegation_expiry, and
//      current_date <= delegation_expiry <= latest_expiry. The prover knows
//      delegation_secret.
//   3. The date of birth from the signed TBS is compared with `current_date`.
//   4. nullifier = Poseidon(Poseidon(holder modulus), app_id): the same value as
//      with the card present, so a person is one person either way.
//
// `nonce` does not enter a constraint: as a public input it is part of what the
// proof is for, so a proof made for one nonce does not verify for another
// (internal/verifier tests check this). `latest_expiry` is the verifier's limit
// on how long delegations may run; the expiry itself stays private.

mod fixtures;
mod tests;

use shoji_core::cert::{MAX_TBS_LEN, MODULUS_BYTES, parse_tbs};
use shoji_core::keys::{LIMBS, pubkey_hash, rsa_params, verify_rsa_sha256};
use poseidon::poseidon::bn254::{hash_1, hash_2};
use sha256::{digest, sha256_var};

// "shoji-v1-deleg::" — domain separator of the delegation the card signs. It
// differs from the card-present circuit's "shoji-v1-nonce::", so a signature
// made for one circuit is never valid in the other.
global DELEGATION_DOMAIN: [u8; 16] = [
    0x73, 0x68, 0x6f, 0x6a, 0x69, 0x2d, 0x76, 0x31, 0x2d, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x3a, 0x3a,
];

fn main(
    ca_pubkey_hash: pub Field,
    nonce: pub Field,
    app_id: pub Field,
    current_date: pub u32,
    age_threshold: pub u8,
    latest_expiry: pub u32,
    tbs: [u8; MAX_TBS_LEN],
    tbs_len: u32,
    ca_modulus: [u8; MODULUS_BYTES],
    ca_redc: [u128; LIMBS],
    cert_sig: [u8; MODULUS_BYTES],
    user_redc: [u128; LIMBS],
    delegation_sig: [u8; MODULUS_BYTES],
    delegation_secret: Field,
    delegation_expiry: u32,
) -> pub (Field, bool) {
    // (1) The certificate is signed by the CA committed to in `ca_pubkey_hash`.
    assert(pubkey_hash(ca_modulus) == ca_pubkey_hash, "CA key does not match ca_pubkey_hash");
    let tbs_digest = sha256_var(tbs, tbs_len);
    assert(
        verify_rsa_sha256(rsa_params(ca_modulus, ca_redc), tbs_digest, cert_sig),
        "certificate signature invalid",
    );

    // Everything below reads only from the signed TBS.
    let fields = parse_tbs(tbs, tbs_len);

    // (2) Delegated possession: the holder's key signed a commitment to the
    // secret the prover knows, with an expiry that has not passed and is not
    // further away than the verifier allows.
    let commitment_bytes: [u8; 32] = hash_1([delegation_secret]).to_be_bytes();
    let expiry_bytes: [u8; 4] = (delegation_expiry as Field).to_be_bytes();
    let mut msg = [0; 52];
    for i in 0..16 {
        msg[i] = DELEGATION_DOMAIN[i];
    }
    for i in 0..32 {
        msg[16 + i] = commitment_bytes[i];
    }
    for i in 0..4 {
        msg[48 + i] = expiry_bytes[i];
    }
    assert(
        verify_rsa_sha256(rsa_params(fields.modulus, user_redc), digest(msg), delegation_sig),
        "delegation signature invalid",
    );
    assert(current_date <= delegation_expiry, "delegation has expired");
    assert(delegation_expiry <= latest_expiry, "delegation runs longer than allowed");

    // The nonce is bound by being a public input; see the header.
    let _ = nonce;

    // (3) Age, as in the card-present circuit.
    let is_over_threshold =
        fields.date_of_birth + (age_threshold as u32) * 10000 <= current_date;

    // (4) Nullifier, as in the card-present circuit.
    let nullifier = hash_2([pubkey_hash(fields.modulus), app_id]);

    (nullifier, is_over_threshold)
}
