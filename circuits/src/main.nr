// shoji: proves "a real person over the age threshold holds this card" and
// derives a per-application nullifier, without revealing the certificate.
//
// Invariants (see AGENTS.md):
//   1. The TBSCertificate is signed (SHA-256, RSA-2048 PKCS#1 v1.5) by the CA whose
//      key hashes to the public input `ca_pubkey_hash`. The verifier compares that
//      hash with its own trusted list.
//   2. Card possession: the holder's key, taken from the signed TBS, signed a
//      message containing the verifier's `nonce` and `app_id`.
//   3. The date of birth, located by parsing the signed TBS, is compared with
//      `current_date` and `age_threshold`.
//   4. nullifier = Poseidon(Poseidon(holder modulus), app_id). Both arguments are
//      fixed by the signed TBS and a public input; no free witness enters it.
//
// The only prover-supplied values that are not bound by a signature or a hash are
// the two `*_redc` Barrett parameters. They are hints for noir-bignum's
// unconstrained witness computation and do not affect soundness.

mod cert;
mod der;
mod fixtures;
mod tests;

use cert::{MAX_TBS_LEN, MODULUS_BYTES, parse_tbs};
use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon::bn254::{hash_2, hash_9};
use rsa::pkcs1v15::verify_sha256_pkcs1v15;
use sha256::{digest, sha256_var};

global LIMBS: u32 = 18;
global MOD_BITS: u32 = 2048;
global RSA_EXPONENT: u32 = 65537;

// "shoji-v1-nonce::" — domain separator of the message the card signs.
global NONCE_DOMAIN: [u8; 16] = [
    0x73, 0x68, 0x6f, 0x6a, 0x69, 0x2d, 0x76, 0x31, 0x2d, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x3a, 0x3a,
];

/// Packs 256 big-endian bytes into noir-bignum's little-endian 120-bit limbs.
fn to_limbs(be: [u8; MODULUS_BYTES]) -> [u128; LIMBS] {
    let mut limbs = [0; LIMBS];
    for i in 0..LIMBS {
        // Limb i covers bytes [15 i, 15 i + 15) counted from the least significant end.
        let mut acc: Field = 0;
        for j in 0..15 {
            let k = i * 15 + (14 - j);
            if k < MODULUS_BYTES {
                acc = acc * 256 + be[MODULUS_BYTES - 1 - k] as Field;
            }
        }
        // acc < 2^120, so the cast is lossless.
        limbs[i] = acc as u128;
    }
    limbs
}

/// Poseidon over the modulus split into nine big-endian chunks (8 x 31 bytes, 1 x 8 bytes).
fn pubkey_hash(be: [u8; MODULUS_BYTES]) -> Field {
    let mut chunks = [0; 9];
    for i in 0..9 {
        let mut acc: Field = 0;
        for j in 0..31 {
            let k = i * 31 + j;
            if k < MODULUS_BYTES {
                acc = acc * 256 + be[k] as Field;
            }
        }
        chunks[i] = acc;
    }
    hash_9(chunks)
}

fn rsa_params(modulus: [u8; MODULUS_BYTES], redc: [u128; LIMBS]) -> BigNumParams<LIMBS, MOD_BITS> {
    // BigNumParams::new range-checks the limbs and requires the top bit to be set.
    BigNumParams::new(false, to_limbs(modulus), redc)
}

fn verify_rsa_sha256(
    params: BigNumParams<LIMBS, MOD_BITS>,
    digest: [u8; 32],
    sig: [u8; MODULUS_BYTES],
) -> bool {
    let sig: RuntimeBigNum<LIMBS, MOD_BITS> = RuntimeBigNum::from_array(params, to_limbs(sig));
    verify_sha256_pkcs1v15(digest, sig, RSA_EXPONENT)
}

fn main(
    ca_pubkey_hash: pub Field,
    nonce: pub Field,
    app_id: pub Field,
    current_date: pub u32,
    age_threshold: pub u8,
    tbs: [u8; MAX_TBS_LEN],
    tbs_len: u32,
    ca_modulus: [u8; MODULUS_BYTES],
    ca_redc: [u128; LIMBS],
    cert_sig: [u8; MODULUS_BYTES],
    user_redc: [u128; LIMBS],
    nonce_sig: [u8; MODULUS_BYTES],
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

    // (2) Card possession: the holder's key signed NONCE_DOMAIN || app_id || nonce.
    let app_id_bytes: [u8; 32] = app_id.to_be_bytes();
    let nonce_bytes: [u8; 32] = nonce.to_be_bytes();
    let mut msg = [0; 80];
    for i in 0..16 {
        msg[i] = NONCE_DOMAIN[i];
    }
    for i in 0..32 {
        msg[16 + i] = app_id_bytes[i];
        msg[48 + i] = nonce_bytes[i];
    }
    assert(
        verify_rsa_sha256(rsa_params(fields.modulus, user_redc), digest(msg), nonce_sig),
        "nonce signature invalid",
    );

    // (3) Age. Dates are YYYYMMDD integers, so adding threshold * 10000 to the
    // date of birth gives the first day on which the threshold is met.
    let is_over_threshold =
        fields.date_of_birth + (age_threshold as u32) * 10000 <= current_date;

    // (4) Nullifier.
    let nullifier = hash_2([pubkey_hash(fields.modulus), app_id]);

    (nullifier, is_over_threshold)
}
