// RSA-2048 keys and signatures as the circuits use them. RSA, SHA-256 and
// Poseidon come from existing libraries; nothing here is hand-rolled cryptography.

use crate::cert::MODULUS_BYTES;
use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon::bn254::hash_9;
use rsa::pkcs1v15::verify_sha256_pkcs1v15;

pub global LIMBS: u32 = 18;
pub global MOD_BITS: u32 = 2048;
global RSA_EXPONENT: u32 = 65537;

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
pub fn pubkey_hash(be: [u8; MODULUS_BYTES]) -> Field {
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

/// `redc` is the Barrett parameter of the modulus: a hint for noir-bignum's
/// unconstrained witness computation that does not affect soundness.
pub fn rsa_params(modulus: [u8; MODULUS_BYTES], redc: [u128; LIMBS]) -> BigNumParams<LIMBS, MOD_BITS> {
    // BigNumParams::new range-checks the limbs and requires the top bit to be set.
    BigNumParams::new(false, to_limbs(modulus), redc)
}

/// RSA PKCS#1 v1.5 verification of a SHA-256 digest, public exponent 65537.
pub fn verify_rsa_sha256(
    params: BigNumParams<LIMBS, MOD_BITS>,
    digest: [u8; 32],
    sig: [u8; MODULUS_BYTES],
) -> bool {
    let sig: RuntimeBigNum<LIMBS, MOD_BITS> = RuntimeBigNum::from_array(params, to_limbs(sig));
    verify_sha256_pkcs1v15(digest, sig, RSA_EXPONENT)
}
