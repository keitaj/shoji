//! C interface, used from Swift.

use std::ffi::{c_char, CString};
use std::slice;

/// Result of `shoji_prove`. Exactly one of (`proof`, `public_inputs`) or `error`
/// is set. Release with `shoji_result_free`.
#[repr(C)]
pub struct ShojiProveResult {
    pub proof: *mut u8,
    pub proof_len: usize,
    pub public_inputs: *mut u8,
    pub public_inputs_len: usize,
    /// NUL-terminated message, or null on success. Never contains input values.
    pub error: *mut c_char,
}

fn leak(mut v: Vec<u8>) -> (*mut u8, usize) {
    v.shrink_to_fit();
    let len = v.len();
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    (ptr, len)
}

/// Generates a proof. See `crate::prove`.
///
/// # Safety
/// Each pointer must be valid for reads of the given number of bytes.
/// `circuit_json` and `inputs_json` must be UTF-8.
#[no_mangle]
pub unsafe extern "C" fn shoji_prove(
    circuit_json: *const u8,
    circuit_json_len: usize,
    inputs_json: *const u8,
    inputs_json_len: usize,
    srs_g1: *const u8,
    srs_g1_len: usize,
    verification_key: *const u8,
    verification_key_len: usize,
) -> ShojiProveResult {
    let fail = |msg: &str| ShojiProveResult {
        proof: std::ptr::null_mut(),
        proof_len: 0,
        public_inputs: std::ptr::null_mut(),
        public_inputs_len: 0,
        error: CString::new(msg).unwrap_or_default().into_raw(),
    };
    if circuit_json.is_null() || inputs_json.is_null() || srs_g1.is_null() || verification_key.is_null() {
        return fail("null argument");
    }
    let circuit = match std::str::from_utf8(slice::from_raw_parts(circuit_json, circuit_json_len)) {
        Ok(s) => s,
        Err(_) => return fail("circuit: not UTF-8"),
    };
    let inputs = match std::str::from_utf8(slice::from_raw_parts(inputs_json, inputs_json_len)) {
        Ok(s) => s,
        Err(_) => return fail("inputs: not UTF-8"),
    };
    let srs = slice::from_raw_parts(srs_g1, srs_g1_len);
    let vk = slice::from_raw_parts(verification_key, verification_key_len);

    match crate::prove(circuit, inputs, srs, vk) {
        Ok(out) => {
            let (proof, proof_len) = leak(out.proof);
            let (public_inputs, public_inputs_len) = leak(out.public_inputs);
            ShojiProveResult { proof, proof_len, public_inputs, public_inputs_len, error: std::ptr::null_mut() }
        }
        Err(msg) => fail(&msg),
    }
}

/// Generates a proof from the card material. See `crate::prove_card`.
///
/// # Safety
/// Each pointer must be valid for reads of the given number of bytes.
/// `circuit_json` and `request_json` must be UTF-8.
#[no_mangle]
pub unsafe extern "C" fn shoji_prove_card(
    circuit_json: *const u8,
    circuit_json_len: usize,
    certificate: *const u8,
    certificate_len: usize,
    ca_certificate: *const u8,
    ca_certificate_len: usize,
    nonce_signature: *const u8,
    nonce_signature_len: usize,
    request_json: *const u8,
    request_json_len: usize,
    srs_g1: *const u8,
    srs_g1_len: usize,
    verification_key: *const u8,
    verification_key_len: usize,
) -> ShojiProveResult {
    let fail = |msg: &str| ShojiProveResult {
        proof: std::ptr::null_mut(),
        proof_len: 0,
        public_inputs: std::ptr::null_mut(),
        public_inputs_len: 0,
        error: CString::new(msg).unwrap_or_default().into_raw(),
    };
    if circuit_json.is_null()
        || certificate.is_null()
        || ca_certificate.is_null()
        || nonce_signature.is_null()
        || request_json.is_null()
        || srs_g1.is_null()
        || verification_key.is_null()
    {
        return fail("null argument");
    }
    let circuit = match std::str::from_utf8(slice::from_raw_parts(circuit_json, circuit_json_len)) {
        Ok(s) => s,
        Err(_) => return fail("circuit: not UTF-8"),
    };
    let request = match std::str::from_utf8(slice::from_raw_parts(request_json, request_json_len)) {
        Ok(s) => s,
        Err(_) => return fail("request: not UTF-8"),
    };
    match crate::prove_card(
        circuit,
        slice::from_raw_parts(certificate, certificate_len),
        slice::from_raw_parts(ca_certificate, ca_certificate_len),
        slice::from_raw_parts(nonce_signature, nonce_signature_len),
        request,
        slice::from_raw_parts(srs_g1, srs_g1_len),
        slice::from_raw_parts(verification_key, verification_key_len),
    ) {
        Ok(out) => {
            let (proof, proof_len) = leak(out.proof);
            let (public_inputs, public_inputs_len) = leak(out.public_inputs);
            ShojiProveResult { proof, proof_len, public_inputs, public_inputs_len, error: std::ptr::null_mut() }
        }
        Err(msg) => fail(&msg),
    }
}

/// Releases the buffers of a `ShojiProveResult`.
///
/// # Safety
/// `result` must come from `shoji_prove` and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn shoji_result_free(result: ShojiProveResult) {
    if !result.proof.is_null() {
        drop(Vec::from_raw_parts(result.proof, result.proof_len, result.proof_len));
    }
    if !result.public_inputs.is_null() {
        drop(Vec::from_raw_parts(result.public_inputs, result.public_inputs_len, result.public_inputs_len));
    }
    if !result.error.is_null() {
        drop(CString::from_raw(result.error));
    }
}
