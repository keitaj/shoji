//! Builds the circuit inputs from what a phone has after talking to the card:
//! the holder's certificate, the CA certificate, the card's signature over the
//! nonce message, and the verifier's request.
//!
//! This mirrors `internal/witness` on the Go side; a test checks that both
//! produce the same inputs for the same material. The certificate is only ever
//! read here, never logged, and no error message contains anything from it.

use num_bigint::BigUint;
use serde_json::{json, Value};

const MAX_TBS_LEN: usize = 2048;
const TBS_HEADROOM: usize = 16;
const MODULUS_BYTES: usize = 256;
const NUM_LIMBS: usize = 18;
const LIMB_BITS: u64 = 120;
/// BARRETT_REDUCTION_OVERFLOW_BITS in noir-bignum.
const BARRETT_OVERFLOW_BITS: u64 = 6;

/// subjectPublicKeyInfo content of an RSA-2048 key with e = 65537: this prefix,
/// 256 modulus bytes, then the suffix (the same pattern the circuit enforces).
const SPKI_PREFIX: [u8; 29] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
];
const SPKI_SUFFIX: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];

/// One DER element: its tag, its content, and its full encoding (header included).
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    raw: &'a [u8],
}

/// Reads the element at the start of `data` and returns it with the rest.
fn read_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let err = || "certificate: malformed DER".to_string();
    if data.len() < 2 {
        return Err(err());
    }
    let (header, len) = match data[1] {
        l if l < 0x80 => (2, l as usize),
        0x81 if data.len() >= 3 => (3, data[2] as usize),
        0x82 if data.len() >= 4 => (4, (data[2] as usize) << 8 | data[3] as usize),
        _ => return Err(err()),
    };
    let end = header + len;
    if end > data.len() {
        return Err(err());
    }
    Ok((Tlv { tag: data[0], content: &data[header..end], raw: &data[..end] }, &data[end..]))
}

/// What the circuit needs from one certificate.
struct Certificate<'a> {
    /// The complete TBSCertificate encoding (the bytes the issuer signed).
    tbs: &'a [u8],
    /// The issuer's signature.
    signature: &'a [u8],
    /// The subject's RSA modulus, big-endian.
    modulus: &'a [u8],
}

fn parse_certificate(der: &[u8]) -> Result<Certificate<'_>, String> {
    let shape = || "certificate: unexpected structure".to_string();
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
    let (cert, rest) = read_tlv(der)?;
    if cert.tag != 0x30 || !rest.is_empty() {
        return Err(shape());
    }
    let (tbs, rest) = read_tlv(cert.content)?;
    let (_algorithm, rest) = read_tlv(rest)?;
    let (sig, rest) = read_tlv(rest)?;
    if tbs.tag != 0x30 || sig.tag != 0x03 || !rest.is_empty() {
        return Err(shape());
    }
    // BIT STRING: one leading "unused bits" byte, which must be zero.
    if sig.content.len() != MODULUS_BYTES + 1 || sig.content[0] != 0 {
        return Err("certificate: signature is not RSA-2048".to_string());
    }

    // TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer,
    //                               validity, subject, subjectPublicKeyInfo, ... }
    let mut fields = tbs.content;
    let mut spki = None;
    for index in 0..7 {
        let (field, rest) = read_tlv(fields)?;
        fields = rest;
        if index == 6 {
            spki = Some(field);
        }
    }
    let spki = spki.ok_or_else(shape)?;
    let c = spki.content;
    if spki.tag != 0x30
        || c.len() != SPKI_PREFIX.len() + MODULUS_BYTES + SPKI_SUFFIX.len()
        || c[..SPKI_PREFIX.len()] != SPKI_PREFIX
        || c[SPKI_PREFIX.len() + MODULUS_BYTES..] != SPKI_SUFFIX
    {
        return Err("certificate: key is not RSA-2048 with e=65537".to_string());
    }
    Ok(Certificate {
        tbs: tbs.raw,
        signature: &sig.content[1..],
        modulus: &c[SPKI_PREFIX.len()..SPKI_PREFIX.len() + MODULUS_BYTES],
    })
}

/// noir-bignum's Barrett parameter floor(2^(2*2048+6) / modulus) as 18
/// little-endian 120-bit limbs. Only a hint for witness generation.
fn redc_limbs(modulus: &[u8]) -> Result<Vec<String>, String> {
    let n = BigUint::from_bytes_be(modulus);
    if n.bits() != (MODULUS_BYTES * 8) as u64 {
        return Err("certificate: modulus is not exactly 2048 bits".to_string());
    }
    let mut rest = (BigUint::from(1u8) << (2 * MODULUS_BYTES as u64 * 8 + BARRETT_OVERFLOW_BITS)) / n;
    let mask = (BigUint::from(1u8) << LIMB_BITS) - 1u8;
    let mut limbs = Vec::with_capacity(NUM_LIMBS);
    for _ in 0..NUM_LIMBS {
        limbs.push(format!("0x{}", (&rest & &mask).to_str_radix(16)));
        rest >>= LIMB_BITS;
    }
    Ok(limbs)
}

fn bytes(b: &[u8]) -> Value {
    Value::Array(b.iter().map(|&v| Value::from(v)).collect())
}

/// A field element given as "0x" + up to 64 hex digits, normalised to 64 digits.
fn field_hex(text: &str, what: &str) -> Result<String, String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("request: {what} is not a field element"));
    }
    Ok(format!("0x{:0>64}", digits.to_ascii_lowercase()))
}

/// The verifier's request as relayed to the phone:
/// `{"challenge": "shoji1:<app_id>:<nonce>", "current_date": 20261123,
///   "age_threshold": 18, "ca_pubkey_hash": "0x..."}`
pub struct Request {
    pub app_id: String,
    pub nonce: String,
    pub current_date: u32,
    pub age_threshold: u8,
    pub ca_pubkey_hash: String,
}

impl Request {
    pub fn parse(json_text: &str) -> Result<Request, String> {
        let bad = || "request: malformed".to_string();
        let v: Value = serde_json::from_str(json_text).map_err(|_| bad())?;
        let challenge = v["challenge"].as_str().ok_or_else(bad)?;
        let parts: Vec<&str> = challenge.split(':').collect();
        if parts.len() != 3 || parts[0] != "shoji1" || parts[1].len() != 64 || parts[2].len() != 64 {
            return Err(bad());
        }
        Ok(Request {
            app_id: field_hex(parts[1], "app_id")?,
            nonce: field_hex(parts[2], "nonce")?,
            current_date: v["current_date"].as_u64().and_then(|d| u32::try_from(d).ok()).ok_or_else(bad)?,
            age_threshold: v["age_threshold"].as_u64().and_then(|d| u8::try_from(d).ok()).ok_or_else(bad)?,
            ca_pubkey_hash: field_hex(v["ca_pubkey_hash"].as_str().ok_or_else(bad)?, "ca_pubkey_hash")?,
        })
    }
}

/// Assembles the inputs of `main` as JSON, keyed by parameter name.
pub fn build_inputs(
    certificate_der: &[u8],
    ca_certificate_der: &[u8],
    nonce_signature: &[u8],
    request: &Request,
) -> Result<String, String> {
    let cert = parse_certificate(certificate_der)?;
    let ca = parse_certificate(ca_certificate_der)?;
    if cert.tbs.len() + TBS_HEADROOM > MAX_TBS_LEN {
        return Err("certificate: too long for the circuit".to_string());
    }
    if nonce_signature.len() != MODULUS_BYTES {
        return Err("signature: not 256 bytes".to_string());
    }
    let mut tbs = cert.tbs.to_vec();
    tbs.resize(MAX_TBS_LEN, 0);

    let inputs = json!({
        "ca_pubkey_hash": request.ca_pubkey_hash,
        "nonce": request.nonce,
        "app_id": request.app_id,
        "current_date": request.current_date,
        "age_threshold": request.age_threshold,
        "tbs": bytes(&tbs),
        "tbs_len": cert.tbs.len(),
        "ca_modulus": bytes(ca.modulus),
        "ca_redc": redc_limbs(ca.modulus)?,
        "cert_sig": bytes(cert.signature),
        "user_redc": redc_limbs(cert.modulus)?,
        "nonce_sig": bytes(nonce_signature),
    });
    Ok(inputs.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, path::PathBuf};

    /// Directory written by `go run ./cmd/genfixtures -card-fixture <dir>`.
    fn fixture() -> Option<PathBuf> {
        env::var_os("SHOJI_CARD_FIXTURE").map(PathBuf::from)
    }

    #[test]
    fn matches_the_go_implementation() {
        let Some(dir) = fixture() else {
            eprintln!("SHOJI_CARD_FIXTURE not set; skipping");
            return;
        };
        let read = |name: &str| fs::read(dir.join(name)).unwrap();
        let request = Request::parse(&String::from_utf8(read("request.json")).unwrap()).unwrap();
        let got = build_inputs(&read("cert.der"), &read("ca.der"), &read("nonce_sig.bin"), &request).unwrap();
        let got: Value = serde_json::from_str(&got).unwrap();
        let want: Value = serde_json::from_slice(&read("inputs.json")).unwrap();
        assert!(got == want, "inputs differ from the Go implementation");
    }

    #[test]
    fn rejects_material_that_is_not_what_it_should_be() {
        let Some(dir) = fixture() else { return };
        let read = |name: &str| fs::read(dir.join(name)).unwrap();
        let request = Request::parse(&String::from_utf8(read("request.json")).unwrap()).unwrap();
        let (cert, ca, sig) = (read("cert.der"), read("ca.der"), read("nonce_sig.bin"));

        assert!(build_inputs(&cert[..cert.len() - 1], &ca, &sig, &request).is_err(), "truncated certificate");
        assert!(build_inputs(&[cert.clone(), vec![0]].concat(), &ca, &sig, &request).is_err(), "trailing bytes");
        assert!(build_inputs(&cert, &ca, &sig[1..], &request).is_err(), "short signature");
        assert!(build_inputs(b"not a certificate", &ca, &sig, &request).is_err());
    }

    #[test]
    fn request_parsing_is_strict() {
        let app = "0".repeat(64);
        let ok = format!(r#"{{"challenge":"shoji1:{app}:{app}","current_date":20261123,"age_threshold":18,"ca_pubkey_hash":"0x01"}}"#);
        let r = Request::parse(&ok).unwrap();
        assert_eq!(r.ca_pubkey_hash, format!("0x{}1", "0".repeat(63)));
        for bad in [
            "",
            "{}",
            &ok.replace("shoji1", "shoji2"),
            &ok.replace("20261123", "\"today\""),
            &ok.replace(":18,", ":300,"),
            &ok.replace("0x01", "0xzz"),
            &ok.replace(&format!(":{app}\""), ":1234\""),
        ] {
            assert!(Request::parse(bad).is_err(), "should reject: {bad}");
        }
    }
}
