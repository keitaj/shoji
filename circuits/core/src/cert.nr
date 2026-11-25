// Extraction of the holder's public key and date of birth from a TBSCertificate
// shaped like a JPKI signing certificate.
//
// The parser walks the DER structure from the root, so the positions of the key
// and of the date of birth are fixed by the signed bytes. Bytes that merely look
// like a date-of-birth entry inside some other attribute are never visited.

use crate::der::{content_eq, read_tlv, Tlv};

pub global MAX_TBS_LEN: u32 = 2048;
// Slack required after the TBS so fixed-size look-aheads stay inside the buffer.
pub global TBS_HEADROOM: u32 = 16;
pub global MODULUS_BYTES: u32 = 256;
global MAX_EXTENSIONS: u32 = 12;
global MAX_GENERAL_NAMES: u32 = 10;

// subjectPublicKeyInfo of an RSA-2048 key with e = 65537 is always 294 bytes:
// 4-byte header, the 29 bytes below, 256 modulus bytes, then SPKI_SUFFIX.
global SPKI_CONTENT_LEN: u32 = 290;
global SPKI_PREFIX: [u8; 29] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, // AlgorithmIdentifier { rsaEncryption, NULL }
    0x03, 0x82, 0x01, 0x0f, 0x00, // BIT STRING, 0 unused bits
    0x30, 0x82, 0x01, 0x0a, // RSAPublicKey SEQUENCE
    0x02, 0x82, 0x01, 0x01, 0x00, // INTEGER modulus (257 bytes, leading 0x00)
];
// INTEGER publicExponent = 65537
global SPKI_SUFFIX: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];

// id-ce-subjectAltName 2.5.29.17
global OID_SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1d, 0x11];
// Date-of-birth otherName type 1.2.392.200149.8.5.5.4 (confirmed on a real card,
// see docs/open-questions.md).
global OID_DATE_OF_BIRTH: [u8; 10] = [0x2a, 0x83, 0x08, 0x8c, 0x9b, 0x55, 0x08, 0x05, 0x05, 0x04];

global TAG_BOOLEAN: u8 = 0x01;
global TAG_INTEGER: u8 = 0x02;
global TAG_OCTET_STRING: u8 = 0x04;
global TAG_OID: u8 = 0x06;
global TAG_UTF8_STRING: u8 = 0x0c;
global TAG_SEQUENCE: u8 = 0x30;
global TAG_CONTEXT_0: u8 = 0xa0;
global TAG_CONTEXT_3: u8 = 0xa3;

pub struct CertFields {
    // RSA modulus of the holder's key, big-endian.
    pub modulus: [u8; MODULUS_BYTES],
    // Date of birth as the integer YYYYMMDD.
    pub date_of_birth: u32,
}

fn child(tbs: [u8; MAX_TBS_LEN], off: u32, limit: u32, tag: u8) -> Tlv {
    let t = read_tlv(tbs, off, limit);
    assert(t.tag == tag, "TBS: unexpected tag");
    t
}

pub fn parse_tbs(tbs: [u8; MAX_TBS_LEN], tbs_len: u32) -> CertFields {
    assert(tbs_len + TBS_HEADROOM <= MAX_TBS_LEN, "TBS too long");

    // TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer,
    //                               validity, subject, subjectPublicKeyInfo, [3] extensions }
    let root = child(tbs, 0, tbs_len, TAG_SEQUENCE);
    assert(root.end == tbs_len, "TBS: trailing bytes");
    let version = child(tbs, root.start, root.end, TAG_CONTEXT_0);
    let serial = child(tbs, version.end, root.end, TAG_INTEGER);
    let sig_alg = child(tbs, serial.end, root.end, TAG_SEQUENCE);
    let issuer = child(tbs, sig_alg.end, root.end, TAG_SEQUENCE);
    let validity = child(tbs, issuer.end, root.end, TAG_SEQUENCE);
    let subject = child(tbs, validity.end, root.end, TAG_SEQUENCE);
    let spki = child(tbs, subject.end, root.end, TAG_SEQUENCE);
    // issuerUniqueID / subjectUniqueID are not supported: extensions must follow directly.
    let ext_wrap = child(tbs, spki.end, root.end, TAG_CONTEXT_3);
    assert(ext_wrap.end == root.end, "TBS: data after extensions");

    // --- Holder public key ---
    assert(spki.len == SPKI_CONTENT_LEN, "SPKI: not RSA-2048 with e=65537");
    for i in 0..29 {
        assert(tbs[spki.start + i] == SPKI_PREFIX[i], "SPKI: not RSA-2048 with e=65537");
    }
    let mut modulus = [0; MODULUS_BYTES];
    for i in 0..MODULUS_BYTES {
        modulus[i] = tbs[spki.start + 29 + i];
    }
    for i in 0..5 {
        assert(
            tbs[spki.start + 29 + MODULUS_BYTES + i] == SPKI_SUFFIX[i],
            "SPKI: not RSA-2048 with e=65537",
        );
    }

    // --- Locate the subjectAltName extension ---
    // Extensions ::= SEQUENCE OF SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    let exts = child(tbs, ext_wrap.start, ext_wrap.end, TAG_SEQUENCE);
    assert(exts.end == ext_wrap.end, "extensions: trailing bytes");

    let mut san = Tlv { tag: 0, start: 0, len: 0, end: 0 };
    let mut san_found = false;
    let mut cur = exts.start;
    for _ in 0..MAX_EXTENSIONS {
        if cur != exts.end {
            let ext = child(tbs, cur, exts.end, TAG_SEQUENCE);
            let oid = child(tbs, ext.start, ext.end, TAG_OID);
            if content_eq(tbs, oid, OID_SUBJECT_ALT_NAME) {
                assert(!san_found, "extensions: duplicate subjectAltName");
                let mut value = read_tlv(tbs, oid.end, ext.end);
                if value.tag == TAG_BOOLEAN {
                    value = read_tlv(tbs, value.end, ext.end);
                }
                assert(value.tag == TAG_OCTET_STRING, "extensions: bad extnValue");
                assert(value.end == ext.end, "extensions: trailing bytes");
                san = value;
                san_found = true;
            }
            cur = ext.end;
        }
    }
    // Every extension was visited (so none beyond MAX_EXTENSIONS was skipped).
    assert(cur == exts.end, "extensions: too many");
    assert(san_found, "extensions: no subjectAltName");

    // --- Locate the date-of-birth otherName ---
    // GeneralNames ::= SEQUENCE OF GeneralName
    // otherName ::= [0] { type-id OID, value [0] EXPLICIT ANY }
    let names = child(tbs, san.start, san.end, TAG_SEQUENCE);
    assert(names.end == san.end, "subjectAltName: trailing bytes");

    let mut date_of_birth: u32 = 0;
    let mut dob_found = false;
    let mut cur = names.start;
    for _ in 0..MAX_GENERAL_NAMES {
        if cur != names.end {
            let name = read_tlv(tbs, cur, names.end);
            if name.tag == TAG_CONTEXT_0 {
                let oid = child(tbs, name.start, name.end, TAG_OID);
                if content_eq(tbs, oid, OID_DATE_OF_BIRTH) {
                    assert(!dob_found, "subjectAltName: duplicate date of birth");
                    let wrap = child(tbs, oid.end, name.end, TAG_CONTEXT_0);
                    assert(wrap.end == name.end, "date of birth: trailing bytes");
                    let s = read_tlv(tbs, wrap.start, wrap.end);
                    assert(s.tag == TAG_UTF8_STRING, "date of birth: unexpected string type");
                    assert(s.end == wrap.end, "date of birth: trailing bytes");
                    // The value is nine digits: a Japanese era code (1 Meiji .. 5 Reiwa)
                    // followed by the Gregorian date YYYYMMDD. The era digit carries no
                    // extra information, so it is only required to be a digit.
                    assert(s.len == 9, "date of birth: expected era digit + YYYYMMDD");
                    let mut v: u32 = 0;
                    for i in 0..9 {
                        let c = tbs[s.start + i];
                        assert((c >= 0x30) & (c <= 0x39), "date of birth: not a digit");
                        if i != 0 {
                            v = v * 10 + (c - 0x30) as u32;
                        }
                    }
                    date_of_birth = v;
                    dob_found = true;
                }
            }
            cur = name.end;
        }
    }
    assert(cur == names.end, "subjectAltName: too many names");
    assert(dob_found, "subjectAltName: no date of birth");

    CertFields { modulus, date_of_birth }
}
