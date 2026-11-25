// Minimal, fully constrained DER reader.
//
// Nothing in this module is `unconstrained` and no position is ever supplied by
// the prover: every offset is derived by reading tag/length bytes out of the
// (CA-signed) buffer itself, starting from offset 0.

pub struct Tlv {
    pub tag: u8,
    // Offset of the first content byte.
    pub start: u32,
    // Number of content bytes.
    pub len: u32,
    // Offset one past the last content byte (= offset of the next sibling).
    pub end: u32,
}

/// Reads the TLV header at `off`. The whole element must lie inside `[off, limit)`,
/// where `limit` is the end of the enclosing element.
///
/// Accepts only what DER allows for elements shorter than 64 KiB: single-byte
/// tags and minimally encoded definite lengths (short form, 0x81, 0x82).
pub fn read_tlv<let N: u32>(data: [u8; N], off: u32, limit: u32) -> Tlv {
    assert(off + 2 <= limit, "DER: header out of bounds");
    let tag = data[off];
    // High-tag-number form (multi-byte tags) never appears in the structures we walk.
    assert(tag & 0x1f != 0x1f, "DER: multi-byte tag");

    let l0 = data[off + 1];
    let mut hdr: u32 = 2;
    let mut len: u32 = l0 as u32;
    if l0 == 0x81 {
        assert(off + 3 <= limit, "DER: header out of bounds");
        len = data[off + 2] as u32;
        assert(len >= 0x80, "DER: non-minimal length");
        hdr = 3;
    } else if l0 == 0x82 {
        assert(off + 4 <= limit, "DER: header out of bounds");
        len = (data[off + 2] as u32) * 256 + (data[off + 3] as u32);
        assert(len >= 0x100, "DER: non-minimal length");
        hdr = 4;
    } else {
        assert(l0 < 0x80, "DER: unsupported length form");
    }

    let start = off + hdr;
    let end = start + len;
    assert(end <= limit, "DER: element overruns its parent");
    Tlv { tag, start, len, end }
}

/// True iff the content of `t` is exactly `expected`.
/// Requires `t.start + M <= N` (callers guarantee this via the TBS headroom).
pub fn content_eq<let N: u32, let M: u32>(data: [u8; N], t: Tlv, expected: [u8; M]) -> bool {
    let mut eq = t.len == M;
    for i in 0..M {
        eq = eq & (data[t.start + i] == expected[i]);
    }
    eq
}
