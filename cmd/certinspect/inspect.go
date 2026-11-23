package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/keitaj/shoji/internal/mockjpki"
	"github.com/keitaj/shoji/internal/proto"
)

// Limits mirrored from circuits/src/cert.nr.
const (
	maxExtensions   = 12
	maxGeneralNames = 10
)

func readCert(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		return block.Bytes, nil
	}
	return raw, nil
}

type tlv struct {
	class, tag  int
	constructed bool
	content     []byte
	total       int // header + content
}

func readTLV(b []byte) (tlv, error) {
	if len(b) < 2 {
		return tlv{}, errors.New("truncated element")
	}
	t := tlv{class: int(b[0] >> 6), tag: int(b[0] & 0x1f), constructed: b[0]&0x20 != 0}
	if t.tag == 0x1f {
		return tlv{}, errors.New("multi-byte tag")
	}
	hdr, n := 2, int(b[1])
	switch {
	case b[1] < 0x80:
	case b[1] == 0x81 && len(b) >= 3:
		hdr, n = 3, int(b[2])
	case b[1] == 0x82 && len(b) >= 4:
		hdr, n = 4, int(b[2])<<8|int(b[3])
	default:
		return tlv{}, errors.New("unsupported length form")
	}
	if hdr+n > len(b) {
		return tlv{}, errors.New("element overruns its parent")
	}
	t.content, t.total = b[hdr:hdr+n], hdr+n
	return t, nil
}

func children(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		t, err := readTLV(b)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		b = b[t.total:]
	}
	return out, nil
}

var universalNames = map[int]string{
	1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING", 5: "NULL", 6: "OID",
	12: "UTF8String", 16: "SEQUENCE", 17: "SET", 19: "PrintableString", 20: "T61String",
	22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime", 30: "BMPString",
}

func (t tlv) name() string {
	if t.class == 0 {
		if n, ok := universalNames[t.tag]; ok {
			return n
		}
		return fmt.Sprintf("UNIVERSAL %d", t.tag)
	}
	return fmt.Sprintf("[%d]", t.tag)
}

func (t tlv) isString() bool {
	return t.class == 0 && (t.tag == 12 || t.tag == 19 || t.tag == 20 || t.tag == 22 || t.tag == 30)
}

func oidString(content []byte) string {
	var oid asn1.ObjectIdentifier
	full := append([]byte{0x06, byte(len(content))}, content...)
	if len(content) > 127 {
		return "?"
	}
	if _, err := asn1.Unmarshal(full, &oid); err != nil {
		return "?"
	}
	return oid.String()
}

// charClasses describes a string by character class only, never by content:
// D = ASCII digit, A = ASCII letter, S = other ASCII, X = non-ASCII byte.
func charClasses(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			sb.WriteByte('D')
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			sb.WriteByte('A')
		case c < 0x80:
			sb.WriteByte('S')
		default:
			sb.WriteByte('X')
		}
	}
	return sb.String()
}

// describe returns what may be shown for a primitive element. Contents are
// shown only where they are structural: OIDs, booleans and tiny integers.
// Strings are reduced to character classes, and only when short and pure ASCII.
func describe(t tlv) string {
	switch {
	case t.class == 0 && t.tag == 6:
		return oidString(t.content)
	case t.class == 0 && t.tag == 1 && len(t.content) == 1:
		return fmt.Sprintf("%v", t.content[0] != 0)
	case t.class == 0 && t.tag == 2 && len(t.content) <= 3:
		v := 0
		for _, c := range t.content {
			v = v<<8 | int(c)
		}
		return fmt.Sprintf("%d", v)
	case t.isString() && len(t.content) <= 16 && !strings.Contains(charClasses(t.content), "X"):
		return "classes " + charClasses(t.content)
	case t.isString():
		return "(contents hidden)"
	}
	return ""
}

// dump writes the element tree. OCTET STRING and BIT STRING wrappers that hold
// DER (extension values, the public key) are descended into when asked.
func dump(sb *strings.Builder, t tlv, depth int, decodeWrapped bool) {
	fmt.Fprintf(sb, "%s%s len=%d", strings.Repeat("  ", depth), t.name(), len(t.content))
	if d := describe(t); d != "" && !t.constructed {
		fmt.Fprintf(sb, "  %s", d)
	}
	sb.WriteByte('\n')
	inner := t.content
	switch {
	case t.constructed:
	case decodeWrapped && t.class == 0 && t.tag == 4:
	case decodeWrapped && t.class == 0 && t.tag == 3 && len(inner) > 0 && inner[0] == 0:
		inner = inner[1:]
	default:
		return
	}
	kids, err := children(inner)
	if err != nil || len(kids) == 0 {
		return // not DER inside: leave it opaque
	}
	if !t.constructed {
		// Only treat a wrapper as DER when it is a single well-formed constructed element.
		if len(kids) != 1 || !kids[0].constructed {
			return
		}
	}
	for _, k := range kids {
		dump(sb, k, depth+1, decodeWrapped)
	}
}

type check struct {
	name   string
	ok     bool
	detail string
}

func inspect(certDER, caDER []byte) (string, error) {
	var sb strings.Builder
	sb.WriteString("# Certificate structure report\n")
	sb.WriteString("# Contents are not shown: only tags, lengths, OIDs, booleans, tiny integers and\n")
	sb.WriteString("# character classes of short ASCII strings (D digit, A letter, S other ASCII).\n")
	sb.WriteString("# Lengths can still hint at the holder; review before sharing this report.\n\n")

	cert, err := readTLV(certDER)
	if err != nil {
		return "", fmt.Errorf("certificate: %w", err)
	}
	parts, err := children(cert.content)
	if err != nil || len(parts) != 3 {
		return "", errors.New("certificate: expected SEQUENCE { tbs, signatureAlgorithm, signature }")
	}
	tbs := parts[0]
	hdr := cert.total - len(cert.content)
	tbsDER := certDER[hdr : hdr+tbs.total]

	fmt.Fprintf(&sb, "total certificate length: %d bytes\n", len(certDER))
	fmt.Fprintf(&sb, "TBSCertificate length:    %d bytes (circuit limit %d)\n", tbs.total, proto.MaxTBSLen-proto.TBSHeadroom)
	fmt.Fprintf(&sb, "signature length:         %d bytes\n\n", len(parts[2].content)-1)

	sb.WriteString("## TBSCertificate\n")
	dump(&sb, tbs, 0, true)
	sb.WriteString("\n## signatureAlgorithm\n")
	dump(&sb, parts[1], 0, false)

	sb.WriteString("\n## Checks against the current circuit\n")
	for _, c := range runChecks(tbsDER, tbs, parts[1], certDER, caDER) {
		mark := "ok  "
		if !c.ok {
			mark = "FAIL"
		}
		fmt.Fprintf(&sb, "[%s] %s", mark, c.name)
		if c.detail != "" {
			fmt.Fprintf(&sb, " — %s", c.detail)
		}
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

var (
	oidSHA256WithRSA  = "1.2.840.113549.1.1.11"
	oidSubjectAltName = "2.5.29.17"
	spkiPrefix        = []byte{
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
		0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
	}
	spkiSuffix = []byte{0x02, 0x03, 0x01, 0x00, 0x01}
)

func runChecks(tbsDER []byte, tbs, sigAlg tlv, certDER, caDER []byte) []check {
	var out []check
	add := func(name string, ok bool, detail string) { out = append(out, check{name, ok, detail}) }

	add("TBS fits the circuit buffer", len(tbsDER)+proto.TBSHeadroom <= proto.MaxTBSLen, fmt.Sprintf("%d bytes", len(tbsDER)))

	alg, _ := children(sigAlg.content)
	algOID := ""
	if len(alg) > 0 {
		algOID = oidString(alg[0].content)
	}
	add("signature algorithm is sha256WithRSAEncryption", algOID == oidSHA256WithRSA, algOID)

	f, err := children(tbs.content)
	wantTags := []struct {
		class, tag int
		what       string
	}{{2, 0, "[0] version"}, {0, 2, "serialNumber"}, {0, 16, "signature"}, {0, 16, "issuer"}, {0, 16, "validity"}, {0, 16, "subject"}, {0, 16, "subjectPublicKeyInfo"}, {2, 3, "[3] extensions"}}
	shape := err == nil && len(f) == len(wantTags)
	detail := ""
	if err == nil && len(f) != len(wantTags) {
		detail = fmt.Sprintf("%d top-level fields, expected %d (unique IDs present?)", len(f), len(wantTags))
	}
	if shape {
		for i, w := range wantTags {
			if f[i].class != w.class || f[i].tag != w.tag {
				shape, detail = false, "unexpected element where "+w.what+" should be"
				break
			}
		}
	}
	add("TBS has exactly version, serial, signature, issuer, validity, subject, SPKI, extensions", shape, detail)
	if !shape {
		return out
	}

	spki := f[6].content
	spkiOK := len(spki) == 290 && bytes.HasPrefix(spki, spkiPrefix) && bytes.HasSuffix(spki, spkiSuffix)
	add("holder key is RSA-2048 with e=65537 in the expected encoding", spkiOK, fmt.Sprintf("SPKI content %d bytes", len(spki)))

	extSeq, err := readTLV(f[7].content)
	var exts []tlv
	if err == nil {
		exts, err = children(extSeq.content)
	}
	if err != nil {
		add("extensions parse", false, err.Error())
		return out
	}
	add(fmt.Sprintf("at most %d extensions", maxExtensions), len(exts) <= maxExtensions, fmt.Sprintf("%d present", len(exts)))

	var san []byte
	sanCount := 0
	var extOIDs []string
	for _, e := range exts {
		kids, err := children(e.content)
		if err != nil || len(kids) < 2 {
			continue
		}
		oid := oidString(kids[0].content)
		extOIDs = append(extOIDs, oid)
		if oid == oidSubjectAltName {
			sanCount++
			san = kids[len(kids)-1].content
		}
	}
	add("exactly one subjectAltName extension", sanCount == 1, "extensions: "+strings.Join(extOIDs, ", "))
	if sanCount != 1 {
		return out
	}

	names, err := readTLV(san)
	var gns []tlv
	if err == nil {
		gns, err = children(names.content)
	}
	if err != nil {
		add("subjectAltName parses", false, err.Error())
		return out
	}
	add(fmt.Sprintf("at most %d subjectAltName entries", maxGeneralNames), len(gns) <= maxGeneralNames, fmt.Sprintf("%d present", len(gns)))

	wantDOB := mockjpki.OIDDateOfBirth.String()
	dobCount, dobDetail, dobOK := 0, "", false
	var otherOIDs []string
	for _, gn := range gns {
		if gn.class != 2 || gn.tag != 0 {
			otherOIDs = append(otherOIDs, "non-otherName "+gn.name())
			continue
		}
		kids, err := children(gn.content)
		if err != nil || len(kids) != 2 {
			otherOIDs = append(otherOIDs, "malformed otherName")
			continue
		}
		oid := oidString(kids[0].content)
		val, verr := readTLV(kids[1].content)
		desc := oid
		if verr == nil {
			desc += fmt.Sprintf(" (%s, %d bytes", val.name(), len(val.content))
			if d := describe(val); strings.HasPrefix(d, "classes ") {
				desc += ", " + d
			}
			desc += ")"
		}
		otherOIDs = append(otherOIDs, desc)
		if oid == wantDOB {
			dobCount++
			wrapOK := kids[1].class == 2 && kids[1].tag == 0 && verr == nil && val.total == len(kids[1].content)
			typeOK := verr == nil && val.class == 0 && val.tag == 12
			dobOK = wrapOK && typeOK && charClasses(val.content) == "DDDDDDDDD"
			if verr == nil {
				dobDetail = fmt.Sprintf("%s, classes %s", val.name(), charClasses(val.content))
			}
		}
	}
	add("otherName entries", true, strings.Join(otherOIDs, "; "))
	add("exactly one date-of-birth otherName with OID "+wantDOB, dobCount == 1, fmt.Sprintf("%d found", dobCount))
	add("date of birth is a UTF8String of 9 digits (era code + YYYYMMDD) in [0] EXPLICIT", dobCount == 1 && dobOK, dobDetail)

	if caDER == nil {
		add("certificate verifies under the issuer key", false, "no -ca given, not checked")
		return out
	}
	// From here on the standard library is used; a certificate it cannot parse is reported, not fatal.
	cert, err1 := x509.ParseCertificate(certDER)
	ca, err2 := x509.ParseCertificate(caDER)
	if err1 != nil || err2 != nil {
		add("certificates parse with Go's x509", false, "parse error (structure differs from what Go accepts)")
		return out
	}
	caPub, isRSA := ca.PublicKey.(*rsa.PublicKey)
	add("issuer key is RSA-2048 with e=65537", isRSA && caPub.N.BitLen() == 2048 && caPub.E == 65537, "")
	add("issuer certificate is self-signed (single-level hierarchy)", verifyUnder(ca, caPub, isRSA), "")
	add("certificate verifies under the issuer key", verifyUnder(cert, caPub, isRSA), "")
	return out
}

// verifyUnder reports whether cert's signature verifies under pub, without
// requiring the issuer to carry CA extensions.
func verifyUnder(cert *x509.Certificate, caPub *rsa.PublicKey, isRSA bool) bool {
	if !isRSA {
		return false
	}
	issuer := &x509.Certificate{PublicKey: caPub, PublicKeyAlgorithm: x509.RSA}
	return issuer.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
