package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type files struct {
	sod, dg14, dg15, aaNonce, aaSignature []byte
}

// --- ASN.1 structures (RFC 5652, RFC 5280, ICAO Doc 9303 Part 10/11) ---

// SignedData and SignerInfo are read element by element rather than through
// struct tags: encoding/asn1 lets a RawValue field match any element, which would
// mis-assign their optional members.
type signedData struct {
	DigestAlgorithms []pkix.AlgorithmIdentifier
	EContentType     asn1.ObjectIdentifier
	EContent         []byte // the content of the eContent OCTET STRING
	Certificates     []byte // concatenated certificates, if any
	SignerInfos      []signerInfo
}

type signerInfo struct {
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []byte // full encoding with its [0] tag, if present
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// elements splits the content of a constructed value into its members.
func elements(content []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(content) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(content, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		content = rest
	}
	return out, nil
}

func isUniversal(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag
}
func isContext(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassContextSpecific && v.Tag == tag
}

var errStructure = fmt.Errorf("unexpected structure")

func parseSignerInfo(v asn1.RawValue) (signerInfo, error) {
	var si signerInfo
	m, err := elements(v.Bytes)
	if err != nil || len(m) < 5 {
		return si, errStructure
	}
	i := 2 // after version and signer identifier
	if _, err := asn1.Unmarshal(m[i].FullBytes, &si.DigestAlgorithm); err != nil {
		return si, errStructure
	}
	i++
	if isContext(m[i], 0) {
		si.SignedAttrs = m[i].FullBytes
		i++
	}
	if i+1 >= len(m) {
		return si, errStructure
	}
	if _, err := asn1.Unmarshal(m[i].FullBytes, &si.SignatureAlgorithm); err != nil {
		return si, errStructure
	}
	if !isUniversal(m[i+1], asn1.TagOctetString) {
		return si, errStructure
	}
	si.Signature = m[i+1].Bytes
	return si, nil
}

// parseSOD reads EF.SOD: tag 77 around a CMS ContentInfo holding SignedData.
func parseSOD(file []byte) (signedData, error) {
	var sd signedData
	inner, err := unwrap(file, 0x77)
	if err != nil {
		return sd, err
	}
	ci, err := elements(inner)
	if err != nil || len(ci) != 1 {
		return sd, errStructure
	}
	parts, err := elements(ci[0].Bytes) // contentType, [0] content
	if err != nil || len(parts) != 2 || !isContext(parts[1], 0) {
		return sd, errStructure
	}
	wrapped, err := elements(parts[1].Bytes)
	if err != nil || len(wrapped) != 1 {
		return sd, errStructure
	}
	m, err := elements(wrapped[0].Bytes)
	if err != nil || len(m) < 4 {
		return sd, errStructure
	}
	// version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
	algs, err := elements(m[1].Bytes)
	if err != nil {
		return sd, errStructure
	}
	for _, a := range algs {
		var alg pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(a.FullBytes, &alg); err != nil {
			return sd, errStructure
		}
		sd.DigestAlgorithms = append(sd.DigestAlgorithms, alg)
	}
	encap, err := elements(m[2].Bytes)
	if err != nil || len(encap) != 2 || !isContext(encap[1], 0) {
		return sd, errStructure
	}
	if _, err := asn1.Unmarshal(encap[0].FullBytes, &sd.EContentType); err != nil {
		return sd, errStructure
	}
	if _, err := asn1.Unmarshal(encap[1].Bytes, &sd.EContent); err != nil {
		return sd, errStructure
	}
	for _, v := range m[3:] {
		switch {
		case isContext(v, 0):
			sd.Certificates = v.Bytes
		case isUniversal(v, asn1.TagSet):
			infos, err := elements(v.Bytes)
			if err != nil {
				return sd, errStructure
			}
			for _, info := range infos {
				si, err := parseSignerInfo(info)
				if err != nil {
					return sd, err
				}
				sd.SignerInfos = append(sd.SignerInfos, si)
			}
		}
	}
	return sd, nil
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type ldsSecurityObject struct {
	Version       int
	HashAlgorithm pkix.AlgorithmIdentifier
	Hashes        []struct {
		Number int
		Hash   []byte
	}
	Rest asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	TBS struct {
		Raw      asn1.RawContent
		Version  int `asn1:"optional,explicit,default:0,tag:0"`
		Serial   *big.Int
		SigAlg   pkix.AlgorithmIdentifier
		Issuer   asn1.RawValue
		Validity struct{ NotBefore, NotAfter time.Time }
		Subject  asn1.RawValue
		SPKI     subjectPublicKeyInfo
		IssuerID asn1.BitString `asn1:"optional,tag:1"`
		SubjID   asn1.BitString `asn1:"optional,tag:2"`
		Exts     asn1.RawValue  `asn1:"optional,explicit,tag:3"`
	}
	SigAlg pkix.AlgorithmIdentifier
	Sig    asn1.BitString
}

// --- Names for what we may meet ---

var hashes = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.4": crypto.SHA224,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

type sigAlg struct {
	name string
	kind string      // "rsa-pkcs1", "rsa-pss", "ecdsa", "rsa-bare" (hash given elsewhere)
	hash crypto.Hash // 0 when given elsewhere
}

var sigAlgs = map[string]sigAlg{
	"1.2.840.113549.1.1.1":  {"rsaEncryption (hash from digestAlgorithm)", "rsa-pkcs1", 0},
	"1.2.840.113549.1.1.5":  {"sha1WithRSAEncryption", "rsa-pkcs1", crypto.SHA1},
	"1.2.840.113549.1.1.11": {"sha256WithRSAEncryption", "rsa-pkcs1", crypto.SHA256},
	"1.2.840.113549.1.1.12": {"sha384WithRSAEncryption", "rsa-pkcs1", crypto.SHA384},
	"1.2.840.113549.1.1.13": {"sha512WithRSAEncryption", "rsa-pkcs1", crypto.SHA512},
	"1.2.840.113549.1.1.10": {"RSASSA-PSS", "rsa-pss", 0},
	"1.2.840.10045.4.1":     {"ecdsa-with-SHA1", "ecdsa", crypto.SHA1},
	"1.2.840.10045.4.3.1":   {"ecdsa-with-SHA224", "ecdsa", crypto.SHA224},
	"1.2.840.10045.4.3.2":   {"ecdsa-with-SHA256", "ecdsa", crypto.SHA256},
	"1.2.840.10045.4.3.3":   {"ecdsa-with-SHA384", "ecdsa", crypto.SHA384},
	"1.2.840.10045.4.3.4":   {"ecdsa-with-SHA512", "ecdsa", crypto.SHA512},
}

var securityInfoNames = []struct{ prefix, name string }{
	{"2.23.136.1.1.5", "ActiveAuthenticationInfo"},
	{"0.4.0.127.0.7.2.2.4", "PACE"},
	{"0.4.0.127.0.7.2.2.3", "Chip Authentication"},
	{"0.4.0.127.0.7.2.2.1", "Chip Authentication public key"},
	{"0.4.0.127.0.7.2.2.2", "Terminal Authentication"},
}

// ecdsa-plain-* of BSI TR-03111, used to name the Active Authentication algorithm.
var plainECDSA = map[string]crypto.Hash{
	"0.4.0.127.0.7.1.1.4.1.1": crypto.SHA1,
	"0.4.0.127.0.7.1.1.4.1.2": crypto.SHA224,
	"0.4.0.127.0.7.1.1.4.1.3": crypto.SHA256,
	"0.4.0.127.0.7.1.1.4.1.4": crypto.SHA384,
	"0.4.0.127.0.7.1.1.4.1.5": crypto.SHA512,
}

func hashName(h crypto.Hash) string {
	if h == 0 {
		return "?"
	}
	return h.String()
}

// --- Keys ---

type keyInfo struct {
	description string
	rsa         *rsa.PublicKey
	ec          *ecdsa.PublicKey
}

var namedCurves = map[string]elliptic.Curve{
	"1.2.840.10045.3.1.7": elliptic.P256(),
	"1.3.132.0.34":        elliptic.P384(),
	"1.3.132.0.35":        elliptic.P521(),
}

// describeKey names the key type and size. For EC keys given with explicit
// domain parameters (common in passports) it recognises the NIST curves by
// their prime; other curves are reported by size only and cannot be verified here.
func describeKey(spki subjectPublicKeyInfo) keyInfo {
	switch spki.Algorithm.Algorithm.String() {
	case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
		var k struct {
			N *big.Int
			E int
		}
		if _, err := asn1.Unmarshal(spki.PublicKey.RightAlign(), &k); err != nil || k.N == nil {
			return keyInfo{description: "RSA (unreadable key)"}
		}
		return keyInfo{description: fmt.Sprintf("RSA %d bits, e=%d", k.N.BitLen(), k.E), rsa: &rsa.PublicKey{N: k.N, E: k.E}}
	case "1.2.840.10045.2.1":
		var curve elliptic.Curve
		form := ""
		params := spki.Algorithm.Parameters
		if params.Tag == asn1.TagOID {
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(params.FullBytes, &oid); err == nil {
				curve = namedCurves[oid.String()]
				form = "named curve " + oid.String()
			}
		} else {
			var explicit struct {
				Version int
				Field   struct {
					Type  asn1.ObjectIdentifier
					Prime *big.Int
				}
				Rest []asn1.RawValue `asn1:"optional"`
			}
			// Only the prime is needed to recognise the curve; ignore the remaining fields.
			var seq asn1.RawValue
			if _, err := asn1.Unmarshal(params.FullBytes, &seq); err == nil {
				var version int
				rest, err := asn1.Unmarshal(seq.Bytes, &version)
				if err == nil {
					if _, err := asn1.Unmarshal(rest, &explicit.Field); err == nil && explicit.Field.Prime != nil {
						form = fmt.Sprintf("explicit parameters, %d-bit prime", explicit.Field.Prime.BitLen())
						for _, c := range namedCurves {
							if c.Params().P.Cmp(explicit.Field.Prime) == 0 {
								curve = c
							}
						}
					}
				}
			}
		}
		point := spki.PublicKey.RightAlign()
		if curve == nil {
			return keyInfo{description: fmt.Sprintf("EC, %s, not a NIST P curve (point %d bytes)", form, len(point))}
		}
		x, y := elliptic.Unmarshal(curve, point)
		if x == nil {
			return keyInfo{description: fmt.Sprintf("EC %s, %s (unreadable point)", curve.Params().Name, form)}
		}
		return keyInfo{
			description: fmt.Sprintf("EC %s (%s)", curve.Params().Name, form),
			ec:          &ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		}
	}
	return keyInfo{description: "unknown key type " + spki.Algorithm.Algorithm.String()}
}

// verify checks a CMS/X.509 style signature. ok is nil when it could not be checked.
func verify(key keyInfo, alg pkix.AlgorithmIdentifier, fallback crypto.Hash, message, signature []byte) (ok *bool, how string) {
	yes, no := true, false
	a, known := sigAlgs[alg.Algorithm.String()]
	if !known {
		return nil, "unknown signature algorithm"
	}
	h := a.hash
	if h == 0 {
		h = fallback
	}
	if !h.Available() {
		return nil, "hash not available"
	}
	hasher := h.New()
	hasher.Write(message)
	digest := hasher.Sum(nil)
	switch {
	case a.kind == "rsa-pkcs1" && key.rsa != nil:
		if rsa.VerifyPKCS1v15(key.rsa, h, digest, signature) == nil {
			return &yes, "RSA PKCS#1 v1.5, " + hashName(h)
		}
		return &no, "RSA PKCS#1 v1.5, " + hashName(h)
	case a.kind == "rsa-pss" && key.rsa != nil:
		for _, candidate := range []crypto.Hash{h, crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA1} {
			hh := candidate.New()
			hh.Write(message)
			if rsa.VerifyPSS(key.rsa, candidate, hh.Sum(nil), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}) == nil {
				return &yes, "RSASSA-PSS, " + hashName(candidate)
			}
		}
		return &no, "RSASSA-PSS"
	case a.kind == "ecdsa" && key.ec != nil:
		if ecdsa.VerifyASN1(key.ec, digest, signature) {
			return &yes, "ECDSA, " + hashName(h)
		}
		return &no, "ECDSA, " + hashName(h)
	}
	return nil, "key type cannot be checked by this tool"
}

// --- Report ---

type report struct{ strings.Builder }

func (r *report) line(format string, args ...any) { fmt.Fprintf(r, format+"\n", args...) }

func (r *report) check(ok *bool, name, detail string) {
	mark := "n/a "
	if ok != nil {
		mark = map[bool]string{true: "ok  ", false: "FAIL"}[*ok]
	}
	if detail != "" {
		name += " — " + detail
	}
	r.line("[%s] %s", mark, name)
}

func boolp(b bool) *bool { return &b }

func algName(a pkix.AlgorithmIdentifier) string {
	oid := a.Algorithm.String()
	if s, ok := sigAlgs[oid]; ok {
		return s.name + " (" + oid + ")"
	}
	if h, ok := hashes[oid]; ok {
		return h.String() + " (" + oid + ")"
	}
	return oid
}

func dn(raw asn1.RawValue) string {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw.FullBytes, &rdn); err != nil {
		return "(unreadable)"
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	return name.String()
}

// unwrap strips the application tag ICAO puts around a file's content (e.g. 0x77 for EF.SOD).
func unwrap(file []byte, tag byte) ([]byte, error) {
	if len(file) < 2 || file[0] != tag {
		return nil, fmt.Errorf("file does not start with tag %02X", tag)
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(file, &outer); err != nil {
		return nil, err
	}
	return outer.Bytes, nil
}

func inspect(f files) string {
	r := &report{}
	r.line("# Passport signature structure report")
	r.line("# Structure only: algorithms, sizes, object identifiers and check results.")
	r.line("# No hash values, keys or serial numbers, and nothing from the personal data groups.")
	r.line("")

	// ---- EF.SOD ----
	r.line("## Document Security Object (EF.SOD, %d bytes)", len(f.sod))
	sd, err := parseSOD(f.sod)
	if err != nil {
		r.check(boolp(false), "EF.SOD parses as CMS SignedData", "unexpected structure")
		return r.String()
	}
	for _, a := range sd.DigestAlgorithms {
		r.line("digest algorithm:            %s", algName(a))
	}
	r.line("content type:                %s", sd.EContentType)

	var lds ldsSecurityObject
	eContent := sd.EContent
	if _, err := asn1.Unmarshal(eContent, &lds); err != nil {
		r.check(boolp(false), "LDS security object parses", "")
		return r.String()
	}
	ldsHash := hashes[lds.HashAlgorithm.Algorithm.String()]
	var groups []string
	for _, h := range lds.Hashes {
		groups = append(groups, fmt.Sprintf("DG%d", h.Number))
	}
	r.line("LDS security object:         version %d, %d bytes", lds.Version, len(eContent))
	r.line("data group hash algorithm:   %s", algName(lds.HashAlgorithm))
	r.line("data groups covered:         %s", strings.Join(groups, ", "))

	// Document Signer certificate
	var dsc certificate
	dscKey := keyInfo{description: "(no certificate in the SOD)"}
	if len(sd.Certificates) > 0 {
		if _, err := asn1.Unmarshal(sd.Certificates, &dsc); err == nil {
			dscKey = describeKey(dsc.TBS.SPKI)
			r.line("")
			r.line("### Document Signer certificate (%d bytes TBS)", len(dsc.TBS.Raw))
			r.line("issuer (the CSCA):           %s", dn(dsc.TBS.Issuer))
			r.line("subject:                     %s", dn(dsc.TBS.Subject))
			r.line("valid:                       %s to %s", dsc.TBS.Validity.NotBefore.Format("2006-01"), dsc.TBS.Validity.NotAfter.Format("2006-01"))
			r.line("signed by the CSCA with:     %s", algName(dsc.SigAlg))
			if dsc.SigAlg.Algorithm.String() == "1.2.840.113549.1.1.10" {
				r.line("                             (RSASSA-PSS parameters: %d bytes)", len(dsc.SigAlg.Parameters.FullBytes))
			}
			r.line("CSCA signature length:       %d bytes", len(dsc.Sig.RightAlign()))
			r.line("public key:                  %s", dscKey.description)
		} else {
			r.check(boolp(false), "Document Signer certificate parses", "")
		}
	}

	// SignerInfo
	r.line("")
	r.line("### Signature over the security object")
	if len(sd.SignerInfos) != 1 {
		r.check(boolp(false), "exactly one signer", fmt.Sprintf("%d present", len(sd.SignerInfos)))
		return r.String()
	}
	si := sd.SignerInfos[0]
	siHash := hashes[si.DigestAlgorithm.Algorithm.String()]
	r.line("digest algorithm:            %s", algName(si.DigestAlgorithm))
	r.line("signature algorithm:         %s", algName(si.SignatureAlgorithm))
	r.line("signature length:            %d bytes", len(si.Signature))
	r.line("signed attributes:           %d bytes", len(si.SignedAttrs))

	r.line("")
	r.line("## Checks")
	// messageDigest attribute == hash(eContent)
	var attrs []attribute
	signed := append([]byte{}, si.SignedAttrs...)
	if len(signed) > 0 {
		signed[0] = 0x31 // the signature covers the attributes as a SET OF
		_, _ = asn1.UnmarshalWithParams(signed, &attrs, "set")
	}
	digestOK := false
	if siHash.Available() {
		h := siHash.New()
		h.Write(eContent)
		want := h.Sum(nil)
		for _, a := range attrs {
			if a.Type.String() == "1.2.840.113549.1.9.4" {
				var got []byte
				if _, err := asn1.Unmarshal(a.Values.Bytes, &got); err == nil && bytes.Equal(got, want) {
					digestOK = true
				}
			}
		}
	}
	r.check(boolp(digestOK), "signed attributes carry the hash of the security object", hashName(siHash))

	ok, how := verify(dscKey, si.SignatureAlgorithm, siHash, signed, si.Signature)
	r.check(ok, "signature over the signed attributes verifies under the Document Signer key", how)
	r.check(nil, "Document Signer certificate verifies under the CSCA key", "the CSCA certificate is not on the chip; not checked")

	checkGroup := func(number int, file []byte) {
		name := fmt.Sprintf("DG%d matches its hash in the security object", number)
		if file == nil {
			r.check(nil, name, "file not read")
			return
		}
		for _, h := range lds.Hashes {
			if h.Number == number && ldsHash.Available() {
				hh := ldsHash.New()
				hh.Write(file)
				r.check(boolp(bytes.Equal(hh.Sum(nil), h.Hash)), name, hashName(ldsHash))
				return
			}
		}
		r.check(boolp(false), name, "no hash for this data group")
	}
	checkGroup(14, f.dg14)
	checkGroup(15, f.dg15)

	// ---- DG14 ----
	aaHash := crypto.Hash(0)
	r.line("")
	if f.dg14 == nil {
		r.line("## Security infos (DG14): not read")
	} else {
		r.line("## Security infos (DG14, %d bytes)", len(f.dg14))
		var infos []asn1.RawValue
		if body, err := unwrap(f.dg14, 0x6E); err == nil {
			_, err = asn1.UnmarshalWithParams(body, &infos, "set")
			if err != nil {
				r.check(boolp(false), "DG14 parses", "")
			}
		}
		for _, info := range infos {
			var protocol asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(info.Bytes, &protocol)
			if err != nil {
				continue
			}
			label := "unknown"
			for _, n := range securityInfoNames {
				if strings.HasPrefix(protocol.String(), n.prefix) {
					label = n.name
				}
			}
			extra := ""
			if label == "ActiveAuthenticationInfo" {
				var version int
				if rest, err = asn1.Unmarshal(rest, &version); err == nil {
					var alg asn1.ObjectIdentifier
					if _, err := asn1.Unmarshal(rest, &alg); err == nil {
						aaHash = plainECDSA[alg.String()]
						extra = fmt.Sprintf(", signature algorithm %s (ECDSA plain, %s)", alg, hashName(aaHash))
					}
				}
			}
			r.line("- %s: %s%s", label, protocol, extra)
		}
	}

	// ---- DG15 + Active Authentication ----
	r.line("")
	if f.dg15 == nil {
		r.line("## Active Authentication key (DG15): not read")
		return r.String()
	}
	r.line("## Active Authentication (DG15, %d bytes)", len(f.dg15))
	var aaKey keyInfo
	if body, err := unwrap(f.dg15, 0x6F); err == nil {
		var spki subjectPublicKeyInfo
		if _, err := asn1.Unmarshal(body, &spki); err == nil {
			aaKey = describeKey(spki)
		}
	}
	if aaKey.description == "" {
		r.check(boolp(false), "DG15 parses as a public key", "")
		return r.String()
	}
	r.line("chip public key:             %s", aaKey.description)
	if f.aaSignature == nil || len(f.aaNonce) != 8 {
		r.check(nil, "chip signed the nonce", "no Active Authentication signature was obtained")
		return r.String()
	}
	r.line("signature length:            %d bytes", len(f.aaSignature))
	switch {
	case aaKey.ec != nil:
		// Plain format (TR-03111): r | s, each as long as the curve order.
		n := len(f.aaSignature) / 2
		rr, ss := new(big.Int).SetBytes(f.aaSignature[:n]), new(big.Int).SetBytes(f.aaSignature[n:])
		candidates := []crypto.Hash{aaHash, crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA224}
		verified := crypto.Hash(0)
		for _, h := range candidates {
			if h == 0 || !h.Available() || verified != 0 {
				continue
			}
			hh := h.New()
			hh.Write(f.aaNonce)
			if ecdsa.Verify(aaKey.ec, hh.Sum(nil), rr, ss) {
				verified = h
			}
		}
		r.check(boolp(verified != 0), "chip signed the nonce (ECDSA, plain r|s over the hash of the 8-byte nonce)", hashName(verified))
	case aaKey.rsa != nil:
		ok, how := verifyISO9796(aaKey.rsa, f.aaNonce, f.aaSignature)
		r.check(ok, "chip signed the nonce (RSA, ISO/IEC 9796-2 scheme 1)", how)
	default:
		r.check(nil, "chip signed the nonce", "key type cannot be checked by this tool")
	}
	return r.String()
}

// verifyISO9796 checks an Active Authentication signature made with RSA
// (Doc 9303 Part 11, 6.1.2.2): the recovered message is
// 6A | M1 | H(M1 | nonce) | trailer.
func verifyISO9796(pub *rsa.PublicKey, nonce, signature []byte) (*bool, string) {
	yes, no := true, false
	k := (pub.N.BitLen() + 7) / 8
	m := new(big.Int).Exp(new(big.Int).SetBytes(signature), big.NewInt(int64(pub.E)), pub.N)
	em := m.FillBytes(make([]byte, k))
	var h crypto.Hash
	t := 2
	switch {
	case em[k-1] == 0xBC:
		h, t = crypto.SHA1, 1
	case em[k-1] == 0xCC:
		h = map[byte]crypto.Hash{0x38: crypto.SHA224, 0x34: crypto.SHA256, 0x36: crypto.SHA384, 0x35: crypto.SHA512}[em[k-2]]
	}
	if h == 0 || em[0] != 0x6A {
		return &no, "unexpected header or trailer"
	}
	size := h.Size()
	m1, digest := em[1:k-t-size], em[k-t-size:k-t]
	hh := h.New()
	hh.Write(m1)
	hh.Write(nonce)
	if bytes.Equal(hh.Sum(nil), digest) {
		return &yes, hashName(h)
	}
	return &no, hashName(h)
}
