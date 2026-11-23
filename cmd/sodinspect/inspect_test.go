package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The tests build a synthetic passport: a CSCA, a Document Signer certificate,
// a security object over two data groups, and Active Authentication material.

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func tlv(class, tag int, content []byte) asn1.RawValue {
	return asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: content}
}

func der(v any) []byte { return must(asn1.Marshal(v)) }

var (
	oidSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidLDS         = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	oidContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMsgDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAAProtocol  = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 5}
	oidPlainSHA256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1, 3}
)

type synthetic struct {
	files files
	// secrets that must never appear in a report
	secrets []string
}

// build makes a passport whose Document Signer key is `signer` (ECDSA or RSA)
// and whose chip key is `chip`.
func build(t *testing.T, signer crypto.Signer, sigAlgOID asn1.ObjectIdentifier, chip crypto.Signer) synthetic {
	t.Helper()
	csca := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	cscaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Country: []string{"UT"}, CommonName: "Utopia CSCA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(15, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	cscaCert := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, cscaTmpl, cscaTmpl, &csca.PublicKey, csca))))
	serial := new(big.Int).SetBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78})
	dscDER := must(x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{Country: []string{"UT"}, CommonName: "Utopia Document Signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
	}, cscaCert, signer.Public(), csca))

	// Chip key and data groups.
	dg15 := der(tlv(asn1.ClassApplication, 15, must(x509.MarshalPKIXPublicKey(chip.Public()))))
	aaInfo := der(struct {
		Protocol asn1.ObjectIdentifier
		Version  int
		Alg      asn1.ObjectIdentifier
	}{oidAAProtocol, 1, oidPlainSHA256})
	dg14 := der(tlv(asn1.ClassApplication, 14, der(tlv(asn1.ClassUniversal, asn1.TagSet, aaInfo))))
	dg1 := []byte("a stand-in for the personal data group")

	hash := func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	type dgHash struct {
		Number int
		Hash   []byte
	}
	lds := der(struct {
		Version int
		Alg     pkix.AlgorithmIdentifier
		Hashes  []dgHash
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, []dgHash{{1, hash(dg1)}, {14, hash(dg14)}, {15, hash(dg15)}}})

	attr := func(oid asn1.ObjectIdentifier, value any) []byte {
		return der(struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		}{oid, tlv(asn1.ClassUniversal, asn1.TagSet, der(value))})
	}
	attrs := append(attr(oidContentType, oidLDS), attr(oidMsgDigest, hash(lds))...)
	toSign := der(tlv(asn1.ClassUniversal, asn1.TagSet, attrs))
	signature := must(signer.Sign(rand.Reader, hash(toSign), crypto.SHA256))

	signerInfo := der(struct {
		Version     int
		SID         asn1.RawValue
		DigestAlg   pkix.AlgorithmIdentifier
		SignedAttrs asn1.RawValue
		SigAlg      pkix.AlgorithmIdentifier
		Signature   []byte
	}{1, tlv(asn1.ClassUniversal, asn1.TagSequence, der(serial)), pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		tlv(asn1.ClassContextSpecific, 0, attrs), pkix.AlgorithmIdentifier{Algorithm: sigAlgOID}, signature})

	sd := der(struct {
		Version      int
		DigestAlgs   asn1.RawValue
		Encap        asn1.RawValue
		Certificates asn1.RawValue
		SignerInfos  asn1.RawValue
	}{3,
		tlv(asn1.ClassUniversal, asn1.TagSet, der(pkix.AlgorithmIdentifier{Algorithm: oidSHA256})),
		tlv(asn1.ClassUniversal, asn1.TagSequence, append(der(oidLDS), der(tlv(asn1.ClassContextSpecific, 0, der(lds)))...)),
		tlv(asn1.ClassContextSpecific, 0, dscDER),
		tlv(asn1.ClassUniversal, asn1.TagSet, signerInfo)})
	ci := der(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, tlv(asn1.ClassContextSpecific, 0, sd)})
	sod := der(tlv(asn1.ClassApplication, 23, ci))
	if sod[0] != 0x77 || dg15[0] != 0x6F || dg14[0] != 0x6E {
		t.Fatalf("unexpected file tags %02x %02x %02x", sod[0], dg15[0], dg14[0])
	}

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	var aaSig []byte
	switch k := chip.(type) {
	case *ecdsa.PrivateKey:
		r, s := must2(ecdsa.Sign(rand.Reader, k, hash(nonce)))
		size := (k.Curve.Params().N.BitLen() + 7) / 8
		aaSig = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	case *rsa.PrivateKey:
		// ISO/IEC 9796-2 scheme 1 as used by Active Authentication: 6A | M1 | H(M1|nonce) | 34 CC.
		size := k.Size()
		m1 := make([]byte, size-1-32-2)
		rand.Read(m1)
		m1[0] &= 0x0F
		em := append([]byte{0x6A}, m1...)
		em = append(em, hash(append(append([]byte{}, m1...), nonce...))...)
		em = append(em, 0x34, 0xCC)
		aaSig = new(big.Int).Exp(new(big.Int).SetBytes(em), k.D, k.N).FillBytes(make([]byte, size))
	}

	return synthetic{
		files: files{sod: sod, dg14: dg14, dg15: dg15, aaNonce: nonce, aaSignature: aaSig},
		secrets: []string{
			strings.ToLower(serial.Text(16)), hex.EncodeToString(hash(dg15)), hex.EncodeToString(hash(lds)),
			hex.EncodeToString(aaSig[:8]), hex.EncodeToString(signature[:8]),
		},
	}
}

func must2(a, b *big.Int, err error) (*big.Int, *big.Int) {
	if err != nil {
		panic(err)
	}
	return a, b
}

var (
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

func assertClean(t *testing.T, rep string, s synthetic, wants ...string) {
	t.Helper()
	if strings.Contains(rep, "[FAIL]") {
		t.Fatalf("unexpected failure:\n%s", rep)
	}
	for _, w := range wants {
		if !strings.Contains(rep, w) {
			t.Fatalf("report lacks %q:\n%s", w, rep)
		}
	}
	lower := strings.ToLower(rep)
	for _, secret := range s.secrets {
		if strings.Contains(lower, secret) {
			t.Fatalf("report leaks a value (%s…)", secret[:6])
		}
	}
}

func TestECDSAPassport(t *testing.T) {
	s := build(t, must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), oidECDSASHA256, must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)))
	rep := inspect(s.files)
	assertClean(t, rep, s,
		"data groups covered:         DG1, DG14, DG15",
		"issuer (the CSCA):           CN=Utopia CSCA,C=UT",
		"signed by the CSCA with:     ecdsa-with-SHA384",
		"public key:                  EC P-256",
		"[ok  ] signed attributes carry the hash of the security object",
		"[ok  ] signature over the signed attributes verifies under the Document Signer key — ECDSA, SHA-256",
		"[ok  ] DG14 matches its hash", "[ok  ] DG15 matches its hash",
		"ActiveAuthenticationInfo: 2.23.136.1.1.5, signature algorithm 0.4.0.127.0.7.1.1.4.1.3",
		"chip public key:             EC P-256",
		"[ok  ] chip signed the nonce (ECDSA, plain r|s over the hash of the 8-byte nonce) — SHA-256",
	)
}

func TestRSAPassport(t *testing.T) {
	s := build(t, must(rsa.GenerateKey(rand.Reader, 2048)), oidRSASHA256, must(rsa.GenerateKey(rand.Reader, 1024)))
	rep := inspect(s.files)
	assertClean(t, rep, s,
		"public key:                  RSA 2048 bits, e=65537",
		"verifies under the Document Signer key — RSA PKCS#1 v1.5, SHA-256",
		"chip public key:             RSA 1024 bits",
		"[ok  ] chip signed the nonce (RSA, ISO/IEC 9796-2 scheme 1) — SHA-256",
	)
}

func TestDetectsTampering(t *testing.T) {
	chip := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	s := build(t, must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), oidECDSASHA256, chip)

	changed := s.files
	changed.dg15 = append([]byte{}, s.files.dg15...)
	changed.dg15[len(changed.dg15)-1] ^= 1
	if rep := inspect(changed); !strings.Contains(rep, "[FAIL] DG15 matches its hash") {
		t.Fatalf("a modified DG15 should fail its hash check:\n%s", rep)
	}

	changed = s.files
	changed.aaNonce = []byte{8, 7, 6, 5, 4, 3, 2, 1}
	if rep := inspect(changed); !strings.Contains(rep, "[FAIL] chip signed the nonce") {
		t.Fatalf("a signature over another nonce should fail:\n%s", rep)
	}

	changed = s.files
	changed.sod = append([]byte{}, s.files.sod...)
	changed.sod[len(changed.sod)-1] ^= 1 // last byte of the signature
	if rep := inspect(changed); !strings.Contains(rep, "[FAIL] signature over the signed attributes") {
		t.Fatalf("a modified signature should fail:\n%s", rep)
	}
}

func TestWithoutOptionalFiles(t *testing.T) {
	s := build(t, must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), oidECDSASHA256, must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)))
	rep := inspect(files{sod: s.files.sod})
	if strings.Contains(rep, "[FAIL]") || !strings.Contains(rep, "[n/a ] DG15 matches its hash") || !strings.Contains(rep, "Active Authentication key (DG15): not read") {
		t.Fatalf("missing optional files should be reported as not read:\n%s", rep)
	}
	if rep := inspect(files{sod: []byte("garbage")}); !strings.Contains(rep, "[FAIL] EF.SOD parses") {
		t.Fatalf("garbage should be reported:\n%s", rep)
	}
}

// Passports often spell out the curve instead of naming it.
func TestRecognisesExplicitCurveParameters(t *testing.T) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	p := elliptic.P256().Params()
	explicit := der(struct {
		Version int
		Field   struct {
			Type  asn1.ObjectIdentifier
			Prime *big.Int
		}
		Curve struct{ A, B []byte }
		Base  []byte
		Order *big.Int
	}{1, struct {
		Type  asn1.ObjectIdentifier
		Prime *big.Int
	}{asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}, p.P}, struct{ A, B []byte }{new(big.Int).Sub(p.P, big.NewInt(3)).Bytes(), p.B.Bytes()},
		elliptic.Marshal(p, p.Gx, p.Gy), p.N})
	var params asn1.RawValue
	asn1.Unmarshal(explicit, &params)
	point := elliptic.Marshal(key.Curve, key.X, key.Y)
	info := describeKey(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: params},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	if info.ec == nil || !strings.Contains(info.description, "EC P-256 (explicit parameters, 256-bit prime)") {
		t.Fatalf("explicit P-256 parameters not recognised: %s", info.description)
	}
}
