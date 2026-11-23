// Package mockjpki issues test certificates shaped like JPKI signing
// certificates (署名用電子証明書): RSA-2048, sha256WithRSAEncryption, with the
// four basic attributes carried as otherName entries in subjectAltName.
//
// The otherName OIDs, the UTF8String wrapping, the nine-digit date of birth and
// the order of the entries follow what was observed on a real card (structure
// only; see docs/open-questions.md). The encodings of gender and of the
// "substitute character" entries are still placeholders. Never put a real
// person's data through this package.
package mockjpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// otherName type OIDs of the basic attributes.
var (
	OIDName              = asn1.ObjectIdentifier{1, 2, 392, 200149, 8, 5, 5, 1}
	OIDNameSubstitute    = asn1.ObjectIdentifier{1, 2, 392, 200149, 8, 5, 5, 2}
	OIDGender            = asn1.ObjectIdentifier{1, 2, 392, 200149, 8, 5, 5, 3}
	OIDDateOfBirth       = asn1.ObjectIdentifier{1, 2, 392, 200149, 8, 5, 5, 4}
	OIDAddress           = asn1.ObjectIdentifier{1, 2, 392, 200149, 8, 5, 5, 5}
	OIDAddressSubstitute = asn1.ObjectIdentifier{1, 2, 392, 200149, 8, 5, 5, 6}

	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCertPolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
)

// Holder is the mock personal data placed in a certificate.
type Holder struct {
	Name        string
	Gender      string // provisional encoding: "1" male, "2" female
	DateOfBirth string // Gregorian YYYYMMDD; encoded with a leading era digit, see DateOfBirthValue
	// Address is raw bytes so tests can embed hostile content (e.g. bytes that
	// imitate a date-of-birth otherName) in an attribute.
	Address []byte
}

// CA is a mock certificate authority.
type CA struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// NewCA creates a self-signed RSA-2048 mock CA.
func NewCA(commonName string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Country: []string{"JP"}, Organization: []string{"shoji mock (NOT J-LIS)"}, CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Key: key, Cert: cert}, nil
}

// Issue creates a holder key pair and a signing certificate for it.
func (ca *CA) Issue(h Holder) (*x509.Certificate, *rsa.PrivateKey, error) {
	if len(h.DateOfBirth) != 8 {
		return nil, nil, errors.New("DateOfBirth must be YYYYMMDD")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	san, err := subjectAltName(h)
	if err != nil {
		return nil, nil, err
	}
	// A real certificate carries a critical certificatePolicies extension with the
	// signing CA's policy identifier; the mock does too, so that the circuit's
	// extension walk meets a critical flag on an extension other than subjectAltName.
	policies, err := asn1.Marshal([]struct{ ID asn1.ObjectIdentifier }{{asn1.ObjectIdentifier{1, 2, 392, 200149, 8, 5, 1, 1, 20}}})
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{Country: []string{"JP"}, Organization: []string{"shoji mock"}, CommonName: fmt.Sprintf("MOCK%x", serial)},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{Id: oidSubjectAltName, Value: san},
			{Id: oidCertPolicies, Critical: true, Value: policies},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// DateOfBirthValue encodes a Gregorian YYYYMMDD date the way the certificate
// stores it: a Japanese era code (1 Meiji, 2 Taisho, 3 Showa, 4 Heisei, 5 Reiwa)
// followed by the same eight digits.
func DateOfBirthValue(yyyymmdd string) string {
	era := "1"
	switch {
	case yyyymmdd >= "20190501":
		era = "5"
	case yyyymmdd >= "19890108":
		era = "4"
	case yyyymmdd >= "19261225":
		era = "3"
	case yyyymmdd >= "19120730":
		era = "2"
	}
	return era + yyyymmdd
}

// OtherName returns the DER of a GeneralName otherName:
// [0] { type-id OID, [0] EXPLICIT UTF8String(value) }.
func OtherName(oid asn1.ObjectIdentifier, value []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	str, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: value})
	if err != nil {
		return nil, err
	}
	wrapped, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: str})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oidDER, wrapped...)})
}

func subjectAltName(h Holder) ([]byte, error) {
	entries := []struct {
		oid asn1.ObjectIdentifier
		val []byte
	}{
		// Same order as on a real card.
		{OIDName, []byte(h.Name)},
		{OIDDateOfBirth, []byte(DateOfBirthValue(h.DateOfBirth))},
		{OIDGender, []byte(h.Gender)},
		{OIDAddress, h.Address},
		{OIDNameSubstitute, []byte("00000")},
		{OIDAddressSubstitute, []byte("0")},
	}
	var body []byte
	for _, e := range entries {
		der, err := OtherName(e.oid, e.val)
		if err != nil {
			return nil, err
		}
		body = append(body, der...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
}

// --- PEM helpers ---

func WriteCertPEM(path string, cert *x509.Certificate) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
}

func WriteKeyPEM(path string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func ReadCertPEM(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no CERTIFICATE block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// ReadCert reads a certificate in PEM or DER form.
func ReadCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: not a certificate", path)
	}
	return cert, nil
}

func ReadKeyPEM(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an RSA key", path)
	}
	return key, nil
}

// LoadCA reads a CA from <base>.pem and <base>.key.
func LoadCA(base string) (*CA, error) {
	cert, err := ReadCertPEM(base + ".pem")
	if err != nil {
		return nil, err
	}
	key, err := ReadKeyPEM(base + ".key")
	if err != nil {
		return nil, err
	}
	return &CA{Key: key, Cert: cert}, nil
}

// Save writes a CA to <base>.pem and <base>.key.
func (ca *CA) Save(base string) error {
	if err := WriteCertPEM(base+".pem", ca.Cert); err != nil {
		return err
	}
	return WriteKeyPEM(base+".key", ca.Key)
}

// RSAPublicKey returns the certificate's RSA public key.
func RSAPublicKey(cert *x509.Certificate) (*rsa.PublicKey, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate key is not RSA")
	}
	return pub, nil
}
