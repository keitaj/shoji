// Package witness assembles the circuit inputs (Prover.toml) on the holder's
// side. Everything in Inputs below the public section is private witness data
// and must never be logged or sent to a server.
package witness

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/keitaj/shoji/internal/proto"
)

// Inputs mirrors the parameters of main() in circuits/card/src/main.nr.
type Inputs struct {
	// Public inputs.
	CAPubkeyHash *big.Int
	Nonce        *big.Int
	AppID        *big.Int
	CurrentDate  uint32
	AgeThreshold uint8

	// Private witness.
	TBS         []byte
	CAModulus   *big.Int
	CertSig     []byte
	UserModulus *big.Int
	NonceSig    []byte
}

// SignNonce stands in for the card: a SHA-256 / PKCS#1 v1.5 signature over
// proto.NonceMessage made with the holder's private key.
func SignNonce(key *rsa.PrivateKey, appID, nonce *big.Int) ([]byte, error) {
	digest := sha256.Sum256(proto.NonceMessage(appID, nonce))
	return rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
}

// New builds circuit inputs from a certificate, its issuer's public key and the
// card's signature over the nonce message.
func New(cert *x509.Certificate, caPub *rsa.PublicKey, nonceSig []byte, appID, nonce *big.Int, currentDate uint32, ageThreshold uint8) (*Inputs, error) {
	userPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate key is not RSA")
	}
	if userPub.E != 65537 || caPub.E != 65537 {
		return nil, errors.New("only public exponent 65537 is supported")
	}
	if len(cert.RawTBSCertificate)+proto.TBSHeadroom > proto.MaxTBSLen {
		return nil, fmt.Errorf("TBSCertificate too long for the circuit (%d bytes)", len(cert.RawTBSCertificate))
	}
	if len(cert.Signature) != proto.ModulusBytes || len(nonceSig) != proto.ModulusBytes {
		return nil, errors.New("signatures must be 256 bytes")
	}
	caHash, err := proto.PubkeyHash(caPub.N)
	if err != nil {
		return nil, err
	}
	return &Inputs{
		CAPubkeyHash: caHash, Nonce: nonce, AppID: appID, CurrentDate: currentDate, AgeThreshold: ageThreshold,
		TBS: cert.RawTBSCertificate, CAModulus: caPub.N, CertSig: cert.Signature, UserModulus: userPub.N, NonceSig: nonceSig,
	}, nil
}

// PaddedTBS returns the TBS zero-padded to the circuit's buffer size.
func (in *Inputs) PaddedTBS() []byte {
	out := make([]byte, proto.MaxTBSLen)
	copy(out, in.TBS)
	return out
}

// ModulusBytes returns x as 256 big-endian bytes.
func ModulusBytes(x *big.Int) []byte {
	out := make([]byte, proto.ModulusBytes)
	x.FillBytes(out)
	return out
}

// ByteList formats bytes as a decimal list: [1, 2, 3].
func ByteList(b []byte) string {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, v := range b {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%d", v)
	}
	sb.WriteByte(']')
	return sb.String()
}

// LimbList formats x as noir-bignum limbs. With quote=true the limbs are
// quoted strings (TOML); otherwise bare hex literals (Noir source).
func LimbList(x *big.Int, quote bool) string {
	parts := make([]string, 0, proto.NumLimbs)
	for _, l := range proto.Limbs(x) {
		s := "0x" + l.Text(16)
		if quote {
			s = `"` + s + `"`
		}
		parts = append(parts, s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// JSON renders the inputs as a JSON object keyed by the parameter names of
// main(), for provers that take inputs as a map (e.g. the iOS app): byte arrays
// as arrays of numbers, limbs and field elements as hex strings.
func (in *Inputs) JSON() ([]byte, error) {
	bytesOf := func(b []byte) []int {
		out := make([]int, len(b))
		for i, v := range b {
			out[i] = int(v)
		}
		return out
	}
	limbsOf := func(x *big.Int) []string {
		out := make([]string, 0, proto.NumLimbs)
		for _, l := range proto.Limbs(x) {
			out = append(out, "0x"+l.Text(16))
		}
		return out
	}
	return json.Marshal(map[string]any{
		"ca_pubkey_hash": proto.FieldHex(in.CAPubkeyHash),
		"nonce":          proto.FieldHex(in.Nonce),
		"app_id":         proto.FieldHex(in.AppID),
		"current_date":   in.CurrentDate,
		"age_threshold":  in.AgeThreshold,
		"tbs":            bytesOf(in.PaddedTBS()),
		"tbs_len":        len(in.TBS),
		"ca_modulus":     bytesOf(ModulusBytes(in.CAModulus)),
		"ca_redc":        limbsOf(proto.RedcParam(in.CAModulus)),
		"cert_sig":       bytesOf(in.CertSig),
		"user_redc":      limbsOf(proto.RedcParam(in.UserModulus)),
		"nonce_sig":      bytesOf(in.NonceSig),
	})
}

// ProverTOML renders the inputs in nargo's Prover.toml format.
func (in *Inputs) ProverTOML() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ca_pubkey_hash = %q\n", proto.FieldHex(in.CAPubkeyHash))
	fmt.Fprintf(&sb, "nonce = %q\n", proto.FieldHex(in.Nonce))
	fmt.Fprintf(&sb, "app_id = %q\n", proto.FieldHex(in.AppID))
	fmt.Fprintf(&sb, "current_date = %d\n", in.CurrentDate)
	fmt.Fprintf(&sb, "age_threshold = %d\n", in.AgeThreshold)
	fmt.Fprintf(&sb, "tbs = %s\n", ByteList(in.PaddedTBS()))
	fmt.Fprintf(&sb, "tbs_len = %d\n", len(in.TBS))
	fmt.Fprintf(&sb, "ca_modulus = %s\n", ByteList(ModulusBytes(in.CAModulus)))
	fmt.Fprintf(&sb, "ca_redc = %s\n", LimbList(proto.RedcParam(in.CAModulus), true))
	fmt.Fprintf(&sb, "cert_sig = %s\n", ByteList(in.CertSig))
	fmt.Fprintf(&sb, "user_redc = %s\n", LimbList(proto.RedcParam(in.UserModulus), true))
	fmt.Fprintf(&sb, "nonce_sig = %s\n", ByteList(in.NonceSig))
	return sb.String()
}

// Delegation is what the holder's device keeps after the card has signed a
// delegation: the secret, the day it expires and the card's signature. Together
// with the certificate it lets the device prove without the card until Expiry.
// All of it is private witness data.
type Delegation struct {
	Secret *big.Int
	Expiry uint32 // YYYYMMDD, inclusive
	Sig    []byte
}

// SignDelegation stands in for the card: a SHA-256 / PKCS#1 v1.5 signature over
// proto.DelegationMessage made with the holder's private key.
func SignDelegation(key *rsa.PrivateKey, secret *big.Int, expiry uint32) (*Delegation, error) {
	c, err := proto.DelegationCommitment(secret)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(proto.DelegationMessage(c, expiry))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	return &Delegation{Secret: secret, Expiry: expiry, Sig: sig}, nil
}

// DelegatedInputs mirrors the parameters of main() in
// circuits/delegated/src/main.nr.
type DelegatedInputs struct {
	Inputs              // NonceSig is unused
	LatestExpiry uint32 // public
	Delegation   Delegation
}

// NewDelegated builds the inputs of the delegated circuit.
func NewDelegated(cert *x509.Certificate, caPub *rsa.PublicKey, d *Delegation, appID, nonce *big.Int, currentDate uint32, ageThreshold uint8, latestExpiry uint32) (*DelegatedInputs, error) {
	if d == nil || len(d.Sig) != proto.ModulusBytes {
		return nil, errors.New("delegation signature must be 256 bytes")
	}
	if err := proto.CheckField(d.Secret); err != nil {
		return nil, err
	}
	// New only checks the length of the signature it is given.
	in, err := New(cert, caPub, d.Sig, appID, nonce, currentDate, ageThreshold)
	if err != nil {
		return nil, err
	}
	in.NonceSig = nil
	return &DelegatedInputs{Inputs: *in, LatestExpiry: latestExpiry, Delegation: *d}, nil
}

// ProverTOML renders the inputs in nargo's Prover.toml format.
func (in *DelegatedInputs) ProverTOML() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ca_pubkey_hash = %q\n", proto.FieldHex(in.CAPubkeyHash))
	fmt.Fprintf(&sb, "nonce = %q\n", proto.FieldHex(in.Nonce))
	fmt.Fprintf(&sb, "app_id = %q\n", proto.FieldHex(in.AppID))
	fmt.Fprintf(&sb, "current_date = %d\n", in.CurrentDate)
	fmt.Fprintf(&sb, "age_threshold = %d\n", in.AgeThreshold)
	fmt.Fprintf(&sb, "latest_expiry = %d\n", in.LatestExpiry)
	fmt.Fprintf(&sb, "tbs = %s\n", ByteList(in.PaddedTBS()))
	fmt.Fprintf(&sb, "tbs_len = %d\n", len(in.TBS))
	fmt.Fprintf(&sb, "ca_modulus = %s\n", ByteList(ModulusBytes(in.CAModulus)))
	fmt.Fprintf(&sb, "ca_redc = %s\n", LimbList(proto.RedcParam(in.CAModulus), true))
	fmt.Fprintf(&sb, "cert_sig = %s\n", ByteList(in.CertSig))
	fmt.Fprintf(&sb, "user_redc = %s\n", LimbList(proto.RedcParam(in.UserModulus), true))
	fmt.Fprintf(&sb, "delegation_sig = %s\n", ByteList(in.Delegation.Sig))
	fmt.Fprintf(&sb, "delegation_secret = %q\n", proto.FieldHex(in.Delegation.Secret))
	fmt.Fprintf(&sb, "delegation_expiry = %d\n", in.Delegation.Expiry)
	return sb.String()
}
