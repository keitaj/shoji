// Package witness assembles the circuit inputs (Prover.toml) on the holder's
// side. Everything in Inputs below the public section is private witness data
// and must never be logged or sent to a server.
package witness

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/keitaj/shoji/internal/proto"
)

// Inputs mirrors the parameters of main() in circuits/src/main.nr.
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
