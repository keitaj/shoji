// Package proto holds the values that the circuit, the prover-side tooling and
// the verifier must agree on byte-for-byte: field encodings, the message the
// card signs, and the Poseidon hashes used for the CA key hash and nullifier.
//
// Anything changed here must be changed in the circuits (circuits/card, circuits/delegated) as well; the
// fixture tests (cmd/genfixtures + `nargo test`) fail if the two drift apart.
package proto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

const (
	// ModulusBytes is the size of an RSA-2048 modulus / signature.
	ModulusBytes = 256
	// MaxTBSLen is the size of the circuit's TBSCertificate buffer.
	MaxTBSLen = 2048
	// TBSHeadroom is the slack the circuit requires after the TBS so that its
	// fixed-size look-aheads never leave the buffer.
	TBSHeadroom = 16
	// NonceDomain prefixes the message signed by the card. It keeps the
	// signature from being mistaken for (or replayed as) a signature over any
	// other kind of document. Exactly 16 bytes.
	NonceDomain = "shoji-v1-nonce::"
	// NonceMessageLen = len(NonceDomain) + 32 (app_id) + 32 (nonce).
	NonceMessageLen = 80
	// DelegationDomain prefixes the message the card signs to delegate
	// possession to a secret held by the holder's own device (see
	// DelegationMessage). It differs from NonceDomain, so neither kind of
	// signature can stand in for the other. Exactly 16 bytes.
	DelegationDomain = "shoji-v1-deleg::"
	// DelegationMessageLen = len(DelegationDomain) + 32 (commitment) + 4 (expiry).
	DelegationMessageLen = 52
	// MaxDelegationDays is the longest a delegation may run. A verifier passes
	// current_date + MaxDelegationDays as latest_expiry, and the holder's
	// software insists on exactly that value.
	MaxDelegationDays = 30
	// NonceBytes is the number of random bytes in a nonce. 31 bytes always
	// fits in a BN254 field element.
	NonceBytes = 31
	// NumLimbs / LimbBits describe noir-bignum's representation of 2048-bit numbers.
	NumLimbs = 18
	LimbBits = 120
	// barrettOverflowBits mirrors BARRETT_REDUCTION_OVERFLOW_BITS in noir-bignum.
	barrettOverflowBits = 6
)

// FieldModulus is the BN254 scalar field order.
var FieldModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// CheckField reports an error unless 0 <= x < FieldModulus.
func CheckField(x *big.Int) error {
	if x == nil || x.Sign() < 0 || x.Cmp(FieldModulus) >= 0 {
		return errors.New("value is not a canonical field element")
	}
	return nil
}

// FieldBytes returns x as 32 big-endian bytes.
func FieldBytes(x *big.Int) [32]byte {
	var out [32]byte
	x.FillBytes(out[:])
	return out
}

// FieldHex formats x as a 0x-prefixed 32-byte hex string.
func FieldHex(x *big.Int) string {
	b := FieldBytes(x)
	return fmt.Sprintf("0x%x", b[:])
}

// ParseFieldHex parses a 0x-prefixed (or bare) hex string into a canonical field element.
func ParseFieldHex(s string) (*big.Int, error) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	if len(s) == 0 || len(s) > 64 {
		return nil, errors.New("bad field hex length")
	}
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, errors.New("bad field hex")
	}
	if err := CheckField(x); err != nil {
		return nil, err
	}
	return x, nil
}

// AppID maps an application identifier string to a field element:
// the first 31 bytes of SHA-256(name), read big-endian.
func AppID(name string) *big.Int {
	h := sha256.Sum256([]byte(name))
	return new(big.Int).SetBytes(h[:31])
}

// NonceMessage is the exact byte string the card signs (SHA-256, PKCS#1 v1.5)
// to prove possession: NonceDomain || app_id (32 bytes BE) || nonce (32 bytes BE).
func NonceMessage(appID, nonce *big.Int) []byte {
	a, n := FieldBytes(appID), FieldBytes(nonce)
	msg := make([]byte, 0, NonceMessageLen)
	msg = append(msg, NonceDomain...)
	msg = append(msg, a[:]...)
	msg = append(msg, n[:]...)
	return msg
}

// DelegationCommitment = Poseidon(secret): what the card signs in place of the
// secret itself. Knowing the secret then stands in for holding the card.
func DelegationCommitment(secret *big.Int) (*big.Int, error) {
	if err := CheckField(secret); err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{secret})
}

// DelegationMessage is the exact byte string the card signs (SHA-256, PKCS#1
// v1.5) to delegate until the end of the day `expiry` (YYYYMMDD):
// DelegationDomain || commitment (32 bytes BE) || expiry (4 bytes BE).
func DelegationMessage(commitment *big.Int, expiry uint32) []byte {
	c := FieldBytes(commitment)
	msg := make([]byte, 0, DelegationMessageLen)
	msg = append(msg, DelegationDomain...)
	msg = append(msg, c[:]...)
	msg = append(msg, byte(expiry>>24), byte(expiry>>16), byte(expiry>>8), byte(expiry))
	return msg
}

// LatestExpiry is the latest expiry date a delegation may carry when it is
// used on currentDate (both YYYYMMDD): MaxDelegationDays later.
func LatestExpiry(currentDate uint32) (uint32, error) {
	t, err := time.Parse("20060102", fmt.Sprintf("%08d", currentDate))
	if err != nil {
		return 0, fmt.Errorf("bad date %d", currentDate)
	}
	return DateInt(t.AddDate(0, 0, MaxDelegationDays)), nil
}

// ChallengePrefix starts the text form of a challenge handed to the device
// that talks to the card.
const ChallengePrefix = "shoji1"

// ChallengeString is the text form of a challenge: "shoji1:<app_id>:<nonce>",
// both as 64 hex digits. The card-side software rebuilds NonceMessage from it,
// so the card only ever signs messages in shoji's own format, never a digest
// supplied from outside.
func ChallengeString(appID, nonce *big.Int) string {
	a, n := FieldBytes(appID), FieldBytes(nonce)
	return fmt.Sprintf("%s:%x:%x", ChallengePrefix, a[:], n[:])
}

// PubkeyHash is Poseidon over the 256-byte big-endian modulus split into nine
// big-endian chunks (eight of 31 bytes, then one of 8 bytes). The public
// exponent is not hashed because the circuit only accepts 65537.
func PubkeyHash(modulus *big.Int) (*big.Int, error) {
	if modulus.BitLen() != ModulusBytes*8 {
		return nil, fmt.Errorf("modulus must be exactly %d bits", ModulusBytes*8)
	}
	b := make([]byte, ModulusBytes)
	modulus.FillBytes(b)
	chunks := make([]*big.Int, 0, 9)
	for i := 0; i < ModulusBytes; i += 31 {
		chunks = append(chunks, new(big.Int).SetBytes(b[i:min(i+31, ModulusBytes)]))
	}
	return poseidon.Hash(chunks)
}

// Nullifier = Poseidon(PubkeyHash(user modulus), app_id).
func Nullifier(userModulus, appID *big.Int) (*big.Int, error) {
	id, err := PubkeyHash(userModulus)
	if err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{id, appID})
}

// Limbs splits x into NumLimbs little-endian 120-bit limbs (noir-bignum layout).
func Limbs(x *big.Int) []*big.Int {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), LimbBits), big.NewInt(1))
	out := make([]*big.Int, NumLimbs)
	t := new(big.Int).Set(x)
	for i := range out {
		out[i] = new(big.Int).And(t, mask)
		t.Rsh(t, LimbBits)
	}
	return out
}

// RedcParam is noir-bignum's Barrett parameter floor(2^(2*2048+6) / modulus).
// It is only a hint for witness generation; the circuit's soundness does not
// depend on it.
func RedcParam(modulus *big.Int) *big.Int {
	num := new(big.Int).Lsh(big.NewInt(1), 2*ModulusBytes*8+barrettOverflowBits)
	return num.Div(num, modulus)
}

// DateInt encodes a calendar date as the integer YYYYMMDD.
func DateInt(t time.Time) uint32 {
	y, m, d := t.Date()
	return uint32(y*10000 + int(m)*100 + d)
}
