package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// The same vector is checked in ios/ShojiCardKit (ChallengeTests.swift), so the
// Go and Swift sides cannot drift apart on what the card signs.
func TestChallengeVector(t *testing.T) {
	appID := AppID("demo")
	nonce := new(big.Int).SetBytes(bytes.Repeat([]byte{0x11}, NonceBytes))

	const wantChallenge = "shoji1:002a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5a:0011111111111111111111111111111111111111111111111111111111111111"
	if got := ChallengeString(appID, nonce); got != wantChallenge {
		t.Fatalf("challenge string: got %s", got)
	}

	msg := NonceMessage(appID, nonce)
	if len(msg) != NonceMessageLen || string(msg[:16]) != NonceDomain {
		t.Fatalf("unexpected nonce message layout")
	}
	const wantDigest = "2b1dea3932512903492cb6b7affbda2f97959f6c6f1d9539b3d660aec74ded5a"
	digest := sha256.Sum256(msg)
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("digest: got %s", got)
	}
}

// Also checked in ios/ShojiCardKit (VerificationLinkTests.swift): the phone
// derives app_id from the origin it talks to, and must agree with the server.
func TestAppIDOfOriginVector(t *testing.T) {
	const want = "0x00d1b8790504951c2f3c74c61299b9cfb8634ca1b0dc8e3b6ae57475bc37790a"
	if got := FieldHex(AppID("https://verifier.example")); got != want {
		t.Fatalf("app_id: got %s", got)
	}
}
