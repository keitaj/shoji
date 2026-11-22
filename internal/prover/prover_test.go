package prover_test

import (
	"bytes"
	"context"
	"math/big"
	"os"
	"testing"

	"github.com/keitaj/shoji/internal/mockjpki"
	"github.com/keitaj/shoji/internal/proto"
	"github.com/keitaj/shoji/internal/prover"
	"github.com/keitaj/shoji/internal/witness"
)

func TestProveAdult(t *testing.T) {
	tools := prover.DefaultTools("../..")
	if _, err := os.Stat(tools.VK); err != nil {
		t.Skip("circuit not built; run `make circuit`")
	}
	ca, err := mockjpki.LoadCA("../../testdata/ca")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := mockjpki.ReadCertPEM("../../testdata/adult.pem")
	key, _ := mockjpki.ReadKeyPEM("../../testdata/adult.key")
	appID := proto.AppID("prover-test")
	nonce := new(big.Int).SetBytes(bytes.Repeat([]byte{7}, proto.NonceBytes))
	sig, err := witness.SignNonce(key, appID, nonce)
	if err != nil {
		t.Fatal(err)
	}
	in, err := witness.New(cert, &ca.Key.PublicKey, sig, appID, nonce, 20261123, 18)
	if err != nil {
		t.Fatal(err)
	}
	p, err := prover.Prove(context.Background(), tools, in)
	if err != nil {
		t.Fatal(err)
	}
	// Public inputs: 5 inputs + nullifier + is_over_threshold, 32 bytes each.
	if len(p.PublicInputs) != 7*32 {
		t.Fatalf("public inputs: got %d bytes", len(p.PublicInputs))
	}
	want, _ := proto.Nullifier(key.PublicKey.N, appID)
	wantB := proto.FieldBytes(want)
	if !bytes.Equal(p.PublicInputs[5*32:6*32], wantB[:]) {
		t.Fatal("nullifier in proof differs from the Go computation")
	}
	if p.PublicInputs[7*32-1] != 1 {
		t.Fatal("is_over_threshold should be 1")
	}
	t.Logf("proof size: %d bytes", len(p.Proof))
}
