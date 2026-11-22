// Package client is the holder side of the protocol. For now the "card" is a
// mock private key on disk; the signing step will move to the real card.
package client

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/keitaj/shoji/internal/proto"
	"github.com/keitaj/shoji/internal/prover"
	"github.com/keitaj/shoji/internal/verifier"
	"github.com/keitaj/shoji/internal/witness"
)

// Holder holds what stays on the user's device.
type Holder struct {
	Cert  *x509.Certificate
	Key   *rsa.PrivateKey // mock card
	CAPub *rsa.PublicKey  // issuer of Cert
	Tools prover.Tools
}

func post(ctx context.Context, hc *http.Client, url string, in, out any) (int, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return resp.StatusCode, fmt.Errorf("server returned %d: %s", resp.StatusCode, e.Error)
	}
	return resp.StatusCode, json.Unmarshal(raw, out)
}

// Challenge requests a nonce for app.
func Challenge(ctx context.Context, hc *http.Client, base, app string) (*verifier.ChallengeResponse, error) {
	var ch verifier.ChallengeResponse
	if _, err := post(ctx, hc, base+"/challenge", map[string]string{"app": app}, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

// Prove signs the challenge with the (mock) card and builds the request for
// /verify. Only the proof and public values leave this function.
func (h *Holder) Prove(ctx context.Context, ch *verifier.ChallengeResponse) (*verifier.VerifyRequest, error) {
	nonce, err := proto.ParseFieldHex(ch.Nonce)
	if err != nil {
		return nil, err
	}
	appID, err := proto.ParseFieldHex(ch.AppID)
	if err != nil {
		return nil, err
	}
	sig, err := witness.SignNonce(h.Key, appID, nonce)
	if err != nil {
		return nil, err
	}
	in, err := witness.New(h.Cert, h.CAPub, sig, appID, nonce, ch.CurrentDate, ch.AgeThreshold)
	if err != nil {
		return nil, err
	}
	p, err := prover.Prove(ctx, h.Tools, in)
	if err != nil {
		return nil, err
	}
	nullifier, err := proto.Nullifier(in.UserModulus, appID)
	if err != nil {
		return nil, err
	}
	return &verifier.VerifyRequest{
		Nonce:        ch.Nonce,
		CAPubkeyHash: proto.FieldHex(in.CAPubkeyHash),
		Nullifier:    proto.FieldHex(nullifier),
		Proof:        base64.StdEncoding.EncodeToString(p.Proof),
	}, nil
}

// Submit posts a proof to /verify and returns the HTTP status with the result.
func Submit(ctx context.Context, hc *http.Client, base string, req *verifier.VerifyRequest) (int, *verifier.VerifyResponse, error) {
	var res verifier.VerifyResponse
	status, err := post(ctx, hc, base+"/verify", req, &res)
	if err != nil {
		return status, nil, err
	}
	return status, &res, nil
}
