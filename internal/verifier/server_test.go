package verifier_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"shoji/internal/client"
	"shoji/internal/mockjpki"
	"shoji/internal/proto"
	"shoji/internal/prover"
	"shoji/internal/verifier"
)

const app = "test-app"

type env struct {
	t     *testing.T
	url   string
	store *verifier.Store
	tools prover.Tools
	now   *time.Time
	mu    *sync.Mutex
}

// newEnv starts a verifier that trusts only testdata/ca and uses the real bb.
func newEnv(t *testing.T) *env {
	t.Helper()
	tools := prover.DefaultTools("../..")
	if _, err := os.Stat(tools.VK); err != nil {
		t.Skip("circuit not built; run `make circuit`")
	}
	ca, err := mockjpki.LoadCA("../../testdata/ca")
	if err != nil {
		t.Fatal(err)
	}
	caHash, _ := proto.PubkeyHash(ca.Key.PublicKey.N)
	store, err := verifier.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	srv, err := verifier.NewServer(verifier.Config{
		Store:           store,
		Checker:         verifier.BBChecker{BB: tools.BB, VK: tools.VK},
		TrustedCAHashes: []string{proto.FieldHex(caHash)},
		Apps:            []string{app, "other-app"},
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); store.Close() })
	return &env{t: t, url: ts.URL, store: store, tools: tools, now: &now, mu: &mu}
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	*e.now = e.now.Add(d)
}

func (e *env) holder(name, caName string) *client.Holder {
	e.t.Helper()
	cert, err := mockjpki.ReadCertPEM("../../testdata/" + name + ".pem")
	if err != nil {
		e.t.Fatal(err)
	}
	key, err := mockjpki.ReadKeyPEM("../../testdata/" + name + ".key")
	if err != nil {
		e.t.Fatal(err)
	}
	ca, err := mockjpki.LoadCA("../../testdata/" + caName)
	if err != nil {
		e.t.Fatal(err)
	}
	return &client.Holder{Cert: cert, Key: key, CAPub: &ca.Key.PublicKey, Tools: e.tools}
}

func (e *env) challenge(appName string) *verifier.ChallengeResponse {
	e.t.Helper()
	ch, err := client.Challenge(context.Background(), http.DefaultClient, e.url, appName)
	if err != nil {
		e.t.Fatal(err)
	}
	return ch
}

func (e *env) prove(h *client.Holder, ch *verifier.ChallengeResponse) *verifier.VerifyRequest {
	e.t.Helper()
	req, err := h.Prove(context.Background(), ch)
	if err != nil {
		e.t.Fatal(err)
	}
	return req
}

// submit returns the HTTP status, the response (on success) and the error text.
func (e *env) submit(req *verifier.VerifyRequest) (int, *verifier.VerifyResponse, string) {
	status, res, err := client.Submit(context.Background(), http.DefaultClient, e.url, req)
	if err != nil {
		return status, nil, err.Error()
	}
	return status, res, ""
}

func (e *env) expectReject(req *verifier.VerifyRequest, wantStatus int, wantErr string) {
	e.t.Helper()
	status, _, msg := e.submit(req)
	if status != wantStatus || !strings.Contains(msg, wantErr) {
		e.t.Fatalf("want %d %q, got %d %q", wantStatus, wantErr, status, msg)
	}
}

func TestAcceptAndRecogniseReturningHolder(t *testing.T) {
	e := newEnv(t)
	h := e.holder("adult", "ca")

	status, first, msg := e.submit(e.prove(h, e.challenge(app)))
	if status != http.StatusOK || !first.OK || !first.New {
		t.Fatalf("first verification: %d %+v %s", status, first, msg)
	}
	// Same person, same app, new nonce: same nullifier, no longer new.
	_, second, _ := e.submit(e.prove(h, e.challenge(app)))
	if second == nil || second.New || second.Nullifier != first.Nullifier {
		t.Fatalf("second verification: %+v", second)
	}
	// Same person, another app: unrelated nullifier.
	_, other, _ := e.submit(e.prove(h, e.challenge("other-app")))
	if other == nil || !other.New || other.Nullifier == first.Nullifier {
		t.Fatalf("other app: %+v", other)
	}
	// Another person, same app: different nullifier.
	_, h2, _ := e.submit(e.prove(e.holder("adult2", "ca"), e.challenge(app)))
	if h2 == nil || !h2.New || h2.Nullifier == first.Nullifier {
		t.Fatalf("second holder: %+v", h2)
	}
}

func TestNonceIsSingleUse(t *testing.T) {
	e := newEnv(t)
	req := e.prove(e.holder("adult", "ca"), e.challenge(app))
	if status, _, msg := e.submit(req); status != http.StatusOK {
		t.Fatalf("first use: %d %s", status, msg)
	}
	e.expectReject(req, http.StatusBadRequest, "nonce")
}

func TestNonceExpires(t *testing.T) {
	e := newEnv(t)
	req := e.prove(e.holder("adult", "ca"), e.challenge(app))
	e.advance(6 * time.Minute)
	e.expectReject(req, http.StatusBadRequest, "nonce")
}

func TestNonceNotIssuedByServer(t *testing.T) {
	e := newEnv(t)
	ch := e.challenge(app)
	ch.Nonce = proto.FieldHex(proto.AppID("made-up nonce")) // 31 bytes, never issued
	e.expectReject(e.prove(e.holder("adult", "ca"), ch), http.StatusBadRequest, "nonce")
}

func TestUntrustedCA(t *testing.T) {
	e := newEnv(t)
	h := e.holder("other_ca_adult", "ca_other")

	// Honest about which CA signed the certificate: not in the trusted list.
	e.expectReject(e.prove(h, e.challenge(app)), http.StatusForbidden, "untrusted CA")

	// Lying about it: the proof was made for another ca_pubkey_hash.
	req := e.prove(h, e.challenge(app))
	trusted, _ := mockjpki.LoadCA("../../testdata/ca")
	hash, _ := proto.PubkeyHash(trusted.Key.PublicKey.N)
	req.CAPubkeyHash = proto.FieldHex(hash)
	e.expectReject(req, http.StatusForbidden, "invalid proof")
}

func TestMinorIsRejected(t *testing.T) {
	e := newEnv(t)
	h := e.holder("minor", "ca")

	// Honest proof: is_over_threshold = 0, but the server demands 1.
	e.expectReject(e.prove(h, e.challenge(app)), http.StatusForbidden, "invalid proof")

	// Proving against a date far in the future: the server uses its own date.
	ch := e.challenge(app)
	ch.CurrentDate = 20500101
	e.expectReject(e.prove(h, ch), http.StatusForbidden, "invalid proof")

	// Proving against a lower threshold: the server uses its own threshold.
	ch = e.challenge(app)
	ch.AgeThreshold = 5
	e.expectReject(e.prove(h, ch), http.StatusForbidden, "invalid proof")
}

func TestDecoyDateOfBirthIsRejected(t *testing.T) {
	e := newEnv(t)
	e.expectReject(e.prove(e.holder("decoy", "ca"), e.challenge(app)), http.StatusForbidden, "invalid proof")
}

func TestNullifierCannotBeSubstituted(t *testing.T) {
	e := newEnv(t)
	req := e.prove(e.holder("adult", "ca"), e.challenge(app))
	req.Nullifier = proto.FieldHex(proto.AppID("some other nullifier"))
	e.expectReject(req, http.StatusForbidden, "invalid proof")
}

func TestProofBoundToApp(t *testing.T) {
	e := newEnv(t)
	h := e.holder("adult", "ca")
	// Proof built for other-app's identifier, submitted with a nonce issued for `app`.
	ch := e.challenge(app)
	ch.AppID = proto.FieldHex(proto.AppID("other-app"))
	e.expectReject(e.prove(h, ch), http.StatusForbidden, "invalid proof")
}

func TestBannedNullifier(t *testing.T) {
	e := newEnv(t)
	h := e.holder("adult", "ca")
	_, first, _ := e.submit(e.prove(h, e.challenge(app)))
	if first == nil {
		t.Fatal("first verification failed")
	}
	n, _ := proto.ParseFieldHex(first.Nullifier)
	nb := proto.FieldBytes(n)
	if err := e.store.SetBanned(context.Background(), app, nb[:], true); err != nil {
		t.Fatal(err)
	}
	e.expectReject(e.prove(h, e.challenge(app)), http.StatusForbidden, "banned")
	// The ban does not follow the person to another app (no cross-app linkage).
	if status, _, msg := e.submit(e.prove(h, e.challenge("other-app"))); status != http.StatusOK {
		t.Fatalf("other app: %d %s", status, msg)
	}
}

func TestMalformedAndUnknownApp(t *testing.T) {
	e := newEnv(t)
	if _, err := client.Challenge(context.Background(), http.DefaultClient, e.url, "not-configured"); err == nil {
		t.Fatal("challenge for unknown app should fail")
	}
	e.expectReject(&verifier.VerifyRequest{Nonce: "zz", CAPubkeyHash: "0x01", Nullifier: "0x01", Proof: "AA=="}, http.StatusBadRequest, "malformed")
}
