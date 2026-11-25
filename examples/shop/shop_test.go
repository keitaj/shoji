package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVerifier stands in for the shoji verifier: the test decides what each
// session resolves to, as a phone would by proving (or failing to).
type fakeVerifier struct {
	mu       sync.Mutex
	n        int
	sessions map[string][2]string // session -> status, nullifier
	// delegated marks sessions answered without the card (by an agent's wallet).
	delegated map[string]bool
}

func (f *fakeVerifier) Start(context.Context) (string, string, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := fmt.Sprintf("s%d", f.n)
	if f.sessions == nil {
		f.sessions = map[string][2]string{}
	}
	f.sessions[id] = [2]string{"pending", ""}
	return id, "shoji://verify?u=http%3A%2F%2Fverifier.test&s=" + id, 10 * time.Minute, nil
}

func (f *fakeVerifier) Outcome(_ context.Context, session string) (string, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[session]
	if !ok {
		return "expired", "", false, nil
	}
	return s[0], s[1], f.delegated[session], nil
}

type env struct {
	t    *testing.T
	shop *Shop
	v    *fakeVerifier
}

func newEnv(t *testing.T) *env {
	v := &fakeVerifier{}
	shop := NewShop(Config{Verifier: v, Products: []Product{
		{ID: "a", Name: "A", Price: 100, Stock: 2},
		{ID: "b", Name: "B", Price: 100, Stock: 2},
		{ID: "c", Name: "C", Price: 100, Stock: 5, Agents: true},
	}})
	return &env{t: t, shop: shop, v: v}
}

func (e *env) do(method, path string, body any, out any) int {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			e.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.shop.ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			e.t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	return rec.Code
}

// attempt starts an intent, resolves its verification the way the test says
// ("verified" as person, "rejected", or "expired") and returns the outcome.
func (e *env) attempt(req createIntentRequest, status, person string) string {
	e.t.Helper()
	var created struct{ ID string }
	if code := e.do("POST", "/api/intents", req, &created); code != http.StatusOK {
		e.t.Fatalf("create intent: status %d", code)
	}
	var res struct{ Status, Outcome string }
	if e.do("GET", "/api/intents/"+created.ID, nil, &res); res.Status != "pending" {
		e.t.Fatalf("before verification: status %q", res.Status)
	}
	e.v.mu.Lock()
	session := fmt.Sprintf("s%d", e.v.n)
	switch status {
	case "expired":
		delete(e.v.sessions, session)
	case "agent":
		if e.v.delegated == nil {
			e.v.delegated = map[string]bool{}
		}
		e.v.sessions[session], e.v.delegated[session] = [2]string{"verified", person}, true
	default:
		e.v.sessions[session] = [2]string{status, person}
	}
	e.v.mu.Unlock()
	e.do("GET", "/api/intents/"+created.ID, nil, &res)
	// Polling again must not apply the intent a second time.
	var again struct{ Status, Outcome string }
	e.do("GET", "/api/intents/"+created.ID, nil, &again)
	if again != res {
		e.t.Fatalf("outcome changed on a second poll: %v then %v", res, again)
	}
	return res.Outcome
}

func (e *env) buy(product, person string) string {
	e.t.Helper()
	return e.attempt(createIntentRequest{Kind: "buy", Product: product}, "verified", person)
}

func (e *env) review(product, person, text string) string {
	e.t.Helper()
	return e.attempt(createIntentRequest{Kind: "review", Product: product, Rating: 4, Text: text}, "verified", person)
}

func (e *env) products() []publicProduct {
	e.t.Helper()
	var out []publicProduct
	e.do("GET", "/api/products", nil, &out)
	return out
}

func want(t *testing.T, got, expected string) {
	t.Helper()
	if got != expected {
		t.Fatalf("outcome %q, want %q", got, expected)
	}
}

func TestOnePurchasePerPersonPerProduct(t *testing.T) {
	e := newEnv(t)
	want(t, e.buy("a", "0xalice"), OutcomePurchased)
	want(t, e.buy("a", "0xalice"), OutcomeAlreadyPurchased)
	// The limit is per product, and another person is unaffected.
	want(t, e.buy("b", "0xalice"), OutcomePurchased)
	want(t, e.buy("a", "0xbob"), OutcomePurchased)
	if p := e.products(); p[0].Remaining != 0 || p[1].Remaining != 1 {
		t.Fatalf("remaining %d and %d, want 0 and 1", p[0].Remaining, p[1].Remaining)
	}
}

func TestSoldOut(t *testing.T) {
	e := newEnv(t)
	e.buy("a", "0xalice")
	e.buy("a", "0xbob")
	want(t, e.buy("a", "0xcarol"), OutcomeSoldOut)
}

func TestNothingHappensWithoutAVerifiedSession(t *testing.T) {
	e := newEnv(t)
	want(t, e.attempt(createIntentRequest{Kind: "buy", Product: "a"}, "rejected", ""), OutcomeRejected)
	want(t, e.attempt(createIntentRequest{Kind: "buy", Product: "a"}, "expired", ""), OutcomeExpired)
	if p := e.products(); p[0].Remaining != 2 {
		t.Fatalf("remaining %d, want 2", p[0].Remaining)
	}
}

func TestOnlyBuyersReviewAndOnlyOnce(t *testing.T) {
	e := newEnv(t)
	want(t, e.review("a", "0xalice", "not a buyer"), OutcomeNotPurchaser)
	e.buy("a", "0xalice")
	want(t, e.review("a", "0xalice", "good"), OutcomeReviewed)
	want(t, e.review("a", "0xalice", "good again"), OutcomeAlreadyReviewed)
	// Having bought A does not allow reviewing B.
	want(t, e.review("b", "0xalice", "never bought"), OutcomeNotPurchaser)
	p := e.products()
	if len(p[0].Reviews) != 1 || p[0].Reviews[0].Text != "good" || len(p[1].Reviews) != 0 {
		t.Fatalf("reviews: %+v", p)
	}
}

func TestBanStopsAPersonAndHidesTheirReviews(t *testing.T) {
	e := newEnv(t)
	e.buy("a", "0xalice")
	e.review("a", "0xalice", "spam")
	ban := func(banned bool) {
		if code := e.do("POST", "/api/admin/ban", map[string]any{"nullifier": "0xalice", "banned": banned}, nil); code != http.StatusOK {
			t.Fatalf("ban: status %d", code)
		}
	}
	ban(true)
	want(t, e.buy("b", "0xalice"), OutcomeBanned)
	if p := e.products(); len(p[0].Reviews) != 0 || p[1].Remaining != 2 {
		t.Fatalf("after ban: %+v", p)
	}
	want(t, e.buy("b", "0xbob"), OutcomePurchased)
	ban(false)
	want(t, e.buy("b", "0xalice"), OutcomePurchased)
	if p := e.products(); len(p[0].Reviews) != 1 {
		t.Fatalf("after unban: %+v", p)
	}
}

// What visitors see must not contain a nullifier, and one person's reviews of
// two products must not carry the same name.
func TestPublicPageDoesNotExposeOrLinkNullifiers(t *testing.T) {
	e := newEnv(t)
	e.buy("a", "0xalice")
	e.buy("b", "0xalice")
	e.review("a", "0xalice", "one")
	e.review("b", "0xalice", "two")
	rec := httptest.NewRecorder()
	e.shop.ServeHTTP(rec, httptest.NewRequest("GET", "/api/products", nil))
	if strings.Contains(rec.Body.String(), "0xalice") {
		t.Fatal("the public product list contains a nullifier")
	}
	p := e.products()
	if p[0].Reviews[0].Handle == p[1].Reviews[0].Handle {
		t.Fatal("the same handle is shown for two products")
	}
}

// Agents of one person are that one person: one item, however many agents, and
// also not a second one for the person's own card.
func TestAgentsOfOnePersonGetOneItem(t *testing.T) {
	e := newEnv(t)
	byAgent := func(product, person string) string {
		return e.attempt(createIntentRequest{Kind: "buy", Product: product}, "agent", person)
	}
	want(t, byAgent("c", "0xalice"), OutcomePurchased)
	for range 9 {
		want(t, byAgent("c", "0xalice"), OutcomeAlreadyPurchased)
	}
	want(t, e.buy("c", "0xalice"), OutcomeAlreadyPurchased)
	want(t, byAgent("c", "0xbob"), OutcomePurchased)
	if p := e.products(); p[2].Remaining != 3 {
		t.Fatalf("remaining %d, want 3", p[2].Remaining)
	}
	// Where agents are not welcome, the person has to come with their card.
	want(t, byAgent("a", "0xalice"), OutcomeAgentsNotAllowed)
	want(t, e.buy("a", "0xalice"), OutcomePurchased)
	// Reviews are never taken from agents, and a ban holds for them too.
	want(t, e.attempt(createIntentRequest{Kind: "review", Product: "c", Rating: 5, Text: "x"}, "agent", "0xalice"), OutcomeAgentsNotAllowed)
	e.do("POST", "/api/admin/ban", map[string]any{"nullifier": "0xcarol", "banned": true}, nil)
	want(t, byAgent("c", "0xcarol"), OutcomeBanned)
}

func TestBadRequests(t *testing.T) {
	e := newEnv(t)
	for name, req := range map[string]createIntentRequest{
		"unknown product": {Kind: "buy", Product: "zzz"},
		"unknown kind":    {Kind: "refund", Product: "a"},
		"empty review":    {Kind: "review", Product: "a", Rating: 5, Text: "  "},
		"rating 0":        {Kind: "review", Product: "a", Rating: 0, Text: "x"},
		"rating 6":        {Kind: "review", Product: "a", Rating: 6, Text: "x"},
		"long review":     {Kind: "review", Product: "a", Rating: 5, Text: strings.Repeat("あ", maxReviewRunes+1)},
	} {
		if code := e.do("POST", "/api/intents", req, nil); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
	if code := e.do("GET", "/api/intents/nope", nil, nil); code != http.StatusNotFound {
		t.Errorf("unknown intent: status %d, want 404", code)
	}
	// A form post from another site (no JSON content type) is refused.
	req := httptest.NewRequest("POST", "/api/admin/ban", strings.NewReader(`{"nullifier":"0xalice","banned":true}`))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	e.shop.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("non-JSON post: status %d, want 415", rec.Code)
	}
}

// HTTPVerifier against a stub of the verifier's two endpoints.
func TestHTTPVerifier(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"session":"abc","link":"shoji://verify?u=x&s=abc","expires_in":600}`)
	})
	mux.HandleFunc("GET /sessions/abc", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"verified","nullifier":"0x01","new":true}`)
	})
	mux.HandleFunc("GET /sessions/pending", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"pending"}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	v := HTTPVerifier{Base: ts.URL, Client: ts.Client()}
	ctx := context.Background()

	session, link, ttl, err := v.Start(ctx)
	if err != nil || session != "abc" || link == "" || ttl != 10*time.Minute {
		t.Fatalf("Start: %q %q %v %v", session, link, ttl, err)
	}
	for id, wantStatus := range map[string]string{"abc": "verified", "pending": "pending", "gone": "expired"} {
		status, nullifier, delegated, err := v.Outcome(ctx, id)
		if err != nil || delegated || status != wantStatus || (status == "verified") != (nullifier == "0x01") {
			t.Errorf("Outcome(%s): %q %q %v", id, status, nullifier, err)
		}
	}
}
