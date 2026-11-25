package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"rsc.io/qr"
)

const (
	maxBodyBytes   = 8 << 10
	maxReviewRunes = 400
	maxIntents     = 1000
)

// Verifier is the part of the shoji verifier a relying service uses.
type Verifier interface {
	// Start opens a verification session and returns its identifier, the link
	// the holder's phone opens (shown as a QR code) and its lifetime.
	Start(ctx context.Context) (session, link string, ttl time.Duration, err error)
	// Outcome reports "pending", "verified" (with the nullifier), "rejected",
	// or "expired" once the verifier no longer knows the session. delegated is
	// true when no card was present: software holding the person's delegation
	// answered, for instance for an AI agent.
	Outcome(ctx context.Context, session string) (status, nullifier string, delegated bool, err error)
}

// HTTPVerifier reaches a verifier over HTTP.
type HTTPVerifier struct {
	Base   string
	Client *http.Client
}

func (v HTTPVerifier) Start(ctx context.Context) (string, string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Base+"/sessions", nil)
	if err != nil {
		return "", "", 0, err
	}
	var out struct {
		Session   string `json:"session"`
		Link      string `json:"link"`
		ExpiresIn int    `json:"expires_in"`
	}
	status, err := v.do(req, &out)
	if err != nil {
		return "", "", 0, err
	}
	if status != http.StatusOK || out.Session == "" || out.Link == "" {
		return "", "", 0, fmt.Errorf("verifier: POST /sessions returned %d (was it started with -public-origin?)", status)
	}
	return out.Session, out.Link, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (v HTTPVerifier) Outcome(ctx context.Context, session string) (string, string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.Base+"/sessions/"+session, nil)
	if err != nil {
		return "", "", false, err
	}
	var out struct {
		Status    string `json:"status"`
		Nullifier string `json:"nullifier"`
		Delegated bool   `json:"delegated"`
	}
	status, err := v.do(req, &out)
	if err != nil {
		return "", "", false, err
	}
	switch {
	case status == http.StatusNotFound:
		return "expired", "", false, nil
	case status != http.StatusOK:
		return "", "", false, fmt.Errorf("verifier: GET /sessions/… returned %d", status)
	case out.Status == "verified" && out.Nullifier == "":
		return "", "", false, errors.New("verifier: verified session without a nullifier")
	}
	return out.Status, out.Nullifier, out.Delegated, nil
}

func (v HTTPVerifier) do(req *http.Request, out any) (int, error) {
	res, err := v.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return 0, err
	}
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, out); err != nil {
			return 0, err
		}
	}
	return res.StatusCode, nil
}

type Product struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Blurb string `json:"blurb"`
	Price int    `json:"price"`
	Stock int    `json:"stock"` // units offered in total
	// Agents says whether an order may come from software acting for a person
	// (a delegated proof). Otherwise the person has to tap their card.
	Agents bool `json:"agents"`
}

// Outcomes of an intent. Everything but the first two is a refusal.
const (
	OutcomePurchased        = "purchased"
	OutcomeReviewed         = "reviewed"
	OutcomeAlreadyPurchased = "already_purchased"
	OutcomeAlreadyReviewed  = "already_reviewed"
	OutcomeNotPurchaser     = "not_purchaser"
	OutcomeSoldOut          = "sold_out"
	OutcomeBanned           = "banned"
	OutcomeAgentsNotAllowed = "agents_not_allowed"
	OutcomeRejected         = "rejected" // the verifier did not accept a proof
	OutcomeExpired          = "expired"
)

// intent is something a visitor wants to do, waiting for a verification.
type intent struct {
	kind    string // "buy" or "review"
	product string
	rating  int
	text    string
	session string
	link    string
	expires time.Time
	outcome string // "" while pending
}

type purchase struct {
	Nullifier string    `json:"nullifier"`
	Product   string    `json:"product"`
	Agent     bool      `json:"agent"` // ordered by software acting for the person
	At        time.Time `json:"at"`
}

type review struct {
	Nullifier string    `json:"nullifier"`
	Product   string    `json:"product"`
	Rating    int       `json:"rating"`
	Text      string    `json:"text"`
	At        time.Time `json:"at"`
}

type Config struct {
	Verifier Verifier
	Products []Product
	Static   fs.FS
	Now      func() time.Time
}

// Shop holds everything the shop knows. About people it knows nullifiers only.
type Shop struct {
	cfg Config
	mux *http.ServeMux

	mu        sync.Mutex
	intents   map[string]*intent
	purchases []purchase
	reviews   []review
	banned    map[string]bool
}

func NewShop(cfg Config) *Shop {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Shop{cfg: cfg, mux: http.NewServeMux(), intents: map[string]*intent{}, banned: map[string]bool{}}
	s.mux.HandleFunc("GET /api/products", s.handleProducts)
	s.mux.HandleFunc("POST /api/intents", s.handleCreateIntent)
	s.mux.HandleFunc("GET /api/intents/{id}", s.handleIntent)
	s.mux.HandleFunc("GET /api/intents/{id}/qr.png", s.handleIntentQR)
	s.mux.HandleFunc("GET /api/admin/state", s.handleAdminState)
	s.mux.HandleFunc("POST /api/admin/ban", s.handleAdminBan)
	if cfg.Static != nil {
		s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.ServeFileFS(w, r, cfg.Static, "index.html") })
		s.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) { http.ServeFileFS(w, r, cfg.Static, "admin.html") })
	}
	return s
}

func (s *Shop) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Shop) product(id string) (Product, bool) {
	for _, p := range s.cfg.Products {
		if p.ID == id {
			return p, true
		}
	}
	return Product{}, false
}

// The helpers below are called with s.mu held.

func (s *Shop) sold(product string) int {
	n := 0
	for _, p := range s.purchases {
		if p.Product == product {
			n++
		}
	}
	return n
}

func (s *Shop) hasPurchased(nullifier, product string) bool {
	for _, p := range s.purchases {
		if p.Nullifier == nullifier && p.Product == product {
			return true
		}
	}
	return false
}

func (s *Shop) hasReviewed(nullifier, product string) bool {
	for _, r := range s.reviews {
		if r.Nullifier == nullifier && r.Product == product {
			return true
		}
	}
	return false
}

// decide applies a verified intent and returns its outcome. The nullifier is
// the person's, whether they tapped their card or software acted for them
// (delegated): any number of agents of one person are that one person.
func (s *Shop) decide(in *intent, nullifier string, delegated bool) string {
	if s.banned[nullifier] {
		return OutcomeBanned
	}
	p, _ := s.product(in.product)
	now := s.cfg.Now()
	switch in.kind {
	case "buy":
		if delegated && !p.Agents {
			return OutcomeAgentsNotAllowed
		}
		if s.hasPurchased(nullifier, in.product) {
			return OutcomeAlreadyPurchased
		}
		if s.sold(in.product) >= p.Stock {
			return OutcomeSoldOut
		}
		s.purchases = append(s.purchases, purchase{Nullifier: nullifier, Product: in.product, Agent: delegated, At: now})
		return OutcomePurchased
	default: // "review"
		if delegated {
			// Reviews are a person's own words here, whatever the product.
			return OutcomeAgentsNotAllowed
		}
		if !s.hasPurchased(nullifier, in.product) {
			return OutcomeNotPurchaser
		}
		if s.hasReviewed(nullifier, in.product) {
			return OutcomeAlreadyReviewed
		}
		s.reviews = append(s.reviews, review{Nullifier: nullifier, Product: in.product, Rating: in.rating, Text: in.text, At: now})
		return OutcomeReviewed
	}
}

// handle is the name a reviewer is shown under. It differs per product, so the
// public page does not link one person's reviews of different items.
func handle(nullifier, product string) string {
	sum := sha256.Sum256([]byte("shoji-shop-handle\x00" + nullifier + "\x00" + product))
	return hex.EncodeToString(sum[:2])
}

type publicReview struct {
	Handle string    `json:"handle"`
	Rating int       `json:"rating"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
}

type publicProduct struct {
	Product
	Remaining int            `json:"remaining"`
	Reviews   []publicReview `json:"reviews"`
}

func (s *Shop) handleProducts(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	out := make([]publicProduct, 0, len(s.cfg.Products))
	for _, p := range s.cfg.Products {
		pp := publicProduct{Product: p, Remaining: max(p.Stock-s.sold(p.ID), 0), Reviews: []publicReview{}}
		for _, rv := range s.reviews {
			if rv.Product == p.ID && !s.banned[rv.Nullifier] {
				pp.Reviews = append(pp.Reviews, publicReview{Handle: handle(rv.Nullifier, p.ID), Rating: rv.Rating, Text: rv.Text, At: rv.At})
			}
		}
		out = append(out, pp)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

type createIntentRequest struct {
	Kind    string `json:"kind"`
	Product string `json:"product"`
	Rating  int    `json:"rating,omitempty"`
	Text    string `json:"text,omitempty"`
}

func (s *Shop) handleCreateIntent(w http.ResponseWriter, r *http.Request) {
	var req createIntentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, ok := s.product(req.Product); !ok {
		writeError(w, http.StatusBadRequest, "unknown product")
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	switch req.Kind {
	case "buy":
		req.Rating, req.Text = 0, ""
	case "review":
		if req.Rating < 1 || req.Rating > 5 || req.Text == "" || !utf8.ValidString(req.Text) || utf8.RuneCountInString(req.Text) > maxReviewRunes {
			writeError(w, http.StatusBadRequest, "a review needs a rating from 1 to 5 and a text of at most 400 characters")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "unknown kind")
		return
	}

	session, link, ttl, err := s.cfg.Verifier.Start(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "the verifier is not reachable")
		return
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	id := hex.EncodeToString(raw)
	now := s.cfg.Now()

	s.mu.Lock()
	for k, in := range s.intents {
		if now.After(in.expires.Add(time.Hour)) {
			delete(s.intents, k)
		}
	}
	if len(s.intents) >= maxIntents {
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	s.intents[id] = &intent{kind: req.Kind, product: req.Product, rating: req.Rating, text: req.Text, session: session, link: link, expires: now.Add(ttl)}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"id": id, "link": link, "expires_in": int(ttl / time.Second)})
}

func (s *Shop) intent(w http.ResponseWriter, r *http.Request) (*intent, bool) {
	s.mu.Lock()
	in := s.intents[r.PathValue("id")]
	s.mu.Unlock()
	if in == nil {
		writeError(w, http.StatusNotFound, "unknown intent")
	}
	return in, in != nil
}

// handleIntent is polled by the shop's page. While the intent is pending it asks
// the verifier, and on a verified session applies the intent exactly once.
func (s *Shop) handleIntent(w http.ResponseWriter, r *http.Request) {
	in, ok := s.intent(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	outcome := in.outcome
	s.mu.Unlock()

	if outcome == "" {
		status, nullifier, delegated, err := s.cfg.Verifier.Outcome(r.Context(), in.session)
		if err != nil {
			writeError(w, http.StatusBadGateway, "the verifier is not reachable")
			return
		}
		s.mu.Lock()
		if in.outcome == "" { // another poll may have settled it meanwhile
			switch status {
			case "verified":
				in.outcome = s.decide(in, nullifier, delegated)
			case "rejected":
				in.outcome = OutcomeRejected
			case "expired":
				in.outcome = OutcomeExpired
			}
		}
		outcome = in.outcome
		s.mu.Unlock()
	}

	w.Header().Set("Cache-Control", "no-store")
	switch outcome {
	case "":
		writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
	case OutcomePurchased, OutcomeReviewed:
		writeJSON(w, http.StatusOK, map[string]string{"status": "done", "outcome": outcome})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "refused", "outcome": outcome})
	}
}

func (s *Shop) handleIntentQR(w http.ResponseWriter, r *http.Request) {
	in, ok := s.intent(w, r)
	if !ok {
		return
	}
	code, err := qr.Encode(in.link, qr.M)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	code.Scale = 6
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(code.PNG())
}

// handleAdminState returns everything the shop has stored, as the operator page
// shows it: there is nothing else.
func (s *Shop) handleAdminState(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	banned := make([]string, 0, len(s.banned))
	for n := range s.banned {
		banned = append(banned, n)
	}
	sort.Strings(banned)
	out := map[string]any{
		"products":  s.cfg.Products,
		"purchases": append([]purchase{}, s.purchases...),
		"reviews":   append([]review{}, s.reviews...),
		"banned":    banned,
	}
	s.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (s *Shop) handleAdminBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nullifier string `json:"nullifier"`
		Banned    bool   `json:"banned"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Nullifier == "" {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	s.mu.Lock()
	if req.Banned {
		s.banned[req.Nullifier] = true
	} else {
		delete(s.banned, req.Nullifier)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// decodeJSON insists on a JSON content type, which a page on another site
// cannot send here without the browser asking first (CORS preflight).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.TrimSpace(ct) != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}
