// Package verifier implements the verification server: it issues short-lived
// single-use nonces and checks proofs.
//
// Trust rule: every public input of the proof except the nullifier is supplied
// by the server from its own state (trusted CA list, the stored challenge, the
// required is_over_threshold = 1). Nothing the client sends is trusted until the
// proof has verified against those values.
package verifier

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/keitaj/shoji/internal/proto"
	"github.com/keitaj/shoji/internal/prover"
)

const (
	maxBodyBytes  = 64 << 10
	maxProofBytes = 32 << 10
	verifyTimeout = 30 * time.Second
)

// ProofChecker verifies a proof against public inputs (concatenated 32-byte
// big-endian field elements).
type ProofChecker interface {
	Check(ctx context.Context, proof, publicInputs []byte) (bool, error)
}

// BBChecker runs `bb verify` as a subprocess.
type BBChecker struct {
	BB string // path to bb
	VK string // path to the verification key
}

func (c BBChecker) Check(ctx context.Context, proof, publicInputs []byte) (bool, error) {
	dir, err := os.MkdirTemp("", "shoji-verify-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(dir)
	proofPath, pubPath := filepath.Join(dir, "proof"), filepath.Join(dir, "public_inputs")
	if err := os.WriteFile(proofPath, proof, 0o600); err != nil {
		return false, err
	}
	if err := os.WriteFile(pubPath, publicInputs, 0o600); err != nil {
		return false, err
	}
	err = exec.CommandContext(ctx, c.BB, "verify",
		"-k", c.VK, "-p", proofPath, "-i", pubPath, "-t", prover.VerifierTarget).Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && ctx.Err() == nil {
		return false, nil // bb ran and rejected the proof
	}
	return false, err
}

// Config configures a Server.
type Config struct {
	Store   *Store
	Checker ProofChecker
	// DelegatedChecker verifies proofs of the delegated circuit
	// (circuits/delegated). Nil means delegated proofs are not accepted.
	DelegatedChecker ProofChecker
	// TrustedCAHashes are proto.PubkeyHash values of the CA keys the server
	// trusts, as canonical hex (proto.FieldHex).
	TrustedCAHashes []string
	// Apps are the application identifiers the server issues challenges for.
	Apps []string
	// PublicOrigin is the origin (scheme://host[:port]) under which holders'
	// phones reach this server, e.g. "https://verify.example.jp". Setting it
	// enables verification sessions. The application identifier of a session is
	// this origin: the phone derives app_id from the origin it is talking to, so
	// a proof made for one service cannot be passed on to another.
	PublicOrigin string
	SessionTTL   time.Duration
	AgeThreshold uint8
	NonceTTL     time.Duration
	// MaxConcurrentVerifications bounds the number of bb processes.
	MaxConcurrentVerifications int
	// Now is the clock (defaults to time.Now).
	Now func() time.Time
	Log *slog.Logger
}

type Server struct {
	cfg     Config
	trusted map[string]bool
	// trustedList is the same set in configuration order, for the challenge response.
	trustedList []string
	apps        map[string]bool
	sem         chan struct{}
	mux         *http.ServeMux
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Checker == nil {
		return nil, errors.New("verifier: Store and Checker are required")
	}
	if cfg.PublicOrigin != "" {
		if err := checkOrigin(cfg.PublicOrigin); err != nil {
			return nil, err
		}
		cfg.Apps = append(cfg.Apps, cfg.PublicOrigin)
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 10 * time.Minute
	}
	if len(cfg.TrustedCAHashes) == 0 || len(cfg.Apps) == 0 {
		return nil, errors.New("verifier: at least one trusted CA and one app are required")
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = 5 * time.Minute
	}
	if cfg.AgeThreshold == 0 {
		cfg.AgeThreshold = 18
	}
	if cfg.MaxConcurrentVerifications <= 0 {
		cfg.MaxConcurrentVerifications = 4
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, trusted: map[string]bool{}, apps: map[string]bool{}, sem: make(chan struct{}, cfg.MaxConcurrentVerifications), mux: http.NewServeMux()}
	for _, h := range cfg.TrustedCAHashes {
		x, err := proto.ParseFieldHex(h)
		if err != nil {
			return nil, err
		}
		if !s.trusted[proto.FieldHex(x)] {
			s.trustedList = append(s.trustedList, proto.FieldHex(x))
		}
		s.trusted[proto.FieldHex(x)] = true
	}
	for _, a := range cfg.Apps {
		s.apps[a] = true
	}
	s.mux.HandleFunc("POST /challenge", s.handleChallenge)
	s.mux.HandleFunc("POST /verify", s.handleVerify)
	if cfg.PublicOrigin != "" {
		s.mux.HandleFunc("POST /sessions", s.handleCreateSession)
		s.mux.HandleFunc("GET /sessions/{id}", s.handleGetSession)
		s.mux.HandleFunc("GET /sessions/{id}/qr.png", s.handleSessionQR)
		s.mux.HandleFunc("GET /demo", s.handleDemo)
	}
	return s, nil
}

// ServeHTTP also logs one line per request: method, path and status only, never
// a body, a nonce or a nullifier.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.mux.ServeHTTP(rec, r)
	path := r.URL.Path
	if strings.HasPrefix(path, "/sessions/") {
		path = "/sessions/…" // session identifiers are capabilities; keep them out of logs
	}
	s.cfg.Log.Debug("request", "method", r.Method, "path", path, "status", rec.status)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// jst is the calendar the age check uses.
var jst = time.FixedZone("JST", 9*60*60)

type challengeRequest struct {
	App string `json:"app"`
	// Session ties the challenge to a verification session (hex). The app must
	// then be the server's public origin; it may be omitted.
	Session string `json:"session,omitempty"`
	// Delegated asks for a challenge to be answered with a delegated proof (no
	// card present). The choice is stored with the challenge.
	Delegated bool `json:"delegated,omitempty"`
}

// ChallengeResponse carries everything the holder needs to build the proof.
type ChallengeResponse struct {
	Nonce        string `json:"nonce"`  // field element, hex
	AppID        string `json:"app_id"` // field element, hex
	CurrentDate  uint32 `json:"current_date"`
	AgeThreshold uint8  `json:"age_threshold"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	// LatestExpiry is set for a delegated challenge: the public input of the
	// same name, proto.LatestExpiry(CurrentDate). The holder's software
	// recomputes it and refuses any other value.
	LatestExpiry uint32 `json:"latest_expiry,omitempty"`
	// TrustedCAHashes lists the ca_pubkey_hash values the server accepts, so a
	// holder that cannot compute the hash itself can pick the one for its CA.
	// It is public configuration; the server still checks the value it gets back.
	TrustedCAHashes []string `json:"trusted_ca_hashes"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	now := s.cfg.Now()
	var session []byte
	if req.Session != "" {
		if req.App == "" {
			req.App = s.cfg.PublicOrigin
		}
		id, err := hex.DecodeString(req.Session)
		if err != nil || s.cfg.PublicOrigin == "" || req.App != s.cfg.PublicOrigin {
			writeError(w, http.StatusBadRequest, "unknown session")
			return
		}
		sess, err := s.cfg.Store.GetSession(r.Context(), id, now.Unix())
		if err != nil || sess.Status != SessionPending {
			writeError(w, http.StatusBadRequest, "unknown session")
			return
		}
		session = id
	}
	if !s.apps[req.App] {
		writeError(w, http.StatusBadRequest, "unknown app")
		return
	}
	if req.Delegated && s.cfg.DelegatedChecker == nil {
		writeError(w, http.StatusBadRequest, "delegated proofs are not accepted")
		return
	}
	nonce := make([]byte, proto.NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	c := Challenge{
		Nonce:        nonce,
		App:          req.App,
		CurrentDate:  proto.DateInt(now.In(jst)),
		AgeThreshold: s.cfg.AgeThreshold,
		ExpiresAt:    now.Add(s.cfg.NonceTTL).Unix(),
		Session:      session,
		Delegated:    req.Delegated,
	}
	var latestExpiry uint32
	if c.Delegated {
		var err error
		if latestExpiry, err = proto.LatestExpiry(c.CurrentDate); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	if err := s.cfg.Store.PutChallenge(r.Context(), c, now.Unix()); err != nil {
		s.cfg.Log.Error("store challenge", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, ChallengeResponse{
		Nonce:           proto.FieldHex(new(big.Int).SetBytes(nonce)),
		AppID:           proto.FieldHex(proto.AppID(req.App)),
		CurrentDate:     c.CurrentDate,
		AgeThreshold:    c.AgeThreshold,
		ExpiresIn:       int(s.cfg.NonceTTL / time.Second),
		LatestExpiry:    latestExpiry,
		TrustedCAHashes: s.trustedList,
	})
}

// VerifyRequest is what the holder submits. It contains no personal data.
type VerifyRequest struct {
	Nonce        string `json:"nonce"`          // as returned by /challenge
	CAPubkeyHash string `json:"ca_pubkey_hash"` // which trusted CA the proof is for
	Nullifier    string `json:"nullifier"`      // public output of the proof
	Proof        string `json:"proof"`          // base64
}

type VerifyResponse struct {
	OK        bool   `json:"ok"`
	Nullifier string `json:"nullifier"`
	// New is true the first time this nullifier is seen for the app.
	New bool `json:"new"`
	// Delegated is true when the proof was a delegated one.
	Delegated bool `json:"delegated,omitempty"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nonce, err1 := proto.ParseFieldHex(req.Nonce)
	caHash, err2 := proto.ParseFieldHex(req.CAPubkeyHash)
	nullifier, err3 := proto.ParseFieldHex(req.Nullifier)
	proof, err4 := base64.StdEncoding.DecodeString(req.Proof)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(proof) == 0 || len(proof) > maxProofBytes || nonce.BitLen() > proto.NonceBytes*8 {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	nonceBytes := make([]byte, proto.NonceBytes)
	nonce.FillBytes(nonceBytes)

	// Consume the nonce first: from here on it can never be used again.
	ch, err := s.cfg.Store.ConsumeChallenge(r.Context(), nonceBytes, s.cfg.Now().Unix())
	if errors.Is(err, ErrNoChallenge) {
		writeError(w, http.StatusBadRequest, "unknown, used or expired nonce")
		return
	}
	if err != nil {
		s.cfg.Log.Error("consume challenge", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Whatever happens from here on, a session this challenge belongs to gets an
	// outcome: rejected unless the proof is accepted below.
	accepted := false
	var acceptedNullifier []byte
	acceptedNew := false
	if ch.Session != nil {
		defer func() {
			status := SessionRejected
			if accepted {
				status = SessionVerified
			}
			if err := s.cfg.Store.FinishSession(context.WithoutCancel(r.Context()), ch.Session, status, acceptedNullifier, acceptedNew, accepted && ch.Delegated); err != nil {
				s.cfg.Log.Error("finish session", "err", err)
			}
		}()
	}

	// The CA key hash is only an index into our own trusted list.
	if !s.trusted[proto.FieldHex(caHash)] {
		s.cfg.Log.Info("verify rejected", "reason", "untrusted CA")
		writeError(w, http.StatusForbidden, "untrusted CA")
		return
	}

	// Public inputs in circuit order. Only `nullifier` comes from the client,
	// and the proof binds it. is_over_threshold is fixed to 1. Which circuit the
	// proof must be for was fixed when the challenge was issued.
	fields := []*big.Int{
		caHash,
		nonce,
		proto.AppID(ch.App),
		big.NewInt(int64(ch.CurrentDate)),
		big.NewInt(int64(ch.AgeThreshold)),
	}
	checker := s.cfg.Checker
	if ch.Delegated {
		latestExpiry, err := proto.LatestExpiry(ch.CurrentDate)
		if err != nil || s.cfg.DelegatedChecker == nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		fields = append(fields, big.NewInt(int64(latestExpiry)))
		checker = s.cfg.DelegatedChecker
	}
	fields = append(fields, nullifier, big.NewInt(1))
	public := make([]byte, 0, len(fields)*32)
	for _, f := range fields {
		b := proto.FieldBytes(f)
		public = append(public, b[:]...)
	}

	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	defer cancel()
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	ok, err := checker.Check(ctx, proof, public)
	if err != nil {
		s.cfg.Log.Error("proof check", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		s.cfg.Log.Info("verify rejected", "reason", "invalid proof")
		writeError(w, http.StatusForbidden, "invalid proof")
		return
	}

	nb := proto.FieldBytes(nullifier)
	isNew, banned, err := s.cfg.Store.RecordNullifier(r.Context(), ch.App, nb[:])
	if err != nil {
		s.cfg.Log.Error("record nullifier", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if banned {
		s.cfg.Log.Info("verify rejected", "reason", "banned")
		writeError(w, http.StatusForbidden, "banned")
		return
	}
	accepted, acceptedNullifier, acceptedNew = true, nb[:], isNew
	s.cfg.Log.Info("verify accepted", "app", ch.App, "new", isNew, "delegated", ch.Delegated)
	writeJSON(w, http.StatusOK, VerifyResponse{OK: true, Nullifier: "0x" + hex.EncodeToString(nb[:]), New: isNew, Delegated: ch.Delegated})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
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
