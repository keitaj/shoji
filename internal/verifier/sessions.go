package verifier

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

// checkOrigin accepts exactly scheme://host[:port], lower case, nothing else.
// The phone derives app_id from this string, so it must have one spelling.
func checkOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		origin != strings.ToLower(origin) || origin != u.Scheme+"://"+u.Host {
		return errors.New("verifier: PublicOrigin must be scheme://host[:port] in lower case, without a path")
	}
	return nil
}

// SessionLink is what the QR code carries: a link that opens the shoji app with
// the origin to talk to and the session to complete.
func SessionLink(origin string, id []byte) string {
	return "shoji://verify?u=" + url.QueryEscape(origin) + "&s=" + hex.EncodeToString(id)
}

type createSessionResponse struct {
	Session   string `json:"session"`
	Link      string `json:"link"`
	ExpiresIn int    `json:"expires_in"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := s.cfg.Now()
	if err := s.cfg.Store.PutSession(r.Context(), id, now.Add(s.cfg.SessionTTL).Unix(), now.Unix()); err != nil {
		s.cfg.Log.Error("store session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, createSessionResponse{
		Session:   hex.EncodeToString(id),
		Link:      SessionLink(s.cfg.PublicOrigin, id),
		ExpiresIn: int(s.cfg.SessionTTL / time.Second),
	})
}

// SessionResponse is what a relying page learns: the outcome and, on success,
// the holder's nullifier for this service. Never anything else about the holder.
type SessionResponse struct {
	Status    string `json:"status"` // pending | verified | rejected
	Nullifier string `json:"nullifier,omitempty"`
	New       bool   `json:"new,omitempty"`
	// Delegated is true when no card was present: software holding the holder's
	// delegation (for instance on behalf of an AI agent) answered.
	Delegated bool `json:"delegated,omitempty"`
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) (Session, bool) {
	id, err := hex.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != 16 {
		writeError(w, http.StatusNotFound, "unknown session")
		return Session{}, false
	}
	sess, err := s.cfg.Store.GetSession(r.Context(), id, s.cfg.Now().Unix())
	if errors.Is(err, ErrNoSession) {
		writeError(w, http.StatusNotFound, "unknown session")
		return Session{}, false
	}
	if err != nil {
		s.cfg.Log.Error("get session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return Session{}, false
	}
	return sess, true
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	res := SessionResponse{Status: "pending"}
	switch sess.Status {
	case SessionVerified:
		res = SessionResponse{Status: "verified", Nullifier: "0x" + hex.EncodeToString(sess.Nullifier), New: sess.IsNew, Delegated: sess.Delegated}
	case SessionRejected:
		res.Status = "rejected"
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleSessionQR(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	code, err := qr.Encode(SessionLink(s.cfg.PublicOrigin, sess.ID), qr.M)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	code.Scale = 6
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(code.PNG())
}

// handleDemo serves a page that plays the relying service: it starts a session,
// shows the QR code and waits for the outcome.
func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, demoPage, s.cfg.AgeThreshold)
}

const demoPage = `<!doctype html>
<html lang="ja">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>shoji デモ</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem; line-height: 1.7; color: #1d1d1f; }
  h1 { font-size: 1.4rem; }
  #qr { display: block; margin: 1.5rem auto; image-rendering: pixelated; border: 1px solid #ddd; padding: 12px; background: #fff; }
  #state { padding: 1rem; border-radius: 10px; background: #f2f2f7; }
  #state.ok { background: #e3f6e5; } #state.ng { background: #fde8e8; }
  code { word-break: break-all; font-size: 0.8rem; }
  small { color: #6e6e73; }
</style>
<h1>shoji デモサービス</h1>
<p>このページは、利用者が<strong>%d歳以上の実在する人</strong>であることを確認したいサービスの役をします。
iPhone のカメラで QR コードを読み取り、shoji のアプリでマイナンバーカードをかざしてください。</p>
<img id="qr" alt="QR コード" width="246" height="246">
<div id="state">準備しています…</div>
<p><small>このサービスに届くのは、確認の結果と、このサービス専用の匿名IDだけです。氏名・住所・生年月日・証明書は届きません。</small></p>
<script>
const state = document.getElementById('state');
async function start() {
  const res = await fetch('/sessions', { method: 'POST' });
  const s = await res.json();
  document.getElementById('qr').src = '/sessions/' + s.session + '/qr.png';
  state.className = ''; state.textContent = 'アプリでの確認を待っています…';
  const timer = setInterval(async () => {
    const r = await fetch('/sessions/' + s.session);
    if (!r.ok) { clearInterval(timer); state.className = 'ng'; state.textContent = '有効期限が切れました。ページを再読み込みしてください。'; return; }
    const d = await r.json();
    if (d.status === 'verified') {
      clearInterval(timer); state.className = 'ok';
      state.innerHTML = '<strong>確認できました。</strong><br>' + (d.new ? '初めての利用者です。' : '以前にも確認した利用者です。') + '<br>匿名ID: <code></code>';
      state.querySelector('code').textContent = d.nullifier;
    } else if (d.status === 'rejected') {
      clearInterval(timer); state.className = 'ng'; state.textContent = '確認できませんでした。';
    }
  }, 1500);
}
start().catch(() => { state.className = 'ng'; state.textContent = '開始できませんでした。'; });
</script>
</html>
`
