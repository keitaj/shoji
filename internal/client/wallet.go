package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/keitaj/shoji/internal/proto"
	"github.com/keitaj/shoji/internal/verifier"
	"github.com/keitaj/shoji/internal/witness"
)

// Wallet is the holder's device once the card has signed a delegation: it
// answers verification links without the card, for instance when an AI agent
// acting for the holder is asked to show that a person stands behind it. The
// certificate and the delegation never leave it; an agent only hands it a link.
type Wallet struct {
	Holder     *Holder
	Delegation *witness.Delegation
	HTTP       *http.Client
	// Now is the clock (defaults to time.Now).
	Now func() time.Time
}

// jst is the calendar the age check and delegation expiry use.
var jst = time.FixedZone("JST", 9*60*60)

// ParseLink splits a verification link (shoji://verify?u=<origin>&s=<session>)
// into the verifier's origin and the session.
func ParseLink(link string) (origin, session string, err error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "shoji" || u.Host != "verify" {
		return "", "", errors.New("not a shoji verification link")
	}
	origin, session = u.Query().Get("u"), u.Query().Get("s")
	if origin == "" || session == "" {
		return "", "", errors.New("verification link lacks an origin or a session")
	}
	return origin, session, nil
}

// Answer completes the session a link names with a delegated proof.
//
// Like the phone app, it does not take the server's word for what the proof is
// about: the application is the origin it is talking to, the date must be today
// and the limit on the delegation's length must be the protocol's.
func (w *Wallet) Answer(ctx context.Context, link string) (*verifier.VerifyResponse, error) {
	origin, session, err := ParseLink(link)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	today := now().In(jst)
	if w.Delegation.Expiry < proto.DateInt(today) {
		return nil, errors.New("the delegation has expired; the card has to sign a new one")
	}
	ch, err := ChallengeDelegated(ctx, w.HTTP, origin, origin, session)
	if err != nil {
		return nil, err
	}
	appID, err := proto.ParseFieldHex(ch.AppID)
	if err != nil || appID.Cmp(proto.AppID(origin)) != 0 {
		return nil, errors.New("refused: the server named an application other than itself")
	}
	if ch.CurrentDate != proto.DateInt(today) && ch.CurrentDate != proto.DateInt(today.AddDate(0, 0, -1)) && ch.CurrentDate != proto.DateInt(today.AddDate(0, 0, 1)) {
		return nil, errors.New("refused: the server's date is not today")
	}
	if latest, err := proto.LatestExpiry(ch.CurrentDate); err != nil || ch.LatestExpiry != latest {
		return nil, errors.New("refused: the server's limit on delegations is not the protocol's")
	}
	req, err := w.Holder.ProveDelegated(ctx, ch, w.Delegation)
	if err != nil {
		return nil, fmt.Errorf("could not prove: %w", err)
	}
	_, res, err := Submit(ctx, w.HTTP, origin, req)
	return res, err
}
