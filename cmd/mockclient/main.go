// Command mockclient plays the holder until a real card reader exists: it uses a mock certificate and
// key from disk in place of a card, generates a proof on this machine and
// submits it to the verifier.
//
//	mockclient -app demo
//	mockclient -link 'shoji://verify?u=...&s=...'   # complete a session, as the phone app would
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/keitaj/shoji/internal/client"
	"github.com/keitaj/shoji/internal/mockjpki"
	"github.com/keitaj/shoji/internal/prover"
	"github.com/keitaj/shoji/internal/verifier"
)

func main() {
	log.SetFlags(0)
	server := flag.String("server", "http://127.0.0.1:8080", "verifier base URL")
	app := flag.String("app", "demo", "application identifier")
	certPath := flag.String("cert", "testdata/adult.pem", "holder certificate (mock)")
	keyPath := flag.String("key", "testdata/adult.key", "holder private key (mock card)")
	caPath := flag.String("ca", "testdata/ca.pem", "issuing CA certificate")
	link := flag.String("link", "", "verification link from a service's QR code (shoji://verify?u=<origin>&s=<session>); replaces -server and -app")
	flag.Parse()

	// Like the phone, take the origin to talk to from the link and use that
	// same origin as the application the proof is for.
	session := ""
	if *link != "" {
		u, err := url.Parse(*link)
		if err != nil || u.Scheme != "shoji" || u.Host != "verify" || u.Query().Get("u") == "" || u.Query().Get("s") == "" {
			log.Fatal("-link must look like shoji://verify?u=<origin>&s=<session>")
		}
		*server, *app, session = u.Query().Get("u"), u.Query().Get("u"), u.Query().Get("s")
	}

	cert, err := mockjpki.ReadCertPEM(*certPath)
	if err != nil {
		log.Fatal(err)
	}
	key, err := mockjpki.ReadKeyPEM(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := mockjpki.ReadCertPEM(*caPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		log.Fatalf("certificate was not issued by %s", *caPath)
	}
	caPub, err := mockjpki.RSAPublicKey(ca)
	if err != nil {
		log.Fatal(err)
	}
	h := &client.Holder{Cert: cert, Key: key, CAPub: caPub, Tools: prover.DefaultTools(".")}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	hc := &http.Client{Timeout: time.Minute}

	var ch *verifier.ChallengeResponse
	if session != "" {
		ch, err = client.ChallengeForSession(ctx, hc, *server, *app, session)
	} else {
		ch, err = client.Challenge(ctx, hc, *server, *app)
	}
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()
	req, err := h.Prove(ctx, ch)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("proof generated in %s\n", time.Since(start).Round(time.Millisecond))
	_, res, err := client.Submit(ctx, hc, *server, req)
	if err != nil {
		log.Fatalf("rejected: %v", err)
	}
	fmt.Printf("accepted: nullifier=%s new=%v\n", res.Nullifier, res.New)
}
