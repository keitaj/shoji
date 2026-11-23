// Command cardclient plays the holder when the signature comes from a real
// card. The card is driven by a separate device (see ios/), so the flow has two
// steps with a hand-off in between:
//
//	cardclient challenge -state ~/jpki-real/challenge.json
//	    -> prints a challenge string; have the card sign it
//	cardclient prove -state ~/jpki-real/challenge.json \
//	    -cert ~/jpki-real/jpki_sign.der -ca ~/jpki-real/jpki_sign_ca.der -sig <hex>
//
// Keep the certificate and the state file outside the repository. Nothing in
// them is printed.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/keitaj/shoji/internal/client"
	"github.com/keitaj/shoji/internal/mockjpki"
	"github.com/keitaj/shoji/internal/proto"
	"github.com/keitaj/shoji/internal/prover"
	"github.com/keitaj/shoji/internal/verifier"
)

type state struct {
	Server    string                     `json:"server"`
	Challenge verifier.ChallengeResponse `json:"challenge"`
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: cardclient <challenge|prove> [flags]")
	}
	switch os.Args[1] {
	case "challenge":
		challenge(os.Args[2:])
	case "prove":
		prove(os.Args[2:])
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
}

func challenge(args []string) {
	fs := flag.NewFlagSet("challenge", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "verifier base URL")
	app := fs.String("app", "demo", "application identifier")
	statePath := fs.String("state", "", "file to remember the challenge in (outside the repository)")
	fs.Parse(args)
	if *statePath == "" {
		log.Fatal("challenge: -state is required")
	}
	ch, err := client.Challenge(context.Background(), &http.Client{Timeout: 30 * time.Second}, *server, *app)
	if err != nil {
		log.Fatal(err)
	}
	raw, _ := json.Marshal(state{Server: *server, Challenge: *ch})
	if err := os.WriteFile(*statePath, raw, 0o600); err != nil {
		log.Fatal(err)
	}
	appID, err1 := proto.ParseFieldHex(ch.AppID)
	nonce, err2 := proto.ParseFieldHex(ch.Nonce)
	if err1 != nil || err2 != nil {
		log.Fatal("verifier returned a malformed challenge")
	}
	fmt.Fprintf(os.Stderr, "challenge valid for %d seconds; have the card sign this string:\n", ch.ExpiresIn)
	fmt.Println(proto.ChallengeString(appID, nonce))
}

func prove(args []string) {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	statePath := fs.String("state", "", "state file written by `cardclient challenge`")
	certPath := fs.String("cert", "", "holder's signing certificate (DER or PEM), kept outside the repository")
	caPath := fs.String("ca", "", "signing CA certificate (DER or PEM)")
	sigArg := fs.String("sig", "-", "the card's signature as hex, or - to read it from standard input")
	fs.Parse(args)
	if *statePath == "" || *certPath == "" || *caPath == "" {
		log.Fatal("prove: -state, -cert and -ca are required")
	}
	raw, err := os.ReadFile(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		log.Fatal("unreadable state file")
	}
	sigHex := *sigArg
	if sigHex == "-" {
		in, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			log.Fatal(err)
		}
		sigHex = string(in)
	}
	sig, err := hex.DecodeString(strings.Join(strings.Fields(sigHex), ""))
	if err != nil || len(sig) != proto.ModulusBytes {
		log.Fatalf("the signature must be %d bytes of hex", proto.ModulusBytes)
	}
	cert, err := mockjpki.ReadCert(*certPath)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := mockjpki.ReadCert(*caPath)
	if err != nil {
		log.Fatal(err)
	}
	caPub, err := mockjpki.RSAPublicKey(ca)
	if err != nil {
		log.Fatal(err)
	}
	h := &client.Holder{Cert: cert, CAPub: caPub, Tools: prover.DefaultTools(".")}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	req, err := h.ProveWithSignature(ctx, &st.Challenge, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("proof generated in %s\n", time.Since(start).Round(time.Millisecond))
	_, res, err := client.Submit(ctx, &http.Client{Timeout: time.Minute}, st.Server, req)
	if err != nil {
		log.Fatalf("rejected: %v", err)
	}
	_ = os.Remove(*statePath)
	fmt.Printf("accepted: nullifier=%s new=%v\n", res.Nullifier, res.New)
}
