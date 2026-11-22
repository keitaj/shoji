// Command mockclient plays the holder until a real card reader exists: it uses a mock certificate and
// key from disk in place of a card, generates a proof on this machine and
// submits it to the verifier.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"shoji/internal/client"
	"shoji/internal/mockjpki"
	"shoji/internal/prover"
)

func main() {
	log.SetFlags(0)
	server := flag.String("server", "http://127.0.0.1:8080", "verifier base URL")
	app := flag.String("app", "demo", "application identifier")
	certPath := flag.String("cert", "testdata/adult.pem", "holder certificate (mock)")
	keyPath := flag.String("key", "testdata/adult.key", "holder private key (mock card)")
	caPath := flag.String("ca", "testdata/ca.pem", "issuing CA certificate")
	flag.Parse()

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

	ch, err := client.Challenge(ctx, hc, *server, *app)
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
