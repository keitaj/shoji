// Command wallet stands in for the holder's phone in the delegated flow, with a
// mock key on disk in place of the card.
//
//	wallet delegate -cert testdata/adult.pem -key testdata/adult.key   # the "card tap": sign a delegation
//	wallet serve                                                       # answer links for local agents
//	wallet prove -link 'shoji://verify?u=...&s=...'                    # answer one link
//
// After `delegate`, no key is needed any more: the wallet file holds the
// certificate, the delegation and its secret, and proves with those until the
// delegation expires. That file is private witness data (here: of a mock holder).
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/keitaj/shoji/internal/client"
	"github.com/keitaj/shoji/internal/mockjpki"
	"github.com/keitaj/shoji/internal/proto"
	"github.com/keitaj/shoji/internal/prover"
	"github.com/keitaj/shoji/internal/witness"
)

// file is the wallet on disk.
type file struct {
	Cert   []byte `json:"cert"` // DER
	CA     []byte `json:"ca"`   // DER
	Secret string `json:"secret"`
	Expiry uint32 `json:"expiry"`
	Sig    []byte `json:"sig"`
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: wallet delegate|serve|prove [flags]")
	}
	switch os.Args[1] {
	case "delegate":
		delegate(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	case "prove":
		prove(os.Args[2:])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func delegate(args []string) {
	fs := flag.NewFlagSet("delegate", flag.ExitOnError)
	certPath := fs.String("cert", "testdata/adult.pem", "holder certificate (mock)")
	keyPath := fs.String("key", "testdata/adult.key", "holder private key (mock card)")
	caPath := fs.String("ca", "testdata/ca.pem", "issuing CA certificate")
	days := fs.Int("days", proto.MaxDelegationDays, "how long the delegation runs")
	out := fs.String("out", "testdata/wallet.json", "wallet file to write")
	fs.Parse(args)

	cert, err := mockjpki.ReadCertPEM(*certPath)
	must(err)
	key, err := mockjpki.ReadKeyPEM(*keyPath)
	must(err)
	ca, err := mockjpki.ReadCertPEM(*caPath)
	must(err)
	if err := cert.CheckSignatureFrom(ca); err != nil {
		log.Fatalf("certificate was not issued by %s", *caPath)
	}
	if *days < 0 || *days > proto.MaxDelegationDays {
		log.Fatalf("-days must be between 0 and %d", proto.MaxDelegationDays)
	}
	// The secret is chosen here, on the holder's device, and never comes from
	// anywhere else: whoever knows it can act as the holder until the expiry.
	raw := make([]byte, 31)
	_, err = rand.Read(raw)
	must(err)
	expiry := proto.DateInt(time.Now().In(time.FixedZone("JST", 9*60*60)).AddDate(0, 0, *days))
	d, err := witness.SignDelegation(key, new(big.Int).SetBytes(raw), expiry) // 31 bytes always fit the field
	must(err)
	data, err := json.Marshal(file{Cert: cert.Raw, CA: ca.Raw, Secret: proto.FieldHex(d.Secret), Expiry: d.Expiry, Sig: d.Sig})
	must(err)
	must(os.WriteFile(*out, data, 0o600))
	fmt.Printf("delegation signed, valid through %d; wallet written to %s\n", expiry, *out)
}

func load(path string) *client.Wallet {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("%v (run `wallet delegate` first)", err)
	}
	var f file
	must(json.Unmarshal(data, &f))
	cert, err := x509.ParseCertificate(f.Cert)
	must(err)
	ca, err := x509.ParseCertificate(f.CA)
	must(err)
	caPub, err := mockjpki.RSAPublicKey(ca)
	must(err)
	secret, err := proto.ParseFieldHex(f.Secret)
	must(err)
	return &client.Wallet{
		Holder:     &client.Holder{Cert: cert, CAPub: caPub, DelegatedTools: prover.DelegatedTools(".")},
		Delegation: &witness.Delegation{Secret: secret, Expiry: f.Expiry, Sig: f.Sig},
		HTTP:       &http.Client{Timeout: time.Minute},
	}
}

func prove(args []string) {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	path := fs.String("wallet", "testdata/wallet.json", "wallet file")
	link := fs.String("link", "", "verification link (shoji://verify?u=<origin>&s=<session>)")
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := load(*path).Answer(ctx, *link)
	if err != nil {
		log.Fatalf("not accepted: %v", err)
	}
	fmt.Printf("accepted: new=%v delegated=%v\n", res.New, res.Delegated)
}

// serve lets agents on this machine hand the wallet a link. This stand-in
// answers every link; a real wallet would apply the holder's rules (which
// services, how often) or ask the holder.
func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("wallet", "testdata/wallet.json", "wallet file")
	listen := fs.String("listen", "127.0.0.1:8095", "listen address (loopback: anything that can reach it can act as the holder)")
	fs.Parse(args)
	w := load(*path)

	var mu sync.Mutex // one proof at a time: each takes about half a gigabyte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /prove", func(rw http.ResponseWriter, r *http.Request) {
		// A JSON content type keeps pages on other sites from posting here.
		if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.TrimSpace(ct) != "application/json" {
			http.Error(rw, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		var req struct {
			Link string `json:"link"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4<<10)).Decode(&req); err != nil {
			http.Error(rw, "malformed request", http.StatusBadRequest)
			return
		}
		origin, _, err := client.ParseLink(req.Link)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		res, err := w.Answer(r.Context(), req.Link)
		mu.Unlock()
		rw.Header().Set("Content-Type", "application/json")
		if err != nil {
			log.Printf("%s: not accepted: %v", origin, err)
			rw.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(rw).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		log.Printf("%s: proved (delegated)", origin)
		json.NewEncoder(rw).Encode(map[string]any{"ok": res.OK})
	})
	log.Printf("wallet: http://%s, delegation valid through %d", *listen, w.Delegation.Expiry)
	hs := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(hs.ListenAndServe())
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
