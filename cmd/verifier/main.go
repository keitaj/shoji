// Command verifier runs the verification server.
//
//	verifier -trusted-ca testdata/ca.pem -apps demo
//	verifier ban -app demo -nullifier 0x... [-unban]
package main

import (
	"context"
	"crypto/rsa"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/keitaj/shoji/internal/mockjpki"
	"github.com/keitaj/shoji/internal/proto"
	"github.com/keitaj/shoji/internal/prover"
	"github.com/keitaj/shoji/internal/verifier"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "ban" {
		ban(os.Args[2:])
		return
	}
	def := prover.DefaultTools(".")
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	db := flag.String("db", "shoji.db", "SQLite database path")
	bb := flag.String("bb", def.BB, "path to bb")
	vk := flag.String("vk", def.VK, "path to the circuit verification key")
	delegatedVK := flag.String("delegated-vk", "", "verification key of the delegated circuit (circuits/target/vk_delegated/vk); setting it accepts proofs made without the card, from a holder's delegation")
	cas := flag.String("trusted-ca", "", "comma-separated certificates (PEM or DER) of trusted CAs (required)")
	apps := flag.String("apps", "demo", "comma-separated application identifiers")
	age := flag.Uint("age", 18, "age threshold")
	ttl := flag.Duration("nonce-ttl", 5*time.Minute, "nonce lifetime")
	verbose := flag.Bool("v", false, "also log one line per request (method, path, status)")
	origin := flag.String("public-origin", "", "origin under which phones reach this server, e.g. https://verify.example.jp; enables sessions and /demo")
	flag.Parse()

	if *cas == "" {
		log.Fatal("-trusted-ca is required")
	}
	if _, err := os.Stat(*vk); err != nil {
		log.Fatalf("verification key not found at %s (run `make circuit`)", *vk)
	}
	var hashes []string
	for _, p := range strings.Split(*cas, ",") {
		cert, err := mockjpki.ReadCert(p)
		if err != nil {
			log.Fatal(err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			log.Fatalf("%s: not an RSA key", p)
		}
		h, err := proto.PubkeyHash(pub.N)
		if err != nil {
			log.Fatalf("%s: %v", p, err)
		}
		hashes = append(hashes, proto.FieldHex(h))
	}
	store, err := verifier.OpenStore(*db)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	var delegated verifier.ProofChecker
	if *delegatedVK != "" {
		if _, err := os.Stat(*delegatedVK); err != nil {
			log.Fatalf("delegated verification key not found at %s (run `make circuit`)", *delegatedVK)
		}
		delegated = verifier.BBChecker{BB: *bb, VK: *delegatedVK}
	}
	srv, err := verifier.NewServer(verifier.Config{
		Store:            store,
		Checker:          verifier.BBChecker{BB: *bb, VK: *vk},
		DelegatedChecker: delegated,
		TrustedCAHashes:  hashes,
		Apps:             strings.Split(*apps, ","),
		PublicOrigin:     *origin,
		AgeThreshold:     uint8(*age),
		NonceTTL:         *ttl,
		Log:              logger,
	})
	if err != nil {
		log.Fatal(err)
	}
	logger.Info("listening", "addr", *listen, "trusted_cas", len(hashes))
	hs := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		// Without this an idle connection is closed after ReadTimeout, which is
		// about how long a holder takes between the challenge and the proof.
		IdleTimeout: *ttl + time.Minute}
	log.Fatal(hs.ListenAndServe())
}

func ban(args []string) {
	fs := flag.NewFlagSet("ban", flag.ExitOnError)
	db := fs.String("db", "shoji.db", "SQLite database path")
	app := fs.String("app", "", "application identifier")
	nullifier := fs.String("nullifier", "", "nullifier (hex)")
	unban := fs.Bool("unban", false, "clear the ban flag instead")
	fs.Parse(args)
	n, err := proto.ParseFieldHex(*nullifier)
	if err != nil || *app == "" {
		log.Fatal("ban: -app and a valid -nullifier are required")
	}
	store, err := verifier.OpenStore(*db)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	nb := proto.FieldBytes(n)
	if err := store.SetBanned(context.Background(), *app, nb[:], !*unban); err != nil {
		log.Fatal(err)
	}
}
