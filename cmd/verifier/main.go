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
	cas := flag.String("trusted-ca", "", "comma-separated PEM certificates of trusted CAs (required)")
	apps := flag.String("apps", "demo", "comma-separated application identifiers")
	age := flag.Uint("age", 18, "age threshold")
	ttl := flag.Duration("nonce-ttl", 5*time.Minute, "nonce lifetime")
	flag.Parse()

	if *cas == "" {
		log.Fatal("-trusted-ca is required")
	}
	if _, err := os.Stat(*vk); err != nil {
		log.Fatalf("verification key not found at %s (run `make circuit`)", *vk)
	}
	var hashes []string
	for _, p := range strings.Split(*cas, ",") {
		cert, err := mockjpki.ReadCertPEM(p)
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
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := verifier.NewServer(verifier.Config{
		Store:           store,
		Checker:         verifier.BBChecker{BB: *bb, VK: *vk},
		TrustedCAHashes: hashes,
		Apps:            strings.Split(*apps, ","),
		AgeThreshold:    uint8(*age),
		NonceTTL:        *ttl,
		Log:             logger,
	})
	if err != nil {
		log.Fatal(err)
	}
	logger.Info("listening", "addr", *listen, "trusted_cas", len(hashes))
	hs := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
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
