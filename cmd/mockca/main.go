// Command mockca is a test CA that issues certificates shaped like JPKI signing
// certificates. It has nothing to do with J-LIS; use synthetic data only.
//
//	mockca init  -out testdata/ca
//	mockca issue -ca testdata/ca -out testdata/alice -dob 19900115
//	mockca hash  -cert testdata/ca.pem
package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"os"

	"shoji/internal/mockjpki"
	"shoji/internal/proto"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: mockca <init|issue|hash> [flags]")
	}
	switch os.Args[1] {
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		out := fs.String("out", "testdata/ca", "output base path (.pem and .key are appended)")
		cn := fs.String("cn", "shoji mock CA", "common name")
		fs.Parse(os.Args[2:])
		if _, err := os.Stat(*out + ".key"); err == nil {
			log.Fatalf("%s.key already exists; refusing to overwrite", *out)
		}
		ca, err := mockjpki.NewCA(*cn)
		if err != nil {
			log.Fatal(err)
		}
		if err := ca.Save(*out); err != nil {
			log.Fatal(err)
		}
		printHash(&ca.Key.PublicKey)
	case "issue":
		fs := flag.NewFlagSet("issue", flag.ExitOnError)
		caBase := fs.String("ca", "testdata/ca", "CA base path")
		out := fs.String("out", "", "output base path (.pem and .key are appended)")
		dob := fs.String("dob", "", "date of birth, YYYYMMDD")
		name := fs.String("name", "検証 太郎", "mock name (synthetic only)")
		gender := fs.String("gender", "1", "mock gender code")
		addr := fs.String("address", "東京都千代田区テスト町1-1", "mock address (synthetic only)")
		fs.Parse(os.Args[2:])
		if *out == "" || *dob == "" {
			log.Fatal("issue: -out and -dob are required")
		}
		if _, err := os.Stat(*out + ".key"); err == nil {
			log.Fatalf("%s.key already exists; refusing to overwrite", *out)
		}
		ca, err := mockjpki.LoadCA(*caBase)
		if err != nil {
			log.Fatal(err)
		}
		cert, key, err := ca.Issue(mockjpki.Holder{Name: *name, Gender: *gender, DateOfBirth: *dob, Address: []byte(*addr)})
		if err != nil {
			log.Fatal(err)
		}
		if err := mockjpki.WriteCertPEM(*out+".pem", cert); err != nil {
			log.Fatal(err)
		}
		if err := mockjpki.WriteKeyPEM(*out+".key", key); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("issued %s.pem\n", *out)
	case "hash":
		fs := flag.NewFlagSet("hash", flag.ExitOnError)
		certPath := fs.String("cert", "testdata/ca.pem", "CA certificate")
		fs.Parse(os.Args[2:])
		cert, err := mockjpki.ReadCertPEM(*certPath)
		if err != nil {
			log.Fatal(err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			log.Fatal("not an RSA key")
		}
		printHash(pub)
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
}

func printHash(pub *rsa.PublicKey) {
	h, err := proto.PubkeyHash(pub.N)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ca_pubkey_hash = %s\n", proto.FieldHex(h))
}
