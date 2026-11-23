// Command certinspect prints the structure of a certificate (tags, lengths,
// OIDs, string types) without printing its contents, and checks it against what
// the circuit currently expects.
//
// It exists so that the structure of a real JPKI signing certificate can be
// compared with the mock one without the certificate itself, or any personal
// data in it, being written anywhere. Keep real certificates outside this
// repository.
//
//	certinspect -cert /path/outside/repo/sign.der [-ca /path/outside/repo/sign_ca.der]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	certPath := flag.String("cert", "", "certificate to inspect (DER or PEM)")
	caPath := flag.String("ca", "", "issuer certificate (DER or PEM), optional")
	flag.Parse()
	if *certPath == "" {
		log.Fatal("usage: certinspect -cert <file> [-ca <file>]")
	}
	der, err := readCert(*certPath)
	if err != nil {
		log.Fatal(err)
	}
	var caDER []byte
	if *caPath != "" {
		if caDER, err = readCert(*caPath); err != nil {
			log.Fatal(err)
		}
	}
	rep, err := inspect(der, caDER)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprint(os.Stdout, rep)
}
