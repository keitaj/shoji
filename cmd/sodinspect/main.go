// Command sodinspect reports how an electronic passport is signed: the
// algorithms and key sizes in its Document Security Object (EF.SOD), its
// Active Authentication key (DG15) and its security infos (DG14), and whether
// the signatures verify. It prints structure only: no hash values, keys,
// serial numbers or anything from the personal data groups.
//
// The files come from the developer tool in ios/ ("passport" folder). Keep them
// outside the repository and delete them afterwards.
//
//	sodinspect -dir /path/outside/repo/passport
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	log.SetFlags(0)
	dir := flag.String("dir", "", "directory with sod.bin and, if present, dg14.bin, dg15.bin, aa_nonce.bin, aa_signature.bin")
	flag.Parse()
	if *dir == "" {
		log.Fatal("usage: sodinspect -dir <directory>")
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(*dir, name))
		if err != nil {
			return nil
		}
		return b
	}
	sod := read("sod.bin")
	if sod == nil {
		log.Fatalf("%s: sod.bin not found", *dir)
	}
	fmt.Print(inspect(files{
		sod: sod, dg14: read("dg14.bin"), dg15: read("dg15.bin"),
		aaNonce: read("aa_nonce.bin"), aaSignature: read("aa_signature.bin"),
	}))
}
