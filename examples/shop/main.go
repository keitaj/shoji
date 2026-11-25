// Command shop is a made-up online shop that shows how a service embeds shoji.
//
// It sells limited items, one per person, and lets each buyer post one review
// per item, without accounts and without learning who anyone is. All it stores
// about a person is the nullifier the verifier reports for this shop.
//
// For one of the items it also takes orders from AI agents (examples/agent):
// an agent's order carries a delegated proof, which gives the shop the same
// nullifier as the person's card would. Ten agents of one person get one item.
//
// The shop talks to the verifier with two requests: POST /sessions to start a
// verification and GET /sessions/<id> to learn the outcome. The phone talks to
// the verifier, never to the shop.
//
//	verifier -listen 0.0.0.0:8080 -public-origin http://<LAN address>:8080 -trusted-ca <CA>
//	shop -verifier http://127.0.0.1:8080
//
// This is a demonstration: nothing is sold, state is kept in memory, and the
// operator page at /admin has no login. Do not expose it beyond this machine.
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"
)

//go:embed static
var staticFiles embed.FS

func main() {
	log.SetFlags(0)
	listen := flag.String("listen", "127.0.0.1:8090", "listen address (keep it on loopback: /admin has no login)")
	verifierURL := flag.String("verifier", "http://127.0.0.1:8080", "base URL under which this shop reaches its verifier")
	flag.Parse()

	static, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}
	shop := NewShop(Config{
		Verifier: HTTPVerifier{Base: strings.TrimRight(*verifierURL, "/"), Client: &http.Client{Timeout: 10 * time.Second}},
		Products: defaultProducts(),
		Static:   static,
	})
	log.Printf("shop: http://%s (operator page: /admin), verifier: %s", *listen, *verifierURL)
	hs := &http.Server{Addr: *listen, Handler: shop, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	log.Fatal(hs.ListenAndServe())
}

func defaultProducts() []Product {
	return []Product{
		{ID: "lamp", Name: "手漉き和紙のあかり「障子」", Blurb: "職人が一点ずつ仕上げる卓上のあかり。今季の製作分のみ。", Price: 19800, Stock: 30},
		// Orders from agents are welcome here; the limit of one per person holds anyway.
		{ID: "ticket", Name: "冬の夜の朗読会 先行入場券", Blurb: "小さな会場のため、先行分は座席数ぶんだけ。", Price: 4500, Stock: 20, Agents: true},
	}
}
