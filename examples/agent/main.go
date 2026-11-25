// Command agent plays AI agents that shop for one person at the example shop
// (examples/shop). There is no model here, only the part that matters to the
// shop: software, as many copies as you like, placing orders by itself.
//
// Each agent asks the shop to buy, is handed a verification link, and passes
// the link to the person's wallet (cmd/wallet), which answers with a delegated
// proof. The agent never sees the certificate, the delegation or the proof, and
// the shop never learns who the person is; it does learn that every one of the
// agents acts for the same person.
//
//	agent -product ticket -n 10
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

func main() {
	log.SetFlags(0)
	shop := flag.String("shop", "http://127.0.0.1:8090", "the shop")
	wallet := flag.String("wallet", "http://127.0.0.1:8095", "the person's wallet (cmd/wallet serve)")
	product := flag.String("product", "ticket", "what to buy")
	n := flag.Int("n", 1, "how many agents to run at once")
	flag.Parse()

	hc := &http.Client{Timeout: 5 * time.Minute}
	outcomes := make([]string, *n)
	var wg sync.WaitGroup
	for i := range *n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcomes[i] = buy(hc, *shop, *wallet, *product)
		}()
	}
	wg.Wait()
	count := map[string]int{}
	for i, o := range outcomes {
		fmt.Printf("agent %2d: %s\n", i+1, o)
		count[o]++
	}
	fmt.Printf("\n%d agents, %d purchase(s)\n", *n, count["purchased"])
}

func buy(hc *http.Client, shop, wallet, product string) string {
	var intent struct{ ID, Link string }
	if err := post(hc, shop+"/api/intents", map[string]string{"kind": "buy", "product": product}, &intent); err != nil {
		return "the shop did not start a verification: " + err.Error()
	}
	if err := post(hc, wallet+"/prove", map[string]string{"link": intent.Link}, nil); err != nil {
		return "the wallet did not prove: " + err.Error()
	}
	for range 20 {
		res, err := hc.Get(shop + "/api/intents/" + intent.ID)
		if err != nil {
			return err.Error()
		}
		var state struct{ Status, Outcome string }
		err = json.NewDecoder(res.Body).Decode(&state)
		res.Body.Close()
		if err != nil {
			return err.Error()
		}
		if state.Status != "pending" {
			return state.Outcome
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "no outcome"
}

func post(hc *http.Client, url string, in, out any) error {
	body, _ := json.Marshal(in)
	res, err := hc.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
