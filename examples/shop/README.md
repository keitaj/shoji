# Example: a shop that embeds shoji

[日本語](README.ja.md)

A made-up online shop, "こもれび商店", that uses shoji the way a separate service
would. It has no accounts and never learns who its customers are, and still:

- sells limited items **one per person** (against resale and hoarding);
- accepts reviews **only from buyers, one per person per item** (against fake
  reviews);
- lets the operator **stop a person**, who then cannot come back by starting
  over;
- can show **everything it has stored**: nullifiers, purchases, reviews. No
  names, addresses, dates of birth or e-mail addresses.

Nothing is sold. This is a demonstration, not something to deploy (see "Limits").

## How it embeds the verifier

The shop runs its own verifier and talks to it with two requests. The phone
talks to the verifier only; the shop never sees the proof.

```
 browser            shop                     verifier                 phone
    │ "buy"           │                          │                       │
    │ ──────────────▶ │ POST /sessions           │                       │
    │                 │ ───────────────────────▶ │                       │
    │ ◀── QR code ─── │ ◀── session, link ────── │                       │
    │                 │                          │ ◀── scan, card, proof │
    │ poll            │ GET /sessions/<id>       │                       │
    │ ──────────────▶ │ ───────────────────────▶ │                       │
    │ ◀── outcome ─── │ ◀── verified, nullifier  │                       │
```

On a verified session the shop gets the person's nullifier and decides what to
do with it (`decide` in [`shop.go`](shop.go)): has this nullifier bought the item
already, has it reviewed it, is it stopped. That is the whole integration.

The nullifier is specific to the verifier's origin, so each service needs a
verifier origin of its own. Two services behind one origin would see the same
nullifier for the same person.

## Run it without a card

With the mock CA from `make circuit`:

```sh
go run ./cmd/verifier -public-origin http://127.0.0.1:8080 -trusted-ca testdata/ca.pem &
go run ./examples/shop          # http://127.0.0.1:8090
```

Open the shop, press 購入する, open "カードなしで試す" under the QR code and pass
the link to the mock holder:

```sh
go run ./cmd/mockclient -link 'shoji://verify?u=...&s=...'
```

Run it again for the same item to be refused. Other people are
`-cert testdata/adult2.pem -key testdata/adult2.key`; `minor` cannot produce an
accepted proof. The operator page is at `/admin`.

## Orders from AI agents

The entrance ticket can also be ordered by software acting for a person; the
lamp cannot. An agent's order carries a delegated proof, and the shop gets the
same nullifier as from the person's card, so the limit of one per person holds
however many agents there are:

```sh
go run ./cmd/verifier -public-origin http://127.0.0.1:8080 -trusted-ca testdata/ca.pem \
    -delegated-vk circuits/target/vk_delegated/vk &
go run ./examples/shop &
go run ./cmd/wallet delegate          # the "card tap": the mock card signs a delegation
go run ./cmd/wallet serve &           # the person's wallet answers links for local agents
go run ./examples/agent -product ticket -n 10
```

Ten agents, one purchase; the same person tapping their (mock) card afterwards
is told they already bought it. The operator page shows who ordered: the person
or an agent. The agent has no model in it and never sees the certificate, the
delegation or the proof: it passes the shop's link to the wallet. What the
wallet stand-in does not do yet is decide: it answers every link it is given.

## Run it with a real card

Start the verifier as described in the [top-level README](../../README.md#quick-start)
(listening on the local network, trusting the real signing CA), then the shop
with `-verifier http://127.0.0.1:8080`. Scan the QR code with the iOS app from
[`ios/`](../../ios/README.md). The shop itself stays on loopback: only the
browser on this machine talks to it.

## Limits

- State is in memory and is gone when the shop stops. The verifier keeps its own
  database, which the shop does not use.
- `/admin` has no login. Keep the shop on loopback.
- The verifier's `POST /sessions` is open to anyone who can reach it.
- Someone who is shown another person's QR code and completes it gives that
  purchase to the person whose browser showed the code. This is the session
  hijacking described in the [threat model](../../docs/threat-model.md).
- A person's nullifier changes when their certificate is reissued, so the limits
  hold per certificate, not for life (see [open questions](../../docs/open-questions.md)).
- Every action needs a card tap. A real service would likely verify once and
  then keep a login session bound to the nullifier.
