# nostchmaker

Pair **Open Challenges** into **Pairings** (kinds `6418` / `6419`) for
[Nostr](https://github.com/nostr-protocol/nostr): a game-agnostic matchmaking
primitive for turn-based, two-player abstract strategy board games of the chess
family.

> **Status — proposed NIP.** The kinds `6418` (Open Challenge) and `6419`
> (Pairing) belong to a NIP suite that is still a **draft**. The kind numbers
> and wire format may change. Pin an exact version and review the suite before
> relying on it in production.

A player enters a matchmaking pool by publishing a signed **Open Challenge**
(kind `6418`) that names a matchmaker, arbiter, and timestamper, and carries the
session terms (game, per-role variant preferences, time control, opponent
filter) — but no opponent. A designated **matchmaker** pairs two compatible Open
Challenges by publishing a **Pairing** (kind `6419`), without any acceptance
signature from the players: their consent is pre-committed in their Open
Challenges, and a Pairing is binding only if it respects both.

This crate implements the **primitive only**, and is **game-agnostic**: it does
not know any game's variant vocabulary, performs no I/O, and is silent on *which*
game or parties an application designates. Those are a higher layer's concern
(for example a matchmaker service that reads the relay and signs Pairings).

## Pipeline

```text
kind 6418 event ──parse──▶ OpenChallenge ─┐
kind 6418 event ──parse──▶ OpenChallenge ─┴─evaluate(facts)─▶ Compatible{variants}
                                                                     │
                                                          PairingBuilder ──▶ kind 6419
```

- **`open_challenge`** — `OpenChallenge::parse` turns a kind-`6418` event into a
  typed, validated value (the event-local semantic constraints, decidable from
  the event alone).
- **`compatibility`** — `evaluate(a, b, facts)` decides whether two Open
  Challenges can be paired (common matchmaker/arbiter/timestamper, common game,
  identical time control, satisfiable variants, and each player satisfying the
  other's filter), and resolves each player's variant.
- **`pairing`** — `PairingBuilder` lays a compatible pair out as an unsigned
  Pairing `EventBuilder` for the matchmaker to sign.

## Usage

```rust
use nostchmaker::compatibility::{evaluate, Compatibility, Facts};
use nostchmaker::open_challenge::OpenChallenge;
use nostchmaker::pairing::PairingBuilder;
use nostr::PublicKey;

// The consumer resolves the external facts the filters need (NIP-02 contact
// lists, ratings). `everyone`-filtered pools need none of this.
struct MyFacts;
impl Facts for MyFacts {
    fn follows(&self, _follower: &PublicKey, _target: &PublicKey) -> bool { false }
    fn rating_within(
        &self, _game: &str,
        _a: &PublicKey, _av: &str,
        _b: &PublicKey, _bv: &str,
        _max_delta: u16,
    ) -> bool { false }
}

// `a` and `b` are two parsed kind-6418 events (OpenChallenge::parse).
fn pair(a: &OpenChallenge, b: &OpenChallenge) {
    if let Compatibility::Compatible { a_variant, b_variant } = evaluate(a, b, &MyFacts) {
        let mut builder = PairingBuilder::new(a, b);
        // Multi-variant games (e.g. `sanki`) require a variant per player; fill
        // any free (None) variant with the matchmaker's choice from the game's
        // vocabulary.
        if let Some(v) = a_variant.as_deref() { builder = builder.a_variant(v); }
        if let Some(v) = b_variant.as_deref() { builder = builder.b_variant(v); }
        let _pairing = builder.to_event_builder(); // sign with the matchmaker
    }
}
```

## Consent constraints

`evaluate` encodes the consent constraints of kind `6419` that are decidable
from the two Open Challenges plus the resolved facts: distinct signers, a common
matchmaker / arbiter / timestamper, a common game, an identical time control, a
satisfiable variant resolution, and each player satisfying the other's filter.

It is deliberately **silent** on the rest, which a higher layer enforces:

- the accept-deadline (a timing decision anchored on the Pairing's timestamper
  attestation);
- the Pairing event's own shape (it is built by `PairingBuilder`);
- any operational policy such as a game allow-list or NIP-51 mute lists.

## Safety and reliability

- No `unsafe` (`unsafe_code = "forbid"`), no I/O, no clock access — pure
  functions.
- The parsing path consumes untrusted events but only *inspects* fields that
  `nostr` has already parsed: it never reparses, never allocates on input size,
  and is **total**. The lint set denies panic-capable operations
  (`unwrap`/`expect`/`panic`/indexing/arithmetic).
- Building is **infallible**.
- Supply chain is policed in CI by `cargo-deny` (advisories, licenses, sources).

## Status and MSRV

`nostr` `0.44`. Developed and tested on Rust `1.96`. See the status note near the
top of this document regarding the proposed NIP and the tentative kind numbers.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
