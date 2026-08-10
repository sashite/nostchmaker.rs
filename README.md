# nostchmaker

Pair **Open Challenges** into **Pairings** (kinds `3418` / `3419`) for
[Nostr](https://github.com/nostr-protocol/nostr): a game-agnostic matchmaking
primitive for turn-based, two-player abstract strategy board games of the chess
family.

> **Status — proposed NIP.** The kinds `3418` (Open Challenge) and `3419`
> (Pairing) belong to a NIP suite that is still a **draft**. The kind numbers
> and wire format may change. Pin an exact version and review the suite before
> relying on it in production.

A player enters a matchmaking pool by publishing a signed **Open Challenge**
(kind `3418`) that names a matchmaker, an arbiter, and optionally a timestamper
(absent → the session is self-timed, the default), and carries the session
terms (game, per-role variant preferences, time control, opponent filter) — but
no opponent. A designated **matchmaker** pairs two compatible Open
Challenges by publishing a **Pairing** (kind `3419`), without any acceptance
signature from the players: their consent is pre-committed in their Open
Challenges, and a Pairing is binding only if it respects both.

This crate implements the **primitive only**, and is **game-agnostic**: it does
not know any game's variant vocabulary, performs no I/O, and is silent on *which*
game or parties an application designates. Those are a higher layer's concern
(for example a matchmaker service that reads the relay and signs Pairings).

## Pipeline

```text
kind 3418 event ──parse──▶ OpenChallenge ─┐
kind 3418 event ──parse──▶ OpenChallenge ─┴─evaluate(facts)─▶ Compatible{variants}
                                                                     │
                                                          PairingBuilder ──▶ kind 3419
```

- **`open_challenge`** — `OpenChallenge::parse` turns a kind-`3418` event into a
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
use nostchmaker::compatibility::{evaluate, Compatibility, Facts, PoolPolicy, RatingPool};
use nostchmaker::open_challenge::{OpenChallenge, RatingKind};
use nostr::key::PublicKey;
use nostchmaker::pairing::PairingBuilder;

// The consumer resolves the external facts the filters need, anchored at the
// Pairing's canonical timing: the contact list as of the anchor, and the most
// recent attestation by the *pinned* authority (under the pinned kind) with
// created_at at or before the anchor — in the pool the authority's published
// pool policy defines. `everyone`-filtered pools need none of this.
struct MyFacts;
impl Facts for MyFacts {
    fn follows(&self, _follower: &PublicKey, _target: &PublicKey) -> bool { false }
    fn pool_policy(
        &self,
        _authority: &PublicKey,
        _kind: RatingKind,
    ) -> Option<PoolPolicy> {
        // Fail-closed when the pinned authority's published policy is unknown.
        // E.g. Sashité's `sanki` authority publishes `Some(PoolPolicy::PerGame)`.
        None
    }
    fn rating_within(
        &self,
        _authority: &PublicKey,
        _kind: RatingKind,
        _pool: RatingPool<'_>,
        _a: &PublicKey,
        _b: &PublicKey,
        _max_delta: u16,
    ) -> bool { false }
}

// `a` and `b` are two parsed kind-3418 events (OpenChallenge::parse).
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

`evaluate` encodes the consent constraints of kind `3419` that are decidable
from the two Open Challenges plus the resolved facts: distinct signers, a common
matchmaker / arbiter / timestamper, a common game, an identical time control, a
satisfiable variant resolution, and each player satisfying the other's filter. A
`following` filter binds against the filterer's contact list; a `rating` filter
binds against the rating authority the filterer **pins** in their Open Challenge
(an authority pubkey plus the attestation kind, `3426` Elo or `3427` Glicko-2).
The comparison pool follows the pinned authority's **published pool policy**
(kind `3419` §Consent constraints): under a per-`(game, variant)` policy (the
rating specifications' default) the filter is satisfiable only for a
same-variant pairing; under a per-game policy (e.g. Sashité's `sanki` authority)
it binds across any variant combination, resolved or free. An unknown policy is
fail-closed: the pair is not matched.

It is deliberately **silent** on the rest, which a higher layer enforces:

- the accept-deadline (a timing decision anchored on the Pairing's canonical
  timing — its timestamper attestation in attested mode, its own relay-enforced
  `created_at` in self-timed mode);
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

`nostr` `0.45`. Developed and tested on Rust `1.96`. See the status note near the
top of this document regarding the proposed NIP and the tentative kind numbers.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
