# Changelog

All notable changes to this crate are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] — 2026-08-11

### Changed

- **BREAKING — in-band timing designation (Canonical Timing NIP, B-2).**
  `OpenChallenge` now parses and requires **exactly one timing designation**:
  a `timestamper` `p` tag XOR one or more `["timing_relay", "<wss://…>"]` tags
  (new constant `TAG_TIMING_RELAY`; accessor `timing_relays()` returning the
  set). New errors `NoTimingDesignation` / `ConflictingTimingDesignation`;
  compatibility gains `TimingRelayMismatch` (two entries pair only with
  identical designations), and `pairing` mirrors the shared designation onto
  the Pairing it builds.
- **BREAKING — six-element `rating` filter with a declared pool scope (M-9).**
  `Filter::Rating` gains `scope: PoolScope` (`pergame` | `pervariant`,
  constants `POOL_SCOPE_PERGAME`/`POOL_SCOPE_PERVARIANT`): the filter tag is
  now `["filter", "rating", "<max_delta>", "<authority>", "<kind>",
  "<scope>"]`, five-element filters no longer parse, and pool compatibility is
  evaluated per the DECLARED scope. `Facts::pool_policy`, `PoolPolicy`, and
  `UnknownRatingPoolPolicy` are removed — the scope travels on the wire, not
  in deployment facts.
- **BREAKING — `max_delta` bounded to 1–1000 (M-15).** A `rating` filter
  outside the bound is non-conforming and does not parse.

## [0.6.0] — 2026-08-10

### Changed

- **BREAKING — `nostr` 0.44 → 0.45.** The event types this crate takes and
  returns (`Event`, `EventBuilder`, `Tag`, `EventId`, `Kind`, `PublicKey`,
  `RelayUrl`) are `nostr`'s, so its version line is part of this crate's API: a
  consumer on `nostr` 0.44 cannot hand its `Event` to `OpenChallenge::parse`
  here. Both move in the same step.

  The reason to move is
  [RUSTSEC-2026-0243](https://rustsec.org/advisories/RUSTSEC-2026-0243):
  `nostr-relay-pool` is no longer maintained as a standalone crate, its
  functionality having been folded into `nostr-sdk` 0.45. That advisory is
  against the *services*, not this crate — there is no client and no transport
  here — but they cannot move to `nostr-sdk` 0.45 while this primitive still
  hands them 0.44 types.

  What changed in the surface this crate uses:

  - Types are no longer re-exported at the crate root; they come from their
    modules (`nostr::event::{Event, EventBuilder, Tag, EventId, Kind}`,
    `nostr::key::PublicKey`, `nostr::types::RelayUrl`).
  - `TagKind` is gone (per-NIP tag enums replace `TagStandard`). A tag name is
    now just a string, which is what the suite's multi-letter tags (`game`,
    `variant`, `time_control`) always were: `Tag::custom(TAG_GAME, …)` rather
    than `Tag::custom(TagKind::custom(TAG_GAME), …)`. Parsing already read raw
    slices and is untouched.
  - `EventBuilder::sign_with_keys` is gone; building and signing in one step is
    `finalize` (`FinalizeEvent`), and signing is synchronous now.
  - `Keys::generate` sits behind the new `os-rng` feature. Only the test
    fixtures generate keys — the primitive itself never does — so the feature is
    asked for as a **dev**-dependency, and nothing a dependent compiles gets
    wider.

  No behaviour change, no wire-format change, no constant change: the 51 tests
  pass unchanged.

## [0.5.0] — 2026-08-10

### Changed

- **BREAKING — the Sashité kind numbers moved out of NIP-90's reserved range.**
  `KIND_OPEN_CHALLENGE` is now `3418`, `KIND_PAIRING` `3419`,
  `KIND_ELO_RATING_ATTESTATION` `3426`, `KIND_GLICKO2_RATING_ATTESTATION`
  `3427`; the `filter rating` tag's authority-kind values follow. The constants'
  names and types are unchanged, so this compiles anywhere it compiled before —
  and it will not interoperate with anything still on `6xxx`, which is the
  point.

  [NIP-90](https://github.com/nostr-protocol/nips/blob/master/90.md) reserves
  `5000-7000` in one block for data vending machines and pairs a job request
  with its result at a fixed offset of a thousand, so an Open Challenge at
  `6418` *was* the result of job request `5418` to anything that knows NIP-90.
  The suite documents the move in `web-specs.md` README §Kind numbers.

  **A consumer must move with it.** The kind is what a relay filters on, so a
  matchmaker built against the old constants and one built against these do not
  see each other's pool at all. `sashite-nostr-matchmaker-bot` moves in the same
  wave; its 34 tests pass against this crate unchanged, as do the 51 here.

  Entries below keep the numbers that were in force when they were written.

## [0.4.0] — 2026-07-09

Aligns the `rating` filter's comparison pool with the revised kind `6419`
consent constraint 9: the pool follows the **pinned rating authority's published
pool policy** — per-(game, variant) (the rating specifications' default), or
per-game where the authority unifies a game's variants (e.g. Sashité's `sanki`
authority). A same-variant pairing is no longer a universal requirement for the
`rating` filter; it applies only under the per-(game, variant) policy.

### Changed — breaking

- **`Facts` gains a required method** `pool_policy(&self, authority: &PublicKey,
  kind: RatingKind) -> Option<PoolPolicy>`: the pool policy published (out of
  band) by the pinned authority. Returning `None` (policy unknown) makes
  `evaluate` reject the pair with the new
  `Incompatibility::UnknownRatingPoolPolicy` (fail-closed) — a Pairing built on
  a guessed pool would be non-conforming for every verifier that knows the
  policy.
- **`Facts::rating_within` signature changed**: the `game: &str, variant: &str`
  pair is replaced by a single `pool: RatingPool<'_>` — either
  `RatingPool::PerGame { game }` or `RatingPool::PerGameVariant { game, variant }`,
  always consistent with the policy reported by `pool_policy`. Implementers
  select the "most recent qualifying attestation" within that pool (per-game:
  all of the authority's attestations for the game, regardless of their
  `variant` tags; per-(game, variant): those identifying that exact pool).

### Added

- `compatibility::PoolPolicy` (`PerGameVariant` / `PerGame`).
- `compatibility::RatingPool<'_>` (the pool passed to `rating_within`).
- `Incompatibility::UnknownRatingPoolPolicy` (fail-closed unknown policy).
- Under `PoolPolicy::PerGame`, the `rating` filter now binds multi-variant and
  variant-free pairings: `RatingNeedsSameVariant` / `RatingNeedsResolvedVariant`
  are scoped to the per-(game, variant) policy.

### Removed

- The unused `proptest` dev-dependency.

## [0.3.0] — 2026-07-08

Makes the timestamper designation **optional**, so a session can run self-timed
(the default): attestation becomes a dormant capability (nostr-integration
§Timing). The matchmaker and arbiter stay required.

### Changed — breaking

- **`OpenChallenge::timestamper()` now returns `Option<PublicKey>`** (was
  `PublicKey`). A kind-`6418` event may omit the `timestamper` `p` tag; parsing
  then succeeds with `None`. A present tag is still validated (well-formed,
  distinct from the signer, at most one) — a malformed or duplicate one is a
  parse error, and `MissingRole` is no longer produced for `timestamper`.
- **`PairingBuilder` designates a timestamper only when the paired challenges
  named one.** A self-timed pair yields a Pairing (`6419`) with no `timestamper`
  `p` tag. Two Open Challenges are timing-compatible when both name the same
  timestamper or both name none; a one-sided designation is an
  `Incompatibility::TimestamperMismatch`.

## [0.2.0] — 2026-06-13

Aligns the `rating` filter with the revised kind `6418` / `6419` consent
constraints: the rating source is pinned by the signer, and a rating filter is
satisfiable only for a same-variant pairing.

### Changed — breaking

- **`Filter::Rating` carries a pinned rating source.** It now holds, besides
  `max_delta`, the rating `authority` (a `PublicKey`) and the rating `kind`
  (the new `RatingKind`, Elo `6426` or Glicko-2 `6427`). The on-wire `filter`
  tag is consequently five elements:
  `["filter", "rating", "<max_delta>", "<authority_pubkey>", "<6426|6427>"]`
  (was three). This makes the filter's evaluation objective and retroactively
  verifiable — rating attestations are regular, persistent events.
- **`Facts::rating_within` signature changed** to
  `rating_within(&self, authority: &PublicKey, kind: RatingKind, game: &str,
  variant: &str, a: &PublicKey, b: &PublicKey, max_delta: u16) -> bool`. Both
  players are rated in the **same** `(game, variant)` pool (a single `variant`
  argument), under the pinned authority and kind. Implementers must anchor the
  lookup at the Pairing's canonical attestation (most recent qualifying
  attestation with `created_at` at or before the anchor) and fail closed when a
  player is unrated.

### Added

- `RatingKind` (Elo / Glicko-2) in `open_challenge`, with `as_u16()`.
- `Incompatibility::RatingNeedsSameVariant`: a `rating` filter applies but the
  two players' resolved variants differ (no shared rating pool).
- `ParseError::InvalidRatingAuthority` and `ParseError::InvalidRatingKind`.

### Notes

- The `following` filter is unchanged in shape; its anchoring at the Pairing's
  canonical attestation is the `Facts` implementer's responsibility, now stated
  on the trait.

## [0.1.0] — 2026-06-XX

Initial release: parse Open Challenges (kind `6418`), evaluate pairability and
resolve variants (`compatibility`), and build Pairings (kind `6419`,
`PairingBuilder`).
