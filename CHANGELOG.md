# Changelog

All notable changes to this crate are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
