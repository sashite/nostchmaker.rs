# Changelog

All notable changes to this crate are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
