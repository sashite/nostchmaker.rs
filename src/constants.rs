//! Kind numbers, tag names, marker strings, and enumerated vocabularies of the
//! Open Challenge (`3418`) / Pairing (`3419`) protocol.

/// Kind of an Open Challenge event — a player entering the matchmaking pool.
pub const KIND_OPEN_CHALLENGE: u16 = 3418;

/// Kind of a Pairing event — a matchmaker binding two Open Challenges.
pub const KIND_PAIRING: u16 = 3419;

/// `e`-tag marker on a Pairing referencing one of the two paired Open Challenges.
pub const MARKER_OPEN_CHALLENGE: &str = "open_challenge";

/// `p`-tag role marker: the matchmaker authorized to publish the Pairing.
pub const ROLE_MATCHMAKER: &str = "matchmaker";

/// `p`-tag role marker: the timestamper that provides authoritative timing.
pub const ROLE_TIMESTAMPER: &str = "timestamper";

/// `p`-tag role marker on a Pairing: a session player.
pub const ROLE_PLAYER: &str = "player";

/// `variant`-tag role selector on an Open Challenge: the signer's own variant.
pub const SELECTOR_SELF: &str = "self";

/// `variant`-tag role selector on an Open Challenge: the sought opponent's variant.
pub const SELECTOR_OPPONENT: &str = "opponent";

/// `filter` mode: accept any opponent (the default when the tag is absent).
pub const FILTER_EVERYONE: &str = "everyone";

/// `filter` mode: accept only opponents the signer follows (NIP-02).
pub const FILTER_FOLLOWING: &str = "following";

/// `filter` mode: accept only opponents within a rating delta, as rated by a
/// pinned rating authority.
pub const FILTER_RATING: &str = "rating";

/// Kind of an Elo Rating Attestation — a pinnable rating source for the `rating`
/// filter mode.
pub const KIND_ELO_RATING_ATTESTATION: u16 = 3426;

/// Kind of a Glicko-2 Rating Attestation — a pinnable rating source for the
/// `rating` filter mode.
pub const KIND_GLICKO2_RATING_ATTESTATION: u16 = 3427;

/// `game` tag name.
pub const TAG_GAME: &str = "game";

/// `variant` tag name.
pub const TAG_VARIANT: &str = "variant";

/// `time_control` tag name.
pub const TAG_TIME_CONTROL: &str = "time_control";

/// `filter` tag name.
pub const TAG_FILTER: &str = "filter";

/// `accept_until` tag name.
pub const TAG_ACCEPT_UNTIL: &str = "accept_until";

/// `timing_relay` tag name: the designated timing relay (self-timed mode,
/// exactly one — a session has one timing authority; Canonical Timing NIP
/// §Timing modes and mode selection).
pub const TAG_TIMING_RELAY: &str = "timing_relay";

/// `filter` `rating` pool scope: one pool per game, unifying its variants.
pub const POOL_SCOPE_PERGAME: &str = "pergame";

/// `filter` `rating` pool scope: one pool per (game, variant).
pub const POOL_SCOPE_PERVARIANT: &str = "pervariant";

/// `nonce` tag name (NIP-13 proof of work).
pub const TAG_NONCE: &str = "nonce";

/// `e`-tag marker of the **rules** reference: the Rule System event (kind
/// `3417`) a session is played under — `["e", "<rule_system_event_id>",
/// "<relay_hint>", "rules"]` (kind `3420` §Match-terms tags). A matching term:
/// two Open Challenges pair only if they name the same event (kind `3419`
/// §Consent constraints, constraint 9); the relay hint is not a term.
pub const MARKER_RULES: &str = "rules";

/// Kind of a Rule System event — a signed event naming, by digest, the
/// executable module a session's rules are (ADR-0034).
pub const KIND_RULE_SYSTEM: u16 = 3417;

/// `x` tag name on a Rule System event: the SHA-256 digest of the module.
pub const TAG_X: &str = "x";

/// `abi` tag name on a Rule System event: the interface the module implements.
pub const TAG_ABI: &str = "abi";

/// `url` tag name on a Rule System event: a retrieval hint for the module.
pub const TAG_URL: &str = "url";

/// `spec` tag name on a Rule System event: the specification the module was
/// built to (documentary).
pub const TAG_SPEC: &str = "spec";

/// `source` tag name on a Rule System event: the sources and commit the module
/// reproduces from (documentary).
pub const TAG_SOURCE: &str = "source";

/// `expiration` tag name (NIP-40) — forbidden on a Rule System event.
pub const TAG_EXPIRATION: &str = "expiration";

/// `seat` tag name on a Pairing: each player's seat, drawn by the matchmaker
/// (kind `3419` §Match-terms tags).
pub const TAG_SEAT: &str = "seat";

/// `seat` value: the player who moves first.
pub const SEAT_FIRST: &str = "first";

/// `seat` value: the player who moves second.
pub const SEAT_SECOND: &str = "second";

/// `found_until` tag name on a Pairing: the latest moment at which a Game
/// Session founded on it is valid (kind `3419` §Lifecycle tags).
pub const TAG_FOUND_UNTIL: &str = "found_until";
