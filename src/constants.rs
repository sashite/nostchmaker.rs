//! Kind numbers, tag names, marker strings, and enumerated vocabularies of the
//! Open Challenge (`6418`) / Pairing (`6419`) protocol.

/// Kind of an Open Challenge event — a player entering the matchmaking pool.
pub const KIND_OPEN_CHALLENGE: u16 = 6418;

/// Kind of a Pairing event — a matchmaker binding two Open Challenges.
pub const KIND_PAIRING: u16 = 6419;

/// `e`-tag marker on a Pairing referencing one of the two paired Open Challenges.
pub const MARKER_OPEN_CHALLENGE: &str = "open_challenge";

/// `p`-tag role marker: the matchmaker authorized to publish the Pairing.
pub const ROLE_MATCHMAKER: &str = "matchmaker";

/// `p`-tag role marker: the arbiter that ratifies and adjudicates the session.
pub const ROLE_ARBITER: &str = "arbiter";

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

/// `filter` mode: accept only opponents within a rating delta.
pub const FILTER_RATING: &str = "rating";

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

/// `nonce` tag name (NIP-13 proof of work).
pub const TAG_NONCE: &str = "nonce";
