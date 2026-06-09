// SPDX-License-Identifier: Apache-2.0

//! Parse a kind-`6418` event into a typed, validated [`OpenChallenge`].
//!
//! [`OpenChallenge::parse`] enforces the event-local semantic constraints of
//! kind `6418` (§Semantic constraints, decidable from the event alone) and
//! returns the first violated rule as a [`ParseError`]. It performs a
//! *structural* check only; the caller MUST also verify the event's signature
//! (`event.verify()`) per NIP-01, and enforce any relay-advertised NIP-13
//! difficulty (a deployment policy this primitive does not know).

use nostr::{Event, EventId, Kind, PublicKey, Tag};

use crate::constants::{
    FILTER_EVERYONE, FILTER_FOLLOWING, FILTER_RATING, KIND_OPEN_CHALLENGE, ROLE_ARBITER,
    ROLE_MATCHMAKER, ROLE_TIMESTAMPER, SELECTOR_OPPONENT, SELECTOR_SELF, TAG_ACCEPT_UNTIL,
    TAG_FILTER, TAG_GAME, TAG_NONCE, TAG_TIME_CONTROL, TAG_VARIANT,
};
use crate::error::ParseError;

/// A player's eligibility filter for the sought opponent.
///
/// Defaults to [`Filter::Everyone`] when an Open Challenge carries no `filter`
/// tag. The `following` / `rating` modes require facts external to the event
/// (a follow list, ratings); evaluating them is the consumer's responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// Any opponent.
    Everyone,
    /// Only opponents the signer follows (NIP-02).
    Following,
    /// Only opponents within `max_delta` rating points (1..=9999).
    Rating {
        /// The maximum admissible rating difference.
        max_delta: u16,
    },
}

/// One period of a time-control configuration.
///
/// Values are validated for shape (per kind `6420` §Match-terms tags) but not
/// interpreted: time accounting is the arbiter's rule system's concern. Two
/// configurations are comparable for equality, which is what pairing requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeControlPeriod {
    duration: u64,
    increment: Option<u64>,
    plies: Option<u32>,
}

impl TimeControlPeriod {
    /// The time budget for the period, in seconds.
    #[must_use]
    pub const fn duration(&self) -> u64 {
        self.duration
    }

    /// The Fischer increment per ply within this period, in seconds, if any.
    #[must_use]
    pub const fn increment(&self) -> Option<u64> {
        self.increment
    }

    /// The move-count quota after which the period repeats, if any.
    #[must_use]
    pub const fn plies(&self) -> Option<u32> {
        self.plies
    }
}

/// A parsed, structurally valid Open Challenge (kind `6418`).
///
/// Constructed by [`OpenChallenge::parse`]. Per-player variant preferences are
/// keyed by role (`self` / `opponent`) because the opponent is anonymous at
/// pool-entry time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenChallenge {
    id: EventId,
    signer: PublicKey,
    matchmaker: PublicKey,
    arbiter: PublicKey,
    timestamper: PublicKey,
    game: String,
    self_variant: Option<String>,
    opponent_variant: Option<String>,
    time_control: Vec<TimeControlPeriod>,
    filter: Filter,
    accept_until: u64,
}

impl OpenChallenge {
    /// Parses and validates a kind-`6418` event.
    ///
    /// Checks the event-local semantic constraints (kind `6418` §Semantic
    /// constraints) in order, returning the first violated rule. A `nonce` tag
    /// is required to be present, but its NIP-13 difficulty is not checked here
    /// (that is a relay/consumer policy).
    ///
    /// # Errors
    ///
    /// Returns the first violated [`ParseError`].
    pub fn parse(event: &Event) -> Result<Self, ParseError> {
        if event.kind != Kind::Custom(KIND_OPEN_CHALLENGE) {
            return Err(ParseError::WrongKind(event.kind.as_u16()));
        }
        if !event.content.is_empty() {
            return Err(ParseError::NonEmptyContent);
        }

        // Constraint 1 — authorized third parties (each distinct from the signer).
        let matchmaker = role_pubkey(event, ROLE_MATCHMAKER)?;
        let arbiter = role_pubkey(event, ROLE_ARBITER)?;
        let timestamper = role_pubkey(event, ROLE_TIMESTAMPER)?;

        // Constraint 2 — exactly one valid game identifier.
        let game = parse_game(event)?;

        // Constraint 3 — at most one variant per role; valid identifiers.
        let (self_variant, opponent_variant) = parse_variants(event)?;

        // Constraint 4 — at least one well-formed time-control period.
        let time_control = parse_time_control(event)?;

        // Constraint 5 — zero or one filter; default everyone.
        let filter = parse_filter(event)?;

        // Constraint 6 — exactly one accept_until, strictly after created_at.
        let accept_until = parse_accept_until(event)?;

        // Constraint 7 — exactly one nonce tag (difficulty enforced elsewhere).
        require_single_nonce(event)?;

        Ok(Self {
            id: event.id,
            signer: event.pubkey,
            matchmaker,
            arbiter,
            timestamper,
            game,
            self_variant,
            opponent_variant,
            time_control,
            filter,
            accept_until,
        })
    }

    /// The Open Challenge event id.
    #[must_use]
    pub fn id(&self) -> EventId {
        self.id
    }

    /// The signer entering the pool.
    #[must_use]
    pub fn signer(&self) -> PublicKey {
        self.signer
    }

    /// The authorized matchmaker.
    #[must_use]
    pub fn matchmaker(&self) -> PublicKey {
        self.matchmaker
    }

    /// The authorized arbiter.
    #[must_use]
    pub fn arbiter(&self) -> PublicKey {
        self.arbiter
    }

    /// The authorized timestamper.
    #[must_use]
    pub fn timestamper(&self) -> PublicKey {
        self.timestamper
    }

    /// The game context sought.
    #[must_use]
    pub fn game(&self) -> &str {
        &self.game
    }

    /// The signer's own variant preference, if fixed.
    #[must_use]
    pub fn self_variant(&self) -> Option<&str> {
        self.self_variant.as_deref()
    }

    /// The sought opponent's variant preference, if fixed.
    #[must_use]
    pub fn opponent_variant(&self) -> Option<&str> {
        self.opponent_variant.as_deref()
    }

    /// The time-control configuration (one or more sequential periods).
    #[must_use]
    pub fn time_control(&self) -> &[TimeControlPeriod] {
        &self.time_control
    }

    /// The eligibility filter for the sought opponent.
    #[must_use]
    pub fn filter(&self) -> Filter {
        self.filter
    }

    /// The pool-entry deadline (a Unix timestamp in seconds).
    #[must_use]
    pub fn accept_until(&self) -> u64 {
        self.accept_until
    }
}

// --- parsing helpers (total, panic-free) ------------------------------------

/// Resolves the single `p` tag carrying `role` as its fourth element into a
/// pubkey distinct from the signer.
fn role_pubkey(event: &Event, role: &'static str) -> Result<PublicKey, ParseError> {
    let tags: Vec<&Tag> = event
        .tags
        .iter()
        .filter(|tag| is_p_role(tag, role))
        .collect();
    match tags.as_slice() {
        [] => Err(ParseError::MissingRole(role)),
        [tag] => {
            let hex = tag
                .as_slice()
                .get(1)
                .map(String::as_str)
                .unwrap_or_default();
            let pubkey = PublicKey::parse(hex).map_err(|_| ParseError::InvalidRolePubkey(role))?;
            if pubkey == event.pubkey {
                return Err(ParseError::RoleEqualsSigner(role));
            }
            Ok(pubkey)
        }
        _ => Err(ParseError::DuplicateRole(role)),
    }
}

fn parse_game(event: &Event) -> Result<String, ParseError> {
    let tags: Vec<&Tag> = event
        .tags
        .iter()
        .filter(|tag| first_is(tag, TAG_GAME))
        .collect();
    match tags.as_slice() {
        [] => Err(ParseError::MissingGame),
        [tag] => {
            let id = tag
                .as_slice()
                .get(1)
                .map(String::as_str)
                .unwrap_or_default();
            if is_valid_identifier(id) {
                Ok(id.to_string())
            } else {
                Err(ParseError::InvalidGameId(id.to_string()))
            }
        }
        _ => Err(ParseError::MultipleGames(tags.len())),
    }
}

#[allow(clippy::type_complexity)]
fn parse_variants(event: &Event) -> Result<(Option<String>, Option<String>), ParseError> {
    let mut self_variant: Option<String> = None;
    let mut opponent_variant: Option<String> = None;
    for tag in event.tags.iter() {
        let slice = tag.as_slice();
        if slice.first().map(String::as_str) != Some(TAG_VARIANT) {
            continue;
        }
        let role = slice.get(1).map(String::as_str).unwrap_or_default();
        let id = slice.get(2).map(String::as_str).unwrap_or_default();
        match role {
            SELECTOR_SELF => {
                if !is_valid_identifier(id) {
                    return Err(ParseError::InvalidVariantId(id.to_string()));
                }
                if self_variant.is_some() {
                    return Err(ParseError::DuplicateVariantRole(SELECTOR_SELF));
                }
                self_variant = Some(id.to_string());
            }
            SELECTOR_OPPONENT => {
                if !is_valid_identifier(id) {
                    return Err(ParseError::InvalidVariantId(id.to_string()));
                }
                if opponent_variant.is_some() {
                    return Err(ParseError::DuplicateVariantRole(SELECTOR_OPPONENT));
                }
                opponent_variant = Some(id.to_string());
            }
            other => return Err(ParseError::InvalidVariantRole(other.to_string())),
        }
    }
    Ok((self_variant, opponent_variant))
}

fn parse_time_control(event: &Event) -> Result<Vec<TimeControlPeriod>, ParseError> {
    let mut periods: Vec<TimeControlPeriod> = Vec::new();
    for tag in event.tags.iter() {
        let slice = tag.as_slice();
        if slice.first().map(String::as_str) != Some(TAG_TIME_CONTROL) {
            continue;
        }
        let period = parse_period(slice).ok_or(ParseError::InvalidTimeControl)?;
        periods.push(period);
    }
    if periods.is_empty() {
        return Err(ParseError::MissingTimeControl);
    }
    Ok(periods)
}

/// Parses one `time_control` tag's slice (`["time_control", dur, inc?, plies?]`).
/// Returns `None` on any malformation, including plies without an increment.
fn parse_period(slice: &[String]) -> Option<TimeControlPeriod> {
    let duration = slice.get(1)?.parse::<u64>().ok()?;
    let increment = match slice.get(2) {
        None => None,
        Some(raw) => Some(raw.parse::<u64>().ok()?),
    };
    let plies = match slice.get(3) {
        None => None,
        Some(raw) => {
            let value = raw.parse::<u32>().ok()?;
            if value == 0 {
                return None;
            }
            Some(value)
        }
    };
    if plies.is_some() && increment.is_none() {
        return None;
    }
    Some(TimeControlPeriod {
        duration,
        increment,
        plies,
    })
}

fn parse_filter(event: &Event) -> Result<Filter, ParseError> {
    let tags: Vec<&Tag> = event
        .tags
        .iter()
        .filter(|tag| first_is(tag, TAG_FILTER))
        .collect();
    match tags.as_slice() {
        [] => Ok(Filter::Everyone),
        [tag] => filter_from_slice(tag.as_slice()),
        _ => Err(ParseError::MultipleFilters(tags.len())),
    }
}

fn filter_from_slice(slice: &[String]) -> Result<Filter, ParseError> {
    match slice.get(1).map(String::as_str) {
        Some(FILTER_EVERYONE) if slice.len() == 2 => Ok(Filter::Everyone),
        Some(FILTER_FOLLOWING) if slice.len() == 2 => Ok(Filter::Following),
        Some(FILTER_RATING) if slice.len() == 3 => {
            let raw = slice.get(2).map(String::as_str).unwrap_or_default();
            let max_delta = parse_max_delta(raw).ok_or(ParseError::MalformedFilter)?;
            Ok(Filter::Rating { max_delta })
        }
        Some(FILTER_EVERYONE | FILTER_FOLLOWING | FILTER_RATING) => {
            Err(ParseError::MalformedFilter)
        }
        Some(other) => Err(ParseError::InvalidFilterMode(other.to_string())),
        None => Err(ParseError::MalformedFilter),
    }
}

/// Validates `^[1-9][0-9]{0,3}$` and parses it (1..=9999).
fn parse_max_delta(value: &str) -> Option<u16> {
    let bytes = value.as_bytes();
    let first = bytes.first()?;
    if !(b'1'..=b'9').contains(first) {
        return None;
    }
    if bytes.len() > 4 {
        return None;
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.parse::<u16>().ok()
}

fn parse_accept_until(event: &Event) -> Result<u64, ParseError> {
    let tags: Vec<&Tag> = event
        .tags
        .iter()
        .filter(|tag| first_is(tag, TAG_ACCEPT_UNTIL))
        .collect();
    match tags.as_slice() {
        [] => Err(ParseError::MissingAcceptUntil),
        [tag] => {
            let raw = tag
                .as_slice()
                .get(1)
                .map(String::as_str)
                .unwrap_or_default();
            let value = raw
                .parse::<u64>()
                .map_err(|_| ParseError::InvalidAcceptUntil(raw.to_string()))?;
            let created_at = event.created_at.as_secs();
            if value <= created_at {
                return Err(ParseError::AcceptUntilNotAfterCreatedAt {
                    accept_until: value,
                    created_at,
                });
            }
            Ok(value)
        }
        _ => Err(ParseError::MultipleAcceptUntil(tags.len())),
    }
}

fn require_single_nonce(event: &Event) -> Result<(), ParseError> {
    match event
        .tags
        .iter()
        .filter(|tag| first_is(tag, TAG_NONCE))
        .count()
    {
        0 => Err(ParseError::MissingNonce),
        1 => Ok(()),
        count => Err(ParseError::MultipleNonces(count)),
    }
}

/// Whether `tag` is a `p` tag carrying `role` as its fourth element.
fn is_p_role(tag: &Tag, role: &str) -> bool {
    let slice = tag.as_slice();
    slice.first().map(String::as_str) == Some("p") && slice.get(3).map(String::as_str) == Some(role)
}

/// Whether `tag`'s first element equals `name`.
fn first_is(tag: &Tag, name: &str) -> bool {
    tag.as_slice().first().map(String::as_str) == Some(name)
}

/// Whether `s` matches `^[a-z][a-z0-9]{0,31}$` (a game or variant identifier).
fn is_valid_identifier(s: &str) -> bool {
    let bytes = s.as_bytes();
    match bytes.first() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    if bytes.len() > 32 {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::{Filter, OpenChallenge};
    use crate::constants::KIND_OPEN_CHALLENGE;
    use crate::error::ParseError;
    use nostr::prelude::*;

    const KIND: u16 = KIND_OPEN_CHALLENGE;

    struct Parties {
        signer: Keys,
        matchmaker: Keys,
        arbiter: Keys,
        timestamper: Keys,
    }

    fn parties() -> Parties {
        Parties {
            signer: Keys::generate(),
            matchmaker: Keys::generate(),
            arbiter: Keys::generate(),
            timestamper: Keys::generate(),
        }
    }

    fn p(keys: &Keys, role: &str) -> Tag {
        Tag::parse(["p", &keys.public_key().to_hex(), "", role]).unwrap()
    }

    /// A canonical, valid set of Open Challenge tags (no filter -> everyone).
    fn valid_tags(parties: &Parties) -> Vec<Tag> {
        vec![
            p(&parties.matchmaker, "matchmaker"),
            p(&parties.arbiter, "arbiter"),
            p(&parties.timestamper, "timestamper"),
            Tag::parse(["game", "sanki"]).unwrap(),
            Tag::parse(["variant", "self", "ogi"]).unwrap(),
            Tag::parse(["variant", "opponent", "ogi"]).unwrap(),
            Tag::parse(["time_control", "300", "3"]).unwrap(),
            Tag::parse(["accept_until", "2000"]).unwrap(),
            Tag::parse(["nonce", "42", "16"]).unwrap(),
        ]
    }

    fn signed(parties: &Parties, content: &str, tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::Custom(KIND), content)
            .tags(tags)
            .custom_created_at(Timestamp::from(1000))
            .sign_with_keys(&parties.signer)
            .unwrap()
    }

    /// Builds an event straight from JSON, bypassing `EventBuilder` (which strips
    /// a `p` tag pointing at the signer). This is how a malicious, hand-rolled
    /// event reaches a consumer; id/sig are placeholders since `parse` is a
    /// structural check that does not verify them.
    fn forged_event(signer_hex: &str, tags_json: &str) -> Event {
        let id = "a".repeat(64);
        let sig = "b".repeat(128);
        let json = format!(
            r#"{{"id":"{id}","pubkey":"{signer_hex}","created_at":1000,"kind":6418,"content":"","sig":"{sig}","tags":{tags_json}}}"#
        );
        Event::from_json(&json).unwrap()
    }

    #[test]
    fn accepts_a_valid_open_challenge() {
        let parties = parties();
        let event = signed(&parties, "", valid_tags(&parties));
        let oc = OpenChallenge::parse(&event).expect("valid");

        assert_eq!(oc.signer(), parties.signer.public_key());
        assert_eq!(oc.matchmaker(), parties.matchmaker.public_key());
        assert_eq!(oc.arbiter(), parties.arbiter.public_key());
        assert_eq!(oc.timestamper(), parties.timestamper.public_key());
        assert_eq!(oc.game(), "sanki");
        assert_eq!(oc.self_variant(), Some("ogi"));
        assert_eq!(oc.opponent_variant(), Some("ogi"));
        assert_eq!(oc.filter(), Filter::Everyone);
        assert_eq!(oc.accept_until(), 2000);

        let periods = oc.time_control();
        assert_eq!(periods.len(), 1);
        assert_eq!(periods[0].duration(), 300);
        assert_eq!(periods[0].increment(), Some(3));
        assert_eq!(periods[0].plies(), None);
    }

    #[test]
    fn accepts_no_variant_tags() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("variant"));
        let event = signed(&parties, "", tags);
        let oc = OpenChallenge::parse(&event).expect("valid");
        assert_eq!(oc.self_variant(), None);
        assert_eq!(oc.opponent_variant(), None);
    }

    #[test]
    fn parses_following_filter() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["filter", "following"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event).expect("valid").filter(),
            Filter::Following
        );
    }

    #[test]
    fn parses_rating_filter() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["filter", "rating", "200"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event).expect("valid").filter(),
            Filter::Rating { max_delta: 200 }
        );
    }

    #[test]
    fn parses_a_multi_period_time_control() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["time_control", "30", "0", "1"]).unwrap());
        let event = signed(&parties, "", tags);
        let oc = OpenChallenge::parse(&event).expect("valid");
        assert_eq!(oc.time_control().len(), 2);
        assert_eq!(oc.time_control()[1].plies(), Some(1));
    }

    #[test]
    fn rejects_wrong_kind() {
        let parties = parties();
        let event = EventBuilder::new(Kind::Custom(1), "")
            .tags(valid_tags(&parties))
            .custom_created_at(Timestamp::from(1000))
            .sign_with_keys(&parties.signer)
            .unwrap();
        assert_eq!(OpenChallenge::parse(&event), Err(ParseError::WrongKind(1)));
    }

    #[test]
    fn rejects_non_empty_content() {
        let parties = parties();
        let event = signed(&parties, "hello", valid_tags(&parties));
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::NonEmptyContent)
        );
    }

    #[test]
    fn rejects_missing_matchmaker() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().get(3).map(String::as_str) != Some("matchmaker"));
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::MissingRole("matchmaker"))
        );
    }

    #[test]
    fn rejects_duplicate_arbiter() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(p(&Keys::generate(), "arbiter"));
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::DuplicateRole("arbiter"))
        );
    }

    #[test]
    fn rejects_role_equal_to_signer() {
        let parties = parties();
        let mm = parties.matchmaker.public_key().to_hex();
        let arb = parties.arbiter.public_key().to_hex();
        let signer = parties.signer.public_key().to_hex();
        // The timestamper p tag points at the signer (constraint 1 violation).
        let tags_json = format!(
            r#"[["p","{mm}","","matchmaker"],["p","{arb}","","arbiter"],["p","{signer}","","timestamper"],["game","sanki"],["variant","self","ogi"],["variant","opponent","ogi"],["time_control","300","3"],["accept_until","2000"],["nonce","42","16"]]"#
        );
        let event = forged_event(&signer, &tags_json);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::RoleEqualsSigner("timestamper"))
        );
    }

    #[test]
    fn rejects_missing_game() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("game"));
        let event = signed(&parties, "", tags);
        assert_eq!(OpenChallenge::parse(&event), Err(ParseError::MissingGame));
    }

    #[test]
    fn rejects_multiple_games() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["game", "chess"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::MultipleGames(2))
        );
    }

    #[test]
    fn rejects_invalid_game_id() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("game"));
        tags.push(Tag::parse(["game", "Sanki"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::InvalidGameId("Sanki".to_string()))
        );
    }

    #[test]
    fn rejects_duplicate_self_variant() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["variant", "self", "chess"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::DuplicateVariantRole("self"))
        );
    }

    #[test]
    fn rejects_invalid_variant_role() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["variant", "foe", "ogi"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::InvalidVariantRole("foe".to_string()))
        );
    }

    #[test]
    fn rejects_invalid_variant_id() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("variant"));
        tags.push(Tag::parse(["variant", "self", "Ogi"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::InvalidVariantId("Ogi".to_string()))
        );
    }

    #[test]
    fn rejects_missing_time_control() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("time_control"));
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::MissingTimeControl)
        );
    }

    #[test]
    fn rejects_plies_without_increment() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("time_control"));
        // increment omitted (empty) but plies present.
        tags.push(Tag::parse(["time_control", "300", "", "40"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::InvalidTimeControl)
        );
    }

    #[test]
    fn rejects_multiple_filters() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["filter", "everyone"]).unwrap());
        tags.push(Tag::parse(["filter", "following"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::MultipleFilters(2))
        );
    }

    #[test]
    fn rejects_invalid_filter_mode() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.push(Tag::parse(["filter", "nobody"]).unwrap());
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::InvalidFilterMode("nobody".to_string()))
        );
    }

    #[test]
    fn rejects_malformed_rating_filter() {
        let parties = parties();
        for bad in [
            vec!["filter", "rating"],          // missing delta
            vec!["filter", "rating", "0"],     // leading zero / zero
            vec!["filter", "rating", "10000"], // too large (5 digits)
            vec!["filter", "everyone", "x"],   // extra value
        ] {
            let mut tags = valid_tags(&parties);
            tags.push(Tag::parse(bad).unwrap());
            let event = signed(&parties, "", tags);
            assert_eq!(
                OpenChallenge::parse(&event),
                Err(ParseError::MalformedFilter)
            );
        }
    }

    #[test]
    fn rejects_missing_accept_until() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("accept_until"));
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::MissingAcceptUntil)
        );
    }

    #[test]
    fn rejects_accept_until_not_after_created_at() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("accept_until"));
        tags.push(Tag::parse(["accept_until", "1000"]).unwrap()); // == created_at
        let event = signed(&parties, "", tags);
        assert_eq!(
            OpenChallenge::parse(&event),
            Err(ParseError::AcceptUntilNotAfterCreatedAt {
                accept_until: 1000,
                created_at: 1000,
            })
        );
    }

    #[test]
    fn rejects_missing_nonce() {
        let parties = parties();
        let mut tags = valid_tags(&parties);
        tags.retain(|t| t.as_slice().first().map(String::as_str) != Some("nonce"));
        let event = signed(&parties, "", tags);
        assert_eq!(OpenChallenge::parse(&event), Err(ParseError::MissingNonce));
    }
}
