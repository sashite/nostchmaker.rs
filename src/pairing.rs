// SPDX-License-Identifier: Apache-2.0

//! Build a kind-`3419` Pairing from two compatible Open Challenges.
//!
//! [`PairingBuilder`] is the write path. It is **infallible**: tags are built
//! with the verbatim [`Tag::custom`] constructor, and the terminal
//! [`PairingBuilder::to_event_builder`] yields an unsigned [`EventBuilder`] for
//! the matchmaker to sign with any signer (direct keys, NIP-07, NIP-46).
//!
//! The builder assumes the two Open Challenges have already been confirmed
//! compatible (e.g. via [`crate::compatibility::evaluate`]): it takes the
//! common game, `rules` digest, timing designation and time control from the
//! **first** Open Challenge, which a conforming pair shares. What the
//! matchmaker itself **resolves** — both players' variants (the resolved
//! values from compatibility, any free one filled in by the caller, which
//! knows the game's variant vocabulary), the seat draw, and the founding
//! window — is supplied as a [`Resolution`], so that a Pairing is never built
//! with a term left open: kind `3419` carries exactly two `variant` tags, two
//! `seat` tags and one `found_until`, unconditionally.
//!
//! The seat draw is the caller's: this crate holds no randomness. A fair
//! draw is what the pool expects (kind `3419` §Match-terms tags).
//!
//! Note: if the matchmaker key coincides with the timestamper key, `nostr`'s
//! `EventBuilder` drops the self-referential `p` tag at signing, yielding a
//! non-conforming Pairing. Designate distinct keys for these roles (which also
//! strengthens the trust model).

use nostr::event::{EventBuilder, EventId, Kind, Tag};
use nostr::key::PublicKey;
use nostr::types::RelayUrl;

use crate::constants::{
    KIND_PAIRING, MARKER_OPEN_CHALLENGE, ROLE_PLAYER, ROLE_TIMESTAMPER, SEAT_FIRST, SEAT_SECOND,
    TAG_FOUND_UNTIL, TAG_GAME, TAG_RULES, TAG_SEAT, TAG_TIME_CONTROL, TAG_TIMING_RELAY,
    TAG_VARIANT,
};
use crate::open_challenge::{OpenChallenge, TimeControlPeriod};

/// A seat: which of the two players moves first (kind `3420` §Match-terms
/// tags — the protocol's two seat-names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Seat {
    /// The player who moves first.
    First,
    /// The player who moves second.
    Second,
}

impl Seat {
    /// The on-wire seat-name (`first` / `second`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::First => SEAT_FIRST,
            Self::Second => SEAT_SECOND,
        }
    }

    /// The other seat.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::First => Self::Second,
            Self::Second => Self::First,
        }
    }

    /// Parses an on-wire seat-name, or `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            SEAT_FIRST => Some(Self::First),
            SEAT_SECOND => Some(Self::Second),
            _ => None,
        }
    }
}

/// What the matchmaker resolves for a Pairing, beyond the terms the two Open
/// Challenges fix: each player's variant, the seat draw, and the founding
/// window. `a_*` refers to the first Open Challenge's signer, `b_*` to the
/// second's; `b` takes the seat `a` does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution<'a> {
    /// The variant played by the first Open Challenge's signer.
    pub a_variant: &'a str,
    /// The variant played by the second Open Challenge's signer.
    pub b_variant: &'a str,
    /// The seat drawn for the first Open Challenge's signer.
    pub a_seat: Seat,
    /// `found_until`: the latest moment (Unix seconds) at which a Game Session
    /// founded on this Pairing is valid — strictly greater than the Pairing's
    /// `created_at` (kind `3419` §Lifecycle tags), which the caller controls
    /// at signing time.
    pub found_until: u64,
}

/// A builder for a Pairing (kind `3419`) over two compatible Open Challenges.
///
/// Supply the [`Resolution`], optionally a relay hint and a `rules` hint, then
/// call [`PairingBuilder::to_event_builder`].
#[derive(Debug, Clone)]
pub struct PairingBuilder<'a> {
    a: &'a OpenChallenge,
    b: &'a OpenChallenge,
    resolution: Resolution<'a>,
    relay_hint: Option<RelayUrl>,
    rules_hint: Option<&'a str>,
}

impl<'a> PairingBuilder<'a> {
    /// Starts a Pairing of `a` and `b` under `resolution`. The two MUST be a
    /// compatible pair (see the module documentation); `a`'s common terms are
    /// used.
    #[must_use]
    pub fn new(a: &'a OpenChallenge, b: &'a OpenChallenge, resolution: Resolution<'a>) -> Self {
        Self {
            a,
            b,
            resolution,
            relay_hint: None,
            rules_hint: None,
        }
    }

    /// Sets the relay hint emitted in every `e` and `p` tag's relay slot. The
    /// spec recommends (SHOULD) providing one.
    #[must_use]
    pub fn relay_hint(mut self, url: RelayUrl) -> Self {
        self.relay_hint = Some(url);
        self
    }

    /// Sets the retrieval hint of the `rules` tag — the matchmaker's own. When
    /// unset, the first Open Challenge's hint is carried, if it has one (kind
    /// `3419` §Match-terms tags: the hint may be either challenge's or the
    /// matchmaker's).
    #[must_use]
    pub fn rules_hint(mut self, hint: &'a str) -> Self {
        self.rules_hint = Some(hint);
        self
    }

    /// Produces the unsigned [`EventBuilder`]. Sign it with the matchmaker's
    /// signer to obtain the Pairing event. This step is infallible.
    #[must_use]
    pub fn to_event_builder(self) -> EventBuilder {
        let hint = self.relay_hint.as_ref();
        let r = self.resolution;
        let mut tags: Vec<Tag> = vec![
            // The two referenced Open Challenges.
            e_tag(self.a.id(), hint, MARKER_OPEN_CHALLENGE),
            e_tag(self.b.id(), hint, MARKER_OPEN_CHALLENGE),
            // The two players.
            p_tag(self.a.signer(), hint, ROLE_PLAYER),
            p_tag(self.b.signer(), hint, ROLE_PLAYER),
            // Game (shared by both Open Challenges).
            Tag::custom(TAG_GAME, [self.a.game().to_string()]),
            // The rule-system document (shared digest; a hint of the
            // matchmaker's choosing).
            rules_tag(
                self.a.rules().digest(),
                self.rules_hint.or(self.a.rules().hint()),
            ),
        ];

        // The timestamper is optional: designated only when the (compatible) pair named
        // one — attested mode; absent → the session is self-timed. `a` and `b` agree
        // (compatibility rejects a timestamper mismatch), so `a`'s value is canonical.
        if let Some(timestamper) = self.a.timestamper() {
            tags.push(p_tag(timestamper, hint, ROLE_TIMESTAMPER));
        }
        // Self-timed: the Pairing mirrors the (identical — compatibility
        // rejects a mismatch) `timing_relay` set of the two Open Challenges
        // (kind `3419` §Consent constraints, constraint 5).
        for url in self.a.timing_relays() {
            tags.push(Tag::custom(TAG_TIMING_RELAY, [url.clone()]));
        }

        // Per-player resolved variants and drawn seats (pubkey-based), both
        // unconditional.
        tags.push(variant_tag(self.a.signer(), r.a_variant));
        tags.push(variant_tag(self.b.signer(), r.b_variant));
        tags.push(seat_tag(self.a.signer(), r.a_seat));
        tags.push(seat_tag(self.b.signer(), r.a_seat.other()));
        // Time control (shared), one tag per period.
        for period in self.a.time_control() {
            tags.push(time_control_tag(period));
        }
        // The founding window.
        tags.push(Tag::custom(TAG_FOUND_UNTIL, [r.found_until.to_string()]));

        EventBuilder::new(Kind::Custom(KIND_PAIRING), "").tags(tags)
    }
}

/// Builds an `e` tag `["e", <id>, <relay-or-empty>, <marker>]`. The relay slot
/// is kept present (empty when unset) so the marker stays in the fourth slot.
fn e_tag(event_id: EventId, relay_hint: Option<&RelayUrl>, marker: &str) -> Tag {
    let relay = relay_hint.map(RelayUrl::to_string).unwrap_or_default();
    Tag::custom("e", [event_id.to_hex(), relay, marker.to_string()])
}

/// Builds a `p` tag `["p", <pubkey>, <relay-or-empty>, <role>]`.
fn p_tag(pubkey: PublicKey, relay_hint: Option<&RelayUrl>, role: &str) -> Tag {
    let relay = relay_hint.map(RelayUrl::to_string).unwrap_or_default();
    Tag::custom("p", [pubkey.to_hex(), relay, role.to_string()])
}

/// Builds a pubkey-based `variant` tag `["variant", <player_pubkey>, <variant>]`.
fn variant_tag(player: PublicKey, variant: &str) -> Tag {
    Tag::custom(TAG_VARIANT, [player.to_hex(), variant.to_string()])
}

/// Builds a `seat` tag `["seat", <player_pubkey>, <seat-name>]`.
fn seat_tag(player: PublicKey, seat: Seat) -> Tag {
    Tag::custom(TAG_SEAT, [player.to_hex(), seat.as_str().to_string()])
}

/// Builds a `rules` tag `["rules", <digest>]` or `["rules", <digest>, <hint>]`.
fn rules_tag(digest: &str, hint: Option<&str>) -> Tag {
    let mut values = vec![digest.to_string()];
    if let Some(hint) = hint {
        values.push(hint.to_string());
    }
    Tag::custom(TAG_RULES, values)
}

/// Rebuilds a `time_control` tag from a period, omitting trailing fields.
fn time_control_tag(period: &TimeControlPeriod) -> Tag {
    let mut values: Vec<String> = vec![period.duration().to_string()];
    if let Some(increment) = period.increment() {
        values.push(increment.to_string());
        if let Some(plies) = period.plies() {
            values.push(plies.to_string());
        }
    }
    Tag::custom(TAG_TIME_CONTROL, values)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::{PairingBuilder, Resolution, Seat};
    use crate::constants::KIND_PAIRING;
    use crate::open_challenge::OpenChallenge;
    use nostr::prelude::*;

    const RULES: &str = "3f6d1a0c9e4b2a7d5c8e1f0a9b3c7d2e4f6a8b0c1d3e5f7a9b2c4d6e8f0a1b3c";

    fn p(keys: &Keys, role: &str) -> Tag {
        Tag::parse(["p", &keys.public_key().to_hex(), "", role]).unwrap()
    }

    fn rules(hint: Option<&str>) -> Tag {
        match hint {
            Some(hint) => Tag::parse(["rules", RULES, hint]).unwrap(),
            None => Tag::parse(["rules", RULES]).unwrap(),
        }
    }

    fn finish(signer: &Keys, mut tags: Vec<Tag>, terms: Vec<Tag>) -> OpenChallenge {
        tags.extend(terms);
        tags.push(Tag::parse(["accept_until", "2000"]).unwrap());
        tags.push(Tag::parse(["nonce", "42", "16"]).unwrap());
        let event = EventBuilder::new(Kind::Custom(3418), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(1000))
            .finalize(signer)
            .unwrap();
        OpenChallenge::parse(&event).unwrap()
    }

    /// An attested-mode challenge carrying a `rules` hint.
    fn oc(signer: &Keys, matchmaker: &Keys, timestamper: &Keys, terms: Vec<Tag>) -> OpenChallenge {
        finish(
            signer,
            vec![
                p(matchmaker, "matchmaker"),
                p(timestamper, "timestamper"),
                rules(Some("https://blobs.example.com")),
            ],
            terms,
        )
    }

    /// Like [`oc`], but designates NO timestamper — a self-timed challenge —
    /// and carries no `rules` hint.
    fn oc_self_timed(signer: &Keys, matchmaker: &Keys, terms: Vec<Tag>) -> OpenChallenge {
        finish(
            signer,
            vec![
                p(matchmaker, "matchmaker"),
                Tag::parse(["timing_relay", "wss://relay.example.com"]).unwrap(),
                rules(None),
            ],
            terms,
        )
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example.com").unwrap()
    }

    fn resolution<'a>(a: &'a str, b: &'a str) -> Resolution<'a> {
        Resolution {
            a_variant: a,
            b_variant: b,
            a_seat: Seat::Second,
            found_until: 1_700_000_120,
        }
    }

    /// All slices of tags whose first element equals `name`.
    fn tags_named(event: &Event, name: &str) -> Vec<Vec<String>> {
        event
            .tags
            .iter()
            .map(|t| t.as_slice().to_vec())
            .filter(|s| s.first().map(String::as_str) == Some(name))
            .collect()
    }

    fn roles(event: &Event, role: &str) -> Vec<String> {
        tags_named(event, "p")
            .into_iter()
            .filter(|s| s.get(3).map(String::as_str) == Some(role))
            .map(|s| s[1].clone())
            .collect()
    }

    #[test]
    fn builds_a_conforming_pairing() {
        let mm = Keys::generate();
        let ts = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();

        let a = oc(
            &alice,
            &mm,
            &ts,
            vec![
                Tag::parse(["game", "sanki"]).unwrap(),
                Tag::parse(["variant", "self", "ogi"]).unwrap(),
                Tag::parse(["time_control", "300", "3"]).unwrap(),
            ],
        );
        let b = oc(
            &bob,
            &mm,
            &ts,
            vec![
                Tag::parse(["game", "sanki"]).unwrap(),
                Tag::parse(["variant", "self", "chess"]).unwrap(),
                Tag::parse(["time_control", "300", "3"]).unwrap(),
            ],
        );

        let pairing = PairingBuilder::new(&a, &b, resolution("ogi", "chess"))
            .relay_hint(relay())
            .to_event_builder()
            .finalize(&mm)
            .unwrap();

        pairing.verify().unwrap();
        assert_eq!(pairing.kind, Kind::Custom(KIND_PAIRING));
        assert!(pairing.content.is_empty());

        // Two open_challenge e tags referencing the two Open Challenges.
        let e_open: Vec<Vec<String>> = tags_named(&pairing, "e")
            .into_iter()
            .filter(|s| s.get(3).map(String::as_str) == Some("open_challenge"))
            .collect();
        assert_eq!(e_open.len(), 2);
        let referenced: Vec<&str> = e_open.iter().map(|s| s[1].as_str()).collect();
        assert!(referenced.contains(&a.id().to_hex().as_str()));
        assert!(referenced.contains(&b.id().to_hex().as_str()));
        // Relay hint present in the slot.
        assert!(e_open.iter().all(|s| s[2] == relay().to_string()));

        // Exactly two player p tags = the two signers.
        let players = roles(&pairing, "player");
        assert_eq!(players.len(), 2);
        assert!(players.contains(&alice.public_key().to_hex()));
        assert!(players.contains(&bob.public_key().to_hex()));

        // Exactly one timestamper p tag, and no arbiter (constraint 15).
        assert_eq!(roles(&pairing, "timestamper").len(), 1);
        assert!(roles(&pairing, "arbiter").is_empty());

        // game, rules and time_control mirror the Open Challenges.
        assert_eq!(tags_named(&pairing, "game")[0][1], "sanki");
        let rules = tags_named(&pairing, "rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0][1], RULES);
        assert_eq!(rules[0][2], "https://blobs.example.com"); // a's hint
        let tc = &tags_named(&pairing, "time_control")[0];
        assert_eq!(tc[1], "300");
        assert_eq!(tc[2], "3");

        // Pubkey-based variant tags, one per player.
        let variants: Vec<Vec<String>> = tags_named(&pairing, "variant");
        assert_eq!(variants.len(), 2);
        let alice_hex = alice.public_key().to_hex();
        let bob_hex = bob.public_key().to_hex();
        assert!(variants.iter().any(|s| s[1] == alice_hex && s[2] == "ogi"));
        assert!(variants.iter().any(|s| s[1] == bob_hex && s[2] == "chess"));

        // Seats: one per player, the two distinct values, as drawn.
        let seats: Vec<Vec<String>> = tags_named(&pairing, "seat");
        assert_eq!(seats.len(), 2);
        assert!(seats.iter().any(|s| s[1] == alice_hex && s[2] == "second"));
        assert!(seats.iter().any(|s| s[1] == bob_hex && s[2] == "first"));

        // The founding window.
        let found_until = tags_named(&pairing, "found_until");
        assert_eq!(found_until.len(), 1);
        assert_eq!(found_until[0][1], "1700000120");

        // No nonce: a Pairing is not subjected to proof of work.
        assert!(tags_named(&pairing, "nonce").is_empty());
    }

    #[test]
    fn a_self_timed_pairing_designates_no_timestamper() {
        // Two self-timed challenges (no timestamper) pair into a 3419 that likewise
        // designates none — the session runs self-timed.
        let mm = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let terms = || {
            vec![
                Tag::parse(["game", "sanki"]).unwrap(),
                Tag::parse(["time_control", "300", "3"]).unwrap(),
            ]
        };
        let a = oc_self_timed(&alice, &mm, terms());
        let b = oc_self_timed(&bob, &mm, terms());

        let pairing = PairingBuilder::new(&a, &b, resolution("chess", "chess"))
            .to_event_builder()
            .finalize(&mm)
            .unwrap();

        pairing.verify().unwrap();
        // ZERO timestamper p tags, zero arbiter.
        assert!(roles(&pairing, "timestamper").is_empty());
        assert!(roles(&pairing, "arbiter").is_empty());
        // The Pairing mirrors the (identical) timing_relay set of the two
        // entries — the self-timed designation travels with the founding.
        let relays: Vec<String> = tags_named(&pairing, "timing_relay")
            .into_iter()
            .filter_map(|s| s.get(1).cloned())
            .collect();
        assert_eq!(relays, vec!["wss://relay.example.com".to_string()]);
        // A hint-less `rules` on both entries yields a hint-less tag.
        let rules = tags_named(&pairing, "rules");
        assert_eq!(rules[0].len(), 2);
        assert_eq!(rules[0][1], RULES);
        // A single-variant game still writes both variants (unconditional).
        assert_eq!(tags_named(&pairing, "variant").len(), 2);
    }

    #[test]
    fn the_matchmakers_rules_hint_wins_over_the_challenges() {
        let mm = Keys::generate();
        let ts = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let terms = || {
            vec![
                Tag::parse(["game", "sanki"]).unwrap(),
                Tag::parse(["time_control", "600"]).unwrap(),
            ]
        };
        let a = oc(&alice, &mm, &ts, terms());
        let b = oc(&bob, &mm, &ts, terms());

        let pairing = PairingBuilder::new(&a, &b, resolution("ogi", "ogi"))
            .rules_hint("https://blobs.sanki.app")
            .to_event_builder()
            .finalize(&mm)
            .unwrap();

        let rules = tags_named(&pairing, "rules");
        assert_eq!(rules[0][1], RULES);
        assert_eq!(rules[0][2], "https://blobs.sanki.app");
        // A duration-only time control survives the round trip.
        let tc = &tags_named(&pairing, "time_control")[0];
        assert_eq!(tc.len(), 2);
        assert_eq!(tc[1], "600");
    }

    #[test]
    fn the_seat_draw_is_mirrored_for_the_other_player() {
        let mm = Keys::generate();
        let ts = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let terms = || {
            vec![
                Tag::parse(["game", "sanki"]).unwrap(),
                Tag::parse(["time_control", "300", "3"]).unwrap(),
            ]
        };
        let a = oc(&alice, &mm, &ts, terms());
        let b = oc(&bob, &mm, &ts, terms());
        for (a_seat, a_name, b_name) in [
            (Seat::First, "first", "second"),
            (Seat::Second, "second", "first"),
        ] {
            let pairing = PairingBuilder::new(
                &a,
                &b,
                Resolution {
                    a_variant: "ogi",
                    b_variant: "ogi",
                    a_seat,
                    found_until: 3000,
                },
            )
            .to_event_builder()
            .finalize(&mm)
            .unwrap();
            let seats = tags_named(&pairing, "seat");
            let alice_hex = alice.public_key().to_hex();
            let bob_hex = bob.public_key().to_hex();
            assert!(seats.iter().any(|s| s[1] == alice_hex && s[2] == a_name));
            assert!(seats.iter().any(|s| s[1] == bob_hex && s[2] == b_name));
        }
        assert_eq!(Seat::First.other(), Seat::Second);
        assert_eq!(Seat::parse("first"), Some(Seat::First));
        assert_eq!(Seat::parse("second"), Some(Seat::Second));
        assert_eq!(Seat::parse("third"), None);
        assert_eq!(Seat::Second.as_str(), "second");
    }

    #[test]
    fn omits_relay_hint_slot_when_unset() {
        let mm = Keys::generate();
        let ts = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let terms = vec![
            Tag::parse(["game", "sanki"]).unwrap(),
            Tag::parse(["time_control", "300", "3"]).unwrap(),
        ];
        let a = oc(&alice, &mm, &ts, terms.clone());
        let b = oc(&bob, &mm, &ts, terms);

        let pairing = PairingBuilder::new(&a, &b, resolution("ogi", "chess"))
            .to_event_builder()
            .finalize(&mm)
            .unwrap();

        // The relay slot is empty but the marker stays in the fourth position.
        let e_open = &tags_named(&pairing, "e")[0];
        assert_eq!(e_open[2], "");
        assert_eq!(e_open[3], "open_challenge");
    }
}
