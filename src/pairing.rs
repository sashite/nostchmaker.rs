// SPDX-License-Identifier: Apache-2.0

//! Build a kind-`6419` Pairing from two compatible Open Challenges.
//!
//! [`PairingBuilder`] is the write path. It is **infallible**: tags are built
//! with the verbatim [`Tag::custom`] constructor, and the terminal
//! [`PairingBuilder::to_event_builder`] yields an unsigned [`EventBuilder`] for
//! the matchmaker to sign with any signer (direct keys, NIP-07, NIP-46).
//!
//! The builder assumes the two Open Challenges have already been confirmed
//! compatible (e.g. via [`crate::compatibility::evaluate`]): it takes the
//! common game, arbiter, timestamper, and time control from the **first**
//! Open Challenge, which a conforming pair shares. Per-player variants are
//! supplied by the caller — the resolved values from compatibility, with any
//! free (matchmaker's-choice) variant filled in by the caller, which knows the
//! game's variant vocabulary.
//!
//! Note: if the matchmaker key coincides with the arbiter or timestamper key,
//! `nostr`'s `EventBuilder` drops the self-referential `p` tag at signing,
//! yielding a non-conforming Pairing. Designate distinct keys for these roles
//! (which also strengthens the trust model).

use nostr::{EventBuilder, EventId, Kind, PublicKey, RelayUrl, Tag, TagKind};

use crate::constants::{
    KIND_PAIRING, MARKER_OPEN_CHALLENGE, ROLE_ARBITER, ROLE_PLAYER, ROLE_TIMESTAMPER, TAG_GAME,
    TAG_TIME_CONTROL, TAG_VARIANT,
};
use crate::open_challenge::{OpenChallenge, TimeControlPeriod};

/// A builder for a Pairing (kind `6419`) over two compatible Open Challenges.
///
/// Set the per-player variants (required for multi-variant games such as
/// `sanki`) and an optional relay hint, then call
/// [`PairingBuilder::to_event_builder`].
#[derive(Debug, Clone)]
pub struct PairingBuilder<'a> {
    a: &'a OpenChallenge,
    b: &'a OpenChallenge,
    a_variant: Option<&'a str>,
    b_variant: Option<&'a str>,
    relay_hint: Option<RelayUrl>,
}

impl<'a> PairingBuilder<'a> {
    /// Starts a Pairing of `a` and `b`. The two MUST be a compatible pair (see
    /// the module documentation); `a`'s common terms are used.
    #[must_use]
    pub fn new(a: &'a OpenChallenge, b: &'a OpenChallenge) -> Self {
        Self {
            a,
            b,
            a_variant: None,
            b_variant: None,
            relay_hint: None,
        }
    }

    /// Sets the variant played by the first Open Challenge's signer.
    #[must_use]
    pub fn a_variant(mut self, variant: &'a str) -> Self {
        self.a_variant = Some(variant);
        self
    }

    /// Sets the variant played by the second Open Challenge's signer.
    #[must_use]
    pub fn b_variant(mut self, variant: &'a str) -> Self {
        self.b_variant = Some(variant);
        self
    }

    /// Sets the relay hint emitted in every `e` and `p` tag's relay slot. The
    /// spec recommends (SHOULD) providing one.
    #[must_use]
    pub fn relay_hint(mut self, url: RelayUrl) -> Self {
        self.relay_hint = Some(url);
        self
    }

    /// Produces the unsigned [`EventBuilder`]. Sign it with the matchmaker's
    /// signer to obtain the Pairing event. This step is infallible.
    #[must_use]
    pub fn to_event_builder(self) -> EventBuilder {
        let hint = self.relay_hint.as_ref();
        let mut tags: Vec<Tag> = vec![
            // The two referenced Open Challenges.
            e_tag(self.a.id(), hint, MARKER_OPEN_CHALLENGE),
            e_tag(self.b.id(), hint, MARKER_OPEN_CHALLENGE),
            // The two players and the concrete arbiter / timestamper.
            p_tag(self.a.signer(), hint, ROLE_PLAYER),
            p_tag(self.b.signer(), hint, ROLE_PLAYER),
            p_tag(self.a.arbiter(), hint, ROLE_ARBITER),
            p_tag(self.a.timestamper(), hint, ROLE_TIMESTAMPER),
            // Game (shared by both Open Challenges).
            Tag::custom(TagKind::custom(TAG_GAME), [self.a.game().to_string()]),
        ];

        // Per-player resolved variants (pubkey-based), when supplied.
        if let Some(variant) = self.a_variant {
            tags.push(variant_tag(self.a.signer(), variant));
        }
        if let Some(variant) = self.b_variant {
            tags.push(variant_tag(self.b.signer(), variant));
        }
        // Time control (shared), one tag per period.
        for period in self.a.time_control() {
            tags.push(time_control_tag(period));
        }

        EventBuilder::new(Kind::Custom(KIND_PAIRING), "").tags(tags)
    }
}

/// Builds an `e` tag `["e", <id>, <relay-or-empty>, <marker>]`. The relay slot
/// is kept present (empty when unset) so the marker stays in the fourth slot.
fn e_tag(event_id: EventId, relay_hint: Option<&RelayUrl>, marker: &str) -> Tag {
    let relay = relay_hint.map(RelayUrl::to_string).unwrap_or_default();
    Tag::custom(TagKind::e(), [event_id.to_hex(), relay, marker.to_string()])
}

/// Builds a `p` tag `["p", <pubkey>, <relay-or-empty>, <role>]`.
fn p_tag(pubkey: PublicKey, relay_hint: Option<&RelayUrl>, role: &str) -> Tag {
    let relay = relay_hint.map(RelayUrl::to_string).unwrap_or_default();
    Tag::custom(TagKind::p(), [pubkey.to_hex(), relay, role.to_string()])
}

/// Builds a pubkey-based `variant` tag `["variant", <player_pubkey>, <variant>]`.
fn variant_tag(player: PublicKey, variant: &str) -> Tag {
    Tag::custom(
        TagKind::custom(TAG_VARIANT),
        [player.to_hex(), variant.to_string()],
    )
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
    Tag::custom(TagKind::custom(TAG_TIME_CONTROL), values)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::PairingBuilder;
    use crate::constants::KIND_PAIRING;
    use crate::open_challenge::OpenChallenge;
    use nostr::prelude::*;

    fn p(keys: &Keys, role: &str) -> Tag {
        Tag::parse(["p", &keys.public_key().to_hex(), "", role]).unwrap()
    }

    fn oc(
        signer: &Keys,
        matchmaker: &Keys,
        arbiter: &Keys,
        timestamper: &Keys,
        terms: Vec<Tag>,
    ) -> OpenChallenge {
        let mut tags = vec![
            p(matchmaker, "matchmaker"),
            p(arbiter, "arbiter"),
            p(timestamper, "timestamper"),
        ];
        tags.extend(terms);
        tags.push(Tag::parse(["accept_until", "2000"]).unwrap());
        tags.push(Tag::parse(["nonce", "42", "16"]).unwrap());
        let event = EventBuilder::new(Kind::Custom(6418), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(1000))
            .sign_with_keys(signer)
            .unwrap();
        OpenChallenge::parse(&event).unwrap()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example.com").unwrap()
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

    #[test]
    fn builds_a_conforming_pairing() {
        let mm = Keys::generate();
        let arb = Keys::generate();
        let ts = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();

        let a = oc(
            &alice,
            &mm,
            &arb,
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
            &arb,
            &ts,
            vec![
                Tag::parse(["game", "sanki"]).unwrap(),
                Tag::parse(["variant", "self", "chess"]).unwrap(),
                Tag::parse(["time_control", "300", "3"]).unwrap(),
            ],
        );

        let pairing = PairingBuilder::new(&a, &b)
            .a_variant("ogi")
            .b_variant("chess")
            .relay_hint(relay())
            .to_event_builder()
            .sign_with_keys(&mm)
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
        let players: Vec<String> = tags_named(&pairing, "p")
            .iter()
            .filter(|s| s.get(3).map(String::as_str) == Some("player"))
            .map(|s| s[1].clone())
            .collect();
        assert_eq!(players.len(), 2);
        assert!(players.contains(&alice.public_key().to_hex()));
        assert!(players.contains(&bob.public_key().to_hex()));

        // Exactly one arbiter and one timestamper p tag.
        let arbiters = tags_named(&pairing, "p")
            .into_iter()
            .filter(|s| s.get(3).map(String::as_str) == Some("arbiter"))
            .count();
        let timestampers = tags_named(&pairing, "p")
            .into_iter()
            .filter(|s| s.get(3).map(String::as_str) == Some("timestamper"))
            .count();
        assert_eq!(arbiters, 1);
        assert_eq!(timestampers, 1);

        // game and time_control mirror the Open Challenges.
        assert_eq!(tags_named(&pairing, "game")[0][1], "sanki");
        let tc = &tags_named(&pairing, "time_control")[0];
        assert_eq!(tc[1], "300");
        assert_eq!(tc[2], "3");

        // Pubkey-based variant tags.
        let variants: Vec<Vec<String>> = tags_named(&pairing, "variant");
        assert_eq!(variants.len(), 2);
        let alice_hex = alice.public_key().to_hex();
        let bob_hex = bob.public_key().to_hex();
        assert!(variants.iter().any(|s| s[1] == alice_hex && s[2] == "ogi"));
        assert!(variants.iter().any(|s| s[1] == bob_hex && s[2] == "chess"));
    }

    #[test]
    fn omits_variant_tags_when_unset() {
        let mm = Keys::generate();
        let arb = Keys::generate();
        let ts = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let terms = vec![
            Tag::parse(["game", "go"]).unwrap(),
            Tag::parse(["time_control", "600"]).unwrap(),
        ];
        let a = oc(&alice, &mm, &arb, &ts, terms.clone());
        let b = oc(&bob, &mm, &arb, &ts, terms);

        let pairing = PairingBuilder::new(&a, &b)
            .to_event_builder()
            .sign_with_keys(&mm)
            .unwrap();

        assert!(tags_named(&pairing, "variant").is_empty());
        // A duration-only time control survives the round trip.
        let tc = &tags_named(&pairing, "time_control")[0];
        assert_eq!(tc.len(), 2);
        assert_eq!(tc[1], "600");
    }

    #[test]
    fn omits_relay_hint_slot_when_unset() {
        let mm = Keys::generate();
        let arb = Keys::generate();
        let ts = Keys::generate();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let terms = vec![
            Tag::parse(["game", "sanki"]).unwrap(),
            Tag::parse(["time_control", "300", "3"]).unwrap(),
        ];
        let a = oc(&alice, &mm, &arb, &ts, terms.clone());
        let b = oc(&bob, &mm, &arb, &ts, terms);

        let pairing = PairingBuilder::new(&a, &b)
            .to_event_builder()
            .sign_with_keys(&mm)
            .unwrap();

        // The relay slot is empty but the marker stays in the fourth position.
        let e_open = &tags_named(&pairing, "e")[0];
        assert_eq!(e_open[2], "");
        assert_eq!(e_open[3], "open_challenge");
    }
}
