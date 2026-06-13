// SPDX-License-Identifier: Apache-2.0

//! Decide whether two [`OpenChallenge`]s can be paired, and resolve each
//! player's variant.
//!
//! [`evaluate`] encodes the consent constraints of kind `6419` that are
//! decidable from the two challenges plus externally resolved [`Facts`]:
//! distinct signers (constraint 1), a common matchmaker / arbiter / timestamper
//! (constraints 2, 4, 5), a common game (6), an identical time control (8), a
//! satisfiable variant resolution (7), and each player satisfying the other's
//! `filter` (9).
//!
//! It is **silent** on the rest, which a higher layer enforces: the
//! accept-deadline (constraint 10, a timing decision anchored on the Pairing's
//! attestation), the Pairing event's own shape (constraints 3, 11, 12, checked
//! when validating a built Pairing), and any operational policy such as a game
//! allow-list or NIP-51 mute lists. Constraint 11 (the matchmaker differs from
//! both players) follows from constraint 2 together with kind `6418`'s own
//! constraint 1, so it is not re-checked here.

use nostr::PublicKey;

use crate::open_challenge::{Filter, OpenChallenge, RatingKind};

/// External, relay-derived facts needed to evaluate the `following` and
/// `rating` filters. A consumer (e.g. a matchmaker service) implements this by
/// reading NIP-02 contact lists and the suite's rating attestations; the
/// primitive itself performs no I/O.
///
/// Both methods are **anchored at the Pairing's canonical attestation** by
/// contract: the implementer evaluates the follow relation against the
/// filterer's contact list as it stood at the anchor, and a rating against the
/// most recent attestation by the pinned authority with `created_at` at or
/// before the anchor (kind `6419` §Consent constraints). The primitive does not
/// see the anchor; threading it is the implementer's responsibility.
pub trait Facts {
    /// Whether `follower` follows `target`, per `follower`'s NIP-02 contact list.
    fn follows(&self, follower: &PublicKey, target: &PublicKey) -> bool;

    /// Whether `a` and `b` are within `max_delta` rating points in the
    /// `(game, variant)` pool, as rated by the pinned `authority` under the
    /// pinned `kind`. Both players are rated in the **same** pool — a `rating`
    /// filter is satisfiable only for a same-variant pairing, which [`evaluate`]
    /// enforces before calling this. A player with no qualifying attestation
    /// from `authority` is unrated; the implementer returns `false`
    /// (fail-closed).
    // The arguments name the pinned source (authority, kind), the pool
    // (game, variant), and the rated pair (a, b) with its bound; grouping them
    // into a struct would only obscure a faithful query signature.
    #[allow(clippy::too_many_arguments)]
    fn rating_within(
        &self,
        authority: &PublicKey,
        kind: RatingKind,
        game: &str,
        variant: &str,
        a: &PublicKey,
        b: &PublicKey,
        max_delta: u16,
    ) -> bool;
}

/// The outcome of evaluating two Open Challenges for pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// The two Open Challenges can be paired. Each player's variant is `Some`
    /// when the role preferences determine it, or `None` when it is left free
    /// for the matchmaker to choose (bounded by the game's vocabulary, which
    /// this primitive does not know). `a_variant` corresponds to the first
    /// argument's signer, `b_variant` to the second's.
    Compatible {
        /// The first challenge signer's resolved variant, or `None` if free.
        a_variant: Option<String>,
        /// The second challenge signer's resolved variant, or `None` if free.
        b_variant: Option<String>,
    },
    /// The two Open Challenges cannot be paired, with the reason.
    Incompatible(Incompatibility),
}

/// Why two Open Challenges cannot be paired.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Incompatibility {
    /// Both Open Challenges have the same signer (a player cannot face itself).
    SameSigner,
    /// The two Open Challenges designate different matchmakers.
    MatchmakerMismatch,
    /// The two Open Challenges designate different arbiters.
    ArbiterMismatch,
    /// The two Open Challenges designate different timestampers.
    TimestamperMismatch,
    /// The two Open Challenges seek different games.
    GameMismatch,
    /// The two Open Challenges declare different time-control configurations.
    TimeControlMismatch,
    /// A player's `self` variant and the other's `opponent` variant disagree.
    VariantConflict,
    /// A player's `filter` is not satisfied by the other.
    FilterRejected,
    /// A `rating` filter applies but the relevant variant is unresolved (free),
    /// so the rating cannot be looked up; the pair is conservatively rejected.
    RatingNeedsResolvedVariant,
    /// A `rating` filter applies but the two players' resolved variants differ.
    /// Ratings live in per-`(game, variant)` pools, so there is no shared pool
    /// to compare in; the pair is rejected (kind `6419` §Consent constraints).
    RatingNeedsSameVariant,
}

/// Evaluates whether `a` and `b` can be paired, resolving each player's variant.
///
/// Returns [`Compatibility::Incompatible`] with the first violated reason, or
/// [`Compatibility::Compatible`] with the resolved (or free) variants.
#[must_use]
pub fn evaluate(a: &OpenChallenge, b: &OpenChallenge, facts: &impl Facts) -> Compatibility {
    // Term compatibility (constraints 1, 2, 4, 5, 6, 8).
    if a.signer() == b.signer() {
        return Compatibility::Incompatible(Incompatibility::SameSigner);
    }
    if a.matchmaker() != b.matchmaker() {
        return Compatibility::Incompatible(Incompatibility::MatchmakerMismatch);
    }
    if a.arbiter() != b.arbiter() {
        return Compatibility::Incompatible(Incompatibility::ArbiterMismatch);
    }
    if a.timestamper() != b.timestamper() {
        return Compatibility::Incompatible(Incompatibility::TimestamperMismatch);
    }
    if a.game() != b.game() {
        return Compatibility::Incompatible(Incompatibility::GameMismatch);
    }
    if a.time_control() != b.time_control() {
        return Compatibility::Incompatible(Incompatibility::TimeControlMismatch);
    }

    // Variant resolution (constraint 7). Each player's variant is constrained by
    // their own `self` preference and the other player's `opponent` preference.
    let a_variant = match resolve_variant(a.self_variant(), b.opponent_variant()) {
        Ok(v) => v,
        Err(reason) => return Compatibility::Incompatible(reason),
    };
    let b_variant = match resolve_variant(b.self_variant(), a.opponent_variant()) {
        Ok(v) => v,
        Err(reason) => return Compatibility::Incompatible(reason),
    };

    // Mutual filter satisfaction (constraint 9): each player satisfies the
    // other's filter.
    if let Err(reason) = satisfies(
        b.filter(),
        &b.signer(),
        b_variant.as_deref(),
        &a.signer(),
        a_variant.as_deref(),
        a.game(),
        facts,
    ) {
        return Compatibility::Incompatible(reason);
    }
    if let Err(reason) = satisfies(
        a.filter(),
        &a.signer(),
        a_variant.as_deref(),
        &b.signer(),
        b_variant.as_deref(),
        a.game(),
        facts,
    ) {
        return Compatibility::Incompatible(reason);
    }

    Compatibility::Compatible {
        a_variant,
        b_variant,
    }
}

/// Resolves a player's variant from their own `self` preference and the other
/// player's `opponent` preference. Conflicting fixed preferences are an error;
/// an unconstrained variant is `None` (the matchmaker's free choice).
fn resolve_variant(
    own_self: Option<&str>,
    others_opponent: Option<&str>,
) -> Result<Option<String>, Incompatibility> {
    match (own_self, others_opponent) {
        (Some(s), Some(o)) if s != o => Err(Incompatibility::VariantConflict),
        (Some(s), _) => Ok(Some(s.to_string())),
        (None, Some(o)) => Ok(Some(o.to_string())),
        (None, None) => Ok(None),
    }
}

/// Whether `other` satisfies `filterer`'s `filter`. `*_variant` are the resolved
/// variants (needed only by the `rating` mode).
fn satisfies(
    filter: Filter,
    filterer: &PublicKey,
    filterer_variant: Option<&str>,
    other: &PublicKey,
    other_variant: Option<&str>,
    game: &str,
    facts: &impl Facts,
) -> Result<(), Incompatibility> {
    match filter {
        Filter::Everyone => Ok(()),
        Filter::Following => {
            if facts.follows(filterer, other) {
                Ok(())
            } else {
                Err(Incompatibility::FilterRejected)
            }
        }
        Filter::Rating {
            max_delta,
            authority,
            kind,
        } => match (filterer_variant, other_variant) {
            (Some(fv), Some(ov)) if fv != ov => Err(Incompatibility::RatingNeedsSameVariant),
            (Some(variant), Some(_)) => {
                if facts.rating_within(&authority, kind, game, variant, filterer, other, max_delta)
                {
                    Ok(())
                } else {
                    Err(Incompatibility::FilterRejected)
                }
            }
            _ => Err(Incompatibility::RatingNeedsResolvedVariant),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{evaluate, Compatibility, Facts, Incompatibility};
    use crate::open_challenge::{OpenChallenge, RatingKind};
    use nostr::prelude::*;

    /// A mock of the external facts, parameterized by the two players.
    struct MockFacts {
        a: PublicKey,
        b: PublicKey,
        a_follows_b: bool,
        b_follows_a: bool,
        rating_ok: bool,
    }

    impl MockFacts {
        fn new(a: &Keys, b: &Keys) -> Self {
            Self {
                a: a.public_key(),
                b: b.public_key(),
                a_follows_b: false,
                b_follows_a: false,
                rating_ok: false,
            }
        }
    }

    impl Facts for MockFacts {
        fn follows(&self, follower: &PublicKey, target: &PublicKey) -> bool {
            if *follower == self.a && *target == self.b {
                self.a_follows_b
            } else if *follower == self.b && *target == self.a {
                self.b_follows_a
            } else {
                false
            }
        }

        fn rating_within(
            &self,
            _authority: &PublicKey,
            _kind: RatingKind,
            _game: &str,
            _variant: &str,
            _a: &PublicKey,
            _b: &PublicKey,
            _max_delta: u16,
        ) -> bool {
            self.rating_ok
        }
    }

    /// A `rating` filter tag pinning a fresh authority (Glicko-2).
    fn rating_filter(max_delta: &str) -> Tag {
        let authority = Keys::generate().public_key().to_hex();
        Tag::parse(["filter", "rating", max_delta, &authority, "6427"]).unwrap()
    }

    fn p(keys: &Keys, role: &str) -> Tag {
        Tag::parse(["p", &keys.public_key().to_hex(), "", role]).unwrap()
    }

    /// Builds and parses an Open Challenge from its variable `terms` tags (game,
    /// variant(s), time_control, filter), with the given authorized parties.
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

    fn tc() -> Tag {
        Tag::parse(["time_control", "300", "3"]).unwrap()
    }

    fn game() -> Tag {
        Tag::parse(["game", "sanki"]).unwrap()
    }

    fn variant(role: &str, id: &str) -> Tag {
        Tag::parse(["variant", role, id]).unwrap()
    }

    /// Shared third parties plus two distinct player keys.
    struct Stage {
        mm: Keys,
        arb: Keys,
        ts: Keys,
        alice: Keys,
        bob: Keys,
    }

    fn stage() -> Stage {
        Stage {
            mm: Keys::generate(),
            arb: Keys::generate(),
            ts: Keys::generate(),
            alice: Keys::generate(),
            bob: Keys::generate(),
        }
    }

    #[test]
    fn compatible_same_variant_everyone() {
        let s = stage();
        let a = oc(
            &s.alice,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc()],
        );
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc()],
        );
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible {
                a_variant: Some("ogi".to_string()),
                b_variant: Some("ogi".to_string()),
            }
        );
    }

    #[test]
    fn compatible_multi_variant_from_self_preferences() {
        let s = stage();
        let a = oc(
            &s.alice,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc()],
        );
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "chess"), tc()],
        );
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible {
                a_variant: Some("ogi".to_string()),
                b_variant: Some("chess".to_string()),
            }
        );
    }

    #[test]
    fn free_variants_when_unconstrained() {
        let s = stage();
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b = oc(&s.bob, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible {
                a_variant: None,
                b_variant: None,
            }
        );
    }

    #[test]
    fn opponent_preference_fixes_the_other_variant() {
        let s = stage();
        // Alice has no self pref but wants to face an `ogi` opponent.
        let a = oc(
            &s.alice,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("opponent", "ogi"), tc()],
        );
        let b = oc(&s.bob, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let facts = MockFacts::new(&s.alice, &s.bob);
        // Bob's variant is fixed to `ogi` by Alice's opponent preference; Alice's
        // own variant remains free.
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible {
                a_variant: None,
                b_variant: Some("ogi".to_string()),
            }
        );
    }

    #[test]
    fn variant_conflict() {
        let s = stage();
        // Alice plays ogi; Bob wants to face a chess player -> Alice's variant is
        // pulled to both ogi (self) and chess (Bob's opponent): conflict.
        let a = oc(
            &s.alice,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc()],
        );
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("opponent", "chess"), tc()],
        );
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::VariantConflict)
        );
    }

    #[test]
    fn incompatible_same_signer() {
        let s = stage();
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let facts = MockFacts::new(&s.alice, &s.alice);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::SameSigner)
        );
    }

    #[test]
    fn matchmaker_mismatch() {
        let s = stage();
        let other_mm = Keys::generate();
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b = oc(&s.bob, &other_mm, &s.arb, &s.ts, vec![game(), tc()]);
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::MatchmakerMismatch)
        );
    }

    #[test]
    fn arbiter_and_timestamper_mismatch() {
        let s = stage();
        let other = Keys::generate();
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b_arb = oc(&s.bob, &s.mm, &other, &s.ts, vec![game(), tc()]);
        let b_ts = oc(&s.bob, &s.mm, &s.arb, &other, vec![game(), tc()]);
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b_arb, &facts),
            Compatibility::Incompatible(Incompatibility::ArbiterMismatch)
        );
        assert_eq!(
            evaluate(&a, &b_ts, &facts),
            Compatibility::Incompatible(Incompatibility::TimestamperMismatch)
        );
    }

    #[test]
    fn game_mismatch() {
        let s = stage();
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![Tag::parse(["game", "chess"]).unwrap(), tc()],
        );
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::GameMismatch)
        );
    }

    #[test]
    fn time_control_mismatch() {
        let s = stage();
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), Tag::parse(["time_control", "180", "2"]).unwrap()],
        );
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::TimeControlMismatch)
        );
    }

    #[test]
    fn following_filter_satisfied_and_rejected() {
        let s = stage();
        // Bob only pairs with players he follows.
        let a = oc(
            &s.alice,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc()],
        );
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![
                game(),
                variant("self", "ogi"),
                tc(),
                Tag::parse(["filter", "following"]).unwrap(),
            ],
        );

        let mut facts = MockFacts::new(&s.alice, &s.bob);
        facts.b_follows_a = true;
        assert!(matches!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible { .. }
        ));

        facts.b_follows_a = false;
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::FilterRejected)
        );
    }

    #[test]
    fn rating_filter_satisfied_and_rejected() {
        let s = stage();
        let a = oc(
            &s.alice,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc()],
        );
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc(), rating_filter("200")],
        );

        let mut facts = MockFacts::new(&s.alice, &s.bob);
        facts.rating_ok = true;
        assert!(matches!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible { .. }
        ));

        facts.rating_ok = false;
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::FilterRejected)
        );
    }

    #[test]
    fn rating_filter_needs_resolved_variant() {
        let s = stage();
        // Bob filters by rating but Alice's variant is free (unconstrained), so
        // her rating's (game, variant) cannot be determined.
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc(), rating_filter("200")],
        );
        let mut facts = MockFacts::new(&s.alice, &s.bob);
        facts.rating_ok = true;
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::RatingNeedsResolvedVariant)
        );
    }

    #[test]
    fn rating_filter_needs_same_variant() {
        let s = stage();
        // Both variants are resolved but differ (ogi vs chess): a multi-variant
        // pairing has no shared rating pool, so a rating filter cannot apply.
        let a = oc(
            &s.alice,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "chess"), tc()],
        );
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), variant("self", "ogi"), tc(), rating_filter("200")],
        );
        let mut facts = MockFacts::new(&s.alice, &s.bob);
        facts.rating_ok = true;
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::RatingNeedsSameVariant)
        );
    }
}
