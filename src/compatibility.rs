// SPDX-License-Identifier: Apache-2.0

//! Decide whether two [`OpenChallenge`]s can be paired, and resolve each
//! player's variant.
//!
//! [`evaluate`] encodes the consent constraints of kind `3419` that are
//! decidable from the two challenges plus externally resolved [`Facts`]:
//! distinct signers (constraint 1), a common matchmaker / arbiter / timestamper
//! (constraints 2, 4, 5), a common game (6), an identical time control (8), a
//! satisfiable variant resolution (7), and each player satisfying the other's
//! `filter` (9). For the `rating` mode, the comparison pool follows the pinned
//! authority's published [`PoolPolicy`]: per-(game, variant) — satisfiable only
//! by a same-variant pairing; per-game — binding across any variant
//! combination.
//!
//! It is **silent** on the rest, which a higher layer enforces: the
//! accept-deadline (constraint 10, a timing decision anchored on the Pairing's
//! attestation), the Pairing event's own shape (constraints 3, 11, 12, checked
//! when validating a built Pairing), and any operational policy such as a game
//! allow-list or NIP-51 mute lists. Constraint 11 (the matchmaker differs from
//! both players) follows from constraint 2 together with kind `3418`'s own
//! constraint 1, so it is not re-checked here.

use nostr::key::PublicKey;

use crate::open_challenge::{Filter, OpenChallenge, RatingKind};

/// The pool policy a rating authority publishes for its attestations — how its
/// ratings are scoped (see the rating specifications §Rating pool).
///
/// The `rating` filter's comparison pool follows the **pinned authority's**
/// published policy (kind `3419` §Consent constraints): pinning a source
/// implies adopting its pool semantics. The policy determines whether a
/// `rating` filter can bind a multi-variant or variant-free pairing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolPolicy {
    /// Ratings live in per-(game, variant) pools — the rating specifications'
    /// default. A `rating` filter is then satisfiable only by a same-variant
    /// pairing (a multi-variant session has no shared pool to compare in).
    PerGameVariant,
    /// Ratings live in one per-game pool unifying the game's variants (e.g.
    /// Sashité's `sanki` authority). A `rating` filter then binds across any
    /// variant combination — resolved, differing, or left free.
    PerGame,
}

/// The pool a rating comparison is performed in, as passed to
/// [`Facts::rating_within`]. Borrows from the challenges being evaluated, and
/// is always consistent with the [`PoolPolicy`] the implementer reported for
/// the pinned source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatingPool<'a> {
    /// The single per-game pool: the game alone identifies it.
    PerGame {
        /// The game identifier shared by the two Open Challenges.
        game: &'a str,
    },
    /// A per-(game, variant) pool.
    PerGameVariant {
        /// The game identifier shared by the two Open Challenges.
        game: &'a str,
        /// The shared variant of the (necessarily same-variant) pairing.
        variant: &'a str,
    },
}

/// External, relay-derived facts needed to evaluate the `following` and
/// `rating` filters. A consumer (e.g. a matchmaker service) implements this by
/// reading NIP-02 contact lists, the pinned rating authorities' published pool
/// policies, and the suite's rating attestations; the primitive itself performs
/// no I/O.
///
/// The relation queries are **anchored at the Pairing's canonical timing** by
/// contract (kind `3419` §Consent constraints; [Race Resolution] §Canonical
/// timing): the implementer evaluates the follow relation against the
/// filterer's contact list as it stood at the anchor, and a rating against the
/// most recent attestation by the pinned authority with `created_at` at or
/// before the anchor. The primitive does not see the anchor; threading it is
/// the implementer's responsibility.
///
/// [Race Resolution]: https://github.com/sashite/web-specs.md
pub trait Facts {
    /// Whether `follower` follows `target`, per `follower`'s NIP-02 contact list.
    fn follows(&self, follower: &PublicKey, target: &PublicKey) -> bool;

    /// The pool policy published by `authority` for its `kind` attestations, or
    /// `None` when the implementer cannot determine it.
    ///
    /// The policy is published out of band by the rating authority (see the
    /// rating specifications §Rating pool); it is a property of the pinned
    /// source, not of any event. When it is unknown, returning `None` makes
    /// [`evaluate`] reject the pair
    /// ([`Incompatibility::UnknownRatingPoolPolicy`], fail-closed) rather than
    /// guess a pool the authority does not use — a Pairing built on the wrong
    /// pool would be non-conforming for every verifier that knows the policy.
    fn pool_policy(&self, authority: &PublicKey, kind: RatingKind) -> Option<PoolPolicy>;

    /// Whether `a` and `b` are within `max_delta` rating points in `pool`, as
    /// rated by the pinned `authority` under the pinned `kind`. Both players
    /// are rated in the **same** pool, which [`evaluate`] derives from the
    /// policy this trait reported for `(authority, kind)`. A player with no
    /// qualifying attestation from `authority` in `pool` is unrated; the
    /// implementer returns `false` (fail-closed).
    fn rating_within(
        &self,
        authority: &PublicKey,
        kind: RatingKind,
        pool: RatingPool<'_>,
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
    /// A `rating` filter applies under a **per-(game, variant)** pool policy but
    /// the relevant variant is unresolved (free), so no pool can be determined;
    /// the pair is conservatively rejected. (Under a per-game policy this cannot
    /// occur: the game pool needs no variant.)
    RatingNeedsResolvedVariant,
    /// A `rating` filter applies under a **per-(game, variant)** pool policy but
    /// the two players' resolved variants differ: a multi-variant pairing has no
    /// shared per-variant pool to compare in, so the pair is rejected (kind
    /// `3419` §Consent constraints). (Under a per-game policy the single game
    /// pool is shared regardless of the variants.)
    RatingNeedsSameVariant,
    /// A `rating` filter applies but the pinned authority's pool policy is
    /// unknown ([`Facts::pool_policy`] returned `None`), so the comparison pool
    /// cannot be determined; the pair is conservatively rejected (fail-closed).
    UnknownRatingPoolPolicy,
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
/// variants (consulted only by the `rating` mode, and only when the pinned
/// authority pools per-(game, variant)).
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
        } => {
            // The comparison pool follows the pinned authority's published pool
            // policy (kind `3419` §Consent constraints): per-game — the single
            // game pool, whatever the variants; per-(game, variant) — the shared
            // variant's pool, which requires a same-variant resolution. An
            // unknown policy is fail-closed.
            let Some(policy) = facts.pool_policy(&authority, kind) else {
                return Err(Incompatibility::UnknownRatingPoolPolicy);
            };
            let pool = match policy {
                PoolPolicy::PerGame => RatingPool::PerGame { game },
                PoolPolicy::PerGameVariant => match (filterer_variant, other_variant) {
                    (Some(fv), Some(ov)) if fv != ov => {
                        return Err(Incompatibility::RatingNeedsSameVariant);
                    }
                    (Some(variant), Some(_)) => RatingPool::PerGameVariant { game, variant },
                    _ => return Err(Incompatibility::RatingNeedsResolvedVariant),
                },
            };
            if facts.rating_within(&authority, kind, pool, filterer, other, max_delta) {
                Ok(())
            } else {
                Err(Incompatibility::FilterRejected)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{evaluate, Compatibility, Facts, Incompatibility, PoolPolicy, RatingPool};
    use crate::open_challenge::{OpenChallenge, RatingKind};
    use nostr::prelude::*;

    /// A mock of the external facts, parameterized by the two players.
    ///
    /// `expected_pool` (when set) makes `rating_within` answer positively only
    /// for that exact pool, proving [`evaluate`] derived the pool the policy
    /// mandates. `(game, None)` is the per-game pool; `(game, Some(variant))`
    /// the per-(game, variant) pool.
    struct MockFacts {
        a: PublicKey,
        b: PublicKey,
        a_follows_b: bool,
        b_follows_a: bool,
        rating_ok: bool,
        policy: Option<PoolPolicy>,
        expected_pool: Option<(String, Option<String>)>,
    }

    impl MockFacts {
        fn new(a: &Keys, b: &Keys) -> Self {
            Self {
                a: a.public_key(),
                b: b.public_key(),
                a_follows_b: false,
                b_follows_a: false,
                rating_ok: false,
                policy: Some(PoolPolicy::PerGameVariant),
                expected_pool: None,
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

        fn pool_policy(&self, _authority: &PublicKey, _kind: RatingKind) -> Option<PoolPolicy> {
            self.policy
        }

        fn rating_within(
            &self,
            _authority: &PublicKey,
            _kind: RatingKind,
            pool: RatingPool<'_>,
            _a: &PublicKey,
            _b: &PublicKey,
            _max_delta: u16,
        ) -> bool {
            if let Some((game, variant)) = &self.expected_pool {
                let matches = match pool {
                    RatingPool::PerGame { game: g } => g == game && variant.is_none(),
                    RatingPool::PerGameVariant {
                        game: g,
                        variant: v,
                    } => g == game && variant.as_deref() == Some(v),
                };
                if !matches {
                    return false;
                }
            }
            self.rating_ok
        }
    }

    /// A `rating` filter tag pinning a fresh authority (Glicko-2).
    fn rating_filter(max_delta: &str) -> Tag {
        let authority = Keys::generate().public_key().to_hex();
        Tag::parse(["filter", "rating", max_delta, &authority, "3427"]).unwrap()
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
        let event = EventBuilder::new(Kind::Custom(3418), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(1000))
            .finalize(signer)
            .unwrap();
        OpenChallenge::parse(&event).unwrap()
    }

    /// Like [`oc`], but designates NO timestamper — a self-timed challenge.
    fn oc_self_timed(
        signer: &Keys,
        matchmaker: &Keys,
        arbiter: &Keys,
        terms: Vec<Tag>,
    ) -> OpenChallenge {
        let mut tags = vec![p(matchmaker, "matchmaker"), p(arbiter, "arbiter")];
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
    fn compatible_when_both_self_timed() {
        // Two challenges that both designate no timestamper agree on timing
        // (self-timed) and pair — attestation being a dormant capability.
        let s = stage();
        let a = oc_self_timed(&s.alice, &s.mm, &s.arb, vec![game(), tc()]);
        let b = oc_self_timed(&s.bob, &s.mm, &s.arb, vec![game(), tc()]);
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert!(matches!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible { .. }
        ));
    }

    #[test]
    fn incompatible_when_one_self_timed_one_attested() {
        // A self-timed challenge and an attested one disagree on timing mode and
        // cannot be paired (Some vs None is a timestamper mismatch).
        let s = stage();
        let attested = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let self_timed = oc_self_timed(&s.bob, &s.mm, &s.arb, vec![game(), tc()]);
        let facts = MockFacts::new(&s.alice, &s.bob);
        assert_eq!(
            evaluate(&attested, &self_timed, &facts),
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
        // Under the per-(game, variant) policy the comparison pool is the shared
        // variant's pool; a positive answer for any other pool would be a bug.
        facts.expected_pool = Some(("sanki".to_string(), Some("ogi".to_string())));
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
    fn rating_filter_needs_resolved_variant_under_per_variant_pool() {
        let s = stage();
        // Bob filters by rating and the pinned authority pools per-(game, variant),
        // but Alice's variant is free (unconstrained): no pool can be determined.
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
    fn rating_filter_needs_same_variant_under_per_variant_pool() {
        let s = stage();
        // Both variants are resolved but differ (ogi vs chess): under the
        // per-(game, variant) policy a multi-variant pairing has no shared
        // rating pool, so the filter cannot apply.
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

    #[test]
    fn rating_filter_binds_cross_variant_under_per_game_pool() {
        let s = stage();
        // The pinned authority pools per-game (e.g. Sashité's `sanki`): the
        // rating filter binds a multi-variant pairing, compared in the single
        // game pool.
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
        facts.policy = Some(PoolPolicy::PerGame);
        facts.rating_ok = true;
        facts.expected_pool = Some(("sanki".to_string(), None));
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible {
                a_variant: Some("chess".to_string()),
                b_variant: Some("ogi".to_string()),
            }
        );

        facts.rating_ok = false;
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::FilterRejected)
        );
    }

    #[test]
    fn rating_filter_evaluable_with_free_variants_under_per_game_pool() {
        let s = stage();
        // Under a per-game pool, even fully free variants (the matchmaker's later
        // choice) do not block the rating filter: the game pool needs no variant.
        let a = oc(&s.alice, &s.mm, &s.arb, &s.ts, vec![game(), tc()]);
        let b = oc(
            &s.bob,
            &s.mm,
            &s.arb,
            &s.ts,
            vec![game(), tc(), rating_filter("200")],
        );
        let mut facts = MockFacts::new(&s.alice, &s.bob);
        facts.policy = Some(PoolPolicy::PerGame);
        facts.rating_ok = true;
        facts.expected_pool = Some(("sanki".to_string(), None));
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Compatible {
                a_variant: None,
                b_variant: None,
            }
        );
    }

    #[test]
    fn rating_filter_fails_closed_on_unknown_pool_policy() {
        let s = stage();
        // The implementer cannot determine the pinned authority's pool policy:
        // the pair is rejected rather than evaluated against a guessed pool.
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
        facts.policy = None;
        facts.rating_ok = true;
        assert_eq!(
            evaluate(&a, &b, &facts),
            Compatibility::Incompatible(Incompatibility::UnknownRatingPoolPolicy)
        );
    }
}
