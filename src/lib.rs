// SPDX-License-Identifier: Apache-2.0

//! Matchmaking primitive for Nostr — pairing **Open Challenges** (kind `3418`)
//! into **Pairings** (kind `3419`) for turn-based, two-player abstract strategy
//! board games of the chess family.
//!
//! **Status — proposed NIP.** The kinds `3418` / `3419` belong to a NIP suite
//! that is still a draft; the kind numbers and wire format may change. Pin an
//! exact version and review the suite before relying on it in production.
//!
//! This crate implements the **primitive only**, and is **game-agnostic**: it
//! parses and validates Open Challenges, decides whether two are compatible —
//! given externally resolved facts (the follow relation, a rating comparison)
//! — resolves each player's variant, and builds the resulting Pairing with
//! what the matchmaker itself resolves (the variants, the seat draw, the
//! founding window). It is deliberately silent on transport and storage, on
//! randomness (the seat draw is the caller's), and on *which* game, rule-system
//! document or third parties an application designates; those are a higher
//! layer's concern (e.g. a matchmaker service). The suite designates no
//! arbiter (ADR-0033): the Pairing binds two players and a timing designation,
//! and either player founds the session.
//!
//! The modules mirror that pipeline:
//! - [`constants`] — the suite's kind numbers, tag names, and marker strings.
//! - [`error`] — parse and validation error types.
//! - [`open_challenge`] — parse a kind-`3418` event into a typed Open Challenge.
//! - [`compatibility`] — decide pairability and resolve each player's variant.
//! - [`pairing`] — build the kind-`3419` Pairing.

pub mod compatibility;
pub mod constants;
pub mod error;
pub mod open_challenge;
pub mod pairing;
