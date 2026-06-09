// SPDX-License-Identifier: Apache-2.0

//! Matchmaking primitive for Nostr — pairing **Open Challenges** (kind `6418`)
//! into **Pairings** (kind `6419`) for turn-based, two-player abstract strategy
//! board games of the chess family.
//!
//! **Status — proposed NIP.** The kinds `6418` / `6419` belong to a NIP suite
//! that is still a draft; the kind numbers and wire format may change. Pin an
//! exact version and review the suite before relying on it in production.
//!
//! This crate implements the **primitive only**, and is **game-agnostic**: it
//! parses and validates Open Challenges, decides whether two are compatible —
//! given externally resolved facts (the follow relation, a rating delta, a
//! mutual-block status) — resolves each player's variant, and builds the
//! resulting Pairing. It is deliberately silent on transport and storage, and
//! on *which* game or third parties an application designates; those are a
//! higher layer's concern (e.g. a matchmaker service).
//!
//! The modules mirror that pipeline:
//! - [`constants`] — the suite's kind numbers, tag names, and marker strings.
//! - [`error`] — parse and validation error types.
//! - [`open_challenge`] — parse a kind-`6418` event into a typed Open Challenge.
//! - [`compatibility`] — decide pairability and resolve each player's variant.
//! - [`pairing`] — build the kind-`6419` Pairing.

pub mod compatibility;
pub mod constants;
pub mod error;
pub mod open_challenge;
pub mod pairing;
