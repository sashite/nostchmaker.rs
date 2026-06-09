// SPDX-License-Identifier: Apache-2.0

//! Errors from parsing a kind-`6418` event into an
//! [`OpenChallenge`](crate::open_challenge::OpenChallenge).
//!
//! Every variant is decidable from the event alone (kind `6418` §Semantic
//! constraints): no external event need be fetched.
//! [`OpenChallenge::parse`](crate::open_challenge::OpenChallenge::parse) returns
//! the first violated rule.

use core::fmt;

use crate::constants::KIND_OPEN_CHALLENGE;

/// A reason a Nostr event is not a conforming Open Challenge (kind `6418`).
///
/// Returned by [`OpenChallenge::parse`](crate::open_challenge::OpenChallenge::parse).
/// The enum is `#[non_exhaustive]`: future revisions may add variants without a
/// breaking change, so downstream `match` expressions should include a wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The event kind is not [`KIND_OPEN_CHALLENGE`]. Carries the observed kind.
    WrongKind(u16),
    /// The `content` field is not the empty string.
    NonEmptyContent,
    /// A required role `p` tag (`matchmaker`, `arbiter`, or `timestamper`) is
    /// absent. Carries the role marker.
    MissingRole(&'static str),
    /// A role marker appears on more than one `p` tag. Carries the role marker.
    DuplicateRole(&'static str),
    /// A role `p` tag's pubkey does not parse. Carries the role marker.
    InvalidRolePubkey(&'static str),
    /// A role pubkey equals the signer's; a designated party cannot be the
    /// signer. Carries the role marker.
    RoleEqualsSigner(&'static str),
    /// No `game` tag is present.
    MissingGame,
    /// More than one `game` tag is present. Carries the count.
    MultipleGames(usize),
    /// The `game` identifier is malformed (not `^[a-z][a-z0-9]{0,31}$`). Carries
    /// the offending value.
    InvalidGameId(String),
    /// A `variant` tag's role selector is neither `self` nor `opponent`. Carries
    /// the offending selector.
    InvalidVariantRole(String),
    /// Two `variant` tags target the same role. Carries the role selector.
    DuplicateVariantRole(&'static str),
    /// A `variant` identifier is malformed (not `^[a-z][a-z0-9]{0,31}$`). Carries
    /// the offending value.
    InvalidVariantId(String),
    /// No `time_control` tag is present.
    MissingTimeControl,
    /// A `time_control` tag is malformed (bad duration, increment, or plies, or
    /// plies without an increment).
    InvalidTimeControl,
    /// More than one `filter` tag is present. Carries the count.
    MultipleFilters(usize),
    /// A `filter` mode is not one of `everyone`, `following`, `rating`. Carries
    /// the offending mode.
    InvalidFilterMode(String),
    /// A `filter` tag is structurally wrong for its mode: a missing or malformed
    /// `rating` delta (not `^[1-9][0-9]{0,3}$`), or an extra value on
    /// `everyone` / `following`.
    MalformedFilter,
    /// No `accept_until` tag is present.
    MissingAcceptUntil,
    /// More than one `accept_until` tag is present. Carries the count.
    MultipleAcceptUntil(usize),
    /// The `accept_until` value is not a non-negative integer. Carries the value.
    InvalidAcceptUntil(String),
    /// `accept_until` is not strictly greater than the event's `created_at`.
    AcceptUntilNotAfterCreatedAt {
        /// The parsed `accept_until` value.
        accept_until: u64,
        /// The event's `created_at`.
        created_at: u64,
    },
    /// No `nonce` tag is present.
    MissingNonce,
    /// More than one `nonce` tag is present. Carries the count.
    MultipleNonces(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind(kind) => {
                write!(f, "wrong event kind: expected {KIND_OPEN_CHALLENGE}, found {kind}")
            }
            Self::NonEmptyContent => f.write_str("content must be the empty string"),
            Self::MissingRole(role) => write!(f, "missing the required `{role}` p tag"),
            Self::DuplicateRole(role) => write!(f, "more than one `{role}` p tag"),
            Self::InvalidRolePubkey(role) => write!(f, "the `{role}` p tag has an invalid pubkey"),
            Self::RoleEqualsSigner(role) => {
                write!(f, "the `{role}` pubkey must differ from the signer")
            }
            Self::MissingGame => f.write_str("missing the required `game` tag"),
            Self::MultipleGames(count) => write!(f, "expected exactly one `game` tag, found {count}"),
            Self::InvalidGameId(value) => write!(f, "invalid game identifier: {value:?}"),
            Self::InvalidVariantRole(role) => {
                write!(f, "invalid variant role selector: {role:?} (expected `self` or `opponent`)")
            }
            Self::DuplicateVariantRole(role) => write!(f, "more than one `{role}` variant tag"),
            Self::InvalidVariantId(value) => write!(f, "invalid variant identifier: {value:?}"),
            Self::MissingTimeControl => f.write_str("missing the required `time_control` tag"),
            Self::InvalidTimeControl => f.write_str("malformed `time_control` tag"),
            Self::MultipleFilters(count) => {
                write!(f, "expected at most one `filter` tag, found {count}")
            }
            Self::InvalidFilterMode(mode) => write!(f, "invalid filter mode: {mode:?}"),
            Self::MalformedFilter => f.write_str("malformed `filter` tag for its mode"),
            Self::MissingAcceptUntil => f.write_str("missing the required `accept_until` tag"),
            Self::MultipleAcceptUntil(count) => {
                write!(f, "expected exactly one `accept_until` tag, found {count}")
            }
            Self::InvalidAcceptUntil(value) => write!(f, "invalid `accept_until` value: {value:?}"),
            Self::AcceptUntilNotAfterCreatedAt {
                accept_until,
                created_at,
            } => write!(
                f,
                "`accept_until` ({accept_until}) must be strictly greater than `created_at` ({created_at})"
            ),
            Self::MissingNonce => f.write_str("missing the required `nonce` tag"),
            Self::MultipleNonces(count) => {
                write!(f, "expected exactly one `nonce` tag, found {count}")
            }
        }
    }
}

impl std::error::Error for ParseError {}
