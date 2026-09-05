// SPDX-License-Identifier: Apache-2.0

//! Parse a kind-`3417` **Rule System** event — the signed event naming, by
//! digest, the executable module a session's rules are (ADR-0034) — into a
//! typed [`RuleSystem`], checking its structural constraints (kind `3417`
//! §Semantic constraints). The matchmaker resolves each Open Challenge's
//! `rules` reference to one of these and cross-checks the `game`
//! ([`OpenChallenge::check_rule_system`](crate::open_challenge::OpenChallenge::check_rule_system)).
//!
//! What this module does **not** do: retrieve the module the event names,
//! verify its digest, or run it — a consumer's concerns (kind `3417`
//! §Retrieval and verification), outside a matchmaking primitive. The
//! proof-of-work difficulty is likewise enforced elsewhere; only the tag's
//! presence is checked here.

use core::fmt;

use nostr::event::{Event, EventId, Kind, Tag};
use nostr::key::PublicKey;

use crate::constants::{
    KIND_RULE_SYSTEM, TAG_ABI, TAG_EXPIRATION, TAG_GAME, TAG_NONCE, TAG_SOURCE, TAG_SPEC, TAG_URL,
    TAG_X,
};
use crate::open_challenge::is_lower_hex64;

/// A parsed, structurally valid Rule System event (kind `3417`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSystem {
    id: EventId,
    publisher: PublicKey,
    game: String,
    digest: String,
    abi: String,
    urls: Vec<String>,
    spec: Option<Spec>,
    source: Option<Source>,
    label: String,
}

/// The `spec` tag: the specification the module was built to (documentary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// The specification's SHA-256 digest.
    pub digest: String,
    /// A retrieval hint, if the tag carries one.
    pub url: Option<String>,
}

/// The `source` tag: the sources the module reproduces from (documentary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The repository URL.
    pub url: String,
    /// The commit or tag.
    pub commit: String,
}

impl RuleSystem {
    /// Parses and validates a kind-`3417` event.
    ///
    /// # Errors
    ///
    /// The first violated structural constraint, as a [`RuleSystemError`].
    pub fn parse(event: &Event) -> Result<Self, RuleSystemError> {
        if event.kind != Kind::Custom(KIND_RULE_SYSTEM) {
            return Err(RuleSystemError::WrongKind(event.kind.as_u16()));
        }
        let game = exactly_one(event, TAG_GAME)?;
        if !is_game_id(&game) {
            return Err(RuleSystemError::InvalidGameId(game));
        }
        let digest = exactly_one(event, TAG_X)?;
        if !is_lower_hex64(&digest) {
            return Err(RuleSystemError::InvalidDigest(digest));
        }
        let abi = exactly_one(event, TAG_ABI)?;
        if !is_abi_id(&abi) {
            return Err(RuleSystemError::InvalidAbiId(abi));
        }
        let urls: Vec<String> = values(event, TAG_URL)
            .into_iter()
            .map(|slice| slice.get(1).cloned().unwrap_or_default())
            .collect();
        if urls.iter().any(String::is_empty) {
            return Err(RuleSystemError::EmptyUrl);
        }
        let spec = match values(event, TAG_SPEC).as_slice() {
            [] => None,
            [slice] => {
                let digest = slice.get(1).cloned().unwrap_or_default();
                if !is_lower_hex64(&digest) {
                    return Err(RuleSystemError::InvalidSpecDigest(digest));
                }
                let url = slice.get(2).filter(|s| !s.is_empty()).cloned();
                Some(Spec { digest, url })
            }
            more => return Err(RuleSystemError::Multiple(TAG_SPEC, more.len())),
        };
        let source = match values(event, TAG_SOURCE).as_slice() {
            [] => None,
            [slice] => {
                let url = slice.get(1).cloned().unwrap_or_default();
                let commit = slice.get(2).cloned().unwrap_or_default();
                if url.is_empty() || commit.is_empty() {
                    return Err(RuleSystemError::MalformedSource);
                }
                Some(Source { url, commit })
            }
            more => return Err(RuleSystemError::Multiple(TAG_SOURCE, more.len())),
        };
        match values(event, TAG_NONCE).len() {
            0 => return Err(RuleSystemError::MissingNonce),
            1 => {}
            n => return Err(RuleSystemError::Multiple(TAG_NONCE, n)),
        }
        if !values(event, TAG_EXPIRATION).is_empty() {
            return Err(RuleSystemError::Expiration);
        }
        if !is_label(&event.content) {
            return Err(RuleSystemError::Content);
        }
        Ok(Self {
            id: event.id,
            publisher: event.pubkey,
            game,
            digest,
            abi,
            urls,
            spec,
            source,
            label: event.content.clone(),
        })
    }

    /// The event id — the identity of the rule system.
    #[must_use]
    pub fn id(&self) -> EventId {
        self.id
    }

    /// The publisher — the event's signer, the rule system's provenance.
    #[must_use]
    pub fn publisher(&self) -> PublicKey {
        self.publisher
    }

    /// The game the rule system implements.
    #[must_use]
    pub fn game(&self) -> &str {
        &self.game
    }

    /// The SHA-256 digest of the module's bytes (the `x` tag) — the identity
    /// of the rules' behavior.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The ABI identifier the module implements.
    #[must_use]
    pub fn abi(&self) -> &str {
        &self.abi
    }

    /// The retrieval hints, in tag order.
    #[must_use]
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// The `spec` tag, if carried.
    #[must_use]
    pub fn spec(&self) -> Option<&Spec> {
        self.spec.as_ref()
    }

    /// The `source` tag, if carried.
    #[must_use]
    pub fn source(&self) -> Option<&Source> {
        self.source.as_ref()
    }

    /// The event's `content`: a human-readable label, non-normative.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// A reason a Nostr event is not a conforming Rule System (kind `3417`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleSystemError {
    /// The event kind is not [`KIND_RULE_SYSTEM`]. Carries the observed kind.
    WrongKind(u16),
    /// A tag that must appear exactly once is absent. Carries the tag name.
    Missing(&'static str),
    /// A tag that must appear at most once appears more. Carries the tag name
    /// and the count.
    Multiple(&'static str, usize),
    /// The `game` identifier is malformed (not `^[a-z][a-z0-9]{0,31}$`).
    InvalidGameId(String),
    /// The `x` digest is not 64 lowercase hex digits.
    InvalidDigest(String),
    /// The `abi` identifier is empty, longer than 64 characters, or not
    /// printable ASCII without whitespace.
    InvalidAbiId(String),
    /// A `url` tag carries no value.
    EmptyUrl,
    /// The `spec` digest is not 64 lowercase hex digits.
    InvalidSpecDigest(String),
    /// The `source` tag lacks its URL or its commit.
    MalformedSource,
    /// No `nonce` tag is present.
    MissingNonce,
    /// The event carries a NIP-40 `expiration` tag, which kind `3417` forbids.
    Expiration,
    /// The `content` field violates kind `3417` §Content: longer than 4096
    /// bytes, or carrying a control, bidirectional-override or directional
    /// isolate character.
    Content,
}

impl fmt::Display for RuleSystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind(kind) => {
                write!(
                    f,
                    "wrong event kind: expected {KIND_RULE_SYSTEM}, found {kind}"
                )
            }
            Self::Missing(tag) => write!(f, "missing the required `{tag}` tag"),
            Self::Multiple(tag, count) => write!(f, "multiple `{tag}` tags ({count})"),
            Self::InvalidGameId(value) => write!(f, "invalid game identifier: {value:?}"),
            Self::InvalidDigest(value) => {
                write!(
                    f,
                    "invalid `x` digest: {value:?} (expected 64 lowercase hex digits)"
                )
            }
            Self::InvalidAbiId(value) => write!(f, "invalid `abi` identifier: {value:?}"),
            Self::EmptyUrl => f.write_str("a `url` tag carries no value"),
            Self::InvalidSpecDigest(value) => {
                write!(
                    f,
                    "invalid `spec` digest: {value:?} (expected 64 lowercase hex digits)"
                )
            }
            Self::MalformedSource => f.write_str("the `source` tag lacks its URL or its commit"),
            Self::MissingNonce => f.write_str("missing the required `nonce` tag"),
            Self::Expiration => {
                f.write_str("a Rule System event MUST NOT carry an `expiration` tag (NIP-40)")
            }
            Self::Content => f.write_str(
                "the content exceeds 4096 bytes or carries a control, bidi or isolate character",
            ),
        }
    }
}

impl std::error::Error for RuleSystemError {}

/// Why an Open Challenge's rules reference does not resolve to the Rule
/// System event held (kind `3418` §Semantic constraints, item 9).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RulesError {
    /// The event held is not the one the reference names.
    WrongEvent {
        /// The id the challenge references.
        referenced: EventId,
        /// The id of the event held.
        held: EventId,
    },
    /// The Rule System's `game` differs from the challenge's.
    GameMismatch {
        /// The challenge's `game`.
        challenge: String,
        /// The Rule System's `game`.
        rule_system: String,
    },
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongEvent { referenced, held } => write!(
                f,
                "the rules reference names {referenced} but the Rule System held is {held}"
            ),
            Self::GameMismatch {
                challenge,
                rule_system,
            } => write!(
                f,
                "the challenge is for game {challenge:?} but the Rule System governs {rule_system:?}"
            ),
        }
    }
}

impl std::error::Error for RulesError {}

fn values<'a>(event: &'a Event, name: &str) -> Vec<&'a [String]> {
    event
        .tags
        .iter()
        .map(Tag::as_slice)
        .filter(|slice| slice.first().map(String::as_str) == Some(name))
        .collect()
}

fn exactly_one(event: &Event, name: &'static str) -> Result<String, RuleSystemError> {
    match values(event, name).as_slice() {
        [] => Err(RuleSystemError::Missing(name)),
        [slice] => Ok(slice.get(1).cloned().unwrap_or_default()),
        more => Err(RuleSystemError::Multiple(name, more.len())),
    }
}

/// The label's constraints (kind `3417` §Content): at most 4096 bytes, and no
/// C0 control but line feed and tab, no DEL or C1 control, no bidirectional
/// override (U+202A–U+202E) and no directional isolate (U+2066–U+2069). The
/// encoding is already valid UTF-8, the event having been parsed.
fn is_label(content: &str) -> bool {
    content.len() <= 4096
        && content.chars().all(|c| {
            !matches!(
                c,
                '\u{0000}'..='\u{0008}'
                    | '\u{000B}'
                    | '\u{000C}'
                    | '\u{000E}'..='\u{001F}'
                    | '\u{007F}'..='\u{009F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            )
        })
}

/// `^[a-z][a-z0-9]{0,31}$`
fn is_game_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 32
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A non-empty string of printable ASCII without whitespace, at most 64
/// characters (kind `3417` §The module).
fn is_abi_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use nostr::event::{EventBuilder, FinalizeEvent, Kind, Tag};
    use nostr::key::Keys;

    use super::{RuleSystem, RuleSystemError};
    use crate::constants::KIND_RULE_SYSTEM;

    const X: &str = "af46f5a0044a92fccad803db2891bd1a60b20f234dfd95b9946233457b33d5b2";
    const SPEC: &str = "7aeb3f6dfaf623bd71d829dbdf8d6f89c757b9b04fd98010111243089cf84682";

    fn tags() -> Vec<Tag> {
        vec![
            Tag::parse(["game", "sanki"]).unwrap(),
            Tag::parse(["x", X]).unwrap(),
            Tag::parse(["abi", "sashite.sanki.kernel-abi/1"]).unwrap(),
            Tag::parse(["url", &format!("https://blobs.sanki.app/{X}.wasm")]).unwrap(),
            Tag::parse(["spec", SPEC, "https://sashite.dev/rules/sanki/kernel/"]).unwrap(),
            Tag::parse([
                "source",
                "https://github.com/sashite/sashite-sanki-kernel-wasm.rs",
                "0123456789abcdef0123456789abcdef01234567",
            ])
            .unwrap(),
            Tag::parse(["nonce", "42", "20"]).unwrap(),
        ]
    }

    fn event(tags: Vec<Tag>) -> nostr::event::Event {
        let keys = Keys::generate();
        EventBuilder::new(
            Kind::Custom(KIND_RULE_SYSTEM),
            "Sanki — Sashité reference rules",
        )
        .tags(tags)
        .finalize(&keys)
        .unwrap()
    }

    #[test]
    fn parses_a_conforming_event() {
        let rs = RuleSystem::parse(&event(tags())).unwrap();
        assert_eq!(rs.game(), "sanki");
        assert_eq!(rs.digest(), X);
        assert_eq!(rs.abi(), "sashite.sanki.kernel-abi/1");
        assert_eq!(rs.urls().len(), 1);
        assert_eq!(rs.spec().unwrap().digest, SPEC);
        assert_eq!(
            rs.spec().unwrap().url.as_deref(),
            Some("https://sashite.dev/rules/sanki/kernel/")
        );
        assert_eq!(
            rs.source().unwrap().commit,
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(rs.label(), "Sanki — Sashité reference rules");
    }

    #[test]
    fn refuses_the_structural_violations() {
        let drop = |name: &str| {
            let mut t = tags();
            t.retain(|tag| tag.as_slice().first().map(String::as_str) != Some(name));
            t
        };
        assert_eq!(
            RuleSystem::parse(&event(drop("game"))),
            Err(RuleSystemError::Missing("game"))
        );
        assert_eq!(
            RuleSystem::parse(&event(drop("x"))),
            Err(RuleSystemError::Missing("x"))
        );
        assert_eq!(
            RuleSystem::parse(&event(drop("abi"))),
            Err(RuleSystemError::Missing("abi"))
        );
        assert_eq!(
            RuleSystem::parse(&event(drop("nonce"))),
            Err(RuleSystemError::MissingNonce)
        );
        // Documentary tags are optional.
        assert!(RuleSystem::parse(&event(drop("spec")))
            .unwrap()
            .spec()
            .is_none());
        assert!(RuleSystem::parse(&event(drop("source")))
            .unwrap()
            .source()
            .is_none());
        assert!(RuleSystem::parse(&event(drop("url")))
            .unwrap()
            .urls()
            .is_empty());

        let mut twice = tags();
        twice.push(Tag::parse(["x", X]).unwrap());
        assert_eq!(
            RuleSystem::parse(&event(twice)),
            Err(RuleSystemError::Multiple("x", 2))
        );

        let mut upper = drop("x");
        upper.push(Tag::parse(["x", &X.to_uppercase()]).unwrap());
        assert!(matches!(
            RuleSystem::parse(&event(upper)),
            Err(RuleSystemError::InvalidDigest(_))
        ));

        let mut bad_abi = drop("abi");
        bad_abi.push(Tag::parse(["abi", "has a space"]).unwrap());
        assert!(matches!(
            RuleSystem::parse(&event(bad_abi)),
            Err(RuleSystemError::InvalidAbiId(_))
        ));

        let mut expiring = tags();
        expiring.push(Tag::parse(["expiration", "1900000000"]).unwrap());
        assert_eq!(
            RuleSystem::parse(&event(expiring)),
            Err(RuleSystemError::Expiration)
        );

        let mut bad_source = drop("source");
        bad_source.push(Tag::parse(["source", "https://example.com/repo"]).unwrap());
        assert_eq!(
            RuleSystem::parse(&event(bad_source)),
            Err(RuleSystemError::MalformedSource)
        );

        for bad in [
            "a\u{202E}b",
            "tab\tand\u{0007}bell",
            "\u{2066}x",
            &"é".repeat(2049),
        ] {
            let e = EventBuilder::new(Kind::Custom(KIND_RULE_SYSTEM), bad)
                .tags(tags())
                .finalize(&Keys::generate())
                .unwrap();
            assert_eq!(
                RuleSystem::parse(&e),
                Err(RuleSystemError::Content),
                "{bad:?}"
            );
        }
        let fine = EventBuilder::new(Kind::Custom(KIND_RULE_SYSTEM), "Sanki\nv1\t— notes")
            .tags(tags())
            .finalize(&Keys::generate())
            .unwrap();
        assert!(RuleSystem::parse(&fine).is_ok());

        let wrong_kind = EventBuilder::new(Kind::Custom(3418), "")
            .tags(tags())
            .finalize(&Keys::generate())
            .unwrap();
        assert_eq!(
            RuleSystem::parse(&wrong_kind),
            Err(RuleSystemError::WrongKind(3418))
        );
    }
}
