# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not via public issues.

- Preferred: open a private advisory through GitHub's
  [private vulnerability reporting](https://github.com/sashite/nostchmaker.rs/security/advisories/new).
- Alternatively, contact the maintainers at the address listed on the
  repository.

Please include a description, affected versions, and a minimal reproduction
where possible. We aim to acknowledge a report within a few business days and to
coordinate a fix and disclosure timeline with you.

## Supported versions

The crate is pre-1.0. Security fixes target the latest published `0.x` release.

## Scope

This is a pure library with a deliberately small attack surface:

- It contains no `unsafe`, performs no network or filesystem I/O, and reads no
  clock.
- Its only untrusted-input path is **parsing an Open Challenge**
  (`open_challenge::OpenChallenge::parse`), which inspects already-parsed event
  fields and is written to be total (panic-free) on any input. Compatibility
  evaluation operates on those parsed values plus caller-supplied facts.

The following are **by design**, not vulnerabilities:

- A Pairing's authority depends on the consent constraints of the protocol and
  on trust in the designated matchmaker, arbiter, and timestamper. This crate
  implements the primitive only and makes no trustlessness claim; designating
  and trusting those parties is an application-layer concern.
- `parse` checks structural conformance, not the event's signature, and does
  not enforce the relay-advertised proof-of-work difficulty. Verifying
  signatures (`event.verify()`) and difficulty are the consumer's
  responsibility.
- Evaluating the `following` / `rating` filters relies on facts the consumer
  resolves (contact lists, ratings); the correctness of those facts is the
  consumer's responsibility.

Reports concerning the transitive dependency graph (for example a new RUSTSEC
advisory) are welcome; the graph is monitored in CI via `cargo-deny`.
