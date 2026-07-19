//! AgentWall FR-23 dashboard wire-boundary types.
//!
//! This crate defines the ONLY shape in which data may cross from the gateway
//! process into `dashboard-api`. The type system enforces AC-23.10: because
//! [`RedactedEvent`], [`RedactedAlert`], and [`SanitizedCredentialMeta`] have
//! no fields that accept raw secret material, no code path — anywhere in the
//! workspace or downstream — can serialize such material into the wire format.
//!
//! # Guarantee
//! - Raw DLP match content is not representable. Only the [`SecretCategory`]
//!   discriminant, the pattern name (a static regex label), and a match
//!   count cross the boundary.
//! - Raw tool-call parameters are not representable. No field of
//!   [`RedactedEvent`] accepts them.
//! - Raw response bodies are not representable. Only structured findings
//!   cross the boundary.
//! - Credential values are not representable. Only [`SanitizedCredentialMeta`]
//!   (opaque credential id + scope/TTL/rotation history) crosses.
//!
//! # Where redaction happens
//! Inside the gateway, at serialization time, via [`redact::redact_event`].
//! The gateway calls this function before POSTing to `dashboard-api`. There
//! is no code path that produces a [`RedactedEvent`] that bypasses it,
//! because [`RedactedEvent`]'s fields are only reachable through this path.
//!
//! # AC-23.10 test
//! See `tests.rs` — for every [`SecretCategory`] variant, a fake secret is
//! seeded into every raw field that could plausibly carry hostile input; the
//! serialized [`RedactedEvent`] is then asserted to contain none of it.
//!
//! # Dependency direction
//! `dashboard-proto` depends on nothing in the gateway crate. The gateway
//! depends on `dashboard-proto` (one-way). This keeps this crate reusable
//! from a Rust `dashboard-api` and easy to emit JSON schema from for a Go
//! `dashboard-api`.

pub mod event;
pub mod alert;
pub mod credential;
pub mod redact;

pub use event::{
    RedactedDecision, RedactedDlpFinding, RedactedEvent, RedactedInjectionFinding,
    RedactedSemanticFinding, SecretCategory, SemanticFindingType,
};
pub use alert::{AlertSeverity, RedactedAlert};
pub use credential::{RotationReason, RotationRecord, SanitizedCredentialMeta};
pub use redact::{
    redact_event, RawDecision, RawDlpFinding, RawEventForRedaction, RawInjectionFinding,
    RawSemanticFinding,
};

#[cfg(test)]
mod tests;
