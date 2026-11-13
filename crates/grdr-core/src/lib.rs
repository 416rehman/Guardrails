//! The pure, deterministic core: events and a verified bundle in, verdicts and findings out.
#![deny(clippy::arithmetic_side_effects)]

pub mod analyze;
pub mod compile;
pub mod detect;
pub mod discover;
pub mod policy;
pub mod session;
