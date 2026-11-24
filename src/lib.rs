//! `git-signet` — unified BLINCS self-certifying signet IDs and BLAKE3 tree/history binding for Git.
//!
//! **Pre-1.0 experimental software (unsupported):** formats, context strings, and CLI flags may
//! change incompatibly before 1.0, and no independent human cryptographic audit has been performed.

#![forbid(unsafe_code)]

pub mod blake3_chain;
pub mod git;
pub mod hooks;
pub mod id;
pub mod snapshot;
