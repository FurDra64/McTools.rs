//! mctools-lib: port of McCrypt (C#) to Rust.
//!
//! Minecraft Bedrock marketplace content encryption/decryption library.
//!
//! Feature flags:
//! - `native` (default): enables filesystem-dependent modules (marketplace, config,
//!   manifest, pack_data) and `zip` support. Suitable for CLI use.
//! - Without `native`: only in-memory crypto primitives, key management, and
//!   header parsing. Suitable for WASM targets.

pub mod crypto;
pub mod header;
pub mod keys;
pub mod utils;

#[cfg(feature = "native")]
pub mod config;
#[cfg(feature = "native")]
pub mod manifest;
#[cfg(feature = "native")]
pub mod marketplace;
#[cfg(feature = "native")]
pub mod pack_data;
