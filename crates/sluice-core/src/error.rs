//! The crate error type.

use thiserror::Error;

/// Errors produced by `sluice-core`.
#[derive(Debug, Error)]
pub enum Error {
    /// A value could not be encoded to CBOR.
    #[error("CBOR encode error: {0}")]
    Encode(String),
    /// CBOR bytes could not be decoded into the target type.
    #[error("CBOR decode error: {0}")]
    Decode(String),
}

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = std::result::Result<T, Error>;
