//! Content-address identifiers.

use std::fmt;
use std::str::FromStr;

/// A 256-bit content address — the BLAKE3 hash that names a blob, pack, tree, or
/// snapshot object in a repository (see `DESIGN.md` §3).
///
/// `Id` is an opaque 32-byte value with a lowercase-hex textual form. Ordering is
/// lexicographic over the raw bytes, which matches the sorted on-disk index
/// segment layout.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id([u8; Self::LEN]);

impl Id {
    /// Length of an `Id` in bytes.
    pub const LEN: usize = 32;

    /// Wrap raw bytes as an `Id`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes of this `Id`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Render as a 64-character lowercase-hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(Self::LEN * 2);
        for &b in &self.0 {
            s.push(nibble(b >> 4));
            s.push(nibble(b & 0x0f));
        }
        s
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A short prefix keeps logs readable; full value via `Display`.
        let hex = self.to_hex();
        write!(f, "Id({}…)", &hex[..8])
    }
}

impl FromStr for Id {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != Self::LEN * 2 {
            return Err(IdParseError::BadLength { found: bytes.len() });
        }
        let mut out = [0u8; Self::LEN];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = unhex(pair[0]).ok_or(IdParseError::BadDigit { at: i * 2 })?;
            let lo = unhex(pair[1]).ok_or(IdParseError::BadDigit { at: i * 2 + 1 })?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

/// Error returned when parsing an [`Id`] from its hex form fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdParseError {
    /// The input was not exactly `2 * Id::LEN` characters long.
    BadLength {
        /// The number of characters actually supplied.
        found: usize,
    },
    /// The input contained a character that is not a hex digit.
    BadDigit {
        /// The byte offset of the offending character.
        at: usize,
    },
}

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { found } => {
                write!(f, "expected {} hex characters, found {found}", Id::LEN * 2)
            }
            Self::BadDigit { at } => write!(f, "invalid hex digit at position {at}"),
        }
    }
}

impl std::error::Error for IdParseError {}

const fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

const fn unhex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let id = Id::from_bytes([0xab; Id::LEN]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "ab".repeat(32));
        assert_eq!(Id::from_str(&hex).unwrap(), id);
    }

    #[test]
    fn display_is_full_lowercase_hex() {
        assert_eq!(Id::from_bytes([0x00; Id::LEN]).to_string(), "0".repeat(64));
        assert_eq!(Id::from_bytes([0xff; Id::LEN]).to_string(), "f".repeat(64));
    }

    #[test]
    fn parse_accepts_uppercase() {
        let lower = "ab".repeat(32);
        let upper = "AB".repeat(32);
        assert_eq!(Id::from_str(&upper).unwrap(), Id::from_str(&lower).unwrap());
    }

    #[test]
    fn parse_rejects_bad_length() {
        assert_eq!(
            Id::from_str("abcd"),
            Err(IdParseError::BadLength { found: 4 })
        );
    }

    #[test]
    fn parse_rejects_bad_digit() {
        let mut s = "0".repeat(64);
        s.replace_range(10..11, "x");
        assert_eq!(Id::from_str(&s), Err(IdParseError::BadDigit { at: 10 }));
    }

    #[test]
    fn ordering_is_lexicographic_over_bytes() {
        let a = Id::from_bytes([0x00; Id::LEN]);
        let mut hi = [0x00; Id::LEN];
        hi[0] = 0x01;
        assert!(a < Id::from_bytes(hi));
    }

    #[test]
    fn debug_is_short_prefix() {
        let mut bytes = [0u8; Id::LEN];
        bytes[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(format!("{:?}", Id::from_bytes(bytes)), "Id(deadbeef…)");
    }
}
