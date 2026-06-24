//! Compression: zstd with skip-if-incompressible.
//!
//! Applied to a blob *before* encryption (compress-then-encrypt; each blob is an
//! independent zstd frame, so CRIME/BREACH-style attacks do not apply — see
//! `DESIGN.md` §5.3-§5.4). The output is framed with a one-byte marker so the
//! reader knows whether the payload is zstd-compressed or stored verbatim.

/// Marker: the payload is stored verbatim (compression did not help).
const RAW: u8 = 0;
/// Marker: the payload is a zstd frame.
const ZSTD: u8 = 1;
/// Default zstd level (3 balances ratio and throughput); used when a repository
/// records no level. The frame self-describes, so [`decompress`] needs no level.
pub const DEFAULT_LEVEL: i32 = 3;

/// Error reversing [`compress`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompressError {
    /// The frame was empty (no marker byte).
    #[error("empty compression frame")]
    Empty,
    /// The marker byte was not recognized.
    #[error("unknown compression marker {0}")]
    BadMarker(u8),
    /// The zstd payload could not be decoded.
    #[error("zstd decode error: {0}")]
    Zstd(String),
}

/// Compress `plaintext` at zstd `level`, returning `[marker][payload]`.
///
/// Falls back to storing the bytes verbatim when zstd would not shrink them
/// (e.g. already-compressed media) or when the level is rejected, so the output
/// is never larger than `plaintext.len() + 1`.
#[must_use]
pub fn compress(plaintext: &[u8], level: i32) -> Vec<u8> {
    if let Ok(compressed) = zstd::bulk::compress(plaintext, level) {
        if compressed.len() + 1 < plaintext.len() {
            let mut out = Vec::with_capacity(compressed.len() + 1);
            out.push(ZSTD);
            out.extend_from_slice(&compressed);
            return out;
        }
    }
    let mut out = Vec::with_capacity(plaintext.len() + 1);
    out.push(RAW);
    out.extend_from_slice(plaintext);
    out
}

/// Reverse [`compress`], recovering the original plaintext.
pub fn decompress(frame: &[u8]) -> Result<Vec<u8>, CompressError> {
    let (&marker, body) = frame.split_first().ok_or(CompressError::Empty)?;
    match marker {
        RAW => Ok(body.to_vec()),
        ZSTD => zstd::decode_all(body).map_err(|e| CompressError::Zstd(e.to_string())),
        other => Err(CompressError::BadMarker(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressible_data_shrinks_and_roundtrips() {
        let data = vec![0u8; 10_000];
        let frame = compress(&data, DEFAULT_LEVEL);
        assert_eq!(frame[0], ZSTD);
        assert!(frame.len() < data.len());
        assert_eq!(decompress(&frame).unwrap(), data);
    }

    #[test]
    fn incompressible_data_is_stored_raw() {
        let mut s = 0x9E37u64;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (s >> 33) as u8
            })
            .collect();
        let frame = compress(&data, DEFAULT_LEVEL);
        assert_eq!(frame[0], RAW);
        assert_eq!(decompress(&frame).unwrap(), data);
    }

    #[test]
    fn empty_input_roundtrips() {
        let frame = compress(b"", DEFAULT_LEVEL);
        assert_eq!(decompress(&frame).unwrap(), b"");
    }

    #[test]
    fn any_level_roundtrips_and_a_higher_level_is_no_larger() {
        // Repetitive-but-varied data so a higher level can find more.
        let mut data = Vec::new();
        for i in 0..20_000u32 {
            data.extend_from_slice(&(i % 97).to_le_bytes());
        }
        // Every frame decompresses regardless of the level it was written at.
        for level in [1, 3, 9, 19] {
            assert_eq!(decompress(&compress(&data, level)).unwrap(), data);
        }
        // A higher level should not produce a larger frame than a lower one.
        assert!(compress(&data, 19).len() <= compress(&data, 1).len());
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert_eq!(decompress(&[]), Err(CompressError::Empty));
        assert_eq!(decompress(&[9, 1, 2, 3]), Err(CompressError::BadMarker(9)));
    }
}
