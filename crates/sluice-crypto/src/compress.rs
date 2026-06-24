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
/// zstd compression level (level 3 balances ratio and throughput).
const LEVEL: i32 = 3;

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

/// Compress `plaintext`, returning `[marker][payload]`.
///
/// Falls back to storing the bytes verbatim when zstd would not shrink them
/// (e.g. already-compressed media), so the output is never larger than
/// `plaintext.len() + 1`.
#[must_use]
pub fn compress(plaintext: &[u8]) -> Vec<u8> {
    if let Ok(compressed) = zstd::bulk::compress(plaintext, LEVEL) {
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
        let frame = compress(&data);
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
        let frame = compress(&data);
        assert_eq!(frame[0], RAW);
        assert_eq!(decompress(&frame).unwrap(), data);
    }

    #[test]
    fn empty_input_roundtrips() {
        let frame = compress(b"");
        assert_eq!(decompress(&frame).unwrap(), b"");
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert_eq!(decompress(&[]), Err(CompressError::Empty));
        assert_eq!(decompress(&[9, 1, 2, 3]), Err(CompressError::BadMarker(9)));
    }
}
