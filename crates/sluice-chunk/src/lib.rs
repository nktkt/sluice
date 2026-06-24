//! `sluice-chunk` — FastCDC v2020 content-defined chunking.
//!
//! Splits a byte stream at content-defined boundaries so that local edits shift
//! only nearby boundaries and most chunks recur unchanged (the property that
//! makes deduplication effective). Implements normalized chunking with
//! cut-point skipping: no hash is evaluated before `min`, a stricter mask is
//! used in `[min, avg)` and a looser one in `[avg, max)`, with a hard cut at
//! `max`. See `DESIGN.md` §5.2.
//!
//! The gear table is currently seeded from a fixed constant (a public gear). A
//! key-derived gear that keeps chunk boundaries secret from an untrusted backend
//! lands at milestone M3.
#![forbid(unsafe_code)]

/// Normalization level (the FastCDC `NC` parameter): how many bits the strict
/// and loose masks differ from `log2(avg)`.
const NORMALIZATION: u32 = 2;

/// Default gear seed (a public, fixed value used until key-derived gears land).
const DEFAULT_GEAR_SEED: u64 = 0x5111_CE00_5EED_0001;

/// The 256-entry gear table mapping each input byte to a 64-bit value.
#[derive(Clone)]
pub struct Gear(pub [u64; 256]);

impl Gear {
    /// Build a gear table deterministically from `seed` using SplitMix64.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut state = seed;
        let mut table = [0u64; 256];
        for slot in &mut table {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            *slot = z;
        }
        Self(table)
    }

    /// Build a gear table from 32 seed bytes (the repository's `gear_seed`),
    /// folding them into a SplitMix64 seed.
    #[must_use]
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let mut state = 0u64;
        let mut i = 0;
        while i < seed.len() {
            let word = u64::from_le_bytes([
                seed[i],
                seed[i + 1],
                seed[i + 2],
                seed[i + 3],
                seed[i + 4],
                seed[i + 5],
                seed[i + 6],
                seed[i + 7],
            ]);
            state = (state ^ word).wrapping_mul(0x0000_0100_0000_01B3);
            i += 8;
        }
        Self::from_seed(state)
    }
}

impl Default for Gear {
    fn default() -> Self {
        Self::from_seed(DEFAULT_GEAR_SEED)
    }
}

/// Chunk-size parameters. `avg` must be a power of two and `min < avg < max`.
#[derive(Debug, Clone, Copy)]
pub struct ChunkerParams {
    /// Minimum chunk size; no boundary is emitted before this many bytes.
    pub min: usize,
    /// Target average chunk size (a power of two).
    pub avg: usize,
    /// Maximum chunk size; a boundary is forced here.
    pub max: usize,
}

impl Default for ChunkerParams {
    fn default() -> Self {
        Self {
            min: 256 * 1024,
            avg: 1024 * 1024,
            max: 4 * 1024 * 1024,
        }
    }
}

/// A FastCDC chunker: parameters plus a gear table and the two precomputed masks.
pub struct Chunker {
    params: ChunkerParams,
    gear: Gear,
    mask_s: u64,
    mask_l: u64,
}

impl Chunker {
    /// Create a chunker from `params` and a `gear` table.
    #[must_use]
    pub fn new(params: ChunkerParams, gear: Gear) -> Self {
        debug_assert!(params.avg.is_power_of_two(), "avg must be a power of two");
        debug_assert!(
            params.min < params.avg && params.avg < params.max,
            "require min < avg < max"
        );
        let bits = params.avg.trailing_zeros();
        Self {
            mask_s: high_bits_mask(bits + NORMALIZATION),
            mask_l: high_bits_mask(bits.saturating_sub(NORMALIZATION)),
            params,
            gear,
        }
    }

    /// The maximum chunk size: a boundary is forced once a chunk reaches it.
    /// Streaming callers buffer at least this many bytes before cutting, so the
    /// boundaries match whole-buffer chunking exactly.
    #[must_use]
    pub fn max(&self) -> usize {
        self.params.max
    }

    /// Length of the first content-defined chunk of `data`.
    ///
    /// The returned length is in `[min, max]` unless `data` is shorter than
    /// `min`, in which case the whole remainder is one (final) chunk.
    #[must_use]
    pub fn cut(&self, data: &[u8]) -> usize {
        let len = data.len();
        if len <= self.params.min {
            return len;
        }
        let mut hash = 0u64;
        let mut i = self.params.min;

        let strict_end = self.params.avg.min(len);
        while i < strict_end {
            hash = (hash << 1).wrapping_add(self.gear.0[data[i] as usize]);
            if (hash & self.mask_s) == 0 {
                return i + 1;
            }
            i += 1;
        }

        let loose_end = self.params.max.min(len);
        while i < loose_end {
            hash = (hash << 1).wrapping_add(self.gear.0[data[i] as usize]);
            if (hash & self.mask_l) == 0 {
                return i + 1;
            }
            i += 1;
        }
        loose_end
    }

    /// Iterate over the content-defined chunks of `data`.
    #[must_use]
    pub fn chunks<'d>(&self, data: &'d [u8]) -> Chunks<'_, 'd> {
        Chunks {
            chunker: self,
            data,
        }
    }
}

/// Iterator over the chunks of a byte slice; see [`Chunker::chunks`].
pub struct Chunks<'a, 'd> {
    chunker: &'a Chunker,
    data: &'d [u8],
}

impl<'d> Iterator for Chunks<'_, 'd> {
    type Item = &'d [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let n = self.chunker.cut(self.data);
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Some(head)
    }
}

/// A mask with the top `bits` bits set.
const fn high_bits_mask(bits: u32) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        u64::MAX << (64 - bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn gear_from_seed_bytes_is_deterministic_and_seed_sensitive() {
        assert_eq!(
            Gear::from_seed_bytes(&[1u8; 32]).0,
            Gear::from_seed_bytes(&[1u8; 32]).0
        );
        assert_ne!(
            Gear::from_seed_bytes(&[1u8; 32]).0,
            Gear::from_seed_bytes(&[2u8; 32]).0
        );
    }

    fn small() -> Chunker {
        Chunker::new(
            ChunkerParams {
                min: 64,
                avg: 256,
                max: 1024,
            },
            Gear::default(),
        )
    }

    /// Deterministic pseudo-random bytes (an LCG) for reproducible tests.
    fn data(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut s = 0x1234_5678u64;
        for _ in 0..n {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            v.push((s >> 33) as u8);
        }
        v
    }

    #[test]
    fn chunks_cover_input_exactly() {
        let d = data(100_000);
        let c = small();
        let mut reassembled = Vec::new();
        for ch in c.chunks(&d) {
            reassembled.extend_from_slice(ch);
        }
        assert_eq!(reassembled, d);
    }

    #[test]
    fn chunk_sizes_within_bounds() {
        let d = data(100_000);
        let c = small();
        let chunks: Vec<_> = c.chunks(&d).collect();
        for (i, ch) in chunks.iter().enumerate() {
            assert!(ch.len() <= 1024, "chunk exceeds max: {}", ch.len());
            if i + 1 < chunks.len() {
                assert!(ch.len() >= 64, "non-final chunk under min: {}", ch.len());
            }
        }
    }

    #[test]
    fn deterministic() {
        let d = data(50_000);
        let c = small();
        let a: Vec<usize> = c.chunks(&d).map(<[u8]>::len).collect();
        let b: Vec<usize> = c.chunks(&d).map(<[u8]>::len).collect();
        assert_eq!(a, b);
        assert!(a.len() > 1, "expected multiple chunks");
    }

    #[test]
    fn average_size_is_in_the_ballpark() {
        let d = data(500_000);
        let c = small();
        let n = c.chunks(&d).count();
        let avg = d.len() / n;
        assert!(
            (100..=800).contains(&avg),
            "avg {avg} out of band (target 256)"
        );
    }

    #[test]
    fn edit_locality_most_chunks_recur() {
        // Inserting a byte near the start changes only the chunk spanning it;
        // content-defined boundaries resync, so most chunks recur unchanged.
        let d = data(200_000);
        let c = small();
        let base: Vec<Vec<u8>> = c.chunks(&d).map(|ch| ch.to_vec()).collect();

        let mut edited = d.clone();
        edited.insert(1000, 0xAB);
        let after: HashSet<Vec<u8>> = c.chunks(&edited).map(|ch| ch.to_vec()).collect();

        let shared = base.iter().filter(|ch| after.contains(*ch)).count();
        assert!(
            shared * 100 >= base.len() * 80,
            "only {shared}/{} chunks recurred after a 1-byte insertion",
            base.len()
        );
    }

    proptest! {
        #[test]
        fn any_input_chunks_reassemble_and_respect_bounds(
            data in proptest::collection::vec(any::<u8>(), 0..30_000)
        ) {
            let chunker = small();
            let chunks: Vec<&[u8]> = chunker.chunks(&data).collect();

            // Chunks concatenate back to the input exactly.
            let reassembled: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            prop_assert_eq!(reassembled, data.clone());

            // Nothing exceeds max; non-final chunks are at least min; none empty.
            for (i, chunk) in chunks.iter().enumerate() {
                prop_assert!(!chunk.is_empty());
                prop_assert!(chunk.len() <= 1024);
                if i + 1 < chunks.len() {
                    prop_assert!(chunk.len() >= 64);
                }
            }
        }
    }
}
