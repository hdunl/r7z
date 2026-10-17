//! XPRESS with Huffman coding (MS-XCA "LZ77+Huffman"), as WIM stores it: each chunk
//! (at most 64 KiB) starts with 512 four-bit codeword lengths, followed by a stream of
//! 16-bit little-endian words read MSB first, with match-length extension bytes taken
//! from the input at the position the 32-bit bit window has reached.

use super::huffman::{lz_copy, Decoder};
use crate::error::{Error, Result};

const NUM_SYMS: usize = 512;
const TABLE_BITS: u32 = 11;

/// Reusable XPRESS decoder state.
pub struct XpressDecoder {
    huff: Decoder,
    lens: [u8; NUM_SYMS],
}

impl Default for XpressDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn err() -> Error {
    Error::corrupt("XPRESS data error")
}

impl XpressDecoder {
    pub fn new() -> Self {
        XpressDecoder {
            huff: Decoder::new(TABLE_BITS),
            lens: [0; NUM_SYMS],
        }
    }

    /// Decodes one chunk into exactly `out.len()` bytes.
    pub fn decompress(&mut self, input: &[u8], out: &mut [u8]) -> Result<()> {
        if input.len() < NUM_SYMS / 2 {
            return Err(err());
        }
        for (i, &b) in input[..NUM_SYMS / 2].iter().enumerate() {
            self.lens[2 * i] = b & 15;
            self.lens[2 * i + 1] = b >> 4;
        }
        if !self.huff.build(&self.lens) {
            return Err(err());
        }
        let data = &input[NUM_SYMS / 2..];
        let word = |p: usize| -> u32 {
            match data.get(p..p + 2) {
                Some(w) => u16::from_le_bytes([w[0], w[1]]) as u32,
                None => 0,
            }
        };
        // `value` holds the next bits at the top; `used` counts bits consumed since the
        // last refill. A word is loaded as soon as fewer than 16 bits remain, which fixes
        // where the length extension bytes are read from.
        let mut value = (word(0) << 16) | word(2);
        let mut used = 0u32;
        let mut pos = 4usize;
        macro_rules! consume {
            ($n:expr) => {{
                let n: u32 = $n;
                value <<= n;
                used += n;
                if used > 16 {
                    used -= 16;
                    value |= word(pos) << used;
                    pos += 2;
                }
            }};
        }
        let mut dest = 0usize;
        let huff = &self.huff;
        while dest < out.len() {
            let e = huff.entry(value);
            if e == 0 {
                return Err(err());
            }
            let sym = e >> 5;
            consume!(e & 31);
            if sym < 256 {
                out[dest] = sym as u8;
                dest += 1;
                continue;
            }
            let dist_bits = (sym >> 4) & 15;
            let mut mlen = (sym & 15) as usize;
            if mlen == 15 {
                let b = *data.get(pos).ok_or_else(err)? as usize;
                pos += 1;
                if b == 255 {
                    let w = data.get(pos..pos + 2).ok_or_else(err)?;
                    mlen = u16::from_le_bytes([w[0], w[1]]) as usize;
                    pos += 2;
                } else {
                    mlen += b;
                }
            }
            mlen += 3;
            let mut dist = 1usize << dist_bits;
            if dist_bits > 0 {
                dist |= (value >> (32 - dist_bits)) as usize;
                consume!(dist_bits);
            }
            if dist > dest || mlen > out.len() - dest {
                return Err(err());
            }
            lz_copy(out, dest, dist, mlen);
            dest += mlen;
        }
        Ok(())
    }
}
