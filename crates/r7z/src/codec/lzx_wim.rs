//! LZX as WIM uses it: every chunk is an independent stream with a window the size of
//! the chunk (32 KiB to 2 MiB), no E8 header bit, E8 call translation always applied
//! with a translation size of 12000000, and a one-bit flag for the default block size.

use super::huffman::{lz_copy, Decoder};
use crate::error::{Error, Result};

const MAIN_MAX: usize = 256 + 8 * 50;
const LEN_SYMS: usize = 249;
const PRE_SYMS: usize = 20;
const ALIGNED_SYMS: usize = 8;
const E8_SIZE: i32 = 12_000_000;

fn err() -> Error {
    Error::corrupt("LZX data error")
}

/// Forward reader of 16-bit little-endian words, MSB first. Reads past the end yield
/// zero bits.
struct Bits<'a> {
    data: &'a [u8],
    /// Byte offset of the next word to load.
    pos: usize,
    buf: u64,
    n: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Bits {
            data,
            pos,
            buf: 0,
            n: 0,
        }
    }

    #[inline]
    fn refill(&mut self) {
        while self.n <= 48 {
            let w = match self.data.get(self.pos..self.pos + 2) {
                Some(w) => u16::from_le_bytes([w[0], w[1]]) as u64,
                None => 0,
            };
            self.buf |= w << (48 - self.n);
            self.n += 16;
            self.pos += 2;
        }
    }

    #[inline]
    fn peek(&mut self) -> u32 {
        if self.n < 32 {
            self.refill();
        }
        (self.buf >> 32) as u32
    }

    #[inline]
    fn consume(&mut self, k: u32) {
        self.buf <<= k;
        self.n -= k;
    }

    #[inline]
    fn bits(&mut self, k: u32) -> u32 {
        if k == 0 {
            return 0;
        }
        let v = self.peek() >> (32 - k);
        self.consume(k);
        v
    }

    #[inline]
    fn sym(&mut self, d: &Decoder) -> Result<u32> {
        let (s, l) = d.decode(self.peek()).ok_or_else(err)?;
        self.consume(l);
        Ok(s)
    }

    /// Skips 1 to 16 bits to the next word boundary and returns the byte offset there.
    fn align(&mut self) -> usize {
        let consumed = self.pos * 8 - self.n as usize;
        consumed / 16 * 2 + 2
    }
}

/// Reusable LZX decoder state (code tables and lengths).
pub struct LzxDecoder {
    main_lens: [u8; MAIN_MAX],
    len_lens: [u8; LEN_SYMS],
    main: Decoder,
    len: Decoder,
    aligned: Decoder,
    pre: Decoder,
    base: [u32; 50],
    extra: [u8; 50],
}

impl Default for LzxDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl LzxDecoder {
    pub fn new() -> Self {
        let mut base = [0u32; 50];
        let mut extra = [0u8; 50];
        let mut b = 0u32;
        for i in 0..50 {
            extra[i] = if i < 4 {
                0
            } else {
                ((i / 2 - 1) as u8).min(17)
            };
            base[i] = b;
            b += 1 << extra[i];
        }
        LzxDecoder {
            main_lens: [0; MAIN_MAX],
            len_lens: [0; LEN_SYMS],
            main: Decoder::new(11),
            len: Decoder::new(9),
            aligned: Decoder::new(7),
            pre: Decoder::new(8),
            base,
            extra,
        }
    }

    /// Reads delta-coded lengths for `lens` through a fresh pretree.
    fn read_lens(pre: &mut Decoder, bits: &mut Bits, lens: &mut [u8]) -> Result<()> {
        let mut pl = [0u8; PRE_SYMS];
        for l in pl.iter_mut() {
            *l = bits.bits(4) as u8;
        }
        if !pre.build(&pl) {
            return Err(err());
        }
        let mut i = 0;
        while i < lens.len() {
            let s = bits.sym(pre)?;
            match s {
                0..=16 => {
                    lens[i] = ((lens[i] as u32 + 17 - s) % 17) as u8;
                    i += 1;
                }
                17 | 18 => {
                    let run = if s == 17 {
                        4 + bits.bits(4)
                    } else {
                        20 + bits.bits(5)
                    } as usize;
                    let end = (i + run).min(lens.len());
                    lens[i..end].fill(0);
                    i = end;
                }
                _ => {
                    let run = 4 + bits.bits(1) as usize;
                    let s2 = bits.sym(pre)?;
                    if s2 > 17 {
                        return Err(err());
                    }
                    let v = ((lens[i] as u32 + 17 - s2) % 17) as u8;
                    let end = (i + run).min(lens.len());
                    lens[i..end].fill(v);
                    i = end;
                }
            }
        }
        Ok(())
    }

    /// Decodes one chunk into exactly `out.len()` bytes; `window_bits` is log2 of the
    /// chunk size (15..=21).
    pub fn decompress(&mut self, input: &[u8], out: &mut [u8], window_bits: u32) -> Result<()> {
        if !(15..=21).contains(&window_bits) || out.len() > 1 << window_bits {
            return Err(Error::unsupported(format!(
                "LZX window of 2^{window_bits} bytes"
            )));
        }
        let slots = if window_bits < 20 {
            2 * window_bits as usize
        } else {
            2 * (17 + (1usize << (window_bits - 18)))
        };
        let main_syms = 256 + 8 * slots;
        self.main_lens.fill(0);
        self.len_lens.fill(0);
        let mut reps = [1u32; 3];
        let mut bits = Bits::new(input, 0);
        let mut dest = 0usize;
        while dest < out.len() {
            let kind = bits.bits(3);
            let mut size = if bits.bits(1) == 1 {
                1 << 15
            } else {
                let mut s = bits.bits(16) as usize;
                if window_bits >= 16 {
                    s = (s << 8) | bits.bits(8) as usize;
                }
                s
            };
            size = size.min(out.len() - dest);
            match kind {
                3 => {
                    let mut p = bits.align();
                    let hdr = input.get(p..p + 12).ok_or_else(err)?;
                    for (k, r) in reps.iter_mut().enumerate() {
                        *r = u32::from_le_bytes(hdr[4 * k..4 * k + 4].try_into().unwrap());
                        if *r == 0 {
                            return Err(err());
                        }
                    }
                    p += 12;
                    let src = input.get(p..p + size).ok_or_else(err)?;
                    out[dest..dest + size].copy_from_slice(src);
                    dest += size;
                    p += size;
                    if size & 1 == 1 {
                        p += 1;
                    }
                    bits = Bits::new(input, p);
                }
                1 | 2 => {
                    let aligned = kind == 2;
                    if aligned {
                        let mut al = [0u8; ALIGNED_SYMS];
                        for l in al.iter_mut() {
                            *l = bits.bits(3) as u8;
                        }
                        if !self.aligned.build(&al) {
                            return Err(err());
                        }
                    }
                    Self::read_lens(&mut self.pre, &mut bits, &mut self.main_lens[..256])?;
                    Self::read_lens(
                        &mut self.pre,
                        &mut bits,
                        &mut self.main_lens[256..main_syms],
                    )?;
                    if !self.main.build(&self.main_lens[..main_syms]) {
                        return Err(err());
                    }
                    Self::read_lens(&mut self.pre, &mut bits, &mut self.len_lens)?;
                    if !self.len.build(&self.len_lens) {
                        return Err(err());
                    }
                    let end = dest + size;
                    dest = self.decode_block(&mut bits, out, dest, end, aligned, &mut reps)?;
                }
                _ => return Err(err()),
            }
        }
        e8_untranslate(out);
        Ok(())
    }

    fn decode_block(
        &self,
        bits: &mut Bits,
        out: &mut [u8],
        mut dest: usize,
        end: usize,
        aligned: bool,
        reps: &mut [u32; 3],
    ) -> Result<usize> {
        while dest < end {
            let sym = bits.sym(&self.main)?;
            if sym < 256 {
                out[dest] = sym as u8;
                dest += 1;
                continue;
            }
            let s = sym - 256;
            let mut len = (s & 7) as usize + 2;
            if s & 7 == 7 {
                len += bits.sym(&self.len)? as usize;
            }
            let slot = (s >> 3) as usize;
            let dist = if slot < 3 {
                reps.swap(0, slot);
                reps[0]
            } else {
                let extra = self.extra[slot] as u32;
                let v = if aligned && extra >= 3 {
                    (bits.bits(extra - 3) << 3) + bits.sym(&self.aligned)?
                } else {
                    bits.bits(extra)
                };
                let d = self.base[slot] + v - 2;
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = d;
                d
            } as usize;
            if dist == 0 || dist > dest || len > out.len() - dest {
                return Err(err());
            }
            lz_copy(out, dest, dist, len);
            dest += len;
        }
        Ok(dest)
    }
}

/// Undoes the E8 (x86 CALL) translation over one chunk.
fn e8_untranslate(data: &mut [u8]) {
    if data.len() <= 10 {
        return;
    }
    let lim = data.len() - 10;
    let mut i = 0;
    while i < lim {
        if data[i] != 0xE8 {
            // Skip eight bytes at a time while none of them is E8.
            while i + 8 <= lim {
                let w =
                    u64::from_le_bytes(data[i..i + 8].try_into().unwrap()) ^ 0xE8E8_E8E8_E8E8_E8E8;
                if (w.wrapping_sub(0x0101_0101_0101_0101) & !w & 0x8080_8080_8080_8080) != 0 {
                    break;
                }
                i += 8;
            }
            while i < lim && data[i] != 0xE8 {
                i += 1;
            }
            continue;
        }
        let abs = i32::from_le_bytes(data[i + 1..i + 5].try_into().unwrap());
        let cur = i as i32;
        if abs >= -cur && abs < E8_SIZE {
            let rel = if abs >= 0 { abs - cur } else { abs + E8_SIZE };
            data[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
        }
        i += 5;
    }
}
