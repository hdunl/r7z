//! LZMS, the compression of ESD files and solid WIM resources. A chunk interleaves two
//! streams over the same 16-bit little-endian words: a range coder with adaptive bit
//! models reading forward from the start (item types and repeat-offset choices), and
//! adaptive Huffman codes plus raw bits reading backward from the end (literals,
//! offsets, lengths). LZ matches, "delta" matches and three-entry repeat queues with a
//! one-item delayed update follow the format as 7-Zip and wimlib decode it; the output
//! is finished by LZMS's x86 address translation filter.

use super::huffman::{lengths_from_freqs, lz_copy, Decoder};
use crate::error::{Error, Result};

const NUM_LIT: usize = 256;
const NUM_LEN: usize = 54;
const NUM_POS: usize = 799;
const NUM_POWER: usize = 8;
const MAX_CODE_LEN: u32 = 15;
const NUM_REPS: usize = 3;

/// Offset slots per number of extra bits (0..=30); 799 slots in all.
const POS_RUNS: [u8; 31] = [
    8, 0, 9, 7, 10, 15, 15, 20, 20, 30, 33, 40, 42, 45, 60, 73, 80, 85, 95, 105, 6, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1,
];

const LEN_EXTRA: [u8; NUM_LEN] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 16, 30,
];

fn err() -> Error {
    Error::corrupt("LZMS data error")
}

/// Slot base values and extra-bit counts for offsets and lengths.
struct Tables {
    pos_base: [u32; NUM_POS],
    pos_extra: [u8; NUM_POS],
    len_base: [u32; NUM_LEN],
}

impl Tables {
    fn new() -> Self {
        let mut pos_extra = [0u8; NUM_POS];
        let mut k = 0;
        for (bits, &run) in POS_RUNS.iter().enumerate() {
            for _ in 0..run {
                pos_extra[k] = bits as u8;
                k += 1;
            }
        }
        let mut pos_base = [0u32; NUM_POS];
        let mut sum = 1u32;
        for i in 0..NUM_POS {
            pos_base[i] = sum;
            sum = sum.wrapping_add(1 << pos_extra[i]);
        }
        let mut len_base = [0u32; NUM_LEN];
        let mut sum = 1u32;
        for i in 0..NUM_LEN {
            len_base[i] = sum;
            sum += 1 << LEN_EXTRA[i];
        }
        Tables {
            pos_base,
            pos_extra,
            len_base,
        }
    }

    /// Offset slots needed for a chunk of `size` bytes (at least 2).
    fn num_pos_slots(&self, size: usize) -> usize {
        if size < 2 {
            return 2;
        }
        let last = (size - 1) as u64;
        let n = self.pos_base.partition_point(|&b| b as u64 <= last);
        n.max(2)
    }
}

/// An adaptive bit model: the probability of a 0 is the number of zeros among the last
/// 64 decisions.
#[derive(Clone, Copy)]
struct Prob {
    zeros: u32,
    hist: u64,
}

impl Prob {
    const INIT: Prob = Prob {
        zeros: 48,
        hist: 0x5555_5555,
    };
}

struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl RangeDecoder<'_> {
    #[inline]
    fn word(&mut self) -> u32 {
        let w = match self.data.get(self.pos..self.pos + 2) {
            Some(w) => u16::from_le_bytes([w[0], w[1]]) as u32,
            None => 0,
        };
        self.pos += 2;
        w
    }

    #[inline]
    fn bit(&mut self, state: &mut u32, mask: u32, probs: &mut [Prob]) -> u32 {
        let e = &mut probs[*state as usize];
        let prob = e.zeros.clamp(1, 63);
        if self.range <= 0xFFFF {
            self.range <<= 16;
            self.code = (self.code << 16) | self.word();
        }
        let bound = (self.range >> 6) * prob;
        let bit = if self.code < bound {
            self.range = bound;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            1
        };
        e.zeros = (e.zeros as i32 + (e.hist >> 63) as i32 - bit as i32) as u32;
        e.hist = (e.hist << 1) | bit as u64;
        *state = ((*state << 1) | bit) & mask;
        bit
    }
}

/// Backward reader of 16-bit little-endian words, MSB first. Reads past the start yield
/// zero bits.
struct BackBits<'a> {
    data: &'a [u8],
    /// Byte offset just past the next word to load.
    end: usize,
    buf: u64,
    n: u32,
    /// Bits consumed in all.
    used: u64,
}

impl BackBits<'_> {
    #[inline]
    fn refill(&mut self) {
        while self.n <= 48 {
            let w = if self.end >= 2 {
                self.end -= 2;
                u16::from_le_bytes([self.data[self.end], self.data[self.end + 1]]) as u64
            } else {
                0
            };
            self.buf |= w << (48 - self.n);
            self.n += 16;
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
        self.used += k as u64;
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
}

/// A Huffman code rebuilt from running symbol counts every `rebuild` symbols.
struct AdaptiveCode {
    freqs: Vec<u32>,
    lens: Vec<u8>,
    num: usize,
    rebuild: u32,
    left: u32,
    dec: Decoder,
}

impl AdaptiveCode {
    fn new(max_syms: usize, rebuild: u32, table_bits: u32) -> Self {
        AdaptiveCode {
            freqs: vec![0; max_syms],
            lens: vec![0; max_syms],
            num: max_syms,
            rebuild,
            left: rebuild,
            dec: Decoder::new(table_bits),
        }
    }

    fn reset(&mut self, num: usize) -> Result<()> {
        self.num = num;
        self.freqs[..num].fill(1);
        self.left = self.rebuild;
        self.build()
    }

    fn build(&mut self) -> Result<()> {
        let n = self.num;
        lengths_from_freqs(&self.freqs[..n], MAX_CODE_LEN, &mut self.lens[..n]);
        if self.dec.build(&self.lens[..n]) {
            Ok(())
        } else {
            Err(err())
        }
    }

    #[inline]
    fn decode(&mut self, bits: &mut BackBits) -> Result<usize> {
        let (s, l) = self.dec.decode(bits.peek()).ok_or_else(err)?;
        bits.consume(l);
        self.freqs[s as usize] += 1;
        self.left -= 1;
        if self.left == 0 {
            self.build()?;
            for f in &mut self.freqs[..self.num] {
                *f = (*f >> 1) + 1;
            }
            self.left = self.rebuild;
        }
        Ok(s as usize)
    }
}

/// Reusable LZMS decoder state.
pub struct LzmsDecoder {
    tables: Tables,
    lit: AdaptiveCode,
    len: AdaptiveCode,
    pos: AdaptiveCode,
    delta_pos: AdaptiveCode,
    power: AdaptiveCode,
    x86: X86Filter,
}

impl Default for LzmsDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl LzmsDecoder {
    pub fn new() -> Self {
        LzmsDecoder {
            tables: Tables::new(),
            lit: AdaptiveCode::new(NUM_LIT, 1024, 10),
            len: AdaptiveCode::new(NUM_LEN, 512, 9),
            pos: AdaptiveCode::new(NUM_POS, 1024, 10),
            delta_pos: AdaptiveCode::new(NUM_POS, 1024, 10),
            power: AdaptiveCode::new(NUM_POWER, 512, 6),
            x86: X86Filter::new(),
        }
    }

    /// Decodes one chunk into exactly `out.len()` bytes.
    pub fn decompress(&mut self, input: &[u8], out: &mut [u8]) -> Result<()> {
        if input.len() < 4 || input.len() & 1 != 0 {
            return Err(err());
        }
        let r = self.decode(input, out);
        self.x86.apply(out, true);
        r
    }

    fn decode(&mut self, input: &[u8], out: &mut [u8]) -> Result<()> {
        let mut rc = RangeDecoder {
            data: input,
            pos: 4,
            range: u32::MAX,
            code: ((u16::from_le_bytes([input[0], input[1]]) as u32) << 16)
                | u16::from_le_bytes([input[2], input[3]]) as u32,
        };
        if rc.code == u32::MAX {
            return Err(err());
        }
        let mut bits = BackBits {
            data: input,
            end: input.len(),
            buf: 0,
            n: 0,
            used: 0,
        };
        let LzmsDecoder {
            tables: t,
            lit,
            len: len_code,
            pos: pos_code,
            delta_pos,
            power: power_code,
            ..
        } = self;
        let npos = t.num_pos_slots(out.len());
        lit.reset(NUM_LIT)?;
        len_code.reset(NUM_LEN)?;
        power_code.reset(NUM_POWER)?;
        pos_code.reset(npos)?;
        delta_pos.reset(npos)?;

        let mut main_probs = [Prob::INIT; 16];
        let mut match_probs = [Prob::INIT; 32];
        let mut lz_probs = [[Prob::INIT; 64]; NUM_REPS];
        let mut delta_probs = [[Prob::INIT; 64]; NUM_REPS];
        let (mut main_st, mut match_st) = (0u32, 0u32);
        let mut lz_st = [0u32; NUM_REPS];
        let mut delta_st = [0u32; NUM_REPS];
        let mut reps = [1u32, 2, 3, 4];
        let mut delta_reps = [1u64, 2, 3, 4];
        // 0 = literal, 1 = LZ match, 2 = delta match.
        let mut prev = 0u8;
        let mut read_len = |bits: &mut BackBits| -> Result<usize> {
            let slot = len_code.decode(bits)?;
            Ok(t.len_base[slot] as usize + bits.bits(LEN_EXTRA[slot] as u32) as usize)
        };
        let mut dest = 0usize;

        while dest < out.len() {
            if rc.bit(&mut main_st, 15, &mut main_probs) == 0 {
                out[dest] = lit.decode(&mut bits)? as u8;
                dest += 1;
                prev = 0;
                continue;
            }
            let is_delta = rc.bit(&mut match_st, 31, &mut match_probs) == 1;
            let (probs, st, delayed) = if is_delta {
                (&mut delta_probs, &mut delta_st, prev == 2)
            } else {
                (&mut lz_probs, &mut lz_st, prev == 1)
            };
            // Explicit source or repeat index 0..=2.
            let rep = if rc.bit(&mut st[0], 63, &mut probs[0]) == 0 {
                None
            } else if rc.bit(&mut st[1], 63, &mut probs[1]) == 0 {
                Some(0)
            } else if rc.bit(&mut st[2], 63, &mut probs[2]) == 0 {
                Some(1)
            } else {
                Some(2)
            };
            if !is_delta {
                let dist = match rep {
                    None => {
                        let slot = pos_code.decode(&mut bits)?;
                        let d = t.pos_base[slot].wrapping_add(bits.bits(t.pos_extra[slot] as u32));
                        reps.copy_within(0..3, 1);
                        reps[0] = d;
                        d
                    }
                    Some(k) => {
                        // After an LZ match its source is still at the front: skip it.
                        let k = k + delayed as usize;
                        let d = reps[k];
                        reps.copy_within(0..k, 1);
                        reps[0] = d;
                        d
                    }
                } as usize;
                let len = read_len(&mut bits)?;
                if len > out.len() - dest || dist == 0 || dist > dest {
                    return Err(err());
                }
                lz_copy(out, dest, dist, len);
                dest += len;
                prev = 1;
            } else {
                let pair = match rep {
                    None => {
                        let power = power_code.decode(&mut bits)? as u64;
                        let slot = delta_pos.decode(&mut bits)?;
                        let d = t.pos_base[slot].wrapping_add(bits.bits(t.pos_extra[slot] as u32));
                        let p = (power << 32) | d as u64;
                        delta_reps.copy_within(0..3, 1);
                        delta_reps[0] = p;
                        p
                    }
                    Some(k) => {
                        let k = k + delayed as usize;
                        let p = delta_reps[k];
                        delta_reps.copy_within(0..k, 1);
                        delta_reps[0] = p;
                        p
                    }
                };
                let power = (pair >> 32) as u32;
                let raw = pair as u32;
                let len = read_len(&mut bits)?;
                if len > out.len() - dest || power >= 32 {
                    return Err(err());
                }
                let span = 1u64 << power;
                let dist = (raw as u64) << power;
                if dist == 0 || dist + span > dest as u64 {
                    return Err(err());
                }
                let (span, dist) = (span as usize, dist as usize);
                for i in dest..dest + len {
                    out[i] = out[i - span]
                        .wrapping_add(out[i - dist])
                        .wrapping_sub(out[i - dist - span]);
                }
                dest += len;
                prev = 2;
            }
        }
        // The two streams must not overlap.
        if rc.pos.min(input.len()) as u64 + bits.used.div_ceil(8) > input.len() as u64 {
            return Err(err());
        }
        Ok(())
    }
}

/// LZMS's x86 translation filter: relative displacements of likely RIP-relative and
/// CALL instructions are stored as absolute positions.
pub struct X86Filter {
    /// Last position (plus `base`) each 16-bit target was referenced at.
    history: Vec<u64>,
    /// Added to positions so entries from earlier buffers are always too old to count,
    /// which saves clearing `history` for every chunk.
    base: u64,
}

impl Default for X86Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl X86Filter {
    const WINDOW: u64 = 65535;
    const MAX_TRANS: i64 = 1023;

    pub fn new() -> Self {
        X86Filter {
            history: vec![0; 1 << 16],
            base: Self::WINDOW + 1,
        }
    }

    /// Applies (`undo == false`) or undoes the translation over one buffer.
    pub fn apply(&mut self, data: &mut [u8], undo: bool) {
        let base = self.base;
        self.base += data.len() as u64 + Self::WINDOW + 1;
        if data.len() <= 17 {
            return;
        }
        let lim = data.len() - 16;
        let mut last = -Self::MAX_TRANS - 1;
        let mut i = 1usize;
        while i < lim {
            let b = data[i];
            let (op_len, max) = match b {
                0x48 | 0x4C => {
                    let m = data[i + 2];
                    let ok = m & 7 == 5
                        && (data[i + 1] == 0x8D
                            || (data[i + 1] == 0x8B && b & 4 == 0 && m & 0xF0 == 0));
                    if !ok {
                        i += 1;
                        continue;
                    }
                    (3, Self::MAX_TRANS)
                }
                0xE8 => (1, Self::MAX_TRANS / 2),
                0xE9 => {
                    i += 5;
                    continue;
                }
                0xF0 => {
                    if data[i + 1] != 0x83 || data[i + 2] != 0x05 {
                        i += 1;
                        continue;
                    }
                    (3, Self::MAX_TRANS)
                }
                0xFF => {
                    if data[i + 1] != 0x15 {
                        i += 1;
                        continue;
                    }
                    (2, Self::MAX_TRANS)
                }
                _ => {
                    i += 1;
                    continue;
                }
            };
            let pos = i as u32;
            let at = i + op_len;
            let v = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            let near = i as i64 - last <= max;
            let target = if undo {
                let n = if near { v.wrapping_sub(pos) } else { v };
                if near {
                    data[at..at + 4].copy_from_slice(&n.to_le_bytes());
                }
                pos.wrapping_add(n) as u16
            } else {
                if near {
                    data[at..at + 4].copy_from_slice(&v.wrapping_add(pos).to_le_bytes());
                }
                pos.wrapping_add(v) as u16
            };
            let end = i + op_len + 3;
            let abs = base + end as u64;
            let slot = &mut self.history[target as usize];
            if abs - *slot <= Self::WINDOW {
                last = end as i64;
            }
            *slot = abs;
            i = end + 1;
        }
    }
}
