//! Primitives shared by the RAR 3 and RAR 5 decoders: an MSB-first bit reader over the
//! packed stream, canonical Huffman tables, and the in-place filters.
//!
//! The reader pulls bytes from its source only as the decoder needs them, so the byte
//! position is exact after [`Bits::align`]. The PPMd coder of RAR 3 reads whole bytes
//! from the same reader, which keeps the two in step.

use std::io::{self, Read};

use crate::error::{Error, Result};

/// Bytes pulled from the source per refill.
const CHUNK: usize = 1 << 13;

/// MSB-first bit reader. Past the end of its source it reads zero bits and records the
/// overrun, which decoders report as truncated data.
pub struct Bits {
    src: Box<dyn Read + Send>,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
    /// Pending bits; the next bit to read is bit `n - 1`.
    acc: u64,
    n: u32,
    /// Zero bits added past the end of the source, at the low end of `acc`.
    pad: u32,
    eof: bool,
    /// Set once a consumed bit came from `pad`.
    overran: bool,
    /// Bytes taken from the source so far.
    pulled: u64,
}

impl Bits {
    pub fn new(src: Box<dyn Read + Send>) -> Self {
        Bits {
            src,
            buf: vec![0; CHUNK].into_boxed_slice(),
            pos: 0,
            len: 0,
            acc: 0,
            n: 0,
            pad: 0,
            eof: false,
            overran: false,
            pulled: 0,
        }
    }

    #[inline]
    fn pull_byte(&mut self) -> io::Result<u8> {
        if self.pos == self.len {
            if self.eof {
                self.pad += 8;
                return Ok(0);
            }
            loop {
                match self.src.read(&mut self.buf) {
                    Ok(0) => {
                        self.eof = true;
                        self.pad += 8;
                        return Ok(0);
                    }
                    Ok(k) => {
                        self.len = k;
                        self.pos = 0;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        self.pulled += 1;
        Ok(b)
    }

    /// Makes at least `k` (at most 32) bits available.
    #[inline]
    fn fill(&mut self, k: u32) -> io::Result<()> {
        if self.n >= k {
            return Ok(());
        }
        // Top up from the buffer while it has room, so the next few reads need no refill.
        while self.n <= 48 && self.pos < self.len {
            self.acc = (self.acc << 8) | u64::from(self.buf[self.pos]);
            self.pos += 1;
            self.pulled += 1;
            self.n += 8;
        }
        while self.n < k {
            let b = self.pull_byte()?;
            self.acc = (self.acc << 8) | u64::from(b);
            self.n += 8;
        }
        Ok(())
    }

    /// The next `k` bits (k <= 32) without consuming them.
    #[inline]
    pub fn peek(&mut self, k: u32) -> io::Result<u32> {
        if k == 0 {
            return Ok(0);
        }
        self.fill(k)?;
        Ok(((self.acc >> (self.n - k)) & ((1u64 << k) - 1)) as u32)
    }

    #[inline]
    pub fn consume(&mut self, k: u32) {
        self.n -= k;
        if self.n < self.pad {
            self.overran = true;
        }
    }

    /// Reads `k` bits (k <= 32).
    #[inline]
    pub fn read_bits(&mut self, k: u32) -> io::Result<u32> {
        let v = self.peek(k)?;
        self.consume(k);
        Ok(v)
    }

    /// Discards the rest of the current byte.
    pub fn align(&mut self) {
        self.n -= self.n % 8;
        if self.n < self.pad {
            self.overran = true;
        }
    }

    /// Reads one whole byte; the reader must be byte aligned.
    pub fn byte(&mut self) -> io::Result<u8> {
        Ok(self.read_bits(8)? as u8)
    }

    /// Whole source bytes consumed so far, counting a partly consumed byte as unread.
    pub fn byte_pos(&self) -> u64 {
        (self.pulled * 8 + u64::from(self.pad) - u64::from(self.n)) / 8
    }

    /// True once decoding has consumed bits past the end of the source.
    pub fn overrun(&self) -> bool {
        self.overran
    }
}

/// Largest code length a Huffman table here can have.
const MAX_CODE: u32 = 15;

/// A canonical Huffman decoding table indexed by the next `bits` input bits.
pub struct Huff {
    table: Vec<u32>,
    bits: u32,
}

/// Value of [`Huff::decode`] for a bit pattern no code matches.
pub const NO_SYMBOL: u32 = u32::MAX;

impl Huff {
    /// Builds the table for code lengths `lens` (0 = symbol unused). Over-subscribed
    /// lengths are rejected; incomplete codes are allowed, their unmatched patterns decode
    /// as [`NO_SYMBOL`].
    pub fn build(lens: &[u8]) -> Result<Huff> {
        let max = lens.iter().copied().max().unwrap_or(0) as u32;
        if max > MAX_CODE {
            return Err(Error::corrupt("Huffman code length out of range"));
        }
        let bits = max.max(1);
        let mut count = [0u32; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        // Kraft check: codes must not need more space than the table has.
        let mut used: u64 = 0;
        for l in 1..=bits {
            used += u64::from(count[l as usize]) << (bits - l);
        }
        if used > 1u64 << bits {
            return Err(Error::corrupt(format!(
                "over-subscribed Huffman code: used {used} of {} (lens {:?})",
                1u64 << bits,
                lens
            )));
        }
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for l in 1..=bits as usize {
            code = (code + count[l - 1]) << 1;
            next[l] = code;
        }
        let mut table = vec![0u32; 1 << bits];
        for (sym, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = u32::from(l);
            let c = next[l as usize];
            next[l as usize] += 1;
            let span = 1usize << (bits - l);
            let start = (c as usize) << (bits - l);
            let entry = ((sym as u32) << 4) | l;
            table[start..start + span].fill(entry);
        }
        Ok(Huff { table, bits })
    }

    /// Decodes one symbol, or [`NO_SYMBOL`] for an unused code.
    #[inline]
    pub fn decode(&self, b: &mut Bits) -> io::Result<u32> {
        let idx = b.peek(self.bits)? as usize;
        let e = self.table[idx];
        let l = e & 15;
        if l == 0 {
            return Ok(NO_SYMBOL);
        }
        b.consume(l);
        Ok(e >> 4)
    }
}

/// The E8 (x86 CALL) filter of RAR 3: converts absolute call targets back to relative.
/// `pos` is the stream position of `data[0]`; `e9` also converts JMP operands.
pub fn e8_v3(data: &mut [u8], pos: u32, e9: bool) {
    const FILE_SIZE: u32 = 0x100_0000;
    let mut i = 0;
    while i + 4 < data.len() {
        let op = data[i];
        i += 1;
        if op == 0xE8 || (e9 && op == 0xE9) {
            let cur = pos.wrapping_add(i as u32);
            let addr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            let v = if (addr as i32) < 0 && addr.wrapping_neg() <= cur {
                addr.wrapping_add(FILE_SIZE)
            } else if (addr as i32) >= 0 && addr < FILE_SIZE {
                addr.wrapping_sub(cur)
            } else {
                addr
            };
            data[i..i + 4].copy_from_slice(&v.to_le_bytes());
            i += 4;
        }
    }
}

/// The E8 (and E8E9) filter of RAR 5. `pos` is the stream position of `data[0]`.
pub fn e8_v5(data: &mut [u8], pos: u32, e9: bool) {
    const SIZE: u32 = 0x100_0000;
    let mut i = 0;
    while i + 4 < data.len() {
        let op = data[i];
        i += 1;
        if op == 0xE8 || (e9 && op == 0xE9) {
            let cur = pos.wrapping_add(i as u32) % SIZE;
            let addr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            let v = if addr & 0x8000_0000 != 0 && addr.wrapping_add(cur) & 0x8000_0000 == 0 {
                addr.wrapping_add(SIZE)
            } else if addr.wrapping_sub(SIZE) & 0x8000_0000 != 0 {
                addr.wrapping_sub(cur)
            } else {
                addr
            };
            data[i..i + 4].copy_from_slice(&v.to_le_bytes());
            i += 4;
        }
    }
}

/// The ARM branch filter of RAR 5. `pos` is the stream position of `data[0]`.
pub fn arm(data: &mut [u8], pos: u32) {
    let mut i = 0;
    while i + 4 <= data.len() {
        if data[i + 3] == 0xEB {
            let off = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], 0]);
            let target = off.wrapping_sub(pos.wrapping_add(i as u32) / 4) & 0x00FF_FFFF;
            data[i..i + 3].copy_from_slice(&target.to_le_bytes()[..3]);
        }
        i += 4;
    }
}

/// The delta filter: the data is `channels` interleaved runs stored one after another;
/// each run is a running difference, and the output interleaves them again.
pub fn delta(data: &[u8], channels: usize) -> Vec<u8> {
    let len = data.len();
    let mut out = vec![0u8; len];
    let mut src = 0;
    for c in 0..channels.min(len) {
        let mut prev = 0u8;
        for dst in (c..len).step_by(channels) {
            prev = prev.wrapping_sub(data[src]);
            src += 1;
            out[dst] = prev;
        }
    }
    out
}

/// The audio filter of RAR 3: the data is `channels` byte channels stored one after
/// another, and the output interleaves them again. Each channel is decoded by a linear
/// predictor over the last sample and its last three deltas, with weights that adapt every
/// 32 samples towards whichever single-step change would have reduced the error most.
pub fn audio(data: &[u8], channels: usize) -> Vec<u8> {
    let len = data.len();
    let mut out = vec![0u8; len];
    let mut src = 0;
    for c in 0..channels.min(len) {
        let (mut prev, mut prev_delta) = (0u8, 0i32);
        let mut d = [0i32; 3];
        let mut w = [0i32; 3];
        let mut err = [0u32; 7];
        for (count, dst) in (c..len).step_by(channels).enumerate() {
            d = [prev_delta, prev_delta - d[0], d[1]];
            let pred = 8 * i32::from(prev) + w[0] * d[0] + w[1] * d[1] + w[2] * d[2];
            let cur = data[src];
            src += 1;
            let b = ((pred >> 3) as u8).wrapping_sub(cur);
            out[dst] = b;
            prev_delta = i32::from(b.wrapping_sub(prev) as i8);
            prev = b;
            // Error each candidate would have had: unchanged, or one weight moved by one.
            let e = i32::from(cur as i8) << 3;
            err[0] += e.unsigned_abs();
            for (k, &dk) in d.iter().enumerate() {
                err[2 * k + 1] += (e - dk).unsigned_abs();
                err[2 * k + 2] += (e + dk).unsigned_abs();
            }
            if count & 0x1F == 0 {
                let best = (1..7).fold(0, |b, j| if err[j] < err[b] { j } else { b });
                err = [0; 7];
                if best > 0 {
                    let wk = &mut w[(best - 1) / 2];
                    if best % 2 == 1 {
                        if *wk >= -16 {
                            *wk -= 1;
                        }
                    } else if *wk < 16 {
                        *wk += 1;
                    }
                }
            }
        }
    }
    out
}

/// The RGB filter of RAR 3 for 24-bit pixels in rows of `stride` bytes. The data is the
/// three byte planes stored one after another; each byte is decoded by a Paeth predictor
/// over its left, upper and upper-left neighbours (the left one alone on the first row and
/// the first pixel of the second). Then the middle byte of each pixel, counted from byte
/// `first` (0..=2), is added back into the other two.
pub fn rgb(data: &[u8], stride: usize, first: usize) -> Vec<u8> {
    let len = data.len();
    let mut out = vec![0u8; len];
    let mut src = 0;
    for c in 0..3.min(len) {
        let mut prev = 0u8;
        for i in (c..len).step_by(3) {
            let pred = if i >= stride + 3 {
                paeth(prev, out[i - stride], out[i - stride - 3])
            } else {
                prev
            };
            prev = pred.wrapping_sub(data[src]);
            src += 1;
            out[i] = prev;
        }
    }
    let mut i = first;
    while i + 2 < len {
        let g = out[i + 1];
        out[i] = out[i].wrapping_add(g);
        out[i + 2] = out[i + 2].wrapping_add(g);
        i += 3;
    }
    out
}

/// Of the left, upper and upper-left bytes, the one closest to `left + up - up_left`;
/// ties prefer left, then up.
fn paeth(left: u8, up: u8, up_left: u8) -> u8 {
    let (l, u, ul) = (i32::from(left), i32::from(up), i32::from(up_left));
    let p = l + u - ul;
    let (pl, pu, pul) = ((p - l).abs(), (p - u).abs(), (p - ul).abs());
    if pl <= pu && pl <= pul {
        left
    } else if pu <= pul {
        up
    } else {
        up_left
    }
}

/// The Itanium (IA-64) branch filter of RAR 3: converts the 20-bit target of each IP-relative
/// branch back from an absolute bundle number. `pos` is the stream position of `data[0]`.
/// For each 16-byte bundle whose template has branch slots, a branch slot with opcode 5 has
/// the 20 bits from bit 13 of its 41-bit instruction reduced by the bundle number (the sign
/// bit is left alone). Bundles that start within the last 22 bytes are left as they are.
///
/// UNVERIFIED: no archive with an Itanium filter was available to test this against.
pub fn itanium(data: &mut [u8], pos: u32) {
    /// Branch slots of each bundle template, one bit per slot.
    const SLOTS: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4,
        0, 0,
    ];
    const IMM: u128 = 0xF_FFFF;
    let mut bundle = pos >> 4;
    let mut i = 0;
    while i + 21 < data.len() {
        let slots = SLOTS[usize::from(data[i] & 0x1F)];
        if slots != 0 {
            let cell: &mut [u8; 16] = (&mut data[i..i + 16]).try_into().unwrap();
            let mut b = u128::from_le_bytes(*cell);
            for slot in (0..3).filter(|s| slots & (1 << s) != 0) {
                let at = 5 + 41 * slot;
                if (b >> (at + 37)) & 0xF == 5 {
                    let target = ((b >> (at + 13)) & IMM) as u32;
                    let rel = u128::from(target.wrapping_sub(bundle)) & IMM;
                    b = (b & !(IMM << (at + 13))) | (rel << (at + 13));
                }
            }
            *cell = b.to_le_bytes();
        }
        i += 16;
        bundle = bundle.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn itanium_rebases_branch_targets() {
        // Template 0x10 (MIB) has its branch in slot 2, bits 87..128.
        let at = 5 + 41 * 2;
        let b = 0x10u128 | (5u128 << (at + 37)) | (0x1_2345u128 << (at + 13));
        let mut data = [0u8; 32];
        data[..16].copy_from_slice(&b.to_le_bytes());
        let tail = data[16..].to_vec();
        itanium(&mut data, 0x100);
        let got = u128::from_le_bytes(data[..16].try_into().unwrap());
        assert_eq!(got, b - (0x10u128 << (at + 13)));
        assert_eq!(data[16..], tail[..], "the last bundle is too near the end");
    }

    #[test]
    fn filters_accept_any_size() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
            for ch in [1, 2, 3, 7, 64] {
                assert_eq!(audio(&data, ch).len(), len);
            }
            for stride in [0, 1, 3, 9, 1 << 20] {
                assert_eq!(rgb(&data, stride, 2).len(), len);
            }
            itanium(&mut data.clone(), u32::MAX);
        }
    }
}
