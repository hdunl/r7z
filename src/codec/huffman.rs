//! Canonical Huffman codes shared by the WIM codecs (XPRESS, LZX, LZMS): table-driven
//! decoding of MSB-first codewords, the code-length construction LZMS decoders must
//! reproduce exactly, and an overlapping LZ77 copy.

/// Longest codeword any of the WIM codecs uses (LZX lengths reach 16).
pub const MAX_LEN: usize = 16;

/// A decoder for one canonical code. Codewords are matched against the top bits of a
/// 32-bit window in which bit 31 is the next stream bit.
#[derive(Clone, Debug)]
pub struct Decoder {
    table_bits: u32,
    /// Two-level lookup table. Primary entries (the first `1 << table_bits`) hold
    /// `symbol << 5 | length` for short codewords, or `SUB | offset << 5 | bits` pointing
    /// at a subtable indexed by the next `bits` bits. Zero marks an unused codeword.
    table: Vec<u32>,
    /// Scratch: each symbol's codeword, and the subtable size per primary entry.
    codes: Vec<u32>,
    sub: Vec<u8>,
}

const SUB: u32 = 1 << 31;

impl Decoder {
    pub fn new(table_bits: u32) -> Self {
        Decoder {
            table_bits,
            table: vec![0; 1 << table_bits],
            codes: Vec::new(),
            sub: vec![0; 1 << table_bits],
        }
    }

    /// Builds the code from per-symbol lengths (0 = unused). Fails when the lengths
    /// over-subscribe the code space; incomplete codes are accepted and their unused
    /// codewords fail to decode.
    pub fn build(&mut self, lens: &[u8]) -> bool {
        let mut count = [0u32; MAX_LEN + 1];
        for &l in lens {
            if l as usize > MAX_LEN {
                return false;
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut left: i64 = 1;
        for &c in &count[1..] {
            left = left * 2 - c as i64;
            if left < 0 {
                return false;
            }
        }
        let mut next = [0u32; MAX_LEN + 1];
        let mut code = 0u32;
        for len in 1..=MAX_LEN {
            next[len] = code;
            code = (code + count[len]) << 1;
        }
        let tb = self.table_bits;
        let primary = 1usize << tb;
        self.table.truncate(primary);
        self.table.fill(0);
        self.codes.clear();
        let long = count[tb as usize + 1..].iter().any(|&c| c != 0);
        if long {
            self.sub.fill(0);
        }
        for &l in lens {
            let c = next[l as usize];
            next[l as usize] += 1;
            self.codes.push(c);
            let l = l as u32;
            if l > tb {
                let prefix = (c >> (l - tb)) as usize;
                self.sub[prefix] = self.sub[prefix].max((l - tb) as u8);
            }
        }
        for (sym, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = l as u32;
            let c = self.codes[sym];
            let entry = ((sym as u32) << 5) | l;
            if l <= tb {
                let shift = tb - l;
                let start = (c << shift) as usize;
                self.table[start..start + (1 << shift)].fill(entry);
                continue;
            }
            // Long codeword: its first `tb` bits select a subtable sized for the longest
            // codeword sharing them.
            let prefix = (c >> (l - tb)) as usize;
            let bits = self.sub[prefix] as u32;
            if self.table[prefix] == 0 {
                let off = self.table.len() as u32;
                self.table.resize(self.table.len() + (1 << bits), 0);
                self.table[prefix] = SUB | (off << 5) | bits;
            }
            let off = ((self.table[prefix] & !SUB) >> 5) as usize;
            let rest = c & ((1 << (l - tb)) - 1);
            let shift = bits - (l - tb);
            let start = off + (rest << shift) as usize;
            self.table[start..start + (1 << shift)].fill(entry);
        }
        true
    }

    /// Decodes one symbol from `window` (next bit in bit 31): `(symbol, length)`.
    #[inline(always)]
    pub fn decode(&self, window: u32) -> Option<(u32, u32)> {
        let e = self.entry(window);
        if e == 0 {
            return None;
        }
        Some((e >> 5, e & 31))
    }

    /// The table entry for `window`: `symbol << 5 | length`, or 0 for an unused codeword.
    #[inline(always)]
    pub fn entry(&self, window: u32) -> u32 {
        let tb = self.table_bits;
        let e = self.table[(window >> (32 - tb)) as usize];
        if e & SUB == 0 {
            return e;
        }
        let bits = e & 31;
        let off = ((e & !SUB) >> 5) as usize;
        let idx = ((window << tb) >> (32 - bits)) as usize;
        self.table.get(off + idx).copied().unwrap_or(0)
    }
}

/// Builds length-limited Huffman code lengths from symbol frequencies, choosing exactly
/// the lengths 7-Zip's and Microsoft's LZMS coders choose: leaves sorted by (frequency,
/// symbol), two-queue tree construction preferring leaves on ties, depth clamping to
/// `max_len`, and the longest lengths given to the least frequent symbols.
pub fn lengths_from_freqs(freqs: &[u32], max_len: u32, lens: &mut [u8]) {
    const BITS: u32 = 10;
    const MASK: u32 = (1 << BITS) - 1;
    debug_assert!(freqs.len() <= 1 << BITS && lens.len() >= freqs.len());
    // Counting sort by frequency (symbols stay in ascending order within a bucket); the
    // few frequencies past the buckets are sorted by key.
    const BUCKETS: usize = 256;
    let mut start = [0u32; BUCKETS + 1];
    for (i, &f) in freqs.iter().enumerate() {
        lens[i] = 0;
        if f != 0 {
            start[(f as usize).min(BUCKETS)] += 1;
        }
    }
    let mut num = 0u32;
    for c in start.iter_mut().skip(1) {
        let n = *c;
        *c = num;
        num += n;
    }
    let num = num as usize;
    let big = start[BUCKETS] as usize;
    let mut buf = [0u32; 1 << BITS];
    for (i, &f) in freqs.iter().enumerate() {
        if f != 0 {
            let b = (f as usize).min(BUCKETS);
            buf[start[b] as usize] = i as u32 | (f << BITS);
            start[b] += 1;
        }
    }
    let p = &mut buf[..num];
    p[big..].sort_unstable();
    if num <= 2 {
        let (mut lo, mut hi) = (0usize, 1usize);
        if num >= 1 {
            hi = (p[num - 1] & MASK) as usize;
            if num == 2 {
                lo = (p[0] & MASK) as usize;
                if lo > hi {
                    std::mem::swap(&mut lo, &mut hi);
                }
            } else if hi == 0 {
                hi = 1;
            }
        }
        if lo < lens.len() {
            lens[lo] = 1;
        }
        if hi < lens.len() {
            lens[hi] = 1;
        }
        return;
    }
    // Tree construction in place: slots [0, e) become internal nodes (frequency in the
    // high bits until they get a parent, then the parent index); the low bits keep the
    // sorted leaf symbols.
    let (mut i, mut b, mut e) = (0usize, 0usize, 0usize);
    loop {
        let mut freq = 0u32;
        for _ in 0..2 {
            let leaf = i != num && (b == e || (p[i] >> BITS) <= (p[b] >> BITS));
            let n = if leaf {
                i += 1;
                i - 1
            } else {
                b += 1;
                b - 1
            };
            freq += p[n] & !MASK;
            p[n] = (p[n] & MASK) | ((e as u32) << BITS);
        }
        p[e] = (p[e] & MASK) | freq;
        e += 1;
        if num - e <= 1 {
            break;
        }
    }
    let mut counts = [0u32; MAX_LEN + 2];
    counts[1] = 2;
    e -= 1;
    p[e] &= MASK;
    while e > 0 {
        e -= 1;
        let parent = (p[e] >> BITS) as usize;
        let mut len = (p[parent] >> BITS) + 1;
        p[e] = (p[e] & MASK) | (len << BITS);
        if len >= max_len {
            len = max_len - 1;
            while len > 1 && counts[len as usize] == 0 {
                len -= 1;
            }
        }
        counts[len as usize] = counts[len as usize].wrapping_sub(1);
        counts[len as usize + 1] += 2;
    }
    let mut idx = 0;
    for len in (1..=max_len as usize).rev() {
        for _ in 0..counts[len] {
            // Only reachable with an alphabet too large for `max_len`.
            let Some(&v) = p.get(idx) else { return };
            lens[(v & MASK) as usize] = len as u8;
            idx += 1;
        }
    }
}

/// Copies an LZ77 match of `len` bytes from `dist` bytes back to `out[pos..]`. The
/// caller has checked `dist <= pos` and `pos + len <= out.len()`.
#[inline(always)]
pub fn lz_copy(out: &mut [u8], pos: usize, dist: usize, len: usize) {
    let src = pos - dist;
    if dist >= 8 && len <= 64 && pos + len + 8 <= out.len() {
        // Eight bytes at a time; the tail past `len` is overwritten by later output.
        let mut i = 0;
        while i < len {
            let v: [u8; 8] = out[src + i..src + i + 8].try_into().unwrap();
            out[pos + i..pos + i + 8].copy_from_slice(&v);
            i += 8;
        }
        return;
    }
    if dist >= len {
        out.copy_within(src..src + len, pos);
    } else if dist == 1 {
        let b = out[src];
        out[pos..pos + len].fill(b);
    } else {
        let mut done = 0;
        while done < len {
            let n = dist.min(len - done);
            out.copy_within(src + done..src + done + n, pos + done);
            done += n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_canonical() {
        let lens = [2u8, 1, 3, 3];
        let mut d = Decoder::new(2);
        assert!(d.build(&lens));
        // Codes: sym1 = 0, sym0 = 10, sym2 = 110, sym3 = 111.
        assert_eq!(d.decode(0), Some((1, 1)));
        assert_eq!(d.decode(0b10 << 30), Some((0, 2)));
        assert_eq!(d.decode(0b110 << 29), Some((2, 3)));
        assert_eq!(d.decode(0b111 << 29), Some((3, 3)));
        assert!(!d.build(&[1, 1, 1]));
    }

    #[test]
    fn lengths_are_prefix_free_and_limited() {
        let freqs: Vec<u32> = (0..300).map(|i| 1 + (i * i) % 977).collect();
        let mut lens = vec![0u8; 300];
        lengths_from_freqs(&freqs, 15, &mut lens);
        let kraft: f64 = lens.iter().map(|&l| 0.5f64.powi(l as i32)).sum();
        assert!((kraft - 1.0).abs() < 1e-9);
        assert!(lens.iter().all(|&l| (1..=15).contains(&l)));
        // Fibonacci frequencies force depths past the limit.
        let mut fib = vec![1u32, 1];
        while fib.len() < 30 {
            let n = fib[fib.len() - 1] + fib[fib.len() - 2];
            fib.push(n);
        }
        let mut lens = vec![0u8; 30];
        lengths_from_freqs(&fib, 15, &mut lens);
        let kraft: f64 = lens.iter().map(|&l| 0.5f64.powi(l as i32)).sum();
        assert!((kraft - 1.0).abs() < 1e-9);
        assert!(lens.iter().all(|&l| (1..=15).contains(&l)));
    }

    #[test]
    fn overlapping_copy() {
        let mut v = b"abc\0\0\0\0\0\0\0".to_vec();
        lz_copy(&mut v, 3, 3, 7);
        assert_eq!(&v, b"abcabcabca");
    }
}
