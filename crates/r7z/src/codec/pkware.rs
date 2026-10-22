//! PKWARE's legacy zip methods, decode only: Shrink (1), Reduce (2 to 5, compression factor
//! 1 to 4) and Implode (6). All three read the packed entry LSB-first and stop after the
//! entry's declared uncompressed size.
//!
//! Shrink is LZW whose code size the compressor controls: `256 1` widens the codes and
//! `256 2` frees the leaf entries of the table. Reduce has two stages: follower sets decode
//! a probabilistic byte stream, which a DLE-escaped back-reference coder then expands through
//! a sliding window. Implode is LZ77 over a 4 KiB or 8 KiB window whose literals, match lengths
//! and distance high bits are Shannon-Fano coded with two or three stored trees.

use std::io::{self, Read};

/// Shrink's control symbol, which introduces a code-size change or a partial clear.
const CONTROL: usize = 256;
/// First table entry that Shrink can define; codes below it are literals or control.
const FIRST: usize = 257;
/// Shrink's table size: codes are at most 13 bits.
const TABLE: usize = 1 << 13;
/// Marks a free table slot.
const UNUSED: u16 = u16::MAX;
/// Reduce's escape byte. Back-references reach 4096 bytes back, Implode's 8192.
const DLE: u8 = 144;
/// Back-reference window, a power of two covering both Reduce and Implode distances.
const WINDOW: usize = 1 << 13;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("pkware: {msg}"))
}

/// LSB-first bit reader. Input is read ahead into a 64-bit buffer; running out of input is an
/// error only when the decoder needs bits that do not exist.
struct Bits<R> {
    inner: R,
    acc: u64,
    n: u32,
}

impl<R: Read> Bits<R> {
    fn new(inner: R) -> Self {
        Bits {
            inner,
            acc: 0,
            n: 0,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        while self.n <= 56 {
            let mut b = [0u8];
            match self.inner.read(&mut b) {
                Ok(0) => break,
                Ok(_) => {
                    self.acc |= u64::from(b[0]) << self.n;
                    self.n += 8;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// The next `k` (at most 16) bits, not consumed. Bits past the end of input read as zero.
    fn peek(&mut self, k: u32) -> io::Result<u32> {
        self.fill()?;
        Ok((self.acc & ((1u64 << k) - 1)) as u32)
    }

    fn skip(&mut self, k: u32) -> io::Result<()> {
        if k > self.n {
            return Err(bad("truncated stream"));
        }
        self.acc >>= k;
        self.n -= k;
        Ok(())
    }

    fn bits(&mut self, k: u32) -> io::Result<u32> {
        let v = self.peek(k)?;
        self.skip(k)?;
        Ok(v)
    }
}

/// One decoding step. It appends the bytes it produces to `out` and consumes input, or fails.
trait Step {
    fn step(&mut self, out: &mut Vec<u8>) -> io::Result<()>;
}

/// Serves a stepper's output as a reader that ends after exactly `left` bytes.
struct Limited<S> {
    step: S,
    out: Vec<u8>,
    pos: usize,
    left: u64,
}

fn limited<S>(step: S, size: u64) -> Limited<S> {
    Limited {
        step,
        out: Vec::new(),
        pos: 0,
        left: size,
    }
}

impl<S: Step> Read for Limited<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.left == 0 {
            return Ok(0);
        }
        while self.pos == self.out.len() {
            self.out.clear();
            self.pos = 0;
            self.step.step(&mut self.out)?;
        }
        let n = buf
            .len()
            .min(self.out.len() - self.pos)
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        self.left -= n as u64;
        Ok(n)
    }
}

/// The last `WINDOW` bytes produced, for back-references. Positions before the start are zero.
struct Window {
    buf: Vec<u8>,
    pos: usize,
}

impl Window {
    fn new() -> Self {
        Window {
            buf: vec![0; WINDOW],
            pos: 0,
        }
    }

    fn put(&mut self, out: &mut Vec<u8>, b: u8) {
        out.push(b);
        self.buf[self.pos % WINDOW] = b;
        self.pos = self.pos.wrapping_add(1);
    }

    /// Copies `n` bytes starting `dist` bytes back; overlapping copies repeat the pattern.
    fn copy(&mut self, out: &mut Vec<u8>, dist: usize, n: usize) {
        for _ in 0..n {
            let b = self.buf[self.pos.wrapping_sub(dist) % WINDOW];
            self.put(out, b);
        }
    }
}

/// Canonical Shannon-Fano codes from bit lengths (APPNOTE 5.3.8). Symbols are sorted by length
/// (ties by index) and codes are handed out from the longest length down. Each code is a
/// 16-bit left-aligned value. Lengths must be in 1..=16.
fn assign_codes(lens: &[u8]) -> Vec<u32> {
    let mut order: Vec<usize> = (0..lens.len()).collect();
    order.sort_by_key(|&s| lens[s]);
    let mut codes = vec![0u32; lens.len()];
    let (mut code, mut inc, mut last) = (0u32, 0u32, 0u8);
    for &s in order.iter().rev() {
        code += inc;
        if lens[s] != last {
            last = lens[s];
            inc = 1 << (16 - u32::from(last));
        }
        codes[s] = code;
    }
    codes
}

/// A Shannon-Fano code decoded by looking up the next `bits` input bits. Each entry is
/// (symbol, code length); length 0 marks a bit pattern that no code covers.
struct Tree {
    bits: u32,
    table: Vec<(u8, u8)>,
}

impl Tree {
    fn from_lengths(lens: &[u8]) -> io::Result<Tree> {
        let codes = assign_codes(lens);
        let bits = u32::from(lens.iter().copied().max().unwrap_or(1));
        let mut table = vec![(0u8, 0u8); 1 << bits];
        for (sym, (&code, &len)) in codes.iter().zip(lens).enumerate() {
            let l = u32::from(len);
            if code >= 1 << 16 {
                return Err(bad("oversubscribed Shannon-Fano tree"));
            }
            // The stream is LSB-first, so the table index is the bit-reversed code.
            let rev = (code >> (16 - l)).reverse_bits() >> (32 - l);
            for fill in 0..(1u32 << (bits - l)) {
                let idx = (rev | (fill << l)) as usize;
                if table[idx].1 != 0 {
                    return Err(bad("overlapping Shannon-Fano codes"));
                }
                table[idx] = (sym as u8, len);
            }
        }
        Ok(Tree { bits, table })
    }

    fn read<R: Read>(&self, bits: &mut Bits<R>) -> io::Result<usize> {
        let (sym, len) = self.table[bits.peek(self.bits)? as usize];
        if len == 0 {
            return Err(bad("invalid Shannon-Fano code"));
        }
        bits.skip(u32::from(len))?;
        Ok(usize::from(sym))
    }
}

/// Reads one stored tree over `n` symbols: a byte count minus one, then one byte per run with
/// (run length - 1) in the high nibble and (code length - 1) in the low nibble.
fn read_tree<R: Read>(bits: &mut Bits<R>, n: usize) -> io::Result<Tree> {
    let bytes = bits.bits(8)? + 1;
    let mut lens: Vec<u8> = Vec::with_capacity(n);
    for _ in 0..bytes {
        let b = bits.bits(8)?;
        let run = (b >> 4) as usize + 1;
        if lens.len() + run > n {
            return Err(bad("Shannon-Fano tree is larger than its alphabet"));
        }
        lens.resize(lens.len() + run, (b & 15) as u8 + 1);
    }
    if lens.len() != n {
        return Err(bad("Shannon-Fano tree is smaller than its alphabet"));
    }
    Tree::from_lengths(&lens)
}

/// Shrink (method 1), decoding `size` bytes.
pub fn shrink<R: Read>(inner: R, size: u64) -> impl Read {
    limited(
        Shrinker {
            bits: Bits::new(inner),
            code_size: 9,
            prefix: vec![UNUSED; TABLE],
            suffix: vec![0; TABLE],
            parent: vec![false; TABLE],
            prev: None,
            cursor: FIRST,
        },
        size,
    )
}

struct Shrinker<R> {
    bits: Bits<R>,
    code_size: u32,
    /// Parent code of each table entry, `UNUSED` for a free slot.
    prefix: Vec<u16>,
    /// Final byte of each table entry's string.
    suffix: Vec<u8>,
    /// Scratch for partial clears: whether an entry is another entry's parent.
    parent: Vec<bool>,
    /// The previous code. Its entry (previous code, next string's first byte) is added when
    /// the next code arrives, even when a partial clear came in between.
    prev: Option<usize>,
    /// No free slot lies below this index.
    cursor: usize,
}

impl<R: Read> Shrinker<R> {
    fn free_slot(&mut self) -> Option<usize> {
        while self.cursor < TABLE && self.prefix[self.cursor] != UNUSED {
            self.cursor += 1;
        }
        (self.cursor < TABLE).then_some(self.cursor)
    }

    /// Appends the string for `code` to `out` and returns its first byte.
    fn emit(&self, code: usize, out: &mut Vec<u8>) -> io::Result<u8> {
        let start = out.len();
        let mut c = code;
        while c >= 256 {
            if c >= TABLE || self.prefix[c] == UNUSED || out.len() - start >= TABLE {
                return Err(bad("code refers to an unassigned entry"));
            }
            out.push(self.suffix[c]);
            c = usize::from(self.prefix[c]);
        }
        out.push(c as u8);
        out[start..].reverse();
        Ok(out[start])
    }

    fn control(&mut self) -> io::Result<()> {
        match self.bits.bits(self.code_size)? {
            1 if self.code_size < 13 => self.code_size += 1,
            1 => return Err(bad("Shrink code size grows past 13 bits")),
            2 => self.partial_clear(),
            _ => return Err(bad("unknown Shrink control code")),
        }
        Ok(())
    }

    /// Frees every leaf entry, judged on the table as it stands before any is freed. The
    /// previous code's entry is still pending, so it is added after the clear, into the
    /// lowest free slot (which may be the previous code's own, since it may be a leaf too).
    fn partial_clear(&mut self) {
        self.parent.fill(false);
        for &p in &self.prefix[FIRST..] {
            if p != UNUSED {
                self.parent[usize::from(p)] = true;
            }
        }
        for (c, p) in self.prefix.iter_mut().enumerate().skip(FIRST) {
            if *p != UNUSED && !self.parent[c] {
                *p = UNUSED;
            }
        }
        self.cursor = FIRST;
    }
}

impl<R: Read> Step for Shrinker<R> {
    fn step(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let code = self.bits.bits(self.code_size)? as usize;
        if code == CONTROL {
            return self.control();
        }
        let slot = if self.prev.is_some() {
            self.free_slot()
        } else {
            None
        };
        let first = match (self.prev, slot) {
            // The code being defined is the previous string followed by its own first byte.
            (Some(p), Some(s)) if s == code => {
                let f = self.emit(p, out)?;
                out.push(f);
                f
            }
            _ => self.emit(code, out)?,
        };
        if let (Some(p), Some(s)) = (self.prev, slot) {
            self.prefix[s] = p as u16;
            self.suffix[s] = first;
        }
        self.prev = Some(code);
        Ok(())
    }
}

/// Bits needed for an index into a follower set of `n` (at least 1) entries.
fn index_bits(n: usize) -> u32 {
    usize::BITS - (n - 1).leading_zeros()
}

/// Reduce (methods 2 to 5), where `factor` is 1 to 4, decoding `size` bytes.
pub fn reduce<R: Read>(inner: R, factor: u8, size: u64) -> io::Result<impl Read> {
    if !(1..=4).contains(&factor) {
        return Err(bad("Reduce factor outside 1 to 4"));
    }
    let mut bits = Bits::new(inner);
    // Follower sets come from S(255) down to S(0), each a 6-bit count and that many bytes.
    let mut sets: Vec<Vec<u8>> = vec![Vec::new(); 256];
    for set in sets.iter_mut().rev() {
        let n = bits.bits(6)?;
        *set = (0..n)
            .map(|_| bits.bits(8).map(|v| v as u8))
            .collect::<io::Result<Vec<u8>>>()?;
    }
    Ok(limited(
        Reducer {
            bits,
            sets,
            last: 0,
            factor: u32::from(factor),
            state: Expand::Literal,
            win: Window::new(),
        },
        size,
    ))
}

/// Stage two's state, which reads one intermediate byte at a time.
#[derive(Clone, Copy)]
enum Expand {
    Literal,
    /// After a DLE: a length/distance header, or a zero standing for a literal DLE.
    Escape,
    /// A header whose length field saturated: the next byte adds to the length.
    Extended {
        head: u8,
        len: usize,
    },
    /// The next byte is the low byte of the distance.
    Distance {
        head: u8,
        len: usize,
    },
}

struct Reducer<R> {
    bits: Bits<R>,
    sets: Vec<Vec<u8>>,
    /// Stage one's previous output byte, which selects the follower set.
    last: u8,
    factor: u32,
    state: Expand,
    win: Window,
}

impl<R: Read> Reducer<R> {
    /// Stage one: the next byte of the intermediate stream.
    fn next_byte(&mut self) -> io::Result<u8> {
        let set = &self.sets[usize::from(self.last)];
        let v = if set.is_empty() || self.bits.bits(1)? == 1 {
            self.bits.bits(8)? as u8
        } else {
            let i = self.bits.bits(index_bits(set.len()))? as usize;
            *set.get(i)
                .ok_or_else(|| bad("follower index out of range"))?
        };
        self.last = v;
        Ok(v)
    }
}

impl<R: Read> Step for Reducer<R> {
    fn step(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let c = self.next_byte()?;
        let lmask = (1usize << (8 - self.factor)) - 1;
        self.state = match self.state {
            Expand::Literal if c == DLE => Expand::Escape,
            Expand::Literal => {
                self.win.put(out, c);
                Expand::Literal
            }
            Expand::Escape if c == 0 => {
                self.win.put(out, DLE);
                Expand::Literal
            }
            Expand::Escape if (usize::from(c) & lmask) == lmask => Expand::Extended {
                head: c,
                len: lmask,
            },
            Expand::Escape => Expand::Distance {
                head: c,
                len: usize::from(c) & lmask,
            },
            Expand::Extended { head, len } => Expand::Distance {
                head,
                len: len + usize::from(c),
            },
            Expand::Distance { head, len } => {
                let high = usize::from(head) >> (8 - self.factor);
                let dist = ((high << 8) | usize::from(c)) + 1;
                self.win.copy(out, dist, len + 3);
                Expand::Literal
            }
        };
        Ok(())
    }
}

/// Implode (method 6), decoding `size` bytes. `flags` is the entry's general purpose bit
/// flags: bit 1 selects an 8 KiB window (else 4 KiB) and bit 2 three trees (else two).
pub fn implode<R: Read>(inner: R, flags: u16, size: u64) -> io::Result<impl Read> {
    let mut bits = Bits::new(inner);
    let lit = if flags & 4 != 0 {
        Some(read_tree(&mut bits, 256)?)
    } else {
        None
    };
    let len = read_tree(&mut bits, 64)?;
    let dist = read_tree(&mut bits, 64)?;
    let min_len = if lit.is_some() { 3 } else { 2 };
    Ok(limited(
        Imploder {
            bits,
            lit,
            len,
            dist,
            min_len,
            dist_bits: if flags & 2 != 0 { 7 } else { 6 },
            win: Window::new(),
        },
        size,
    ))
}

struct Imploder<R> {
    bits: Bits<R>,
    lit: Option<Tree>,
    len: Tree,
    dist: Tree,
    /// 3 with a literal tree, else 2.
    min_len: usize,
    /// Low distance bits stored raw: 7 with an 8 KiB window, else 6.
    dist_bits: u32,
    win: Window,
}

impl<R: Read> Step for Imploder<R> {
    fn step(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.bits.bits(1)? == 1 {
            let b = match &self.lit {
                Some(t) => t.read(&mut self.bits)?,
                None => self.bits.bits(8)? as usize,
            };
            self.win.put(out, b as u8);
        } else {
            let low = self.bits.bits(self.dist_bits)? as usize;
            let high = self.dist.read(&mut self.bits)?;
            let dist = ((high << self.dist_bits) | low) + 1;
            let mut len = self.len.read(&mut self.bits)? + self.min_len;
            if len == 63 + self.min_len {
                len += self.bits.bits(8)? as usize;
            }
            self.win.copy(out, dist, len);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// LSB-first bit writer, the inverse of `Bits`.
    #[derive(Default)]
    struct BitWriter {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl BitWriter {
        /// Writes the low `k` bits of `v`, least significant first.
        fn put(&mut self, v: u32, k: u32) {
            debug_assert!(k == 32 || v >> k == 0);
            self.acc |= u64::from(v) << self.n;
            self.n += k;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.acc as u8);
            }
            self.out
        }
    }

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. ".repeat(300)
    }

    fn noise(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    /// Inputs covering empty, one byte, DLE, long runs, text, noise, and a skewed mix that
    /// exercises follower sets, escapes and long matches.
    fn samples() -> Vec<Vec<u8>> {
        let mut x = 0x2545_f491u32;
        let skewed: Vec<u8> = (0..150_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                b"aaaaaaaabbbc\x90\x00"[x as usize % 14]
            })
            .collect();
        vec![
            vec![],
            vec![b'A'],
            vec![DLE],
            vec![b'a'; 3000],
            text(),
            noise(300_000, 0x9e37_79b9),
            skewed,
        ]
    }

    fn decode_all(mut r: impl Read) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Decodes `z` as zip method `method` (1 Shrink, 2 to 5 Reduce, 6 Implode).
    fn decode_method(method: u16, flags: u16, z: &[u8], size: u64) -> io::Result<Vec<u8>> {
        match method {
            1 => decode_all(shrink(z, size)),
            2..=5 => decode_all(reduce(z, (method - 1) as u8, size)?),
            _ => decode_all(implode(z, flags, size)?),
        }
    }

    /// Shrink encoder with the decoder's rules. A partial clear comes after every
    /// `clear_every` emitted codes and whenever the table is full, before the pending entry
    /// (previous code plus next byte) is added, so leaves are judged without it.
    fn shrink_encode(data: &[u8], clear_every: Option<usize>) -> Vec<u8> {
        let mut e = ShrinkEncoder {
            w: BitWriter::default(),
            size: 9,
            map: HashMap::new(),
            key: vec![None; TABLE],
            kids: vec![0; TABLE],
            next: FIRST,
        };
        let mut cur: Option<u16> = None;
        let mut emitted = 0usize;
        let mut clear_due = false;
        for &b in data {
            let Some(w) = cur else {
                cur = Some(u16::from(b));
                continue;
            };
            if let Some(&c) = e.map.get(&(w, b)) {
                cur = Some(c);
                continue;
            }
            e.code(w);
            emitted += 1;
            clear_due |= clear_every.is_some_and(|n| emitted.is_multiple_of(n));
            // A periodic clear waits for a code that is a literal or already has a child, so the
            // pending entry never hangs off a freed leaf. A full table clears at once.
            let full = e.free_slot().is_none();
            if full || (clear_due && (w < 256 || e.kids[usize::from(w)] > 0)) {
                e.w.put(CONTROL as u32, e.size);
                e.w.put(2, e.size);
                e.clear();
                clear_due = false;
            }
            if let Some(slot) = e.free_slot() {
                e.add(slot, (w, b));
            }
            cur = Some(u16::from(b));
        }
        if let Some(w) = cur {
            e.code(w);
        }
        e.w.finish()
    }

    struct ShrinkEncoder {
        w: BitWriter,
        size: u32,
        map: HashMap<(u16, u8), u16>,
        /// (parent, byte) of each live entry.
        key: Vec<Option<(u16, u8)>>,
        /// Number of live children of each code.
        kids: Vec<u32>,
        next: usize,
    }

    impl ShrinkEncoder {
        /// Emits a code, first widening the codes with `256 1` when it no longer fits.
        fn code(&mut self, c: u16) {
            while u32::from(c) >> self.size != 0 {
                self.w.put(CONTROL as u32, self.size);
                self.w.put(1, self.size);
                self.size += 1;
            }
            self.w.put(u32::from(c), self.size);
        }

        fn free_slot(&mut self) -> Option<usize> {
            while self.next < TABLE && self.key[self.next].is_some() {
                self.next += 1;
            }
            (self.next < TABLE).then_some(self.next)
        }

        fn add(&mut self, slot: usize, k: (u16, u8)) {
            self.key[slot] = Some(k);
            self.map.insert(k, slot as u16);
            self.kids[usize::from(k.0)] += 1;
        }

        /// Frees the leaves, judged before any is freed.
        fn clear(&mut self) {
            let leaves: Vec<usize> = (FIRST..TABLE)
                .filter(|&c| self.key[c].is_some() && self.kids[c] == 0)
                .collect();
            for c in leaves {
                let k = self.key[c].take().unwrap();
                self.map.remove(&k);
                self.kids[usize::from(k.0)] -= 1;
            }
            self.next = FIRST;
        }
    }

    /// Reduce stage-two tokens: DLE-escaped literals and (distance, length) back-references.
    fn reduce_tokens(data: &[u8], factor: u32) -> Vec<u8> {
        let max_dist = 1usize << (8 + factor);
        let lmask = (1usize << (8 - factor)) - 1;
        let mut out = Vec::new();
        let mut seen: HashMap<&[u8], usize> = HashMap::new();
        let mut i = 0;
        while i < data.len() {
            let mut best = (0usize, 0usize);
            if let Some(&p) = data.get(i..i + 3).and_then(|k| seen.get(k)) {
                if i - p <= max_dist {
                    let max = (lmask + 255 + 3).min(data.len() - i);
                    let len = (0..max).take_while(|&k| data[p + k] == data[i + k]).count();
                    best = (i - p, len);
                }
            }
            // A header byte of zero would read as a literal DLE, so a length-3 match at
            // distance 256 or less is not usable.
            let usable = best.1 >= 3 && !(best.1 == 3 && best.0 <= 256);
            let step = if usable {
                let (d, l) = (best.0 - 1, best.1 - 3);
                out.push(DLE);
                out.push((((d >> 8) << (8 - factor)) | l.min(lmask)) as u8);
                if l >= lmask {
                    out.push((l - lmask) as u8);
                }
                out.push((d & 0xFF) as u8);
                best.1
            } else {
                if data[i] == DLE {
                    out.push(DLE);
                    out.push(0);
                } else {
                    out.push(data[i]);
                }
                1
            };
            for k in i..i + step {
                if let Some(key) = data.get(k..k + 3) {
                    seen.insert(key, k);
                }
            }
            i += step;
        }
        out
    }

    /// Reduce encoder: the stage-two tokens, coded with follower sets.
    fn reduce_encode(data: &[u8], factor: u32) -> Vec<u8> {
        let inter = reduce_tokens(data, factor);
        let mut sets: Vec<Vec<u8>> = vec![Vec::new(); 256];
        let mut last = 0u8;
        for &b in &inter {
            let set = &mut sets[usize::from(last)];
            if set.len() < 32 && !set.contains(&b) {
                set.push(b);
            }
            last = b;
        }
        let mut w = BitWriter::default();
        for set in sets.iter().rev() {
            w.put(set.len() as u32, 6);
            for &v in set {
                w.put(u32::from(v), 8);
            }
        }
        let mut last = 0u8;
        for &b in &inter {
            let set = &sets[usize::from(last)];
            match set.iter().position(|&s| s == b) {
                Some(i) => {
                    w.put(0, 1);
                    w.put(i as u32, index_bits(set.len()));
                }
                None if set.is_empty() => w.put(u32::from(b), 8),
                None => {
                    w.put(1, 1);
                    w.put(u32::from(b), 8);
                }
            }
            last = b;
        }
        w.finish()
    }

    #[derive(Clone, Copy)]
    enum Tok {
        Lit(u8),
        Match { dist: usize, len: usize },
    }

    /// Greedy LZ77 over the most recent occurrence of each `mml`-byte prefix.
    fn implode_tokens(data: &[u8], window: usize, mml: usize) -> Vec<Tok> {
        let max_len = mml + 63 + 255;
        let mut toks = Vec::new();
        let mut seen: HashMap<&[u8], usize> = HashMap::new();
        let mut i = 0;
        while i < data.len() {
            let mut hit = None;
            if let Some(&p) = data.get(i..i + mml).and_then(|k| seen.get(k)) {
                let max = max_len.min(data.len() - i);
                let len = (0..max).take_while(|&k| data[p + k] == data[i + k]).count();
                if i - p <= window && len >= mml {
                    hit = Some((i - p, len));
                }
            }
            let step = match hit {
                Some((dist, len)) => {
                    toks.push(Tok::Match { dist, len });
                    len
                }
                None => {
                    toks.push(Tok::Lit(data[i]));
                    1
                }
            };
            for k in i..i + step {
                if let Some(key) = data.get(k..k + mml) {
                    seen.insert(key, k);
                }
            }
            i += step;
        }
        toks
    }

    /// Huffman code lengths over `freq`, flattened and retried until none exceeds 16 bits.
    fn huffman_lengths(freq: &[u64]) -> Vec<u8> {
        let mut f = freq.to_vec();
        loop {
            let n = f.len();
            let mut parent = vec![usize::MAX; n];
            let mut live: Vec<(u64, usize)> = f.iter().copied().zip(0..).collect();
            while live.len() > 1 {
                live.sort_unstable();
                let (w1, a) = live.remove(0);
                let (w2, b) = live.remove(0);
                let id = parent.len();
                parent.push(usize::MAX);
                parent[a] = id;
                parent[b] = id;
                live.push((w1 + w2, id));
            }
            let lens: Vec<u8> = (0..n)
                .map(|s| {
                    let (mut d, mut x) = (0u8, s);
                    while parent[x] != usize::MAX {
                        x = parent[x];
                        d += 1;
                    }
                    d
                })
                .collect();
            if lens.iter().all(|&l| l <= 16) {
                return lens;
            }
            f = f.iter().map(|&x| x / 2 + 1).collect();
        }
    }

    /// Writes symbol `s` with its canonical code, most significant bit first.
    fn put_code(w: &mut BitWriter, codes: &[u32], lens: &[u8], s: usize) {
        let l = u32::from(lens[s]);
        let canon = codes[s] >> (16 - l);
        w.put(canon.reverse_bits() >> (32 - l), l);
    }

    /// Writes a tree in stored form: a byte count minus one, then nibble pairs per run.
    fn write_tree(w: &mut BitWriter, lens: &[u8]) {
        let mut runs: Vec<(u8, u8)> = Vec::new();
        for &l in lens {
            match runs.last_mut() {
                Some(r) if r.1 == l && r.0 < 16 => r.0 += 1,
                _ => runs.push((1, l)),
            }
        }
        w.put(runs.len() as u32 - 1, 8);
        for (run, l) in runs {
            w.put((u32::from(run - 1) << 4) | u32::from(l - 1), 8);
        }
    }

    /// Implode encoder: `dict8k` selects the 8 KiB window and `three` the literal tree.
    fn implode_encode(data: &[u8], dict8k: bool, three: bool) -> (u16, Vec<u8>) {
        let window = if dict8k { 8192 } else { 4096 };
        let mml = if three { 3 } else { 2 };
        let dist_bits: u32 = if dict8k { 7 } else { 6 };
        let toks = implode_tokens(data, window, mml);
        let mut lit_f = vec![1u64; 256];
        let mut len_f = vec![1u64; 64];
        let mut dist_f = vec![1u64; 64];
        for t in &toks {
            match *t {
                Tok::Lit(b) => lit_f[usize::from(b)] += 1,
                Tok::Match { dist, len } => {
                    len_f[(len - mml).min(63)] += 1;
                    dist_f[(dist - 1) >> dist_bits] += 1;
                }
            }
        }
        let lit = huffman_lengths(&lit_f);
        let len = huffman_lengths(&len_f);
        let dist = huffman_lengths(&dist_f);
        let (lit_c, len_c, dist_c) = (assign_codes(&lit), assign_codes(&len), assign_codes(&dist));
        let mut w = BitWriter::default();
        if three {
            write_tree(&mut w, &lit);
        }
        write_tree(&mut w, &len);
        write_tree(&mut w, &dist);
        for t in &toks {
            match *t {
                Tok::Lit(b) => {
                    w.put(1, 1);
                    if three {
                        put_code(&mut w, &lit_c, &lit, usize::from(b));
                    } else {
                        w.put(u32::from(b), 8);
                    }
                }
                Tok::Match { dist: d, len: l } => {
                    let (d, l) = (d - 1, l - mml);
                    w.put(0, 1);
                    w.put((d & ((1 << dist_bits) - 1)) as u32, dist_bits);
                    put_code(&mut w, &dist_c, &dist, d >> dist_bits);
                    put_code(&mut w, &len_c, &len, l.min(63));
                    if l >= 63 {
                        w.put((l - 63) as u32, 8);
                    }
                }
            }
        }
        let flags = (if dict8k { 2 } else { 0 }) | (if three { 4 } else { 0 });
        (flags, w.finish())
    }

    /// One stream per method and layout for `data`: (method, flags, packed bytes).
    fn streams(data: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
        let mut v = vec![(1, 0, shrink_encode(data, Some(4001)))];
        for f in 1..=4u32 {
            v.push((f as u16 + 1, 0, reduce_encode(data, f)));
        }
        for (dict8k, three) in [(false, false), (false, true), (true, false), (true, true)] {
            let (flags, z) = implode_encode(data, dict8k, three);
            v.push((6, flags, z));
        }
        v
    }

    #[test]
    fn shrink_round_trips_with_and_without_clears() {
        for data in samples() {
            for clear in [None, Some(97), Some(4001)] {
                let z = shrink_encode(&data, clear);
                let out = decode_method(1, 0, &z, data.len() as u64).unwrap();
                assert!(out == data, "len {} clear {clear:?}", data.len());
            }
        }
    }

    #[test]
    fn shrink_decodes_hand_built_codes() {
        // "A", "B", then (A,B) and (A,B) again: 65 66 257 257 gives "ABABAB".
        let mut w = BitWriter::default();
        for c in [65, 66, 257, 257] {
            w.put(c, 9);
        }
        assert_eq!(decode_method(1, 0, &w.finish(), 6).unwrap(), b"ABABAB");
        // 65 then 257 defines 257 in the same step it is used (KwKwK): "A", "AA", "AA".
        let mut w = BitWriter::default();
        for c in [65, 257, 257] {
            w.put(c, 9);
        }
        assert_eq!(decode_method(1, 0, &w.finish(), 5).unwrap(), b"AAAAA");
    }

    #[test]
    fn shrink_rejects_bad_codes() {
        let mut w = BitWriter::default();
        w.put(CONTROL as u32, 9);
        w.put(3, 9);
        let err = decode_method(1, 0, &w.finish(), 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let mut w = BitWriter::default();
        w.put(300, 9);
        let err = decode_method(1, 0, &w.finish(), 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reduce_round_trips_every_factor() {
        for data in samples() {
            for factor in 1..=4u32 {
                let z = reduce_encode(&data, factor);
                let out = decode_method(factor as u16 + 1, 0, &z, data.len() as u64).unwrap();
                assert!(out == data, "len {} factor {factor}", data.len());
            }
        }
    }

    #[test]
    fn reduce_decodes_hand_built_stream() {
        // Every follower set empty: 256 six-bit zero counts, then bytes stored as-is.
        // Intermediate "abc", a 6-byte copy 3 back, then a literal DLE.
        let mut z = vec![0u8; 192];
        z.extend_from_slice(&[b'a', b'b', b'c', DLE, 3, 2, DLE, 0]);
        assert_eq!(
            decode_method(2, 0, &z, 10).unwrap(),
            b"abcabcabc\x90".to_vec()
        );
    }

    #[test]
    fn implode_round_trips_all_layouts() {
        for data in samples() {
            for (dict8k, three) in [(false, false), (false, true), (true, false), (true, true)] {
                let (flags, z) = implode_encode(&data, dict8k, three);
                let out = decode_method(6, flags, &z, data.len() as u64).unwrap();
                assert!(out == data, "len {} flags {flags}", data.len());
            }
        }
    }

    #[test]
    fn codes_match_the_appnote_example() {
        // APPNOTE 5.3.8: lengths (3,3,3,3,3,2,4,4). Canonical codes are 101, 100, 011, 010,
        // 001, 11, 0001, 0000, as 16-bit left-aligned values.
        let codes = assign_codes(&[3, 3, 3, 3, 3, 2, 4, 4]);
        assert_eq!(
            codes,
            [0xA000, 0x8000, 0x6000, 0x4000, 0x2000, 0xC000, 0x1000, 0x0000]
        );
    }

    #[test]
    fn appnote_tree_header_decodes() {
        // APPNOTE 5.3.7 example header 0x02 0x42 0x01 0x13 describes the lengths above.
        // Code bits 11, 0001, 0000 (in stream order) decode to symbols 5, 6, 7; packed
        // LSB-first they are 0x23 0x00.
        let stream = [0x02, 0x42, 0x01, 0x13, 0x23, 0x00];
        let mut bits = Bits::new(&stream[..]);
        let tree = read_tree(&mut bits, 8).unwrap();
        assert_eq!(tree.read(&mut bits).unwrap(), 5);
        assert_eq!(tree.read(&mut bits).unwrap(), 6);
        assert_eq!(tree.read(&mut bits).unwrap(), 7);
    }

    #[test]
    fn rejects_oversubscribed_implode_tree() {
        let err = decode_method(6, 4, &[0xFF; 300], 10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn output_stops_at_the_declared_size() {
        let data = text();
        let half = data.len() / 2;
        for (method, flags, z) in streams(&data) {
            let out = decode_method(method, flags, &z, half as u64).unwrap();
            assert!(out == data[..half], "method {method} flags {flags}");
        }
    }

    #[test]
    fn truncated_streams_fail_as_invalid_data() {
        let data = text();
        for (method, flags, z) in streams(&data) {
            for cut in [0, 1, z.len() / 2, z.len() * 3 / 4] {
                let err = decode_method(method, flags, &z[..cut], data.len() as u64)
                    .expect_err("truncated stream decoded");
                assert_eq!(err.kind(), io::ErrorKind::InvalidData, "method {method}");
            }
        }
    }

    #[test]
    fn corrupt_streams_never_panic() {
        for data in [text(), noise(20_000, 7)] {
            let mut x = 12345u32;
            for (method, flags, z) in streams(&data) {
                for _ in 0..150 {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    let mut bad_z = z.clone();
                    let at = x as usize % bad_z.len();
                    bad_z[at] ^= 1 << (x >> 29);
                    let _ = decode_method(method, flags, &bad_z, data.len() as u64);
                }
            }
        }
    }
}
