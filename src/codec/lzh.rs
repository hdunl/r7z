//! LZ77 + Huffman decoders of the LHA family, shared by the LZH and ARJ handlers.
//!
//! - [`St1`]: the static-Huffman block coder of LHA `-lh4-`..`-lh7-` and ARJ methods 1-3
//!   (per block: a code-length tree, a literal/length tree and a position tree).
//! - [`Lh1`]: LHarc `-lh1-`, adaptive Huffman literals/lengths with fixed position codes.
//! - [`Lzs`] / [`Lz5`]: LArc `-lzs-` and `-lz5-`, plain LZSS with prefilled windows.
//! - [`ArjFast`]: ARJ method 4, Elias-gamma-like length and position codes.
//!
//! Every decoder writes into a [`Window`] ring and is driven by [`LzReader`], which decodes
//! a ring-sized chunk at a time and hands it out through `Read`. Bit streams are MSB-first.
//! Malformed input yields `Error::Corrupt`; every decode step either emits at least one byte
//! or consumes table input, so decoding always terminates.

use std::io::{self, Read};

use crate::error::{Error, Result};

/// Literal/length alphabet of the static-Huffman coders: 256 literals + lengths 3..=256.
const NC: usize = 510;
/// Code-length alphabet.
const NT: usize = 19;
/// Longest Huffman code.
const MAX_LEN: u32 = 16;

/// An MSB-first bit reader over a byte buffer. Reads past the end yield zero bits; the
/// decoders check [`Bits::overrun`] so that consuming them is reported as corruption.
pub struct Bits<D> {
    src: D,
    pos: usize,
    /// Pending bits, left-aligned.
    buf: u64,
    n: u32,
}

impl<D: AsRef<[u8]>> Bits<D> {
    pub fn new(src: D) -> Self {
        Bits {
            src,
            pos: 0,
            buf: 0,
            n: 0,
        }
    }

    /// Ensures at least 32 pending bits.
    #[inline(always)]
    fn refill(&mut self) {
        if self.n < 32 {
            self.load();
        }
    }

    fn load(&mut self) {
        let data = self.src.as_ref();
        if let Some(chunk) = data.get(self.pos..self.pos + 8) {
            let v = u64::from_be_bytes(chunk.try_into().unwrap());
            // The partial byte past the counted ones is ORed in again, identically, later.
            self.buf |= v >> self.n;
            let k = (64 - self.n) / 8;
            self.pos += k as usize;
            self.n += k * 8;
        } else {
            while self.n <= 56 {
                let b = data.get(self.pos).copied().unwrap_or(0);
                self.pos += 1;
                self.buf |= (b as u64) << (56 - self.n);
                self.n += 8;
            }
        }
    }

    /// The next `k` (1..=32) bits without consuming them.
    #[inline]
    fn peek(&mut self, k: u32) -> u32 {
        self.refill();
        (self.buf >> (64 - k)) as u32
    }

    #[inline]
    fn consume(&mut self, k: u32) {
        self.buf <<= k;
        self.n -= k;
    }

    /// Reads `k` (0..=16) bits.
    #[inline]
    pub fn bits(&mut self, k: u32) -> u32 {
        if k == 0 {
            return 0;
        }
        let v = self.peek(k);
        self.consume(k);
        v
    }

    #[inline]
    fn bit(&mut self) -> u32 {
        self.bits(1)
    }

    /// More bits were consumed than the input holds.
    pub fn overrun(&self) -> bool {
        (self.pos as u64) * 8 - self.n as u64 > self.src.as_ref().len() as u64 * 8
    }

    fn check(&self) -> Result<()> {
        if self.overrun() {
            Err(Error::corrupt("compressed data ends early"))
        } else {
            Ok(())
        }
    }
}

/// A canonical MSB-first Huffman decoder: a `bits`-wide lookup table for short codes and a
/// canonical search for longer ones.
pub struct Huffman {
    bits: u32,
    /// `symbol << 5 | length`; length 31 marks a long code or an unassigned prefix.
    table: Vec<u16>,
    count: [u16; MAX_LEN as usize + 1],
    first: [u32; MAX_LEN as usize + 1],
    offset: [u16; MAX_LEN as usize + 1],
    sorted: Vec<u16>,
}

const SLOW: u16 = 31;

impl Huffman {
    pub fn new(bits: u32) -> Self {
        Huffman {
            bits,
            table: vec![SLOW; 1 << bits],
            count: [0; MAX_LEN as usize + 1],
            first: [0; MAX_LEN as usize + 1],
            offset: [0; MAX_LEN as usize + 1],
            sorted: Vec::new(),
        }
    }

    /// A tree with one symbol and zero-length code.
    pub fn single(&mut self, sym: usize) {
        self.table.fill((sym as u16) << 5);
        self.count = [0; MAX_LEN as usize + 1];
    }

    /// Builds from code lengths (0 = unused). Over-subscribed lengths are corrupt; codes an
    /// incomplete tree leaves unassigned fail when they are read.
    pub fn build(&mut self, lens: &[u8]) -> Result<()> {
        let mut count = [0u16; MAX_LEN as usize + 1];
        for &l in lens {
            if l as u32 > MAX_LEN {
                return Err(Error::corrupt("Huffman code too long"));
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut kraft = 0u32;
        for (l, &c) in count.iter().enumerate().skip(1) {
            kraft += (c as u32) << (MAX_LEN as usize - l);
        }
        if kraft > 1 << MAX_LEN {
            return Err(Error::corrupt("bad Huffman table"));
        }
        let mut code = 0u32;
        let mut idx = 0u16;
        for l in 1..=MAX_LEN as usize {
            code = (code + count[l - 1] as u32) << 1;
            self.first[l] = code;
            self.offset[l] = idx;
            idx += count[l];
        }
        self.count = count;
        self.sorted.clear();
        self.sorted.resize(idx as usize, 0);
        let mut next = self.offset;
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                self.sorted[next[l as usize] as usize] = s as u16;
                next[l as usize] += 1;
            }
        }
        self.table.fill(SLOW);
        let tb = self.bits;
        for (l, &n) in count.iter().enumerate().take(tb as usize + 1).skip(1) {
            let start = self.offset[l] as usize;
            for k in 0..n as usize {
                let c = (self.first[l] as usize + k) << (tb as usize - l);
                let e = (self.sorted[start + k] << 5) | l as u16;
                self.table[c..c + (1 << (tb as usize - l))].fill(e);
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn decode<D: AsRef<[u8]>>(&self, b: &mut Bits<D>) -> Result<usize> {
        let e = self.table[b.peek(self.bits) as usize];
        let l = (e & 31) as u32;
        if l != SLOW as u32 {
            b.consume(l);
            return Ok((e >> 5) as usize);
        }
        self.decode_long(b)
    }

    #[cold]
    fn decode_long<D: AsRef<[u8]>>(&self, b: &mut Bits<D>) -> Result<usize> {
        let code = b.peek(MAX_LEN);
        for l in self.bits + 1..=MAX_LEN {
            let c = code >> (MAX_LEN - l);
            let d = c.wrapping_sub(self.first[l as usize]);
            if d < self.count[l as usize] as u32 {
                b.consume(l);
                return Ok(self.sorted[self.offset[l as usize] as usize + d as usize] as usize);
            }
        }
        Err(Error::corrupt("invalid Huffman code"))
    }
}

/// A power-of-two ring holding decoded output not yet read and the match history.
pub struct Window {
    buf: Vec<u8>,
    mask: usize,
    /// Bytes decoded so far.
    pos: u64,
    /// Bytes handed out so far.
    out: u64,
    /// The ring starts with defined contents that matches may reference.
    prefilled: bool,
}

impl Window {
    pub fn new(size: usize) -> Self {
        let size = size.next_power_of_two();
        Window {
            buf: vec![0; size],
            mask: size - 1,
            pos: 0,
            out: 0,
            prefilled: false,
        }
    }

    /// A ring whose initial contents (length a power of two) are part of the history.
    pub fn prefilled(buf: Vec<u8>) -> Self {
        debug_assert!(buf.len().is_power_of_two());
        Window {
            mask: buf.len() - 1,
            buf,
            pos: 0,
            out: 0,
            prefilled: true,
        }
    }

    #[inline]
    fn put(&mut self, b: u8) {
        self.buf[self.pos as usize & self.mask] = b;
        self.pos += 1;
    }

    /// Copies `len` bytes from `dist` bytes back.
    #[inline]
    fn copy(&mut self, dist: usize, len: usize) -> Result<()> {
        if dist == 0 || dist > self.buf.len() || (!self.prefilled && dist as u64 > self.pos) {
            return Err(Error::corrupt("match distance is out of range"));
        }
        let d = self.pos as usize & self.mask;
        let s = d.wrapping_sub(dist) & self.mask;
        if dist >= len && s + len <= self.buf.len() && d + len <= self.buf.len() {
            self.buf.copy_within(s..s + len, d);
        } else {
            for k in 0..len {
                self.buf[(d + k) & self.mask] = self.buf[(s + k) & self.mask];
            }
        }
        self.pos += len as u64;
        Ok(())
    }

    /// Moves decoded bytes into `dst`.
    fn drain(&mut self, dst: &mut [u8]) -> usize {
        let avail = (self.pos - self.out) as usize;
        let mut n = avail.min(dst.len());
        let mut done = 0;
        while n > 0 {
            let s = self.out as usize & self.mask;
            let k = n.min(self.buf.len() - s);
            dst[done..done + k].copy_from_slice(&self.buf[s..s + k]);
            done += k;
            n -= k;
            self.out += k as u64;
        }
        done
    }
}

/// One LZ decoder: emits symbols into the window until `until` bytes exist (it may overrun
/// `until` by less than `MAX_MATCH`, never `end`).
pub trait Lz {
    const MAX_MATCH: usize;
    fn run(&mut self, w: &mut Window, until: u64, end: u64) -> Result<()>;
}

/// Reads exactly `size` decoded bytes from an [`Lz`] decoder.
pub struct LzReader<L> {
    lz: L,
    win: Window,
    size: u64,
}

impl<L: Lz> LzReader<L> {
    pub fn new(lz: L, win: Window, size: u64) -> Self {
        debug_assert!(win.buf.len() > L::MAX_MATCH);
        LzReader { lz, win, size }
    }
}

impl<L: Lz> Read for LzReader<L> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if self.win.out == self.win.pos {
            if self.win.pos >= self.size {
                return Ok(0);
            }
            let room = (self.win.buf.len() - L::MAX_MATCH) as u64;
            let until = (self.win.pos + room).min(self.size);
            self.lz
                .run(&mut self.win, until, self.size)
                .map_err(Error::into_io)?;
        }
        Ok(self.win.drain(dst))
    }
}

/// A ring big enough for every match a stream of `size` bytes can make with distances up to
/// `max_dist`, and at least 64 KiB for long streams so chunks stay large.
fn ring_size(size: u64, max_dist: usize) -> usize {
    let want = size.min(max_dist.max(1 << 16) as u64).max(1024) as usize;
    want.next_power_of_two()
}

/// Reads LHA's 3-bit-with-unary-extension code lengths (`pt_len`).
fn read_pt_len<D: AsRef<[u8]>>(
    b: &mut Bits<D>,
    lens: &mut [u8],
    nbit: u32,
    special: Option<usize>,
    tree: &mut Huffman,
) -> Result<()> {
    let nn = lens.len();
    let n = b.bits(nbit) as usize;
    if n == 0 {
        let c = b.bits(nbit) as usize;
        if c >= nn {
            return Err(Error::corrupt("bad Huffman table"));
        }
        lens.fill(0);
        tree.single(c);
        return Ok(());
    }
    if n > nn {
        return Err(Error::corrupt("bad Huffman table"));
    }
    let mut i = 0;
    while i < n {
        let mut c = b.peek(3);
        if c == 7 {
            let rest = ((b.peek(16) << 3) as u16).leading_ones();
            c += rest;
            if c > MAX_LEN {
                return Err(Error::corrupt("Huffman code too long"));
            }
            b.consume(c - 3);
        } else {
            b.consume(3);
        }
        lens[i] = c as u8;
        i += 1;
        if special == Some(i) {
            let z = b.bits(2) as usize;
            if i + z > nn {
                return Err(Error::corrupt("bad Huffman table"));
            }
            lens[i..i + z].fill(0);
            i += z;
        }
    }
    lens[i..].fill(0);
    tree.build(lens)
}

/// The static-Huffman block decoder (`-lh4-`..`-lh7-`, ARJ methods 1-3).
pub struct St1<D> {
    bits: Bits<D>,
    np: usize,
    pbit: u32,
    block_left: u32,
    c: Huffman,
    p: Huffman,
    t: Huffman,
    c_len: [u8; NC],
    t_len: [u8; NT],
    p_len: [u8; 17],
}

impl<D: AsRef<[u8]>> St1<D> {
    /// `np` position codes (dictionary bits + 1), sent with `pbit`-bit counts.
    pub fn new(src: D, np: usize, pbit: u32) -> Self {
        assert!(np <= 17);
        St1 {
            bits: Bits::new(src),
            np,
            pbit,
            block_left: 0,
            c: Huffman::new(12),
            p: Huffman::new(8),
            t: Huffman::new(8),
            c_len: [0; NC],
            t_len: [0; NT],
            p_len: [0; 17],
        }
    }

    fn read_c_len(&mut self) -> Result<()> {
        let b = &mut self.bits;
        let n = b.bits(9) as usize;
        if n == 0 {
            let c = b.bits(9) as usize;
            if c >= NC {
                return Err(Error::corrupt("bad Huffman table"));
            }
            self.c_len.fill(0);
            self.c.single(c);
            return Ok(());
        }
        if n > NC {
            return Err(Error::corrupt("bad Huffman table"));
        }
        let mut i = 0;
        while i < n {
            let c = self.t.decode(b)?;
            if c <= 2 {
                let run = match c {
                    0 => 1,
                    1 => b.bits(4) as usize + 3,
                    _ => b.bits(9) as usize + 20,
                };
                if i + run > NC {
                    return Err(Error::corrupt("bad Huffman table"));
                }
                self.c_len[i..i + run].fill(0);
                i += run;
            } else {
                self.c_len[i] = (c - 2) as u8;
                i += 1;
            }
        }
        self.c_len[i..].fill(0);
        self.c.build(&self.c_len)
    }

    fn start_block(&mut self) -> Result<()> {
        self.bits.check()?;
        let size = self.bits.bits(16);
        if size == 0 {
            return Err(Error::corrupt("empty compressed block"));
        }
        read_pt_len(&mut self.bits, &mut self.t_len, 5, Some(3), &mut self.t)?;
        self.read_c_len()?;
        let np = self.np;
        read_pt_len(
            &mut self.bits,
            &mut self.p_len[..np],
            self.pbit,
            None,
            &mut self.p,
        )?;
        self.block_left = size;
        Ok(())
    }
}

impl<D: AsRef<[u8]>> Lz for St1<D> {
    const MAX_MATCH: usize = 256;

    fn run(&mut self, w: &mut Window, until: u64, end: u64) -> Result<()> {
        while w.pos < until {
            if self.block_left == 0 {
                self.start_block()?;
            }
            self.block_left -= 1;
            let c = self.c.decode(&mut self.bits)?;
            if c < 256 {
                w.put(c as u8);
                continue;
            }
            let len = c - 253;
            let p = self.p.decode(&mut self.bits)? as u32;
            let dist = if p <= 1 {
                p as usize + 1
            } else {
                (1usize << (p - 1)) + self.bits.bits(p - 1) as usize + 1
            };
            w.copy(dist, len.min((end - w.pos) as usize))?;
        }
        self.bits.check()
    }
}

/// Reader for `-lh4-`..`-lh7-`: `dict_bits` 12, 13, 15 or 16.
pub fn lh_reader<D: AsRef<[u8]>>(src: D, size: u64, dict_bits: u32) -> LzReader<St1<D>> {
    let np = if dict_bits <= 13 {
        14
    } else {
        dict_bits as usize + 1
    };
    let pbit = if dict_bits <= 13 { 4 } else { 5 };
    st1_reader(src, size, np, pbit)
}

/// Reader for ARJ methods 1-3 (26 KiB dictionary, 17 position codes).
pub fn arj_reader<D: AsRef<[u8]>>(src: D, size: u64) -> LzReader<St1<D>> {
    st1_reader(src, size, 17, 5)
}

fn st1_reader<D: AsRef<[u8]>>(src: D, size: u64, np: usize, pbit: u32) -> LzReader<St1<D>> {
    let max_dist = 1usize << (np - 1);
    LzReader::new(
        St1::new(src, np, pbit),
        Window::new(ring_size(size, max_dist)),
        size,
    )
}

/// `-lh1-`: Okumura's LZHUF adaptive Huffman over 314 symbols (256 literals + lengths
/// 3..=60), 4 KiB window prefilled with spaces, fixed position codes plus 6 raw bits.
pub struct Lh1<D> {
    bits: Bits<D>,
    freq: Vec<u32>,
    son: Vec<usize>,
    prnt: Vec<usize>,
    pos_tree: Huffman,
}

const LH1_CHARS: usize = 314;
const LH1_T: usize = LH1_CHARS * 2 - 1;
const LH1_ROOT: usize = LH1_T - 1;
const LH1_MAX_FREQ: u32 = 0x8000;

impl<D: AsRef<[u8]>> Lh1<D> {
    pub fn new(src: D) -> Self {
        let mut d = Lh1 {
            bits: Bits::new(src),
            freq: vec![0; LH1_T + 1],
            son: vec![0; LH1_T],
            prnt: vec![0; LH1_T + LH1_CHARS],
            pos_tree: Huffman::new(8),
        };
        for i in 0..LH1_CHARS {
            d.freq[i] = 1;
            d.son[i] = i + LH1_T;
            d.prnt[i + LH1_T] = i;
        }
        let (mut i, mut j) = (0, LH1_CHARS);
        while j <= LH1_ROOT {
            d.freq[j] = d.freq[i] + d.freq[i + 1];
            d.son[j] = i;
            d.prnt[i] = j;
            d.prnt[i + 1] = j;
            i += 2;
            j += 1;
        }
        d.freq[LH1_T] = 0xFFFF;
        d.prnt[LH1_ROOT] = 0;
        // Position upper 6 bits: 1 code of 3 bits, 3 of 4, 8 of 5, 12 of 6, 24 of 7, 16 of 8.
        let mut lens = [0u8; 64];
        let mut k = 0;
        for (len, n) in [(3u8, 1), (4, 3), (5, 8), (6, 12), (7, 24), (8, 16)] {
            lens[k..k + n].fill(len);
            k += n;
        }
        d.pos_tree.build(&lens).expect("fixed table is complete");
        d
    }

    fn reconst(&mut self) {
        let (freq, son) = (&mut self.freq, &mut self.son);
        let mut j = 0;
        for i in 0..LH1_T {
            if son[i] >= LH1_T {
                freq[j] = freq[i].div_ceil(2);
                son[j] = son[i];
                j += 1;
            }
        }
        let mut i = 0;
        for j in LH1_CHARS..LH1_T {
            let f = freq[i] + freq[i + 1];
            freq[j] = f;
            let mut k = j - 1;
            while f < freq[k] {
                k -= 1;
            }
            k += 1;
            freq.copy_within(k..j, k + 1);
            freq[k] = f;
            son.copy_within(k..j, k + 1);
            son[k] = i;
            i += 2;
        }
        for (i, &k) in son.iter().enumerate() {
            self.prnt[k] = i;
            if k < LH1_T {
                self.prnt[k + 1] = i;
            }
        }
    }

    fn update(&mut self, sym: usize) {
        if self.freq[LH1_ROOT] == LH1_MAX_FREQ {
            self.reconst();
        }
        let mut c = self.prnt[sym + LH1_T];
        loop {
            self.freq[c] += 1;
            let k = self.freq[c];
            let mut l = c + 1;
            if k > self.freq[l] {
                while k > self.freq[l + 1] {
                    l += 1;
                }
                self.freq[c] = self.freq[l];
                self.freq[l] = k;
                let i = self.son[c];
                self.prnt[i] = l;
                if i < LH1_T {
                    self.prnt[i + 1] = l;
                }
                let j = self.son[l];
                self.son[l] = i;
                self.prnt[j] = c;
                if j < LH1_T {
                    self.prnt[j + 1] = c;
                }
                self.son[c] = j;
                c = l;
            }
            c = self.prnt[c];
            if c == 0 {
                break;
            }
        }
    }

    fn decode_char(&mut self) -> usize {
        let mut c = self.son[LH1_ROOT];
        while c < LH1_T {
            c += self.bits.bit() as usize;
            c = self.son[c];
        }
        let sym = c - LH1_T;
        self.update(sym);
        sym
    }
}

impl<D: AsRef<[u8]>> Lz for Lh1<D> {
    const MAX_MATCH: usize = 60;

    fn run(&mut self, w: &mut Window, until: u64, end: u64) -> Result<()> {
        while w.pos < until {
            let c = self.decode_char();
            if c < 256 {
                w.put(c as u8);
                continue;
            }
            let hi = self.pos_tree.decode(&mut self.bits)?;
            let dist = ((hi << 6) | self.bits.bits(6) as usize) + 1;
            w.copy(dist, (c - 253).min((end - w.pos) as usize))?;
        }
        self.bits.check()
    }
}

pub fn lh1_reader<D: AsRef<[u8]>>(src: D, size: u64) -> LzReader<Lh1<D>> {
    LzReader::new(Lh1::new(src), Window::prefilled(vec![b' '; 4096]), size)
}

/// LArc `-lzs-`: flag bit, then a literal byte or an 11-bit ring position and 4-bit length.
pub struct Lzs<D> {
    bits: Bits<D>,
}

impl<D: AsRef<[u8]>> Lz for Lzs<D> {
    const MAX_MATCH: usize = 17;

    fn run(&mut self, w: &mut Window, until: u64, end: u64) -> Result<()> {
        let b = &mut self.bits;
        while w.pos < until {
            if b.bit() == 1 {
                w.put(b.bits(8) as u8);
                continue;
            }
            let mpos = b.bits(11) as u64;
            let len = b.bits(4) as usize + 2;
            let dist = (w.pos.wrapping_sub(mpos).wrapping_sub(18) & 0x7FF) as usize + 1;
            w.copy(dist, len.min((end - w.pos) as usize))?;
        }
        b.check()
    }
}

pub fn lzs_reader<D: AsRef<[u8]>>(src: D, size: u64) -> LzReader<Lzs<D>> {
    let lz = Lzs {
        bits: Bits::new(src),
    };
    LzReader::new(lz, Window::prefilled(vec![b' '; 2048]), size)
}

/// LArc `-lz5-`: a flag byte per 8 items (LSB first), literal bytes or 12-bit ring position
/// plus 4-bit length; the 4 KiB ring starts with LArc's fixed pattern.
pub struct Lz5<D> {
    bits: Bits<D>,
    flags: u32,
    flag_count: u32,
}

impl<D: AsRef<[u8]>> Lz for Lz5<D> {
    const MAX_MATCH: usize = 18;

    fn run(&mut self, w: &mut Window, until: u64, end: u64) -> Result<()> {
        let b = &mut self.bits;
        while w.pos < until {
            if self.flag_count == 0 {
                self.flags = b.bits(8);
                self.flag_count = 8;
            }
            self.flag_count -= 1;
            let lit = self.flags & 1 != 0;
            self.flags >>= 1;
            let c = b.bits(8);
            if lit {
                w.put(c as u8);
                continue;
            }
            let c2 = b.bits(8);
            let mpos = (c | ((c2 & 0xF0) << 4)) as u64;
            let len = (c2 & 0x0F) as usize + 3;
            let dist = (w.pos.wrapping_sub(mpos).wrapping_sub(19) & 0xFFF) as usize + 1;
            w.copy(dist, len.min((end - w.pos) as usize))?;
        }
        b.check()
    }
}

pub fn lz5_reader<D: AsRef<[u8]>>(src: D, size: u64) -> LzReader<Lz5<D>> {
    let mut ring = vec![b' '; 4096];
    for i in 0..256 {
        ring[i * 13 + 18..i * 13 + 31].fill(i as u8);
    }
    for i in 0..256 {
        ring[256 * 13 + 18 + i] = i as u8;
        ring[256 * 13 + 256 + 18 + i] = 255 - i as u8;
    }
    ring[256 * 13 + 512 + 18..256 * 13 + 512 + 128 + 18].fill(0);
    let lz = Lz5 {
        bits: Bits::new(src),
        flags: 0,
        flag_count: 0,
    };
    LzReader::new(lz, Window::prefilled(ring), size)
}

/// ARJ method 4: unary-prefixed lengths (0 = literal) and positions.
pub struct ArjFast<D> {
    bits: Bits<D>,
}

impl<D: AsRef<[u8]>> ArjFast<D> {
    /// A value coded as up to `stop - start` one bits, a zero (omitted at the maximum) and
    /// `width` bits, where each one bit doubles the base and widens the field.
    #[inline]
    fn gamma(&mut self, start: u32, stop: u32) -> u32 {
        let mut plus = 0;
        let mut pwr = 1 << start;
        let mut width = start;
        while width < stop {
            if self.bits.bit() == 0 {
                break;
            }
            plus += pwr;
            pwr <<= 1;
            width += 1;
        }
        plus + self.bits.bits(width)
    }
}

impl<D: AsRef<[u8]>> Lz for ArjFast<D> {
    const MAX_MATCH: usize = 256;

    fn run(&mut self, w: &mut Window, until: u64, end: u64) -> Result<()> {
        while w.pos < until {
            let c = self.gamma(0, 7) as usize;
            if c == 0 {
                w.put(self.bits.bits(8) as u8);
                continue;
            }
            let dist = self.gamma(9, 13) as usize + 1;
            w.copy(dist, (c + 2).min((end - w.pos) as usize))?;
        }
        self.bits.check()
    }
}

pub fn arj_fast_reader<D: AsRef<[u8]>>(src: D, size: u64) -> LzReader<ArjFast<D>> {
    let lz = ArjFast {
        bits: Bits::new(src),
    };
    LzReader::new(lz, Window::new(ring_size(size, 1 << 14)), size)
}

/// CRC-16/ARC (reflected 0x8005, initial 0), the LZH data checksum. Slicing-by-8.
pub fn crc16(mut crc: u16, data: &[u8]) -> u16 {
    let t = &CRC16;
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let lo = crc ^ u16::from_le_bytes([c[0], c[1]]);
        crc = t[7][(lo & 0xFF) as usize]
            ^ t[6][(lo >> 8) as usize]
            ^ t[5][c[2] as usize]
            ^ t[4][c[3] as usize]
            ^ t[3][c[4] as usize]
            ^ t[2][c[5] as usize]
            ^ t[1][c[6] as usize]
            ^ t[0][c[7] as usize];
    }
    for &b in chunks.remainder() {
        crc = t[0][((crc ^ b as u16) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// `CRC16[k][b]`: the CRC of byte `b` followed by `k` zero bytes.
const CRC16: [[u16; 256]; 8] = {
    let mut t = [[0u16; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u16;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xA001
            } else {
                c >> 1
            };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[k - 1][i];
            t[k][i] = t[0][(prev & 0xFF) as usize] ^ (prev >> 8);
            i += 1;
        }
        k += 1;
    }
    t
};

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(mut r: impl Read) -> io::Result<Vec<u8>> {
        let mut v = Vec::new();
        r.read_to_end(&mut v)?;
        Ok(v)
    }

    #[test]
    fn crc16_check_value() {
        assert_eq!(crc16(0, b"123456789"), 0xBB3D);
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        let bytewise = data.iter().fold(0u16, |c, &b| crc16(c, &[b]));
        assert_eq!(crc16(0, &data), bytewise);
        assert_eq!(crc16(crc16(0, &data[..333]), &data[333..]), bytewise);
    }

    #[test]
    fn huffman_canonical() {
        let mut h = Huffman::new(2);
        // a=0, b=10, c=110, d=111
        h.build(&[1, 2, 3, 3]).unwrap();
        let mut b = Bits::new(vec![0b0101_1011, 0b1000_0000]);
        let got: Vec<usize> = (0..5).map(|_| h.decode(&mut b).unwrap()).collect();
        assert_eq!(got, [0, 1, 2, 3, 0]);
        assert!(h.build(&[1, 1, 1]).is_err());
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        for round in 0..400 {
            let len = (round * 7) % 300;
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            let size = 5000;
            let _ = read_all(lh_reader(data.clone(), size, 13));
            let _ = read_all(lh_reader(data.clone(), size, 16));
            let _ = read_all(arj_reader(data.clone(), size));
            let _ = read_all(arj_fast_reader(data.clone(), size));
            let _ = read_all(lh1_reader(data.clone(), size));
            let _ = read_all(lzs_reader(data.clone(), size));
            let _ = read_all(lz5_reader(data.clone(), size));
        }
    }

    #[test]
    fn empty_input_is_corrupt() {
        assert!(read_all(lh_reader(Vec::new(), 10, 13)).is_err());
        assert!(read_all(arj_fast_reader(Vec::new(), 10)).is_err());
        assert_eq!(read_all(lh_reader(Vec::new(), 0, 13)).unwrap(), b"");
    }
}
