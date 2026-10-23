//! Parallel bzip2 decoding.
//!
//! bzip2 blocks are independent, but they start at arbitrary bit offsets. The input is
//! scanned for the 48-bit block and end-of-stream magics, the candidate blocks are decoded
//! on separate threads by a self-contained block decoder (Huffman, MTF/RLE2, inverse BWT,
//! RLE1), and each block's CRC plus every stream's combined CRC is checked. A magic that
//! occurs by chance inside compressed data makes a candidate fail; then the reader falls
//! back to the sequential decoder from the start and skips what it already produced.

use std::io::{self, Read};
use std::sync::Arc;

use rayon::prelude::*;

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const EOS_MAGIC: u64 = 0x1772_4538_5090;
const MAX_BLOCK: usize = 900_000;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("bzip2: {msg}"))
}

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04C1_1DB7
            } else {
                c << 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC: [u32; 256] = crc_table();

fn crc_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = (crc << 8) ^ CRC[((crc >> 24) as u8 ^ b) as usize];
    }
    crc
}

/// MSB-first bit reader over a byte slice, starting at any bit.
struct Bits<'a> {
    data: &'a [u8],
    /// Next byte to load.
    pos: usize,
    buf: u64,
    count: u32,
}

impl<'a> Bits<'a> {
    fn at(data: &'a [u8], bit: u64) -> Self {
        let mut b = Bits {
            data,
            pos: (bit / 8) as usize,
            buf: 0,
            count: 0,
        };
        let skip = (bit % 8) as u32;
        if skip > 0 {
            let _ = b.get(skip);
        }
        b
    }

    fn refill(&mut self) {
        while self.count <= 56 {
            let byte = if self.pos < self.data.len() {
                self.data[self.pos]
            } else if self.pos < self.data.len() + 16 {
                0 // a little zero padding; reading far past the end is an error below
            } else {
                break;
            };
            self.pos += 1;
            self.buf |= (byte as u64) << (56 - self.count);
            self.count += 8;
        }
    }

    fn get(&mut self, n: u32) -> io::Result<u32> {
        if self.count < n {
            self.refill();
            if self.count < n || self.pos > self.data.len() + 8 {
                return Err(bad("unexpected end of data"));
            }
        }
        let v = (self.buf >> (64 - n)) as u32;
        self.buf <<= n;
        self.count -= n;
        Ok(v)
    }

    fn bit(&mut self) -> io::Result<bool> {
        Ok(self.get(1)? == 1)
    }

    /// Peeks up to 20 bits (zero-filled past the end).
    fn peek20(&mut self) -> u32 {
        if self.count < 20 {
            self.refill();
        }
        (self.buf >> 44) as u32
    }

    fn consume(&mut self, n: u32) -> io::Result<()> {
        if self.count < n {
            return Err(bad("unexpected end of data"));
        }
        self.buf <<= n;
        self.count -= n;
        Ok(())
    }

    fn bit_pos(&self) -> u64 {
        self.pos as u64 * 8 - self.count as u64
    }
}

const LUT_BITS: u32 = 10;

/// Canonical Huffman decoder for one bzip2 coding group.
struct Huff {
    /// (symbol << 5 | length) for codes up to LUT_BITS; 0 = longer code.
    lut: Vec<u32>,
    /// For lengths 1..=20: first code value, its index into `perm`, and the count.
    limit: [i32; 22],
    base: [i32; 22],
    perm: Vec<u16>,
    min_len: u32,
    max_len: u32,
}

impl Huff {
    fn new(lens: &[u8]) -> io::Result<Self> {
        let min_len = *lens.iter().min().unwrap() as u32;
        let max_len = *lens.iter().max().unwrap() as u32;
        let mut perm = Vec::with_capacity(lens.len());
        for l in min_len..=max_len {
            for (s, &x) in lens.iter().enumerate() {
                if x as u32 == l {
                    perm.push(s as u16);
                }
            }
        }
        let mut count = [0i32; 22];
        for &l in lens {
            count[l as usize] += 1;
        }
        let mut limit = [0i32; 22];
        let mut base = [0i32; 22];
        let mut code = 0i32;
        let mut idx = 0i32;
        for l in 1..=20usize {
            base[l] = idx - code; // perm index = code + base
            code += count[l];
            idx += count[l];
            limit[l] = code - 1; // last code of this length
            code <<= 1;
        }
        if code > (1 << 21) {
            return Err(bad("oversubscribed Huffman code"));
        }
        let mut lut = vec![0u32; 1 << LUT_BITS];
        // Fill the table by walking codes in canonical order.
        let mut c = 0u32;
        let mut p = 0usize;
        for l in 1..=LUT_BITS {
            for _ in 0..count[l as usize] {
                if c >= 1 << l {
                    return Err(bad("oversubscribed Huffman code"));
                }
                let sym = perm[p] as u32;
                p += 1;
                let shift = LUT_BITS - l;
                for k in 0..(1u32 << shift) {
                    lut[((c << shift) | k) as usize] = (sym << 5) | l;
                }
                c += 1;
            }
            c <<= 1;
        }
        Ok(Huff {
            lut,
            limit,
            base,
            perm,
            min_len,
            max_len,
        })
    }

    fn decode(&self, b: &mut Bits) -> io::Result<u16> {
        let w = b.peek20();
        let e = self.lut[(w >> (20 - LUT_BITS)) as usize];
        if e != 0 {
            b.consume(e & 31)?;
            return Ok((e >> 5) as u16);
        }
        for l in self.min_len.max(LUT_BITS + 1)..=self.max_len {
            let code = (w >> (20 - l)) as i32;
            if code <= self.limit[l as usize] {
                b.consume(l)?;
                let i = code + self.base[l as usize];
                return self
                    .perm
                    .get(i as usize)
                    .copied()
                    .ok_or_else(|| bad("bad Huffman code"));
            }
        }
        Err(bad("bad Huffman code"))
    }
}

/// Decodes one block whose magic starts at bit `start`. Returns the block's bytes, its
/// stored CRC and the bit position after it.
fn decode_block(data: &[u8], start: u64) -> io::Result<(Vec<u8>, u32, u64)> {
    let mut b = Bits::at(data, start + 48);
    let block_crc = b.get(32)?;
    if b.bit()? {
        return Err(bad(
            "randomised blocks are not handled by the parallel decoder",
        ));
    }
    let (out, end) = decode_body(data, b.bit_pos())?;
    let crc = !crc_update(!0, &out);
    if crc != block_crc {
        return Err(bad("block CRC mismatch"));
    }
    Ok((out, block_crc, end))
}

/// Decodes a block from its origin pointer on: after the magic, the CRC and the randomised
/// bit, which NSIS's bzip2 leaves out. Returns the bytes and the bit position after the
/// block; the caller checks any CRC.
fn decode_body(data: &[u8], at: u64) -> io::Result<(Vec<u8>, u64)> {
    let mut b = Bits::at(data, at);
    let orig_ptr = b.get(24)? as usize;
    let used = b.get(16)?;
    let mut seq = Vec::with_capacity(256);
    for i in 0..16 {
        if used & (0x8000 >> i) != 0 {
            let m = b.get(16)?;
            for j in 0..16 {
                if m & (0x8000 >> j) != 0 {
                    seq.push((i * 16 + j) as u8);
                }
            }
        }
    }
    if seq.is_empty() {
        return Err(bad("block uses no symbols"));
    }
    let alpha = seq.len() + 2;
    let n_groups = b.get(3)? as usize;
    if !(2..=6).contains(&n_groups) {
        return Err(bad("bad group count"));
    }
    let n_sel = b.get(15)? as usize;
    if n_sel == 0 {
        return Err(bad("no selectors"));
    }
    let mut mtf_g: Vec<u8> = (0..n_groups as u8).collect();
    let mut selectors = Vec::with_capacity(n_sel.min(18002));
    for _ in 0..n_sel {
        let mut j = 0usize;
        while b.bit()? {
            j += 1;
            if j >= n_groups {
                return Err(bad("bad selector"));
            }
        }
        let v = mtf_g[j];
        mtf_g.copy_within(0..j, 1);
        mtf_g[0] = v;
        if selectors.len() < 18002 {
            selectors.push(v);
        }
    }
    let mut tables = Vec::with_capacity(n_groups);
    for _ in 0..n_groups {
        let mut lens = vec![0u8; alpha];
        let mut cur = b.get(5)? as i32;
        for l in lens.iter_mut() {
            loop {
                if !(1..=20).contains(&cur) {
                    return Err(bad("bad code length"));
                }
                if !b.bit()? {
                    break;
                }
                cur += if b.bit()? { -1 } else { 1 };
            }
            *l = cur as u8;
        }
        tables.push(Huff::new(&lens)?);
    }

    // MTF/RLE2 → byte values (in `tt` low bytes) with counts for the BWT.
    let eob = (alpha - 1) as u16;
    let mut mtf: [u8; 256] = [0; 256];
    for (i, m) in mtf.iter_mut().enumerate() {
        *m = i as u8;
    }
    let mut counts = [0u32; 256];
    let mut tt: Vec<u32> = Vec::with_capacity(MAX_BLOCK);
    let mut group = 0usize;
    let mut left = 0usize;
    let mut run = 0usize;
    let mut run_bit = 1usize;
    loop {
        if left == 0 {
            let s = *selectors
                .get(group)
                .ok_or_else(|| bad("ran out of selectors"))? as usize;
            if s >= n_groups {
                return Err(bad("bad selector"));
            }
            group += 1;
            left = 50;
        }
        left -= 1;
        let sym = tables[selectors[group - 1] as usize].decode(&mut b)?;
        if sym <= 1 {
            run += run_bit << sym;
            run_bit <<= 1;
            if run > MAX_BLOCK {
                return Err(bad("run too long"));
            }
            continue;
        }
        if run > 0 {
            let byte = seq[mtf[0] as usize];
            if tt.len() + run > MAX_BLOCK {
                return Err(bad("block too large"));
            }
            counts[byte as usize] += run as u32;
            tt.extend(std::iter::repeat_n(byte as u32, run));
            run = 0;
            run_bit = 1;
        }
        if sym == eob {
            break;
        }
        let idx = (sym - 1) as usize;
        if idx >= seq.len() {
            return Err(bad("bad MTF index"));
        }
        let v = mtf[idx];
        mtf.copy_within(0..idx, 1);
        mtf[0] = v;
        let byte = seq[v as usize];
        if tt.len() >= MAX_BLOCK {
            return Err(bad("block too large"));
        }
        counts[byte as usize] += 1;
        tt.push(byte as u32);
    }
    let n = tt.len();
    if orig_ptr >= n.max(1) {
        return Err(bad("bad BWT origin"));
    }
    // Inverse BWT: link each position to its successor in the high 24 bits.
    let mut cf = [0u32; 256];
    let mut sum = 0u32;
    for i in 0..256 {
        cf[i] = sum;
        sum += counts[i];
    }
    for i in 0..n {
        let c = (tt[i] & 0xFF) as usize;
        let at = cf[c] as usize;
        tt[at] |= (i as u32) << 8;
        cf[c] += 1;
    }
    let mut out = Vec::with_capacity(n + n / 8);
    let mut pos = tt[orig_ptr] >> 8;
    // RLE1: four equal bytes are followed by a count of further repeats.
    let mut last: i32 = -1;
    let mut same = 0;
    for _ in 0..n {
        let e = tt[pos as usize];
        let byte = (e & 0xFF) as u8;
        pos = e >> 8;
        if same == 4 {
            out.extend(std::iter::repeat_n(last as u8, byte as usize));
            same = 0;
            last = -1;
            continue;
        }
        if byte as i32 == last {
            same += 1;
        } else {
            same = 1;
            last = byte as i32;
        }
        out.push(byte);
    }
    Ok((out, b.bit_pos()))
}

/// One block of NSIS's bzip2 at bit `at`: NSIS writes no stream header, magic or CRC, and
/// each block is a one-byte marker (`0x31`) followed by the block's bits. Blocks are not
/// byte aligned. Returns the block's bytes and the bit after it, or `None` at the end
/// marker (`0x17`).
pub fn decode_nsis_block(data: &[u8], at: u64) -> io::Result<Option<(Vec<u8>, u64)>> {
    match Bits::at(data, at).get(8)? {
        0x17 => Ok(None),
        0x31 => decode_body(data, at + 8).map(Some),
        _ => Err(bad("bad NSIS block marker")),
    }
}

/// Bit offsets of every block and end-of-stream magic.
fn scan(data: &[u8], threads: usize) -> Vec<(u64, bool)> {
    const MASK: u64 = (1 << 48) - 1;
    let chunk = (data.len() / threads.max(1)).max(1 << 16);
    let starts: Vec<usize> = (0..data.len()).step_by(chunk).collect();
    let mut found: Vec<(u64, bool)> = starts
        .par_iter()
        .flat_map_iter(|&s| {
            let e = (s + chunk + 6).min(data.len());
            let mut hits = Vec::new();
            let mut w: u64 = 0;
            for (k, &byte) in data[s..e].iter().enumerate() {
                for bit in (0..8).rev() {
                    w = (w << 1) | ((byte >> bit) & 1) as u64;
                    let got = (s + k) as u64 * 8 + (7 - bit) as u64 + 1;
                    if got >= 48 && got - 48 >= s as u64 * 8 && got - 48 < (s + chunk) as u64 * 8 {
                        let v = w & MASK;
                        if v == BLOCK_MAGIC {
                            hits.push((got - 48, false));
                        } else if v == EOS_MAGIC {
                            hits.push((got - 48, true));
                        }
                    }
                }
            }
            hits
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// Where the blocks are and which ones end a stream.
struct Plan {
    /// Block start bits, in order.
    blocks: Vec<u64>,
    /// For each block: Some(stream CRC) when it is the last block of its stream.
    stream_end: Vec<Option<u32>>,
}

fn plan(data: &[u8], threads: usize) -> Option<Plan> {
    let marks = scan(data, threads);
    let mut blocks = Vec::new();
    let mut stream_end: Vec<Option<u32>> = Vec::new();
    for &(bit, eos) in &marks {
        if eos {
            // Closes the stream of the preceding block; an end marker right after another
            // one is an empty stream.
            let crc = Bits::at(data, bit + 48).get(32).ok()?;
            if let Some(last @ None) = stream_end.last_mut() {
                *last = Some(crc);
            }
        } else {
            blocks.push(bit);
            stream_end.push(None);
        }
    }
    (!blocks.is_empty()).then_some(Plan { blocks, stream_end })
}

/// A reader that decodes a whole in-memory bzip2 file with `threads` threads.
pub struct ParBzip2Reader<D: AsRef<[u8]> + Send + Sync + 'static> {
    data: Arc<D>,
    threads: usize,
    plan: Option<Plan>,
    next: usize,
    out: Vec<u8>,
    out_pos: usize,
    /// Combined CRC of the current stream so far.
    stream_crc: u32,
    produced: u64,
    fallback: Option<Box<dyn Read + Send>>,
    started: bool,
}

impl<D: AsRef<[u8]> + Send + Sync + 'static> ParBzip2Reader<D> {
    pub fn new(data: D, threads: usize) -> Self {
        ParBzip2Reader {
            data: Arc::new(data),
            threads: threads.max(1),
            plan: None,
            next: 0,
            out: Vec::new(),
            out_pos: 0,
            stream_crc: 0,
            produced: 0,
            fallback: None,
            started: false,
        }
    }

    fn start_fallback(&mut self) -> io::Result<()> {
        struct Shared<D: AsRef<[u8]>>(Arc<D>, usize);
        impl<D: AsRef<[u8]>> Read for Shared<D> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let d = &self.0.as_ref().as_ref()[self.1..];
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                self.1 += n;
                Ok(n)
            }
        }
        let mut r: Box<dyn Read + Send> = Box::new(bzip2::read::MultiBzDecoder::new(Shared(
            self.data.clone(),
            0,
        )));
        // Skip what the parallel path already returned.
        let skipped = io::copy(&mut (&mut r).take(self.produced), &mut io::sink())?;
        if skipped != self.produced {
            return Err(bad("unexpected end of data"));
        }
        self.out.clear();
        self.out_pos = 0;
        self.fallback = Some(r);
        Ok(())
    }

    /// Decodes the next batch of blocks into `out`. Returns false at the end.
    fn fill(&mut self) -> io::Result<bool> {
        if !self.started {
            self.started = true;
            let d = self.data.as_ref().as_ref();
            if d.len() < 14 || &d[..3] != b"BZh" {
                return Err(bad("not a bzip2 stream"));
            }
            self.plan = plan(d, self.threads);
            if self.plan.is_none() {
                self.start_fallback()?;
                return Ok(true);
            }
        }
        let plan = self.plan.as_ref().unwrap();
        if self.next >= plan.blocks.len() {
            // Every stream's trailer was checked; a stream without one is truncated.
            if plan.stream_end.last().is_some_and(|e| e.is_none()) {
                return Err(bad("stream end marker missing (truncated?)"));
            }
            return Ok(false);
        }
        let batch = (self.threads * 2).max(2);
        let end = (self.next + batch).min(plan.blocks.len());
        let d = self.data.as_ref().as_ref();
        let results: Vec<io::Result<(Vec<u8>, u32, u64)>> = plan.blocks[self.next..end]
            .par_iter()
            .map(|&s| decode_block(d, s))
            .collect();
        self.out.clear();
        self.out_pos = 0;
        for (k, r) in results.into_iter().enumerate() {
            let i = self.next + k;
            let ok = match r {
                Ok((bytes, crc, end_bit)) => {
                    // The next mark must not lie inside this block.
                    let next_start = plan.blocks.get(i + 1).copied().unwrap_or(u64::MAX);
                    if end_bit > next_start {
                        None
                    } else {
                        self.stream_crc = self.stream_crc.rotate_left(1) ^ crc;
                        let stream_ok = match plan.stream_end[i] {
                            Some(want) => {
                                let good = want == self.stream_crc;
                                self.stream_crc = 0;
                                good
                            }
                            None => true,
                        };
                        stream_ok.then_some(bytes)
                    }
                }
                Err(_) => None,
            };
            match ok {
                Some(bytes) => self.out.extend_from_slice(&bytes),
                None => {
                    // A chance magic, a randomised block or real damage: let the
                    // sequential decoder decide, after the bytes already returned.
                    self.start_fallback()?;
                    return Ok(true);
                }
            }
        }
        self.next = end;
        Ok(true)
    }
}

impl<D: AsRef<[u8]> + Send + Sync + 'static> Read for ParBzip2Reader<D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(f) = self.fallback.as_mut() {
                let n = f.read(buf)?;
                self.produced += n as u64;
                return Ok(n);
            }
            if self.out_pos < self.out.len() {
                let n = (self.out.len() - self.out_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                self.produced += n as u64;
                return Ok(n);
            }
            if !self.fill()? {
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn bz(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn sample(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x = 7u32;
        while v.len() < n {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            match (x >> 16) % 5 {
                0 => v.extend(std::iter::repeat_n(b'a', (x % 300) as usize)),
                1 => v.extend_from_slice(b"the quick brown fox "),
                _ => v.push((x >> 8) as u8),
            }
        }
        v.truncate(n);
        v
    }

    #[test]
    fn matches_libbz2_on_multi_block_and_multi_stream() {
        for (n, level) in [(0usize, 9), (1, 1), (2_500_000, 1), (3_000_000, 9)] {
            let data = sample(n);
            let mut c = bz(&data, level);
            c.extend(bz(b"second stream", 5));
            let mut out = Vec::new();
            let mut r = ParBzip2Reader::new(c, 4);
            r.read_to_end(&mut out).unwrap();
            assert!(
                r.fallback.is_none(),
                "n={n}: fell back to the sequential decoder"
            );
            let mut want = data.clone();
            want.extend_from_slice(b"second stream");
            assert_eq!(out, want, "n={n} level={level}");
        }
    }

    #[test]
    fn damage_is_an_error() {
        let data = sample(500_000);
        let mut c = bz(&data, 1);
        let at = c.len() / 2;
        c[at] ^= 0x10;
        let mut out = Vec::new();
        assert!(ParBzip2Reader::new(c.clone(), 4)
            .read_to_end(&mut out)
            .is_err());
        c.truncate(c.len() - 20);
        let mut out = Vec::new();
        assert!(ParBzip2Reader::new(c, 4).read_to_end(&mut out).is_err());
    }
}
