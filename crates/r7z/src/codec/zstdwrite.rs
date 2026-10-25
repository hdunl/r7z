//! Zstandard output (RFC 8878): one frame per stream, 128 KiB blocks.
//!
//! The matcher is an LZ77 search over hash chains with repeat offsets and one-step lazy
//! evaluation. Literals are Huffman-coded (one or four streams) when that is smaller, and
//! sequences use the predefined FSE tables, so a block needs no table headers. A block
//! that does not shrink is stored raw, and a block of one repeated byte is an RLE block.
//! The output needs no dictionary and decodes with any zstd decoder.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{self, Write};
use std::ops::Range;

use xxhash_rust::xxh64::Xxh64;

const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const BLOCK_MAX: usize = 128 << 10;
const MIN_MATCH: usize = 4;
const HUF_MAX_LOG: u32 = 11;
/// Longest match searched for. Longer runs continue as the next match.
const MAX_MATCH: usize = 1 << 12;
/// A match this long ends the search, as longer ones rarely do better.
const NICE_MATCH: usize = 128;

/// Per-level search settings. `-mx` maps onto these: a longer chain search and lazy
/// matching cost time for a smaller output.
#[derive(Clone, Copy, Debug)]
pub struct Level {
    /// Window size as a power of two.
    pub window_log: u32,
    /// Hash chain candidates examined per position.
    pub depth: u32,
    /// Also try the next position and take a literal when that match is clearly longer.
    pub lazy: bool,
    /// Store the input in raw blocks (`-mx0`).
    pub store: bool,
}

impl Level {
    /// The same level with a window no larger than an input of `size` bytes needs.
    pub fn sized_for(self, size: u64) -> Level {
        let need = (64 - size.max(1).saturating_sub(1).leading_zeros()).clamp(17, 64);
        Level {
            window_log: self.window_log.min(need),
            ..self
        }
    }

    /// The level for a 7-Zip `-mx` value (0-9).
    pub fn for_mx(mx: u32) -> Level {
        let (window_log, depth, lazy) = match mx {
            0 => (17, 1, false),
            1 => (20, 1, false),
            2 => (20, 2, true),
            3 => (21, 4, true),
            4 => (21, 6, true),
            5 => (22, 8, true),
            6 => (22, 12, true),
            7 => (23, 16, true),
            8 => (23, 24, true),
            _ => (23, 32, true),
        };
        Level {
            window_log,
            depth,
            lazy,
            store: mx == 0,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Code tables (RFC 8878, sections 3.1.1.3.2.1.1 and 3.1.1.3.2.1.2).

/// Literals length code baselines and extra bits.
const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u32; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
/// Match length code baselines (in match length units) and extra bits.
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u32; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// Predefined normalized distributions (accuracy logs 6, 6 and 5).
const LL_NORM: [i32; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const ML_NORM: [i32; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_NORM: [i32; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

fn ll_code(l: u32) -> usize {
    if l < 16 {
        l as usize
    } else {
        (16..36).rev().find(|&c| LL_BASE[c] <= l).unwrap_or(16)
    }
}

/// `ml` is the real match length (at least 3).
fn ml_code(ml: u32) -> usize {
    if ml < 35 {
        (ml - 3) as usize
    } else {
        (32..53).rev().find(|&c| ML_BASE[c] <= ml).unwrap_or(32)
    }
}

// ---------------------------------------------------------------------------------------
// Bit output. Zstd's bit streams are written forward and read backward by the decoder,
// so the last bit written is the first one read; a closing 1 bit marks where they end.

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    /// Appends the low `bits` (at most 32) bits of `value`.
    #[inline]
    fn add(&mut self, value: u64, bits: u32) {
        debug_assert!(bits <= 32 && value >> bits == 0);
        self.acc |= value << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.add(1, 1);
        self.bytes()
    }

    /// The bits written so far, the last byte padded with zeros, without an end mark.
    fn bytes(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

// ---------------------------------------------------------------------------------------
// Finite state entropy coding (RFC 8878, appendix on FSE; state tables as libzstd builds
// them).

struct FseTable {
    log: u32,
    /// Next state for each (cumulative index) slot.
    next: Vec<u16>,
    /// Per symbol: bits to emit (`delta_nb` >> 16 adjusted) and the state offset.
    delta_nb: Vec<u32>,
    delta_find: Vec<i32>,
}

impl FseTable {
    fn new(norm: &[i32], log: u32) -> FseTable {
        let size = 1usize << log;
        let mask = size - 1;
        let step = (size >> 1) + (size >> 3) + 3;
        let mut spread = vec![0usize; size];
        // Symbols with probability -1 take the slots at the top of the table.
        let mut high = size - 1;
        let mut cumul = vec![0usize; norm.len() + 1];
        for (s, &p) in norm.iter().enumerate() {
            if p == -1 {
                cumul[s + 1] = cumul[s] + 1;
                spread[high] = s;
                high = high.saturating_sub(1);
            } else {
                cumul[s + 1] = cumul[s] + p.max(0) as usize;
            }
        }
        let mut pos = 0usize;
        for (s, &p) in norm.iter().enumerate() {
            for _ in 0..p.max(0) {
                spread[pos] = s;
                pos = (pos + step) & mask;
                while pos > high {
                    pos = (pos + step) & mask;
                }
            }
        }
        let mut next = vec![0u16; size];
        let mut start = cumul.clone();
        for (u, &s) in spread.iter().enumerate() {
            next[start[s]] = (size + u) as u16;
            start[s] += 1;
        }
        let mut delta_nb = vec![0u32; norm.len()];
        let mut delta_find = vec![0i32; norm.len()];
        let mut total = 0i32;
        for (s, &p) in norm.iter().enumerate() {
            match p {
                -1 | 1 => {
                    delta_nb[s] = (log << 16) - size as u32;
                    delta_find[s] = total - 1;
                    total += 1;
                }
                c if c > 1 => {
                    let c = c as u32;
                    let max_bits = log - (31 - (c - 1).leading_zeros());
                    delta_nb[s] = (max_bits << 16).wrapping_sub(c << max_bits);
                    delta_find[s] = total - c as i32;
                    total += c as i32;
                }
                _ => {}
            }
        }
        FseTable {
            log,
            next,
            delta_nb,
            delta_find,
        }
    }

    /// The state that starts encoding `sym` (the last symbol of the block, written first).
    fn init(&self, sym: usize) -> u32 {
        let dnb = self.delta_nb[sym];
        let nb = (dnb.wrapping_add(1 << 15)) >> 16;
        let value = (nb << 16).wrapping_sub(dnb);
        self.next[((value >> nb) as i32 + self.delta_find[sym]) as usize] as u32
    }

    #[inline]
    fn encode(&self, state: &mut u32, sym: usize, bw: &mut BitWriter) {
        let dnb = self.delta_nb[sym];
        let nb = (*state + dnb) >> 16;
        bw.add((*state as u64) & ((1u64 << nb) - 1), nb);
        *state = self.next[((*state >> nb) as i32 + self.delta_find[sym]) as usize] as u32;
    }

    fn flush(&self, state: u32, bw: &mut BitWriter) {
        bw.add((state as u64) & ((1u64 << self.log) - 1), self.log);
    }
}

// ---------------------------------------------------------------------------------------
// Huffman coding of literals.

/// Code lengths for `freq`, none longer than `max_log`. Symbols with no occurrences get 0.
fn code_lengths(freq: &[u64; 256], max_log: u32) -> [u8; 256] {
    let mut f = *freq;
    loop {
        let mut len = [0u8; 256];
        let mut parent: Vec<usize> = vec![usize::MAX; 256];
        let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
        for (s, &w) in f.iter().enumerate() {
            if w > 0 {
                heap.push(Reverse((w, s)));
            }
        }
        while heap.len() > 1 {
            let Reverse((wa, a)) = heap.pop().unwrap();
            let Reverse((wb, b)) = heap.pop().unwrap();
            let id = parent.len();
            parent.push(usize::MAX);
            parent[a] = id;
            parent[b] = id;
            heap.push(Reverse((wa + wb, id)));
        }
        let mut deepest = 0;
        for s in 0..256 {
            if freq[s] > 0 {
                let mut d = 0u32;
                let mut n = s;
                while parent[n] != usize::MAX {
                    n = parent[n];
                    d += 1;
                }
                len[s] = d.max(1) as u8;
                deepest = deepest.max(d);
            }
        }
        if deepest <= max_log {
            return len;
        }
        // Flatten the distribution and try again; the tree gets shallower each round.
        for w in f.iter_mut().filter(|w| **w > 0) {
            *w = (*w >> 1).max(1);
        }
    }
}

/// Canonical codes for `len`, as zstd numbers them: the longest codes come first, from
/// zero, and each step to shorter codes shifts the running value right. Within a length,
/// symbols are in order. (The decoder rebuilds the same codes from the weights.)
fn canonical_codes(len: &[u8; 256]) -> [u32; 256] {
    let mut codes = [0u32; 256];
    let max = len.iter().copied().max().unwrap_or(0) as u32;
    let mut code = 0u32;
    let mut at = max;
    for bits in (1..=max).rev() {
        code >>= at - bits;
        at = bits;
        for (s, &l) in len.iter().enumerate() {
            if l as u32 == bits {
                codes[s] = code;
                code += 1;
            }
        }
    }
    codes
}

/// The literal section for a block of two or more distinct bytes, when Huffman coding it
/// is smaller than storing it raw. `None` when the literals do not fit the format.
fn huffman_section(lits: &[u8]) -> Option<Vec<u8>> {
    let mut freq = [0u64; 256];
    for &b in lits {
        freq[b as usize] += 1;
    }
    let maxsym = (0..256).rev().find(|&s| freq[s] > 0)?;
    let len = code_lengths(&freq, HUF_MAX_LOG);
    let table_log = len.iter().copied().max()? as u32;
    let codes = canonical_codes(&len);
    // Weights for symbols 0..maxsym; the last used symbol's weight is implied.
    let weights: Vec<u8> = (0..maxsym)
        .map(|s| {
            if len[s] > 0 {
                (table_log + 1 - len[s] as u32) as u8
            } else {
                0
            }
        })
        .collect();
    // Direct weights (four bits each) hold at most 128 symbols; FSE-coded ones up to 255.
    let direct = (maxsym <= 128).then(|| {
        let mut tree = vec![127 + maxsym as u8];
        for pair in weights.chunks(2) {
            tree.push((pair[0] << 4) | pair.get(1).copied().unwrap_or(0));
        }
        tree
    });
    let tree = match (direct, fse_weights(&weights)) {
        (Some(d), Some(f)) => {
            if f.len() < d.len() {
                f
            } else {
                d
            }
        }
        (d, f) => d.or(f)?,
    };
    let encode_stream = |part: &[u8]| -> Vec<u8> {
        let mut bw = BitWriter::default();
        for &b in part.iter().rev() {
            bw.add(codes[b as usize] as u64, len[b as usize] as u32);
        }
        bw.finish()
    };
    let n = lits.len();
    if n < 1024 {
        let body = encode_stream(lits);
        let comp = tree.len() + body.len();
        if comp < 1024 {
            let mut out = Vec::with_capacity(3 + comp);
            let h = 2u32 | (n as u32) << 4 | (comp as u32) << 14;
            out.extend_from_slice(&h.to_le_bytes()[..3]);
            out.extend_from_slice(&tree);
            out.extend_from_slice(&body);
            return Some(out);
        }
    }
    let seg = n.div_ceil(4);
    let parts: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            let a = (i * seg).min(n);
            let b = ((i + 1) * seg).min(n);
            encode_stream(&lits[a..b])
        })
        .collect();
    let streams: usize = parts.iter().map(Vec::len).sum();
    let comp = tree.len() + 6 + streams;
    let mut out = Vec::with_capacity(5 + comp);
    if n < 16384 && comp < 16384 {
        let h = 2u32 | (2 << 2) | (n as u32) << 4 | (comp as u32) << 18;
        out.extend_from_slice(&h.to_le_bytes());
    } else {
        let h = 2u64 | (3 << 2) | (n as u64) << 4 | (comp as u64) << 22;
        out.extend_from_slice(&h.to_le_bytes()[..5]);
    }
    out.extend_from_slice(&tree);
    for p in &parts[..3] {
        out.extend_from_slice(&(p.len() as u16).to_le_bytes());
    }
    for p in &parts {
        out.extend_from_slice(p);
    }
    Some(out)
}

/// Huffman weights in their FSE-coded form (RFC 8878, 4.2.1.2): a byte with the coded size,
/// a table description, and a bit stream with two interleaved states, the first coding the
/// weights at even positions and the second those at odd ones. `None` when it would not fit
/// in 127 bytes. Both table sizes the format allows are tried.
fn fse_weights(weights: &[u8]) -> Option<Vec<u8>> {
    let n = weights.len();
    if n < 2 {
        return None;
    }
    let mut count = [0u32; 16];
    for &w in weights {
        count[w as usize] += 1;
    }
    let max_w = (0..16).rev().find(|&w| count[w] > 0)?;
    let mut best: Option<Vec<u8>> = None;
    for log in 5..=6 {
        let Some(norm) = normalize(&count[..=max_w], n as u32, log) else {
            continue;
        };
        let t = FseTable::new(&norm, log);
        let mut out = vec![0u8];
        out.extend(table_description(&norm, log));
        // The decoder ends with one symbol from each state without updating it, so each
        // state starts on its last weight; the bits read after each earlier weight are
        // written in reverse order, and the second state's start goes out first.
        let mut bw = BitWriter::default();
        let (mut even, mut odd) = if (n - 1).is_multiple_of(2) {
            (
                t.init(weights[n - 1] as usize),
                t.init(weights[n - 2] as usize),
            )
        } else {
            (
                t.init(weights[n - 2] as usize),
                t.init(weights[n - 1] as usize),
            )
        };
        for i in (0..n - 2).rev() {
            let state = if i.is_multiple_of(2) {
                &mut even
            } else {
                &mut odd
            };
            t.encode(state, weights[i] as usize, &mut bw);
        }
        t.flush(odd, &mut bw);
        t.flush(even, &mut bw);
        out.extend(bw.finish());
        let size = out.len() - 1;
        if size < 128 && best.as_ref().is_none_or(|b| out.len() < b.len()) {
            out[0] = size as u8;
            best = Some(out);
        }
    }
    best
}

/// Counts scaled to `1 << log`, each used symbol keeping at least 1, the rounding taken up
/// by the most frequent symbol. `None` when that leaves it below 1.
fn normalize(count: &[u32], total: u32, log: u32) -> Option<Vec<i32>> {
    let size = 1i64 << log;
    let mut norm: Vec<i32> = count
        .iter()
        .map(|&c| {
            if c == 0 {
                0
            } else {
                ((i64::from(c) * size + i64::from(total) / 2) / i64::from(total)).max(1) as i32
            }
        })
        .collect();
    let big = (0..norm.len()).max_by_key(|&s| (count[s], std::cmp::Reverse(s)))?;
    let sum: i64 = norm.iter().map(|&p| i64::from(p)).sum();
    norm[big] += (size - sum) as i32;
    (norm[big] >= 1).then_some(norm)
}

/// An FSE table description (RFC 8878, 4.1.1): the accuracy log, then each count plus
/// one in as few bits as the counts still to come allow, with runs of zero counts after a
/// zero given as repeat flags.
fn table_description(norm: &[i32], log: u32) -> Vec<u8> {
    let mut bw = BitWriter::default();
    bw.add(u64::from(log - 5), 4);
    let mut remaining = (1i32 << log) + 1;
    let mut threshold = 1i32 << log;
    let mut nb = log + 1;
    let mut sym = 0;
    let mut prev_zero = false;
    while sym < norm.len() && remaining > 1 {
        if prev_zero {
            let mut start = sym;
            while sym < norm.len() && norm[sym] == 0 {
                sym += 1;
            }
            while sym >= start + 24 {
                start += 24;
                bw.add(0xFFFF, 16);
            }
            while sym >= start + 3 {
                start += 3;
                bw.add(3, 2);
            }
            bw.add((sym - start) as u64, 2);
        }
        let c = norm[sym];
        sym += 1;
        let max = (2 * threshold - 1) - remaining;
        remaining -= c.abs();
        let mut v = c + 1;
        if v >= threshold {
            v += max;
        }
        bw.add(v as u64, nb - u32::from(v < max));
        prev_zero = v == 1;
        while remaining < threshold {
            nb -= 1;
            threshold >>= 1;
        }
    }
    bw.bytes()
}

/// A literals section: RLE, Huffman or raw, whichever is smallest.
fn literals_section(lits: &[u8], out: &mut Vec<u8>) {
    let n = lits.len();
    if n > 1 && lits.iter().all(|&b| b == lits[0]) {
        // RLE: one byte repeated n times.
        push_literal_header(0b01, n, out);
        out.push(lits[0]);
        return;
    }
    if let Some(huff) = (n >= 32).then(|| huffman_section(lits)).flatten() {
        let mut raw = Vec::new();
        push_literal_header(0, n, &mut raw);
        raw.extend_from_slice(lits);
        if huff.len() < raw.len() {
            out.extend_from_slice(&huff);
            return;
        }
    }
    push_literal_header(0, n, out);
    out.extend_from_slice(lits);
}

/// A raw or RLE literals header for `n` bytes.
fn push_literal_header(kind: u32, n: usize, out: &mut Vec<u8>) {
    if n < 32 {
        out.push((kind | (n as u32) << 3) as u8);
    } else if n < 4096 {
        let h = (kind | 1 << 2 | (n as u32) << 4) as u16;
        out.extend_from_slice(&h.to_le_bytes());
    } else {
        let h = (kind as u64 | 3 << 2 | (n as u64) << 4) as u32;
        out.extend_from_slice(&h.to_le_bytes()[..3]);
    }
}

// ---------------------------------------------------------------------------------------
// Sequences.

/// One LZ77 step: `ll` literals, then a match of `ml` bytes at offset code `ov` (1-3 are
/// repeat offsets; larger values are the distance plus 3).
#[derive(Clone, Copy, Debug)]
struct Seq {
    ll: u32,
    ml: u32,
    ov: u32,
}

/// Repeat offsets after a sequence that used offset code `ov` with `ll` literals before
/// it. Returns the match distance; the decoder performs the same update.
fn apply_offset(reps: &mut [u32; 3], ov: u32, ll: u32) -> u32 {
    if ov >= 4 {
        let d = ov - 3;
        *reps = [d, reps[0], reps[1]];
        return d;
    }
    if ll == 0 && ov == 3 {
        let d = reps[0] - 1;
        *reps = [d, reps[0], reps[1]];
        return d;
    }
    let idx = if ll == 0 {
        ov as usize
    } else {
        ov as usize - 1
    };
    let d = reps[idx];
    let mut next = [0u32; 3];
    next[0] = d;
    let mut k = 1;
    for (i, &r) in reps.iter().enumerate() {
        if i != idx {
            next[k] = r;
            k += 1;
        }
    }
    *reps = next;
    d
}

/// The offset code for a match at distance `d` after `ll` literals, updating `reps`.
fn code_offset(reps: &mut [u32; 3], d: u32, ll: u32) -> u32 {
    let ov = if ll != 0 {
        match d {
            x if x == reps[0] => 1,
            x if x == reps[1] => 2,
            x if x == reps[2] => 3,
            _ => d + 3,
        }
    } else {
        match d {
            x if x == reps[1] => 1,
            x if x == reps[2] => 2,
            x if reps[0] > 1 && x == reps[0] - 1 => 3,
            _ => d + 3,
        }
    };
    apply_offset(reps, ov, ll);
    ov
}

/// Match finder over the window kept by the encoder: each hash bucket holds the most
/// recent positions with that hash, newest first, so one lookup touches one cache line
/// instead of following a chain through memory.
///
/// An entry packs the low 24 bits of a position above an 8-bit tag of its hash. Entries
/// whose tag differs from the probe's are skipped without reading the input, which is
/// most of the work in a bucket that holds other 4-byte strings. Positions are checked
/// against the input again before use, so a stale or aliased entry costs time only.
struct Finder {
    table: Vec<u32>,
    bucket_bits: u32,
    ways: usize,
    window: usize,
    lazy: bool,
}

#[inline]
fn hash4(d: &[u8]) -> u32 {
    let v = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    v.wrapping_mul(2_654_435_761)
}

/// The bucket index and tag for a hash, with `bits` bits of bucket index.
#[inline]
fn split(h: u32, bits: u32) -> (usize, u32) {
    ((h >> (32 - bits)) as usize, (h >> 8) & 0xFF)
}

/// Length of the common prefix of `a` and `b`, which is at most `a.len()` long.
#[inline]
fn common(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i + 8 <= n {
        let x = u64::from_le_bytes(a[i..i + 8].try_into().unwrap());
        let y = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        if x != y {
            return i + ((x ^ y).trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    while i < n && a[i] == b[i] {
        i += 1;
    }
    i
}

impl Finder {
    fn new(level: Level) -> Finder {
        let ways = (level.depth as usize).clamp(1, 32);
        // A table of about 2^(window_log - 6) buckets: large windows get the full table, small
        // inputs (many small zip members) a small one.
        let bucket_bits = (level.window_log - 6).clamp(8, 16);
        Finder {
            table: vec![0; (1usize << bucket_bits) * ways],
            bucket_bits,
            ways,
            window: 1usize << level.window_log,
            lazy: level.lazy,
        }
    }

    /// Records position `idx` (absolute position `base + idx`) for later matches.
    #[inline]
    fn insert(&mut self, buf: &[u8], base: u64, idx: usize, end: usize) {
        if idx + MIN_MATCH > end {
            return;
        }
        let (b, tag) = split(hash4(&buf[idx..]), self.bucket_bits);
        let row = &mut self.table[b * self.ways..(b + 1) * self.ways];
        row.copy_within(0..self.ways - 1, 1);
        row[0] = ((base + idx as u64) as u32) << 8 | tag;
    }

    /// The longest match starting at `idx` inside `buf[..end]`, as (length, distance).
    /// Length 0 means none of at least `MIN_MATCH` bytes.
    fn find(
        &self,
        buf: &[u8],
        base: u64,
        idx: usize,
        end: usize,
        reps: &[u32; 3],
    ) -> (usize, usize) {
        let max = (end - idx).min(MAX_MATCH);
        if max < MIN_MATCH {
            return (0, 0);
        }
        let cur = &buf[idx..idx + max];
        let mut best = (0usize, 0usize);
        for &r in reps {
            let d = r as usize;
            if d == 0 || d > idx || d > self.window {
                continue;
            }
            let l = common(cur, &buf[idx - d..]);
            if l >= MIN_MATCH && l > best.0 {
                best = (l, d);
            }
        }
        if best.0 >= NICE_MATCH {
            return best;
        }
        let now = ((base + idx as u64) as u32) << 8;
        let (b, tag) = split(hash4(&buf[idx..]), self.bucket_bits);
        for &entry in &self.table[b * self.ways..(b + 1) * self.ways] {
            // Newest first: once a position is too far back, the rest are.
            let d = (now.wrapping_sub(entry & !0xFF) >> 8) as usize;
            if d > idx || d > self.window {
                break;
            }
            if d == 0 || entry & 0xFF != tag {
                continue;
            }
            let c = idx - d;
            if best.0 < max && buf[c + best.0] == buf[idx + best.0] {
                let l = common(cur, &buf[c..]);
                if l > best.0 {
                    best = (l, d);
                    if l >= NICE_MATCH {
                        break;
                    }
                }
            }
        }
        if best.0 >= MIN_MATCH {
            best
        } else {
            (0, 0)
        }
    }

    /// Splits `buf[start..end]` into sequences and literal bytes. `reps` tracks the repeat
    /// offsets the decoder will hold after each sequence.
    fn parse(
        &mut self,
        buf: &[u8],
        base: u64,
        range: Range<usize>,
        reps: &mut [u32; 3],
        seqs: &mut Vec<Seq>,
        lits: &mut Vec<u8>,
    ) {
        let (start, end) = (range.start, range.end);
        let mut idx = start;
        let mut lit_start = start;
        // A match already found for `pos` by the lazy look-ahead.
        let mut pending: Option<(usize, usize, usize)> = None;
        while idx < end {
            let (len, dist) = match pending.take() {
                Some((p, l, d)) if p == idx => (l, d),
                _ => self.find(buf, base, idx, end, reps),
            };
            self.insert(buf, base, idx, end);
            if len == 0 {
                idx += 1;
                continue;
            }
            if self.lazy && idx + 1 < end {
                let (l2, d2) = self.find(buf, base, idx + 1, end, reps);
                if l2 > len + 1 {
                    pending = Some((idx + 1, l2, d2));
                    idx += 1;
                    continue;
                }
            }
            let ll = (idx - lit_start) as u32;
            let ov = code_offset(reps, dist as u32, ll);
            lits.extend_from_slice(&buf[lit_start..idx]);
            seqs.push(Seq {
                ll,
                ml: len as u32,
                ov,
            });
            for p in idx + 1..idx + len {
                self.insert(buf, base, p, end);
            }
            idx += len;
            lit_start = idx;
        }
        lits.extend_from_slice(&buf[lit_start..end]);
    }
}

/// The predefined FSE tables used for every sequence section.
struct Tables {
    ll: FseTable,
    ml: FseTable,
    of: FseTable,
}

impl Tables {
    fn new() -> Tables {
        Tables {
            ll: FseTable::new(&LL_NORM, 6),
            ml: FseTable::new(&ML_NORM, 6),
            of: FseTable::new(&OF_NORM, 5),
        }
    }
}

/// The sequences section: a count, the (all predefined) table modes and the bit stream.
fn sequences_section(seqs: &[Seq], t: &Tables, out: &mut Vec<u8>) {
    let n = seqs.len();
    if n < 128 {
        out.push(n as u8);
    } else if n < 0x7F00 {
        out.push((n >> 8) as u8 + 0x80);
        out.push(n as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&((n - 0x7F00) as u16).to_le_bytes());
    }
    if n == 0 {
        return;
    }
    out.push(0); // Predefined modes for literals lengths, offsets and match lengths.
    let mut bw = BitWriter::default();
    let codes = |s: &Seq| {
        let llc = ll_code(s.ll);
        let mlc = ml_code(s.ml);
        let ofc = (31 - s.ov.leading_zeros()) as usize;
        (llc, mlc, ofc)
    };
    let extras = |bw: &mut BitWriter, s: &Seq, llc: usize, mlc: usize, ofc: usize| {
        bw.add((s.ll - LL_BASE[llc]) as u64, LL_BITS[llc]);
        bw.add((s.ml - ML_BASE[mlc]) as u64, ML_BITS[mlc]);
        bw.add((s.ov - (1 << ofc)) as u64, ofc as u32);
    };
    let last = &seqs[n - 1];
    let (llc, mlc, ofc) = codes(last);
    let mut s_ll = t.ll.init(llc);
    let mut s_ml = t.ml.init(mlc);
    let mut s_of = t.of.init(ofc);
    extras(&mut bw, last, llc, mlc, ofc);
    for s in seqs[..n - 1].iter().rev() {
        let (llc, mlc, ofc) = codes(s);
        t.of.encode(&mut s_of, ofc, &mut bw);
        t.ml.encode(&mut s_ml, mlc, &mut bw);
        t.ll.encode(&mut s_ll, llc, &mut bw);
        extras(&mut bw, s, llc, mlc, ofc);
    }
    // The decoder reads the initial states as literals, offsets, match lengths, so the
    // final states go out in reverse.
    t.ml.flush(s_ml, &mut bw);
    t.of.flush(s_of, &mut bw);
    t.ll.flush(s_ll, &mut bw);
    out.extend_from_slice(&bw.finish());
}

// ---------------------------------------------------------------------------------------
// Frames and blocks.

/// Zstandard frame writer. Input is buffered into 128 KiB blocks; `finish` writes the last
/// block and the content checksum.
pub struct ZstdWriter<W: Write> {
    out: W,
    level: Level,
    /// Bytes not yet encoded are `buf[start..]`; `buf[..start]` is history for matches.
    buf: Vec<u8>,
    start: usize,
    /// Absolute position of `buf[0]`.
    base: u64,
    finder: Finder,
    tables: Tables,
    reps: [u32; 3],
    seqs: Vec<Seq>,
    lits: Vec<u8>,
    block: Vec<u8>,
    checksum: Xxh64,
    blocks: u64,
}

impl<W: Write> ZstdWriter<W> {
    /// Writes the frame header and returns the writer. `size_hint` is the input size when it
    /// is known; the window and tables are then no larger than the input needs.
    pub fn new(mut out: W, level: Level, size_hint: Option<u64>) -> io::Result<Self> {
        let level = match size_hint {
            Some(n) => level.sized_for(n),
            None => level,
        };
        let mut header = Vec::with_capacity(6);
        header.extend_from_slice(&MAGIC);
        // No single-segment flag, no content size, a content checksum, no dictionary ID.
        header.push(0x04);
        header.push(((level.window_log - 10) << 3) as u8);
        out.write_all(&header)?;
        Ok(ZstdWriter {
            out,
            level,
            buf: Vec::new(),
            start: 0,
            base: 0,
            finder: Finder::new(level),
            tables: Tables::new(),
            reps: [1, 4, 8],
            seqs: Vec::new(),
            lits: Vec::new(),
            block: Vec::new(),
            checksum: Xxh64::new(0),
            blocks: 0,
        })
    }

    /// Encodes `buf[start..end]` as one block: RLE for a run of one byte, otherwise
    /// compressed, or raw when compression does not shrink it.
    fn encode_block(&mut self, end: usize, last: bool) -> io::Result<()> {
        let start = self.start;
        let size = end - start;
        self.blocks += 1;
        if size == 0 {
            // An empty frame is one empty raw block.
            return self.write_header(last, 0, 0);
        }
        let first = self.buf[start];
        if self.buf[start..end].iter().all(|&b| b == first) {
            self.write_header(last, 1, size)?;
            self.out.write_all(&[first])?;
        } else {
            let mut stored = true;
            if !self.level.store {
                let saved = self.reps;
                self.seqs.clear();
                self.lits.clear();
                self.finder.parse(
                    &self.buf,
                    self.base,
                    start..end,
                    &mut self.reps,
                    &mut self.seqs,
                    &mut self.lits,
                );
                self.block.clear();
                literals_section(&self.lits, &mut self.block);
                sequences_section(&self.seqs, &self.tables, &mut self.block);
                if self.block.len() < size {
                    stored = false;
                    let packed = self.block.len();
                    self.write_header(last, 2, packed)?;
                    self.out.write_all(&self.block)?;
                } else {
                    // The decoder never sees these sequences, so it must not see their
                    // repeat offsets either.
                    self.reps = saved;
                }
            }
            if stored {
                self.write_header(last, 0, size)?;
                self.out.write_all(&self.buf[start..end])?;
            }
        }
        self.start = end;
        Ok(())
    }

    fn write_header(&mut self, last: bool, kind: u32, size: usize) -> io::Result<()> {
        let v = last as u32 | kind << 1 | (size as u32) << 3;
        self.out.write_all(&v.to_le_bytes()[..3])
    }

    /// Drops history that no match can reach any more.
    fn trim(&mut self) {
        let keep = self.finder.window;
        if self.start > 2 * keep {
            let cut = self.start - keep;
            self.buf.drain(..cut);
            self.base += cut as u64;
            self.start -= cut;
        }
    }

    /// Ends the frame and returns the sink.
    pub fn finish(mut self) -> io::Result<W> {
        let pending = self.buf.len();
        if pending > self.start || self.blocks == 0 {
            self.encode_block(pending, true)?;
        } else {
            self.write_header(true, 0, 0)?;
        }
        self.out
            .write_all(&(self.checksum.digest() as u32).to_le_bytes())?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for ZstdWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.checksum.update(data);
        self.buf.extend_from_slice(data);
        // Keep the newest (possibly partial) block for `finish` or the next write.
        while self.buf.len() - self.start > BLOCK_MAX {
            let end = self.start + BLOCK_MAX;
            self.encode_block(end, false)?;
            self.trim();
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample(n: usize, seed: u64) -> Vec<u8> {
        let words: [&[u8]; 6] = [
            b"alpha ", b"beta ", b"gamma\n", b"delta_", b"zstd ", b"frame ",
        ];
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if x.is_multiple_of(5) {
                v.push((x >> 24) as u8);
            } else {
                v.extend_from_slice(words[(x >> 33) as usize % words.len()]);
            }
        }
        v.truncate(n);
        v
    }

    fn encode(data: &[u8], mx: u32) -> Vec<u8> {
        let mut w = ZstdWriter::new(Vec::new(), Level::for_mx(mx), None).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn decode(z: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut d = ruzstd::decoding::StreamingDecoder::new(z).unwrap();
        d.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_through_ruzstd() {
        for (n, mx) in [
            (0usize, 5u32),
            (1, 5),
            (31, 3),
            (1000, 1),
            (200_000, 5),
            (3 << 20, 9),
        ] {
            let data = sample(n, n as u64 + 7);
            let z = encode(&data, mx);
            assert_eq!(decode(&z), data, "n={n} mx={mx}");
        }
    }

    #[test]
    fn runs_and_store_round_trip() {
        let zeros = vec![0u8; 500_000];
        let z = encode(&zeros, 5);
        assert!(z.len() < 200, "runs compress to {} bytes", z.len());
        assert_eq!(decode(&z), zeros);
        let data = sample(300_000, 3);
        assert_eq!(decode(&encode(&data, 0)), data);
    }

    #[test]
    fn incompressible_data_is_stored() {
        let mut x = 88172645463325252u64;
        let data: Vec<u8> = (0..300_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let z = encode(&data, 5);
        assert!(z.len() <= data.len() + data.len() / 100 + 64);
        assert_eq!(decode(&z), data);
    }

    /// Literals over all 256 byte values need FSE-coded Huffman weights; before those, such
    /// blocks were stored raw.
    #[test]
    fn wide_alphabets_are_huffman_coded() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let data: Vec<u8> = (0..400_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // Skewed towards small values, but every byte value occurs.
                let r = (x >> 40) & 0xFFFF;
                ((r * r * r) >> 40) as u8 ^ ((x >> 8) as u8 & 1)
            })
            .collect();
        assert!((0..=255u8).all(|b| data.contains(&b)));
        let z = encode(&data, 5);
        // Their entropy is 6.97 bits a byte; stored raw, they would not shrink at all.
        let lits = huffman_section(&data[..BLOCK_MAX]).expect("Huffman-coded literals");
        assert!(
            lits.len() < BLOCK_MAX * 9 / 10,
            "{} literal bytes",
            lits.len()
        );
        assert!(
            z.len() < data.len() * 23 / 25,
            "{} of {}",
            z.len(),
            data.len()
        );
        assert_eq!(decode(&z), data);
        // Small blocks of a few hundred distinct-ish bytes, and weights at both table sizes.
        for n in [200usize, 700, 3000, 20_000] {
            let part = &data[..n];
            assert_eq!(decode(&encode(part, 3)), part, "n={n}");
        }
    }

    #[test]
    fn table_descriptions_match_libzstd() {
        // Counts 8,4,2,1,1 (total 16) at log 5 doubled: written as libzstd's FSE_writeNCount
        // writes them.
        let norm = normalize(&[8, 4, 2, 1, 1], 16, 5).unwrap();
        assert_eq!(norm, [16, 8, 4, 2, 2]);
        assert_eq!(norm.iter().sum::<i32>(), 32);
    }

    #[test]
    fn repeat_offsets_follow_the_decoder() {
        let mut reps = [1u32, 4, 8];
        // Literal count nonzero: codes 1-3 pick the current repeat offsets.
        assert_eq!(code_offset(&mut reps, 4, 2), 2);
        assert_eq!(reps, [4, 1, 8]);
        assert_eq!(code_offset(&mut reps, 8, 2), 3);
        assert_eq!(reps, [8, 4, 1]);
        // Zero literals shift the choice: offset code 1 is the second repeat.
        assert_eq!(code_offset(&mut reps, 4, 0), 1);
        assert_eq!(reps, [4, 8, 1]);
        assert_eq!(code_offset(&mut reps, 100, 5), 103);
        assert_eq!(reps, [100, 4, 8]);
    }
}
