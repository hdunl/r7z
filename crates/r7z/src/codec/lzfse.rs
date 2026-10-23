//! LZFSE, Apple's LZ77 codec with finite-state entropy coding (`ULFO` disk images, chunk
//! type 0x80000007).
//!
//! A stream is a sequence of blocks, each opened by a four-byte magic, and ends with the
//! `bvx$` marker:
//!
//! * `bvx-`: stored bytes. Magic, `n_raw_bytes` (u32 LE), then the bytes.
//! * `bvxn`: an LZVN block. Magic, `n_raw_bytes` and `n_payload_bytes` (u32 LE), then LZVN
//!   data, decoded by the `lzvn` crate.
//! * `bvx2`: an FSE block. A 32-byte header (little-endian bit fields), then the weight
//!   table, the literal stream and the literal-length, match-length and match-distance
//!   (LMD) stream.
//!
//! The weight table gives the symbol frequencies of four alphabets: literal lengths (20
//! symbols, 64 states), match lengths (20, 64), match distances (64, 256) and literal
//! bytes (256, 1024). Each alphabet becomes a state table. A state decodes to a symbol,
//! and each symbol carries extra bits that add to its base value. The entropy streams are
//! read from their last byte backwards.
//!
//! `bvx1` (obsolete blocks with uncompressed tables) is unsupported.

use crate::error::{Error, Result};

const V2_HEADER: usize = 32;
/// Weights for literal lengths (20), match lengths (20), distances (64) and bytes (256).
const N_WEIGHTS: usize = 360;
const WEIGHT_BYTES_MAX: usize = (N_WEIGHTS * 14).div_ceil(8);
const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const U_STATES: usize = 1024;
const MAX_LITERALS: usize = 4 * 10_000;
const MAX_LMDS: usize = 10_000;

/// Base value and extra-bit count of the last four literal-length and match-length symbols.
/// The first sixteen symbols of each alphabet stand for themselves.
const L_TAIL: [(u32, u8); 4] = [(16, 2), (20, 3), (28, 5), (60, 8)];
const M_TAIL: [(u32, u8); 4] = [(16, 3), (24, 5), (56, 8), (312, 11)];

/// Bit count and value of each 5-bit code of the weight table. Codes of 8 and 14 bits carry
/// their value in the bits above the code.
const W_BITS: [u8; 32] = [
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2,
    14,
];
const W_VALUE: [u8; 32] = [
    0, 2, 1, 4, 0, 3, 1, 0, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 0, 0, 2, 1, 7, 0, 3, 1, 0,
];

fn truncated() -> Error {
    Error::corrupt("LZFSE stream is truncated")
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Decodes one LZFSE stream into `out`, which is the exact decoded size. Input after the
/// end marker is not read.
pub fn decode(src: &[u8], out: &mut [u8]) -> Result<()> {
    let (mut pos, mut done) = (0usize, 0usize);
    loop {
        let block = src.get(pos..).ok_or_else(truncated)?;
        let magic = block
            .get(..4)
            .ok_or_else(|| Error::corrupt("LZFSE stream has no end marker"))?;
        let (used, n) = match magic {
            b"bvx$" => break,
            b"bvx-" => raw_block(block, out, done)?,
            b"bvxn" => lzvn_block(block, out, done)?,
            b"bvx2" => fse_block(block, out, done)?,
            b"bvx1" => {
                return Err(Error::unsupported(
                    "LZFSE blocks with uncompressed tables (bvx1)",
                ))
            }
            _ => return Err(Error::corrupt("LZFSE block has an unknown magic")),
        };
        pos += used;
        done += n;
    }
    if done != out.len() {
        return Err(Error::corrupt(format!(
            "LZFSE stream decodes to {done} bytes, expected {}",
            out.len()
        )));
    }
    Ok(())
}

/// The `n` output bytes a block starting at `done` writes.
fn output_at(out: &mut [u8], done: usize, n: usize) -> Result<&mut [u8]> {
    out.get_mut(done..)
        .and_then(|rest| rest.get_mut(..n))
        .ok_or_else(|| Error::corrupt("LZFSE block overruns its chunk"))
}

fn raw_block(block: &[u8], out: &mut [u8], done: usize) -> Result<(usize, usize)> {
    let n = u32_at(block, 4).ok_or_else(truncated)? as usize;
    let data = block
        .get(8..)
        .and_then(|rest| rest.get(..n))
        .ok_or_else(truncated)?;
    output_at(out, done, n)?.copy_from_slice(data);
    Ok((8 + n, n))
}

fn lzvn_block(block: &[u8], out: &mut [u8], done: usize) -> Result<(usize, usize)> {
    let n_raw = u32_at(block, 4).ok_or_else(truncated)? as usize;
    let n_payload = u32_at(block, 8).ok_or_else(truncated)? as usize;
    let payload = block
        .get(12..)
        .and_then(|rest| rest.get(..n_payload))
        .ok_or_else(truncated)?;
    let dst = output_at(out, done, n_raw)?;
    if n_raw != 0 {
        let got = lzvn::decode_into(payload, dst)
            .map_err(|e| Error::corrupt(format!("LZVN block in LZFSE stream: {e}")))?;
        if got != n_raw {
            return Err(Error::corrupt(format!(
                "LZVN block decodes to {got} bytes, expected {n_raw}"
            )));
        }
    }
    Ok((12 + n_payload, n_raw))
}

/// A decoding table: `k` bits select the next state from `delta`, and `extra` bits add to
/// `value`. Literal tables use `value` as the symbol itself.
#[derive(Clone, Copy, Default)]
struct Entry {
    k: u8,
    extra: u8,
    delta: u16,
    value: u32,
}

/// Builds the table of an alphabet of `weights` over `states` states, where `value(sym)`
/// gives each symbol's base value and extra-bit count. Symbol `s` owns `weights[s]`
/// consecutive states, and the leftover states latch in place.
fn build(weights: &[u16], states: usize, value: impl Fn(usize) -> (u32, u8)) -> Result<Vec<Entry>> {
    let total: usize = weights.iter().map(|&w| usize::from(w)).sum();
    if total > states {
        return Err(Error::corrupt(
            "LZFSE weight table is larger than its state count",
        ));
    }
    let log = states.trailing_zeros();
    let mut t = vec![Entry::default(); states];
    let mut at = 0usize;
    for (sym, &w) in weights.iter().enumerate() {
        let w = usize::from(w);
        if w == 0 {
            continue;
        }
        let (base, extra) = value(sym);
        let f = w.ilog2();
        let k = log - f;
        let short = ((states << 1) >> k) - w;
        for j in 0..short {
            t[at + j] = Entry {
                k: k as u8,
                extra,
                delta: (((w + j) << k) - states) as u16,
                value: base,
            };
        }
        for j in short..w {
            t[at + j] = Entry {
                k: (k - 1) as u8,
                extra,
                delta: ((j - short) << (k - 1)) as u16,
                value: base,
            };
        }
        at += w;
    }
    for (i, e) in t.iter_mut().enumerate().skip(at) {
        *e = Entry {
            k: 0,
            extra: 0,
            delta: i as u16,
            value: 0,
        };
    }
    Ok(t)
}

/// Literal-length and match-length base values: symbols below 16 stand for themselves.
fn lm_value(sym: usize, tail: &[(u32, u8); 4]) -> (u32, u8) {
    if sym < 16 {
        (sym as u32, 0)
    } else {
        tail.get(sym - 16).copied().unwrap_or((0, 0))
    }
}

/// Match-distance values: groups of four symbols share an extra-bit count that grows by one
/// per group.
fn d_value(sym: usize) -> (u32, u8) {
    let g = (sym / 4) as u32;
    let step = 1u32 << g;
    (4 * (step - 1) + (sym as u32 % 4) * step, g as u8)
}

/// Reads a bit stream from its end: the last byte holds the first bits, and the top
/// `unused` bits of that byte are zero padding.
struct Bits<'a> {
    src: &'a [u8],
    acc: u64,
    n: u32,
}

impl<'a> Bits<'a> {
    fn new(src: &'a [u8], unused: u32) -> Result<Self> {
        let (&last, rest) = src
            .split_last()
            .ok_or_else(|| Error::corrupt("LZFSE entropy stream is empty"))?;
        let pad = if unused == 0 { 0 } else { last >> (8 - unused) };
        if unused > 7 || pad != 0 {
            return Err(Error::corrupt("LZFSE entropy stream has bad padding"));
        }
        Ok(Bits {
            src: rest,
            acc: u64::from(last),
            n: 8 - unused,
        })
    }

    fn pull(&mut self, bits: u32) -> Result<u32> {
        if bits > self.n {
            while self.n <= 48 {
                let Some((&b, rest)) = self.src.split_last() else {
                    break;
                };
                self.src = rest;
                self.acc = (self.acc << 8) | u64::from(b);
                self.n += 8;
            }
            if bits > self.n {
                return Err(Error::corrupt("LZFSE entropy stream is truncated"));
            }
        }
        self.n -= bits;
        let v = (self.acc >> self.n) & ((1u64 << bits) - 1);
        self.acc &= (1u64 << self.n) - 1;
        Ok(v as u32)
    }
}

/// One decoding step: the state picks an entry, the entry gives the next state, and the
/// entry's value adds its extra bits.
fn step(t: &[Entry], bits: &mut Bits, state: &mut usize) -> Result<u32> {
    let e = *t
        .get(*state)
        .ok_or_else(|| Error::corrupt("LZFSE state is out of range"))?;
    *state = usize::from(e.delta) + bits.pull(u32::from(e.k))? as usize;
    Ok(e.value + bits.pull(u32::from(e.extra))?)
}

/// The weight table: 360 weights, each a 5-, 8- or 14-bit code, read least significant bit
/// first. The payload must be used exactly.
fn read_weights(src: &[u8]) -> Result<Vec<u16>> {
    let mut w = vec![0u16; N_WEIGHTS];
    let (mut acc, mut n, mut at) = (0u64, 0u32, 0usize);
    for slot in &mut w {
        while n <= 24 {
            let Some(&b) = src.get(at) else { break };
            acc |= u64::from(b) << n;
            n += 8;
            at += 1;
        }
        let code = (acc & 0x1F) as usize;
        let bits = u32::from(W_BITS[code]);
        if bits > n {
            return Err(Error::corrupt("LZFSE weight table is truncated"));
        }
        let value = match bits {
            8 => 8 + ((acc >> 4) & 0xF),
            14 => 24 + ((acc >> 4) & 0x3FF),
            _ => u64::from(W_VALUE[code]),
        };
        *slot = value as u16;
        acc >>= bits;
        n -= bits;
    }
    if at != src.len() || n >= 8 {
        return Err(Error::corrupt(
            "LZFSE weight table does not match its header",
        ));
    }
    Ok(w)
}

/// The literal stream: symbols come four at a time from four interleaved states.
fn decode_literals(
    src: &[u8],
    num: usize,
    unused: u32,
    state: [usize; 4],
    u: &[Entry],
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; num];
    if num == 0 {
        return Ok(out);
    }
    let mut bits = Bits::new(src, unused)?;
    let mut st = state;
    let (quads, _) = out.as_chunks_mut::<4>();
    for quad in quads {
        for (slot, s) in quad.iter_mut().zip(st.iter_mut()) {
            *slot = step(u, &mut bits, s)? as u8;
        }
    }
    if st != [0; 4] {
        return Err(Error::corrupt("LZFSE literal states do not end at zero"));
    }
    Ok(out)
}

struct Tables {
    l: Vec<Entry>,
    m: Vec<Entry>,
    d: Vec<Entry>,
}

/// Where a block's entropy streams are and where their states start.
struct Lmd<'a> {
    src: &'a [u8],
    num: usize,
    unused: u32,
    state: [usize; 3],
}

/// Decodes `num` literal-length, match-length and distance triples, writing `n_raw` bytes
/// at `start`. A zero distance reuses the last nonzero distance.
fn decode_lmds(
    lmd: &Lmd,
    t: &Tables,
    lits: &[u8],
    out: &mut [u8],
    start: usize,
    n_raw: usize,
) -> Result<()> {
    let end = start + n_raw;
    let (mut sl, mut sm, mut sd) = (lmd.state[0], lmd.state[1], lmd.state[2]);
    let (mut lp, mut o, mut dist) = (0usize, start, 0usize);
    if lmd.num > 0 {
        let mut bits = Bits::new(lmd.src, lmd.unused)?;
        for _ in 0..lmd.num {
            let l = step(&t.l, &mut bits, &mut sl)? as usize;
            let m = step(&t.m, &mut bits, &mut sm)? as usize;
            let d = step(&t.d, &mut bits, &mut sd)? as usize;
            if d != 0 {
                dist = d;
            }
            let lit_end = lp + l;
            let run = lits
                .get(lp..lit_end)
                .ok_or_else(|| Error::corrupt("LZFSE literal run passes the literal stream"))?;
            let o_end = o + l;
            if o_end > end {
                return Err(Error::corrupt("LZFSE literal run overruns its block"));
            }
            out[o..o_end].copy_from_slice(run);
            lp = lit_end;
            o = o_end;
            if m != 0 {
                if dist == 0 || dist > o {
                    return Err(Error::corrupt("LZFSE match distance is out of range"));
                }
                let m_end = o + m;
                if m_end > end {
                    return Err(Error::corrupt("LZFSE match overruns its block"));
                }
                copy_match(out, o, dist, m);
                o = m_end;
            }
        }
    }
    if o != end || sl != 0 || sm != 0 || sd != 0 {
        return Err(Error::corrupt(
            "LZFSE block does not end where its header says",
        ));
    }
    Ok(())
}

/// Copies `len` bytes from `dist` bytes back to `at`. Overlapping copies repeat the bytes.
fn copy_match(out: &mut [u8], at: usize, dist: usize, len: usize) {
    if dist >= len {
        out.copy_within(at - dist..at - dist + len, at);
    } else {
        let mut p = at;
        while p < at + len {
            out[p] = out[p - dist];
            p += 1;
        }
    }
}

/// Decodes one `bvx2` block. Returns (encoded length, decoded length).
fn fse_block(block: &[u8], out: &mut [u8], done: usize) -> Result<(usize, usize)> {
    let n_raw = u32_at(block, 4).ok_or_else(truncated)? as usize;
    let p1 = u64_at(block, 8).ok_or_else(truncated)?;
    let p2 = u64_at(block, 16).ok_or_else(truncated)?;
    let p3 = u64_at(block, 24).ok_or_else(truncated)?;
    let lit_num = (p1 & 0xF_FFFF) as usize;
    let lit_len = ((p1 >> 20) & 0xF_FFFF) as usize;
    let lmd_num = ((p1 >> 40) & 0xF_FFFF) as usize;
    let lit_unused = 7 - ((p1 >> 60) & 7) as u32;
    let lit_state = [0u32, 10, 20, 30].map(|s| ((p2 >> s) & 0x3FF) as usize);
    let lmd_len = ((p2 >> 40) & 0xF_FFFF) as usize;
    let lmd_unused = 7 - ((p2 >> 60) & 7) as u32;
    // The header size counts the 32 header bytes and the weight table.
    let weights_end = (p3 & 0xFFFF_FFFF) as usize;
    let lmd_state = [32u32, 42, 52].map(|s| ((p3 >> s) & 0x3FF) as usize);

    if weights_end < V2_HEADER || weights_end - V2_HEADER > WEIGHT_BYTES_MAX {
        return Err(Error::corrupt("LZFSE weight table has a bad size"));
    }
    if lit_num > MAX_LITERALS || !lit_num.is_multiple_of(4) || lmd_num > MAX_LMDS {
        return Err(Error::corrupt("LZFSE block has bad symbol counts"));
    }
    if lmd_state[0] >= L_STATES || lmd_state[1] >= M_STATES || lmd_state[2] >= D_STATES {
        return Err(Error::corrupt("LZFSE match state is out of range"));
    }
    if n_raw > out.len() - done {
        return Err(Error::corrupt("LZFSE block overruns its chunk"));
    }
    let end = weights_end
        .checked_add(lit_len)
        .and_then(|e| e.checked_add(lmd_len))
        .filter(|&e| e <= block.len())
        .ok_or_else(truncated)?;

    let w = read_weights(block.get(V2_HEADER..weights_end).ok_or_else(truncated)?)?;
    let tables = Tables {
        l: build(&w[0..20], L_STATES, |s| lm_value(s, &L_TAIL))?,
        m: build(&w[20..40], M_STATES, |s| lm_value(s, &M_TAIL))?,
        d: build(&w[40..104], D_STATES, d_value)?,
    };
    let u = build(&w[104..], U_STATES, |s| (s as u32, 0))?;

    let lit_src = block
        .get(weights_end..weights_end + lit_len)
        .ok_or_else(truncated)?;
    let lits = decode_literals(lit_src, lit_num, lit_unused, lit_state, &u)?;
    let lmd = Lmd {
        src: block
            .get(weights_end + lit_len..end)
            .ok_or_else(truncated)?,
        num: lmd_num,
        unused: lmd_unused,
        state: [lmd_state[0], lmd_state[1], lmd_state[2]],
    };
    decode_lmds(&lmd, &tables, &lits, out, done, n_raw)?;
    Ok((end, n_raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        lzfse_rust::encode_bytes(data, &mut out).unwrap();
        out
    }

    fn sample(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|i| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                match (i / 97) % 3 {
                    0 => (x >> 16) as u8,
                    1 => b"the quick brown fox "[i % 20],
                    _ => (i % 7) as u8,
                }
            })
            .collect()
    }

    #[test]
    fn round_trips_encoder_output() {
        for (n, seed) in [(0usize, 1u32), (1, 2), (100, 3), (4096, 4), (70_000, 5)] {
            let data = sample(n, seed);
            let enc = encode(&data);
            let mut out = vec![0u8; data.len()];
            decode(&enc, &mut out).unwrap();
            assert_eq!(out, data, "size {n}");
        }
    }

    #[test]
    fn rejects_wrong_output_size() {
        let data = sample(5000, 9);
        let enc = encode(&data);
        let mut short = vec![0u8; data.len() - 1];
        assert!(decode(&enc, &mut short).is_err());
        let mut long = vec![0u8; data.len() + 1];
        assert!(decode(&enc, &mut long).is_err());
    }

    #[test]
    fn damage_never_panics() {
        let data = sample(3000, 11);
        let enc = encode(&data);
        for cut in 0..enc.len() {
            let mut out = vec![0u8; data.len()];
            let _ = decode(&enc[..cut], &mut out);
        }
        for at in (0..enc.len()).step_by(7) {
            for bit in 0..8 {
                let mut bad = enc.clone();
                bad[at] ^= 1 << bit;
                let mut out = vec![0u8; data.len()];
                let _ = decode(&bad, &mut out);
            }
        }
    }

    #[test]
    fn encoder_output_uses_the_lzvn_and_fse_block_kinds() {
        // Short text is coded as LZVN blocks, longer repetitive text as FSE blocks.
        let short = encode(b"abcabcabcabcabcabcabcabc hello hello hello hello");
        assert!(short.windows(4).any(|w| w == b"bvxn"));
        let long = encode(&sample(20_000, 3));
        assert!(long.windows(4).any(|w| w == b"bvx2"));
        let mut out = vec![0u8; 48];
        decode(&short, &mut out).unwrap();
        assert_eq!(
            &out[..],
            b"abcabcabcabcabcabcabcabc hello hello hello hello"
        );
    }

    #[test]
    fn raw_block_is_stored_bytes() {
        let mut src = b"bvx-".to_vec();
        src.extend(3u32.to_le_bytes());
        src.extend(b"abc");
        src.extend(b"bvx$");
        let mut out = [0u8; 3];
        decode(&src, &mut out).unwrap();
        assert_eq!(&out, b"abc");
    }

    #[test]
    fn rejects_unknown_magic_and_missing_end() {
        let mut out = [0u8; 0];
        assert!(decode(b"bvxq", &mut out).is_err());
        assert!(decode(b"", &mut out).is_err());
        assert!(decode(b"bvx1", &mut out).is_err());
    }
}
