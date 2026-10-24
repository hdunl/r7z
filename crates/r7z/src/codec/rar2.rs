//! RAR 1.5 and 2.0 decompression (unpack versions 15, 20 and 26).
//!
//! Unlike later versions, every file's packed data is a bit stream of its own: a solid
//! unit restarts the input at each file and carries over only the window and the model.
//!
//! RAR 1.5 has no transmitted tables. It codes literals, lengths and distances by fixed
//! prefix tables picked from running averages, over symbol rankings that adapt as they
//! are used, and switches between literal-heavy and match-heavy coding by the same
//! statistics. RAR 2.0 is LZ77 with canonical Huffman tables sent in blocks, with an
//! audio mode that codes up to four interleaved channels by an adaptive linear predictor.

use std::io::Read;

use super::rar::{Bits, Huff, NO_SYMBOL};
use super::rar3::{DIST_BASE, DIST_BITS, LEN_BASE, LEN_BITS, SHORT_BASE, SHORT_BITS};
use crate::error::{Error, Result};

/// Decoder state for one solid unit of RAR 1.5 or 2.0 files.
pub struct Lz2 {
    v20: bool,
    win: Vec<u8>,
    mask: usize,
    /// Bytes decoded into the window, and bytes handed out, as absolute positions.
    total: u64,
    delivered: u64,
    /// Absolute position where the current entry ends.
    end: u64,
    /// The current file's packed input and its length.
    bits: Option<Bits>,
    packed: u64,
    /// Set once the current file's trailing tables (RAR 2.0) have been looked for.
    finished: bool,
    old_dist: [u32; 4],
    old_dist_ptr: u32,
    last_dist: u32,
    last_length: u32,
    v15: State15,
    t20: State20,
}

impl Lz2 {
    /// A decoder for unpack version `version` with a window of `win` bytes (a power of
    /// two, at least the dictionary size).
    pub fn new(version: u8, win: usize) -> Lz2 {
        debug_assert!(win.is_power_of_two());
        Lz2 {
            v20: version >= 20,
            win: vec![0; win],
            mask: win - 1,
            total: 0,
            delivered: 0,
            end: 0,
            bits: None,
            packed: 0,
            finished: true,
            old_dist: [0; 4],
            old_dist_ptr: 0,
            last_dist: 0,
            last_length: 0,
            v15: State15::default(),
            t20: State20::default(),
        }
    }

    /// Starts the next file: `size` bytes decoded from the `packed` bytes of `src`.
    /// `solid` continues from the previous file's model instead of starting afresh.
    pub fn begin(
        &mut self,
        src: Box<dyn Read + Send>,
        packed: u64,
        size: u64,
        solid: bool,
    ) -> Result<()> {
        self.finish()?;
        self.end = self.delivered + size;
        self.bits = Some(Bits::new(src));
        self.packed = packed;
        self.finished = false;
        if !solid {
            self.old_dist = [0; 4];
            self.old_dist_ptr = 0;
            self.last_dist = 0;
            self.last_length = 0;
        }
        if packed == 0 {
            return Ok(());
        }
        if self.v20 {
            if !solid {
                self.t20 = State20::default();
            }
            if !solid || !self.t20.tables_read {
                self.read_tables()?;
            }
        } else {
            self.v15.reset(solid);
            if size > 0 {
                self.flags()?;
                self.v15.flags_cnt = 8;
            }
        }
        Ok(())
    }

    /// Reads from the current file; returns 0 at its end.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let want = out.len().min(1 << 14) as u64;
        loop {
            let lim = self.total.min(self.end);
            let avail = lim - self.delivered;
            if avail > 0 && (avail >= want || lim == self.end) {
                let at = (self.delivered as usize) & self.mask;
                let n = (avail as usize).min(out.len()).min(self.win.len() - at);
                out[..n].copy_from_slice(&self.win[at..at + n]);
                self.delivered += n as u64;
                return Ok(n);
            }
            if self.delivered >= self.end {
                self.finish()?;
                return Ok(0);
            }
            if self.bits_mut()?.overrun() {
                return Err(Error::corrupt("unexpected end of compressed data"));
            }
            if self.v20 {
                self.step20()?;
            } else {
                self.step15()?;
            }
        }
    }

    /// Ends the current file. A RAR 2.0 file can end with the next file's tables: with at
    /// least five packed bytes left, a table switch there is read now.
    fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        self.delivered = self.end;
        if !self.v20 || self.bits.is_none() {
            return Ok(());
        }
        let left = self.packed.saturating_sub(self.bits_mut()?.byte_pos());
        if left < 5 {
            return Ok(());
        }
        let t = &self.t20;
        let table = if t.audio {
            t.md[t.cur].as_ref()
        } else {
            t.ld.as_ref()
        };
        let Some(table) = table else {
            return Ok(());
        };
        let sym = table.decode(self.bits.as_mut().unwrap())?;
        if sym == if self.t20.audio { 256 } else { 269 } {
            self.read_tables()?;
        }
        Ok(())
    }

    fn bits_mut(&mut self) -> Result<&mut Bits> {
        self.bits
            .as_mut()
            .ok_or_else(|| Error::corrupt("RAR data read before its file started"))
    }

    #[inline]
    fn peek16(&mut self) -> Result<u32> {
        Ok(self.bits_mut()?.peek(16)?)
    }

    #[inline]
    fn skip(&mut self, n: u32) {
        if let Some(b) = self.bits.as_mut() {
            b.consume(n);
        }
    }

    #[inline]
    fn put(&mut self, b: u8) {
        self.win[(self.total as usize) & self.mask] = b;
        self.total += 1;
    }

    /// Copies `len` bytes from `dist` bytes back. Like the original, a distance reaching
    /// before the start of the data reads the window's initial zeros.
    fn copy(&mut self, dist: u32, len: u32) {
        let mut src = (self.total as usize).wrapping_sub(dist as usize);
        for _ in 0..len {
            let b = self.win[src & self.mask];
            self.put(b);
            src = src.wrapping_add(1);
        }
    }
}

// ---- RAR 2.0 ----

const NC20: usize = 298;
const DC20: usize = 48;
const RC20: usize = 28;
const BC20: usize = 19;
const MC20: usize = 257;

#[derive(Default)]
struct State20 {
    tables_read: bool,
    audio: bool,
    channels: usize,
    cur: usize,
    channel_delta: i32,
    aud: [Audio; 4],
    /// Code lengths of the last tables; new ones are sent as differences.
    old: Vec<u8>,
    ld: Option<Huff>,
    dd: Option<Huff>,
    rd: Option<Huff>,
    md: [Option<Huff>; 4],
}

#[derive(Default, Clone, Copy)]
struct Audio {
    k: [i32; 5],
    d: [i32; 4],
    last_delta: i32,
    dif: [u32; 11],
    count: u32,
    last_char: i32,
}

impl Lz2 {
    fn step20(&mut self) -> Result<()> {
        if self.t20.audio {
            let ch = self.t20.cur;
            let sym = self.decode20(Table::Audio(ch))?;
            if sym == 256 {
                return self.read_tables();
            }
            let b = self.t20.audio_byte(sym as i32);
            self.put(b);
            self.t20.cur += 1;
            if self.t20.cur == self.t20.channels {
                self.t20.cur = 0;
            }
            return Ok(());
        }
        let sym = self.decode20(Table::Main)? as usize;
        if sym < 256 {
            self.put(sym as u8);
        } else if sym > 269 {
            let i = sym - 270;
            let mut len = LEN_BASE[i] + 3 + self.extra(LEN_BITS[i])?;
            let d = self.decode20(Table::Dist)? as usize;
            let dist = DIST_BASE[d] + 1 + self.extra(DIST_BITS[d])?;
            if dist >= 0x2000 {
                len += 1;
                if dist >= 0x40000 {
                    len += 1;
                }
            }
            self.copy20(len, dist);
        } else if sym == 269 {
            self.read_tables()?;
        } else if sym == 256 {
            self.copy20(self.last_length, self.last_dist);
        } else if sym < 261 {
            let dist =
                self.old_dist[(self.old_dist_ptr.wrapping_sub((sym - 256) as u32) & 3) as usize];
            let i = self.decode20(Table::Rep)? as usize;
            let mut len = LEN_BASE[i] + 2 + self.extra(LEN_BITS[i])?;
            if dist >= 0x101 {
                len += 1;
                if dist >= 0x2000 {
                    len += 1;
                    if dist >= 0x40000 {
                        len += 1;
                    }
                }
            }
            self.copy20(len, dist);
        } else {
            let i = sym - 261;
            let dist = SHORT_BASE[i] + 1 + self.extra(SHORT_BITS[i])?;
            self.copy20(2, dist);
        }
        Ok(())
    }

    fn copy20(&mut self, len: u32, dist: u32) {
        self.old_dist[(self.old_dist_ptr & 3) as usize] = dist;
        self.old_dist_ptr = self.old_dist_ptr.wrapping_add(1);
        self.last_dist = dist;
        self.last_length = len;
        self.copy(dist, len);
    }

    fn extra(&mut self, n: u32) -> Result<u32> {
        Ok(self.bits_mut()?.read_bits(n)?)
    }

    fn decode20(&mut self, t: Table) -> Result<u32> {
        let s = &self.t20;
        let table = match t {
            Table::Main => s.ld.as_ref(),
            Table::Dist => s.dd.as_ref(),
            Table::Rep => s.rd.as_ref(),
            Table::Audio(c) => s.md[c].as_ref(),
        };
        let table = table.ok_or_else(|| Error::corrupt("RAR 2.0 data before its tables"))?;
        let sym = table.decode(self.bits.as_mut().unwrap())?;
        if sym == NO_SYMBOL {
            return Err(Error::corrupt("invalid RAR 2.0 Huffman code"));
        }
        Ok(sym)
    }

    /// Reads a table block: the mode (LZ or audio with 1-4 channels), then the code
    /// lengths, each coded as a change from the previous table's.
    fn read_tables(&mut self) -> Result<()> {
        let bits = self.bits.as_mut().unwrap();
        let head = bits.read_bits(2)?;
        let audio = head & 2 != 0;
        let t = &mut self.t20;
        if t.old.is_empty() || head & 1 == 0 {
            t.old = vec![0; MC20 * 4];
        }
        let size = if audio {
            t.channels = bits.read_bits(2)? as usize + 1;
            if t.cur >= t.channels {
                t.cur = 0;
            }
            MC20 * t.channels
        } else {
            NC20 + DC20 + RC20
        };
        t.audio = audio;
        let mut pre = [0u8; BC20];
        for l in pre.iter_mut() {
            *l = bits.read_bits(4)? as u8;
        }
        let pre = Huff::build(&pre)?;
        let mut lens = vec![0u8; size];
        let mut i = 0;
        while i < size {
            let n = pre.decode(bits)?;
            match n {
                0..=15 => {
                    lens[i] = (n as u8 + t.old[i]) & 0xF;
                    i += 1;
                }
                16 => {
                    if i == 0 {
                        return Err(Error::corrupt("RAR 2.0 table repeats before its start"));
                    }
                    let k = bits.read_bits(2)? as usize + 3;
                    let v = lens[i - 1];
                    let e = (i + k).min(size);
                    lens[i..e].fill(v);
                    i = e;
                }
                17 | 18 => {
                    let k = if n == 17 {
                        bits.read_bits(3)? as usize + 3
                    } else {
                        bits.read_bits(7)? as usize + 11
                    };
                    i = (i + k).min(size);
                }
                _ => return Err(Error::corrupt("invalid RAR 2.0 table code")),
            }
        }
        t.tables_read = true;
        if bits.overrun() {
            // The original keeps its old tables when the block runs past the data.
            return Ok(());
        }
        if audio {
            for c in 0..t.channels {
                t.md[c] = Some(Huff::build(&lens[c * MC20..(c + 1) * MC20])?);
            }
        } else {
            t.ld = Some(Huff::build(&lens[..NC20])?);
            t.dd = Some(Huff::build(&lens[NC20..NC20 + DC20])?);
            t.rd = Some(Huff::build(&lens[NC20 + DC20..])?);
        }
        t.old[..size].copy_from_slice(&lens);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Table {
    Main,
    Dist,
    Rep,
    Audio(usize),
}

impl State20 {
    /// Decodes one audio byte of the current channel from its coded difference `delta`
    /// against a prediction from the channel's recent deltas and the other channels'.
    fn audio_byte(&mut self, delta: i32) -> u8 {
        let cd = self.channel_delta;
        let v = &mut self.aud[self.cur];
        v.count = v.count.wrapping_add(1);
        v.d[3] = v.d[2];
        v.d[2] = v.d[1];
        v.d[1] = v.last_delta - v.d[0];
        v.d[0] = v.last_delta;
        let p = 8 * v.last_char
            + v.k[0] * v.d[0]
            + v.k[1] * v.d[1]
            + v.k[2] * v.d[2]
            + v.k[3] * v.d[3]
            + v.k[4] * cd;
        let p = (p >> 3) & 0xFF;
        let ch = p - delta;
        let d = i32::from(delta as u8 as i8) * 8;
        let cands = [
            d,
            d - v.d[0],
            d + v.d[0],
            d - v.d[1],
            d + v.d[1],
            d - v.d[2],
            d + v.d[2],
            d - v.d[3],
            d + v.d[3],
            d - cd,
            d + cd,
        ];
        for (dif, c) in v.dif.iter_mut().zip(cands) {
            *dif = dif.wrapping_add(c.unsigned_abs());
        }
        let nd = i32::from((ch - v.last_char) as u8 as i8);
        v.last_delta = nd;
        v.last_char = ch;
        if v.count & 0x1F == 0 {
            let mut min = v.dif[0];
            let mut best = 0;
            for (i, &x) in v.dif.iter().enumerate().skip(1) {
                if x < min {
                    min = x;
                    best = i;
                }
            }
            v.dif = [0; 11];
            if best > 0 {
                let k = &mut v.k[(best - 1) / 2];
                if best % 2 == 1 {
                    if *k >= -16 {
                        *k -= 1;
                    }
                } else if *k < 16 {
                    *k += 1;
                }
            }
        }
        self.channel_delta = nd;
        ch as u8
    }
}

// ---- RAR 1.5 ----

// Prefix tables: `DecodeNum` counts how many thresholds of a table the next 16 bits
// reach, which gives the code length, and the position table maps the code to a rank.
const STARTL1: u32 = 2;
const DEC_L1: [u32; 11] = [
    0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff,
];
const POS_L1: [u32; 13] = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const STARTL2: u32 = 3;
const DEC_L2: [u32; 10] = [
    0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff,
];
const POS_L2: [u32; 13] = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const STARTHF0: u32 = 4;
const DEC_HF0: [u32; 9] = [
    0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff,
];
const POS_HF0: [u32; 13] = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const STARTHF1: u32 = 5;
const DEC_HF1: [u32; 8] = [
    0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff,
];
const POS_HF1: [u32; 13] = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const STARTHF2: u32 = 5;
const DEC_HF2: [u32; 8] = [
    0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff,
];
const POS_HF2: [u32; 13] = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const STARTHF3: u32 = 6;
const DEC_HF3: [u32; 7] = [0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const STARTHF4: u32 = 8;
const DEC_HF4: [u32; 6] = [0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

// Short match length codes for the two length statistics; entry 1 (or 3) takes its
// length from `buf60`, and the last entry matches anything.
const SHORT_LEN1: [u32; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u32; 16] = [
    0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0,
];
const SHORT_LEN2: [u32; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u32; 16] = [
    0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0,
];

struct State15 {
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    num_huf: u32,
    buf60: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    flags_cnt: i32,
    flag_buf: u32,
    st_mode: bool,
    lcount: u32,
    /// Rankings: literals, long distances, short distances and flag bytes. Each entry is
    /// a value in the high byte and an adaptation counter in the low byte.
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
}

impl Default for State15 {
    fn default() -> Self {
        let mut s = State15 {
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            num_huf: 0,
            buf60: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            flags_cnt: 0,
            flag_buf: 0,
            st_mode: false,
            lcount: 0,
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
        };
        for i in 0..256u16 {
            s.ch_set[i as usize] = i << 8;
            s.ch_set_b[i as usize] = i << 8;
            s.ch_set_a[i as usize] = i;
            s.ch_set_c[i as usize] = (i.wrapping_neg() & 0xff) << 8;
        }
        corr_huff(&mut s.ch_set_b, &mut s.n_to_pl_b);
        s
    }
}

impl State15 {
    fn reset(&mut self, solid: bool) {
        if !solid {
            *self = State15::default();
        }
        self.flags_cnt = 0;
        self.flag_buf = 0;
        self.st_mode = false;
        self.lcount = 0;
    }
}

/// Resets the adaptation counters of a ranking: the first 32 entries get 7, the next 32
/// get 6, and so on down to 0.
fn corr_huff(set: &mut [u16; 256], to_place: &mut [u8; 256]) {
    for (i, e) in set.iter_mut().enumerate() {
        *e = (*e & !0xff) | (7 - (i / 32) as u16);
    }
    to_place.fill(0);
    for (i, p) in to_place.iter_mut().take(7).enumerate() {
        *p = ((7 - i) * 32) as u8;
    }
}

impl Lz2 {
    fn step15(&mut self) -> Result<()> {
        if self.v15.st_mode {
            return self.huff_decode();
        }
        self.v15.flags_cnt -= 1;
        if self.v15.flags_cnt < 0 {
            self.flags()?;
            self.v15.flags_cnt = 7;
        }
        let s = &mut self.v15;
        if s.flag_buf & 0x80 != 0 {
            s.flag_buf <<= 1;
            if s.nlzb > s.nhfb {
                self.long_lz()
            } else {
                self.huff_decode()
            }
        } else {
            s.flag_buf <<= 1;
            s.flags_cnt -= 1;
            if s.flags_cnt < 0 {
                self.flags()?;
                self.v15.flags_cnt = 7;
            }
            let s = &mut self.v15;
            if s.flag_buf & 0x80 != 0 {
                s.flag_buf <<= 1;
                if s.nlzb > s.nhfb {
                    self.huff_decode()
                } else {
                    self.long_lz()
                }
            } else {
                s.flag_buf <<= 1;
                self.short_lz()
            }
        }
    }

    /// Decodes a number from the next 16 bits `num` with a threshold table.
    fn decode_num(&mut self, num: u32, start: u32, dec: &[u32], pos: &[u32; 13]) -> Result<u32> {
        let num = num & 0xfff0;
        let mut i = 0;
        let mut len = start;
        while dec[i] <= num {
            len += 1;
            i += 1;
        }
        self.skip(len);
        let base = if i > 0 { dec[i - 1] } else { 0 };
        let p = pos
            .get(len as usize)
            .ok_or_else(|| Error::corrupt("invalid RAR 1.5 code"))?;
        Ok(((num - base) >> (16 - len)) + p)
    }

    fn copy15(&mut self, dist: u32, len: u32) {
        self.copy(dist, len);
    }

    fn push15(&mut self, dist: u32, len: u32) {
        self.old_dist[(self.old_dist_ptr & 3) as usize] = dist;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = len;
        self.last_dist = dist;
        self.copy15(dist, len);
    }

    fn short_lz(&mut self) -> Result<()> {
        self.v15.num_huf = 0;
        let mut bf = self.peek16()?;
        if self.v15.lcount == 2 {
            self.skip(1);
            if bf >= 0x8000 {
                self.copy15(self.last_dist, self.last_length);
                return Ok(());
            }
            bf <<= 1;
            self.v15.lcount = 0;
        }
        let bf = (bf >> 8) & 0xff;
        let s = &self.v15;
        let (lens, xors, alt) = if s.avr_ln1 < 37 {
            (&SHORT_LEN1, &SHORT_XOR1, 1)
        } else {
            (&SHORT_LEN2, &SHORT_XOR2, 3)
        };
        let len_of = |i: usize| if i == alt { s.buf60 + 3 } else { lens[i] };
        let mut length = 0;
        while length < 15 && (bf ^ xors[length]) & !(0xffu32 >> len_of(length)) & 0xff != 0 {
            length += 1;
        }
        let skip = len_of(length);
        self.skip(skip);
        let mut length = length as u32;
        if length >= 9 {
            if length == 9 {
                self.v15.lcount += 1;
                self.copy15(self.last_dist, self.last_length);
                return Ok(());
            }
            if length == 14 {
                self.v15.lcount = 0;
                let n = self.peek16()?;
                let len = self.decode_num(n, STARTL2, &DEC_L2, &POS_L2)? + 5;
                let dist = (self.peek16()? >> 1) | 0x8000;
                self.skip(15);
                self.last_length = len;
                self.last_dist = dist;
                self.copy15(dist, len);
                return Ok(());
            }
            self.v15.lcount = 0;
            let save = length;
            let dist = self.old_dist[(self.old_dist_ptr.wrapping_sub(length - 9) & 3) as usize];
            let n = self.peek16()?;
            length = self.decode_num(n, STARTL1, &DEC_L1, &POS_L1)? + 2;
            if length == 0x101 && save == 10 {
                self.v15.buf60 ^= 1;
                return Ok(());
            }
            if dist > 256 {
                length += 1;
            }
            if dist >= self.v15.max_dist3 {
                length += 1;
            }
            self.push15(dist, length);
            return Ok(());
        }
        let s = &mut self.v15;
        s.lcount = 0;
        s.avr_ln1 += length;
        s.avr_ln1 -= s.avr_ln1 >> 4;
        let n = self.peek16()?;
        let place = (self.decode_num(n, STARTHF2, &DEC_HF2, &POS_HF2)? & 0xff) as usize;
        let s = &mut self.v15;
        let dist = s.ch_set_a[place];
        if place > 0 {
            s.ch_set_a[place] = s.ch_set_a[place - 1];
            s.ch_set_a[place - 1] = dist;
        }
        self.push15(u32::from(dist) + 1, length + 2);
        Ok(())
    }

    fn long_lz(&mut self) -> Result<()> {
        let s = &mut self.v15;
        s.num_huf = 0;
        s.nlzb += 16;
        if s.nlzb > 0xff {
            s.nlzb = 0x90;
            s.nhfb >>= 1;
        }
        let old_avr2 = s.avr_ln2;
        let bf = self.peek16()?;
        let mut length = if old_avr2 >= 122 {
            self.decode_num(bf, STARTL2, &DEC_L2, &POS_L2)?
        } else if old_avr2 >= 64 {
            self.decode_num(bf, STARTL1, &DEC_L1, &POS_L1)?
        } else if bf < 0x100 {
            self.skip(16);
            bf
        } else {
            let mut l = 0;
            while (bf << l) & 0x8000 == 0 {
                l += 1;
            }
            self.skip(l + 1);
            l
        };
        let s = &mut self.v15;
        s.avr_ln2 += length;
        s.avr_ln2 -= s.avr_ln2 >> 5;
        let avr_b = s.avr_plc_b;
        let bf = self.peek16()?;
        let place = if avr_b > 0x28ff {
            self.decode_num(bf, STARTHF2, &DEC_HF2, &POS_HF2)?
        } else if avr_b > 0x6ff {
            self.decode_num(bf, STARTHF1, &DEC_HF1, &POS_HF1)?
        } else {
            self.decode_num(bf, STARTHF0, &DEC_HF0, &POS_HF0)?
        };
        let s = &mut self.v15;
        s.avr_plc_b += place;
        s.avr_plc_b -= s.avr_plc_b >> 8;
        let place = (place & 0xff) as usize;
        let (mut dist, new_place) = loop {
            let d = u32::from(s.ch_set_b[place]);
            let np = s.n_to_pl_b[(d & 0xff) as usize];
            s.n_to_pl_b[(d & 0xff) as usize] = np.wrapping_add(1);
            let d = d + 1;
            if d & 0xff == 0 {
                corr_huff(&mut s.ch_set_b, &mut s.n_to_pl_b);
            } else {
                break (d, np as usize);
            }
        };
        s.ch_set_b[place] = s.ch_set_b[new_place];
        s.ch_set_b[new_place] = dist as u16;
        let low = self.peek16()? >> 8;
        dist = ((dist & 0xff00) | low) >> 1;
        self.skip(7);
        let s = &mut self.v15;
        let old_avr3 = s.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && dist <= s.max_dist3 {
                s.avr_ln3 += 1;
                s.avr_ln3 -= s.avr_ln3 >> 8;
            } else if s.avr_ln3 > 0 {
                s.avr_ln3 -= 1;
            }
        }
        length += 3;
        if dist >= s.max_dist3 {
            length += 1;
        }
        if dist <= 256 {
            length += 8;
        }
        s.max_dist3 = if old_avr3 > 0xb0 || (s.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            0x7f00
        } else {
            0x2001
        };
        self.push15(dist, length);
        Ok(())
    }

    fn huff_decode(&mut self) -> Result<()> {
        let bf = self.peek16()?;
        let avr = self.v15.avr_plc;
        let mut place = if avr > 0x75ff {
            self.decode_num(bf, STARTHF4, &DEC_HF4, &POS_HF4)?
        } else if avr > 0x5dff {
            self.decode_num(bf, STARTHF3, &DEC_HF3, &POS_HF3)?
        } else if avr > 0x35ff {
            self.decode_num(bf, STARTHF2, &DEC_HF2, &POS_HF2)?
        } else if avr > 0x0dff {
            self.decode_num(bf, STARTHF1, &DEC_HF1, &POS_HF1)?
        } else {
            self.decode_num(bf, STARTHF0, &DEC_HF0, &POS_HF0)?
        } & 0xff;
        if self.v15.st_mode {
            if place == 0 && bf > 0xfff {
                place = 0x100;
            }
            if place == 0 {
                // Escape: leave the literal-run mode, or a short match.
                let b = self.peek16()?;
                self.skip(1);
                if b & 0x8000 != 0 {
                    self.v15.num_huf = 0;
                    self.v15.st_mode = false;
                    return Ok(());
                }
                let len = if b & 0x4000 != 0 { 4 } else { 3 };
                self.skip(1);
                let n = self.peek16()?;
                let d = self.decode_num(n, STARTHF2, &DEC_HF2, &POS_HF2)?;
                let d = (d << 5) | (self.peek16()? >> 11);
                self.skip(5);
                self.copy15(d, len);
                return Ok(());
            }
            place -= 1;
        } else {
            let n = self.v15.num_huf;
            self.v15.num_huf += 1;
            if n >= 16 && self.v15.flags_cnt == 0 {
                self.v15.st_mode = true;
            }
        }
        let place = place as usize;
        let s = &mut self.v15;
        s.avr_plc += place as u32;
        s.avr_plc -= s.avr_plc >> 8;
        s.nhfb += 16;
        if s.nhfb > 0xff {
            s.nhfb = 0x90;
            s.nlzb >>= 1;
        }
        let b = (s.ch_set[place] >> 8) as u8;
        let (cur, new_place) = loop {
            let c = u32::from(s.ch_set[place]);
            let np = s.n_to_pl[(c & 0xff) as usize];
            s.n_to_pl[(c & 0xff) as usize] = np.wrapping_add(1);
            let c = c + 1;
            if c & 0xff > 0xa1 {
                corr_huff(&mut s.ch_set, &mut s.n_to_pl);
            } else {
                break (c, np as usize);
            }
        };
        s.ch_set[place] = s.ch_set[new_place];
        s.ch_set[new_place] = cur as u16;
        self.put(b);
        Ok(())
    }

    /// Reads the next byte of match/literal flags.
    fn flags(&mut self) -> Result<()> {
        let n = self.peek16()?;
        let place = self.decode_num(n, STARTHF2, &DEC_HF2, &POS_HF2)? as usize;
        if place >= 256 {
            return Ok(());
        }
        let s = &mut self.v15;
        let (f, new_place) = loop {
            let f = u32::from(s.ch_set_c[place]);
            s.flag_buf = f >> 8;
            let np = s.n_to_pl_c[(f & 0xff) as usize];
            s.n_to_pl_c[(f & 0xff) as usize] = np.wrapping_add(1);
            let f = f + 1;
            if f & 0xff != 0 {
                break (f, np as usize);
            }
            corr_huff(&mut s.ch_set_c, &mut s.n_to_pl_c);
        };
        s.ch_set_c[place] = s.ch_set_c[new_place];
        s.ch_set_c[new_place] = f as u16;
        Ok(())
    }
}
