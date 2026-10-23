//! RAR 2.9/3.x decompression (unpack version 29): LZ77 with per-block Huffman tables, the
//! PPMd variant H mode, and the standard VM filters (E8, E8E9, delta, RGB, audio and
//! Itanium), which are recognised by the fingerprint of their bytecode.
//!
//! One [`Lz3`] decodes a whole solid unit: entries are read in order from one stream, and
//! the window and tables carry over from entry to entry.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::rc::Rc;

use ppmd_rust::Ppmd7aDecoder;

use super::rar::{self, Bits, Huff, NO_SYMBOL};
use crate::error::{Error, Result};

const MAIN: usize = 299;
const DIST: usize = 60;
const LOW: usize = 17;
const REP: usize = 28;
const PRE: usize = 20;
const TABLES: usize = MAIN + DIST + LOW + REP;

const LEN_BASE: [u32; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LEN_BITS: [u32; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const SHORT_BASE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Extra bits of each distance slot: 0 for the first four, then one more every two slots,
/// with 16 and 18 bits at the top. The base of a slot is the sum of the slots before it.
const fn distance_tables() -> ([u32; DIST], [u32; DIST]) {
    let mut bits = [0u32; DIST];
    let mut i = 4;
    while i < DIST {
        bits[i] = if i < 36 {
            ((i - 2) / 2) as u32
        } else if i < 48 {
            16
        } else {
            18
        };
        i += 1;
    }
    let mut base = [0u32; DIST];
    let mut k = 1;
    while k < DIST {
        base[k] = base[k - 1] + (1u32 << bits[k - 1]);
        k += 1;
    }
    (base, bits)
}
const DIST_TABLES: ([u32; DIST], [u32; DIST]) = distance_tables();
const DIST_BASE: [u32; DIST] = DIST_TABLES.0;
const DIST_BITS: [u32; DIST] = DIST_TABLES.1;

/// Filters with a standard program in RAR 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Std {
    Delta,
    E8,
    E8E9,
    Rgb,
    Audio,
    Itanium,
}

/// Recognises a standard program by its length and CRC-32, as RAR's own encoder writes it.
fn identify(program: &[u8]) -> Option<Std> {
    match (program.len(), crc32fast::hash(program)) {
        (29, 0x0E06_077D) => Some(Std::Delta),
        (53, 0xAD57_6887) => Some(Std::E8),
        (57, 0x3CD7_E57E) => Some(Std::E8E9),
        (149, 0x1C2C_5DC8) => Some(Std::Rgb),
        (216, 0xBC85_E701) => Some(Std::Audio),
        (120, 0x3769_893F) => Some(Std::Itanium),
        _ => None,
    }
}

struct Program {
    kind: Option<Std>,
    /// Block length of the last filter that used this program.
    old_len: u64,
}

/// A filter waiting for its block to be fully decoded.
struct Filter {
    start: u64,
    end: u64,
    kind: Std,
    /// Registers R0..R6 of the program: R0 is the channel count or stride, R1 the RGB byte
    /// offset, R4 the block length.
    regs: [u32; 7],
}

/// The PPMd coder reads its bytes from the same reader as the LZ bit stream.
struct PpmBytes(Rc<RefCell<Bits>>);

impl Read for PpmBytes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bits = self.0.borrow_mut();
        for slot in buf.iter_mut() {
            *slot = bits.byte()?;
        }
        Ok(buf.len())
    }
}

/// Decoder state for one solid unit.
pub struct Lz3 {
    bits: Rc<RefCell<Bits>>,
    win: Vec<u8>,
    mask: usize,
    /// Bytes decoded into the window, and bytes handed out, as absolute positions.
    total: u64,
    delivered: u64,
    /// Absolute position where the current entry ends, and where it starts.
    end: u64,
    entry_base: u64,
    tables: Option<[Huff; 4]>,
    lens: [u8; TABLES],
    need_block: bool,
    in_ppm: bool,
    ppm: Option<Ppmd7aDecoder<PpmBytes>>,
    esc: u8,
    low_repeat: u32,
    last_low: u32,
    /// Four most recent match distances, the newest first.
    cache: [usize; 4],
    last_len: usize,
    programs: Vec<Program>,
    last_prog: usize,
    filters: VecDeque<Filter>,
    /// Filtered blocks waiting to be handed out, with their stream positions. The window
    /// keeps the unfiltered bytes, which later matches copy.
    done: VecDeque<(u64, Vec<u8>)>,
}

impl Lz3 {
    /// A decoder over `src` with a window of `win` bytes (a power of two).
    pub fn new(src: Box<dyn Read + Send>, win: usize) -> Lz3 {
        debug_assert!(win.is_power_of_two());
        Lz3 {
            bits: Rc::new(RefCell::new(Bits::new(src))),
            win: vec![0; win],
            mask: win - 1,
            total: 0,
            delivered: 0,
            end: 0,
            entry_base: 0,
            tables: None,
            lens: [0; TABLES],
            need_block: true,
            in_ppm: false,
            ppm: None,
            esc: 2,
            low_repeat: 0,
            last_low: 0,
            cache: [0; 4],
            last_len: 0,
            programs: Vec::new(),
            last_prog: 0,
            filters: VecDeque::new(),
            done: VecDeque::new(),
        }
    }

    /// Starts the next entry, which is `size` bytes of the stream.
    pub fn begin(&mut self, size: u64) {
        self.entry_base = self.delivered;
        self.end = self.delivered + size;
    }

    /// Reads from the current entry; returns 0 at its end.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        // Decode ahead until a sizeable span is ready: handing out one symbol's worth of
        // bytes per call would make every caller's write and checksum step tiny.
        let want = out.len().min(1 << 14) as u64;
        loop {
            let lim = self.limit();
            let avail = lim - self.delivered;
            let blocked = lim < self.total.min(self.end);
            let room = self.total - self.delivered + 1024 <= self.win.len() as u64;
            if avail > 0 && (avail >= want || blocked || lim == self.end || !room) {
                let n = self.deliver(out, lim);
                self.delivered += n as u64;
                return Ok(n);
            }
            if self.delivered >= self.end {
                return Ok(0);
            }
            self.step()?;
        }
    }

    /// Copies output from `delivered` up to `lim` into `out`: a filtered block from its
    /// buffer, anything else from the window.
    fn deliver(&mut self, out: &mut [u8], lim: u64) -> usize {
        let p = self.delivered;
        let room = ((lim - p) as usize).min(out.len());
        match self.done.front() {
            Some((s, data)) if *s <= p => {
                let off = (p - s) as usize;
                let n = room.min(data.len() - off);
                out[..n].copy_from_slice(&data[off..off + n]);
                if off + n == data.len() {
                    self.done.pop_front();
                }
                n
            }
            next => {
                let n = next.map_or(room, |(s, _)| room.min((s - p) as usize));
                // One contiguous span of the ring; the caller asks again for the rest.
                let at = (p as usize) & self.mask;
                let n = n.min(self.win.len() - at);
                out[..n].copy_from_slice(&self.win[at..at + n]);
                n
            }
        }
    }

    /// Output that may be handed out now: up to the entry end, and not into a filter block
    /// that is still being decoded.
    fn limit(&self) -> u64 {
        let mut lim = self.total.min(self.end);
        if let Some(f) = self.filters.front() {
            lim = if self.delivered < f.start {
                lim.min(f.start)
            } else {
                self.delivered
            };
        }
        lim
    }

    fn step(&mut self) -> Result<()> {
        if self.bits.borrow().overrun() {
            return Err(Error::corrupt("unexpected end of compressed data"));
        }
        if self.need_block {
            self.block_header()?;
            self.need_block = false;
        }
        if self.in_ppm {
            self.ppm_symbol()?;
        } else {
            self.lz_symbol()?;
        }
        self.apply_filters()
    }

    #[inline]
    fn put(&mut self, b: u8) {
        self.win[(self.total as usize) & self.mask] = b;
        self.total += 1;
    }

    /// Copies `len` bytes from `dist` bytes back.
    fn copy(&mut self, dist: usize, len: usize) -> Result<()> {
        if dist == 0 || dist as u64 > self.total || dist > self.win.len() {
            return Err(Error::corrupt("RAR match distance outside the window"));
        }
        let mut src = (self.total as usize).wrapping_sub(dist) & self.mask;
        let mut dst = (self.total as usize) & self.mask;
        let w = self.win.len();
        if dist < 32 {
            // Short distances overlap their own output: copy byte by byte.
            for _ in 0..len {
                let b = self.win[src];
                self.win[dst] = b;
                src = (src + 1) & self.mask;
                dst = (dst + 1) & self.mask;
            }
        } else {
            // Chunks of at most `dist` bytes read only bytes already written.
            let mut left = len;
            while left > 0 {
                let n = left.min(dist).min(w - src).min(w - dst);
                self.win.copy_within(src..src + n, dst);
                src = (src + n) & self.mask;
                dst = (dst + n) & self.mask;
                left -= n;
            }
        }
        self.total += len as u64;
        Ok(())
    }

    fn push_distance(&mut self, dist: usize) {
        self.cache.copy_within(0..3, 1);
        self.cache[0] = dist;
    }

    fn block_header(&mut self) -> Result<()> {
        let (ppm, f) = {
            let mut bits = self.bits.borrow_mut();
            bits.align();
            let ppm = bits.read_bits(1)?;
            (ppm, if ppm == 1 { bits.read_bits(7)? } else { 0 })
        };
        if ppm == 0 {
            let keep = self.bits.borrow_mut().read_bits(1)? == 1;
            self.low_repeat = 0;
            self.last_low = 0;
            return self.read_tables(keep);
        }
        // PPMd block: flags, then the model size and escape byte when present.
        let mut new_model = None;
        let esc;
        {
            let mut bits = self.bits.borrow_mut();
            if f & 0x20 != 0 {
                let mem_mb = bits.read_bits(8)? + 1;
                let mut order = (f & 0x1F) + 1;
                if order > 16 {
                    order = 16 + (order - 16) * 3;
                }
                if order < 2 {
                    return Err(Error::corrupt("RAR PPMd model order"));
                }
                new_model = Some((order, mem_mb << 20));
            }
            esc = if f & 0x40 != 0 {
                bits.read_bits(8)? as u8
            } else {
                2
            };
            bits.align();
        }
        let Some((order, mem)) = new_model else {
            return Err(Error::unsupported(
                "RAR PPMd block that reuses the previous model",
            ));
        };
        let dec = Ppmd7aDecoder::new(PpmBytes(self.bits.clone()), order, mem)
            .map_err(|e| Error::corrupt(format!("RAR PPMd model: {e:?}")))?;
        self.ppm = Some(dec);
        self.esc = esc;
        self.in_ppm = true;
        Ok(())
    }

    fn read_tables(&mut self, keep: bool) -> Result<()> {
        let mut bits = self.bits.borrow_mut();
        let mut pre_lens = [0u8; PRE];
        let mut i = 0;
        while i < PRE {
            let l = bits.read_bits(4)?;
            if l == 15 {
                let zeros = bits.read_bits(4)? as usize;
                if zeros == 0 {
                    pre_lens[i] = 15;
                    i += 1;
                } else {
                    i += zeros + 2;
                }
            } else {
                pre_lens[i] = l as u8;
                i += 1;
            }
        }
        if i > PRE {
            return Err(Error::corrupt("RAR code length table"));
        }
        let pre = Huff::build(&pre_lens)?;
        let old = if keep { self.lens } else { [0; TABLES] };
        let mut lens = [0u8; TABLES];
        let mut i = 0;
        while i < TABLES {
            let sym = pre.decode(&mut bits)?;
            match sym {
                0..=15 => {
                    lens[i] = (old[i] + sym as u8) & 15;
                    i += 1;
                }
                16 | 17 => {
                    if i == 0 {
                        return Err(Error::corrupt("RAR code length repeat without a value"));
                    }
                    let n = if sym == 16 {
                        bits.read_bits(3)? + 3
                    } else {
                        bits.read_bits(7)? + 11
                    };
                    let v = lens[i - 1];
                    for _ in 0..n {
                        if i == TABLES {
                            break;
                        }
                        lens[i] = v;
                        i += 1;
                    }
                }
                18 | 19 => {
                    let n = if sym == 18 {
                        bits.read_bits(3)? + 3
                    } else {
                        bits.read_bits(7)? + 11
                    };
                    for _ in 0..n {
                        if i == TABLES {
                            break;
                        }
                        lens[i] = 0;
                        i += 1;
                    }
                }
                _ => return Err(Error::corrupt("bad RAR code length symbol")),
            }
        }
        drop(bits);
        self.tables = Some([
            Huff::build(&lens[..MAIN])?,
            Huff::build(&lens[MAIN..MAIN + DIST])?,
            Huff::build(&lens[MAIN + DIST..MAIN + DIST + LOW])?,
            Huff::build(&lens[MAIN + DIST + LOW..])?,
        ]);
        self.lens = lens;
        Ok(())
    }

    fn distance(&mut self, slot: usize) -> Result<usize> {
        let base = DIST_BASE[slot];
        let bits = DIST_BITS[slot];
        let extra = if bits < 4 {
            self.bits.borrow_mut().read_bits(bits)?
        } else {
            let mut b = self.bits.borrow_mut();
            let high = if bits > 4 {
                b.read_bits(bits - 4)? << 4
            } else {
                0
            };
            let low = if self.low_repeat > 0 {
                self.low_repeat -= 1;
                self.last_low
            } else {
                let tables = self.tables.as_ref().ok_or_else(no_tables)?;
                let l = tables[2].decode(&mut b)?;
                if l == NO_SYMBOL {
                    return Err(Error::corrupt("bad RAR distance"));
                }
                if l == 16 {
                    self.low_repeat = 15;
                    self.last_low
                } else {
                    self.last_low = l;
                    l
                }
            };
            high + low
        };
        Ok((base + 1 + extra) as usize)
    }

    fn lz_symbol(&mut self) -> Result<()> {
        let sym = {
            let mut bits = self.bits.borrow_mut();
            let tables = self.tables.as_ref().ok_or_else(no_tables)?;
            tables[0].decode(&mut bits)?
        };
        match sym {
            NO_SYMBOL => return Err(Error::corrupt("bad RAR symbol")),
            0..=255 => self.put(sym as u8),
            256 => {
                // End of a data run: bit 1 means a new block header follows in the
                // stream; bit 0 ends the file, and the next bit says whether the next file
                // starts with a new block header.
                let mut bits = self.bits.borrow_mut();
                if bits.read_bits(1)? == 1 {
                    drop(bits);
                    self.need_block = true;
                } else {
                    self.need_block = bits.read_bits(1)? == 1;
                    // The next file's data starts on a byte boundary.
                    bits.align();
                }
            }
            257 => self.read_filter()?,
            258 => {
                if self.last_len > 0 {
                    let d = self.cache[0];
                    self.copy(d, self.last_len)?;
                }
            }
            259..=262 => {
                let idx = (sym - 259) as usize;
                let d = self.cache[idx];
                self.cache.copy_within(0..idx, 1);
                self.cache[0] = d;
                let len = {
                    let mut bits = self.bits.borrow_mut();
                    let tables = self.tables.as_ref().ok_or_else(no_tables)?;
                    let s = tables[3].decode(&mut bits)?;
                    if s == NO_SYMBOL {
                        return Err(Error::corrupt("bad RAR length"));
                    }
                    LEN_BASE[s as usize] as usize
                        + 2
                        + bits.read_bits(LEN_BITS[s as usize])? as usize
                };
                self.copy(d, len)?;
                self.last_len = len;
            }
            263..=270 => {
                let idx = (sym - 263) as usize;
                let extra = self.bits.borrow_mut().read_bits(SHORT_BITS[idx])?;
                let d = SHORT_BASE[idx] as usize + 1 + extra as usize;
                self.push_distance(d);
                self.copy(d, 2)?;
                self.last_len = 2;
            }
            _ => {
                let idx = (sym - 271) as usize;
                let (len, slot) = {
                    let mut bits = self.bits.borrow_mut();
                    let len = LEN_BASE[idx] as usize + 3 + bits.read_bits(LEN_BITS[idx])? as usize;
                    let tables = self.tables.as_ref().ok_or_else(no_tables)?;
                    (len, tables[1].decode(&mut bits)?)
                };
                if slot == NO_SYMBOL {
                    return Err(Error::corrupt("bad RAR distance"));
                }
                let d = self.distance(slot as usize)?;
                let len = len + usize::from(d >= 0x2000) + usize::from(d >= 0x4_0000);
                self.push_distance(d);
                self.copy(d, len)?;
                self.last_len = len;
            }
        }
        Ok(())
    }

    /// Reads a VM filter record (symbol 257) and queues the filter it defines.
    fn read_filter(&mut self) -> Result<()> {
        let code = {
            let mut bits = self.bits.borrow_mut();
            let flags = bits.read_bits(8)?;
            let l = flags & 7;
            let len = match l {
                0..=5 => l + 1,
                6 => bits.read_bits(8)? + 7,
                _ => bits.read_bits(16)?,
            } as usize;
            let mut code = vec![0u8; len];
            for c in code.iter_mut() {
                *c = bits.read_bits(8)? as u8;
            }
            (flags, code)
        };
        self.parse_filter(code.0, &code.1)
    }

    fn parse_filter(&mut self, flags: u32, code: &[u8]) -> Result<()> {
        let mut r = VmReader::new(code);
        // The selector is the program index plus one; one past the last program defines a
        // new one. Selector 0 discards all programs, then defines one.
        let (idx, new) = if flags & 0x80 != 0 {
            let n = r.number()? as usize;
            if n == 0 {
                self.programs.clear();
            }
            let idx = n.saturating_sub(1);
            if idx > self.programs.len() {
                return Err(Error::corrupt("RAR VM program index"));
            }
            (idx, idx == self.programs.len())
        } else {
            if self.last_prog >= self.programs.len() {
                return Err(Error::corrupt("RAR VM filter without a program"));
            }
            (self.last_prog, false)
        };
        let start_off = u64::from(r.number()?);
        let mut start = self.total + start_off;
        if flags & 0x40 != 0 {
            start += 258;
        }
        let old_len = self.programs.get(idx).map_or(0, |p| p.old_len);
        let blen = if flags & 0x20 != 0 {
            u64::from(r.number()?)
        } else {
            old_len
        };
        let mut regs = [0u32; 7];
        regs[4] = blen as u32;
        if flags & 0x10 != 0 {
            let mask = r.bits(7)?;
            for (i, reg) in regs.iter_mut().enumerate() {
                if mask & (1 << i) != 0 {
                    *reg = r.number()?;
                }
            }
        }
        let idx = if new {
            let n = r.number()? as usize;
            if n == 0 || n > 0x10000 {
                return Err(Error::corrupt("RAR VM program length"));
            }
            let body = r.bytes(n)?;
            if body[1..].iter().fold(0u8, |a, b| a ^ b) != body[0] {
                return Err(Error::corrupt("RAR VM program checksum"));
            }
            // A static-data flag bit may follow the program; a record that ends first has none.
            if r.has_bits(1) && r.bits(1)? == 1 {
                let k = r.number()? as usize + 1;
                r.skip(k)?;
            }
            self.programs.push(Program {
                kind: identify(&body),
                old_len: 0,
            });
            idx
        } else {
            idx
        };
        if flags & 0x08 != 0 {
            let g = r.number()? as usize;
            if g > 0x2000 {
                return Err(Error::corrupt("RAR VM global data size"));
            }
            r.skip(g)?;
        }
        let prog = &mut self.programs[idx];
        prog.old_len = blen;
        let kind = prog.kind;
        if blen == 0 || blen > (self.win.len() / 2) as u64 {
            return Err(Error::unsupported("RAR filter block length"));
        }
        // A filter may repeat the block of the one before it, to run on its output.
        if self
            .filters
            .back()
            .is_some_and(|f| start < f.end && (start, start + blen) != (f.start, f.end))
        {
            return Err(Error::corrupt("RAR filters overlap"));
        }
        let kind = kind.ok_or_else(|| Error::unsupported("RAR VM program filter"))?;
        self.filters.push_back(Filter {
            start,
            end: start + blen,
            kind,
            regs,
        });
        self.last_prog = idx;
        Ok(())
    }

    /// Runs the filters whose block is fully decoded and queues their output. A filter
    /// that follows with the same block runs on the output of the one before.
    fn apply_filters(&mut self) -> Result<()> {
        while self.filters.front().is_some_and(|f| f.end <= self.total) {
            let f = self.filters.pop_front().unwrap();
            let n = (f.end - f.start) as usize;
            let data: Vec<u8> = (0..n)
                .map(|k| self.win[((f.start + k as u64) as usize) & self.mask])
                .collect();
            let pos = (f.start - self.entry_base) as u32;
            let mut data = run(&f, data, pos)?;
            while self
                .filters
                .front()
                .is_some_and(|g| (g.start, g.end) == (f.start, f.end))
            {
                let g = self.filters.pop_front().unwrap();
                data = run(&g, data, pos)?;
            }
            self.done.push_back((f.start, data));
        }
        Ok(())
    }

    fn ppm_symbol(&mut self) -> Result<()> {
        let dec = self.ppm.as_mut().ok_or_else(no_tables)?;
        let mut one = [0u8; 1];
        dec.read_exact(&mut one)
            .map_err(|e| Error::corrupt(format!("RAR PPMd data: {e}")))?;
        let c = one[0];
        if c != self.esc {
            self.put(c);
            return Ok(());
        }
        dec.read_exact(&mut one)
            .map_err(|e| Error::corrupt(format!("RAR PPMd data: {e}")))?;
        let code = one[0];
        match code {
            0 | 2 => {
                // End of the PPMd block: the next block header follows.
                self.in_ppm = false;
                self.need_block = true;
            }
            3 => return Err(Error::unsupported("RAR VM filter inside a PPMd block")),
            4 => {
                let mut v = [0u8; 4];
                dec.read_exact(&mut v[1..])
                    .map_err(|e| Error::corrupt(format!("RAR PPMd data: {e}")))?;
                dec.read_exact(&mut one)
                    .map_err(|e| Error::corrupt(format!("RAR PPMd data: {e}")))?;
                let dist = u32::from_be_bytes(v) as usize + 2;
                let len = one[0] as usize + 32;
                self.copy(dist, len)?;
            }
            5 => {
                dec.read_exact(&mut one)
                    .map_err(|e| Error::corrupt(format!("RAR PPMd data: {e}")))?;
                self.copy(1, one[0] as usize + 4)?;
            }
            _ => {
                let esc = self.esc;
                self.put(esc);
                self.put(code);
            }
        }
        Ok(())
    }
}

/// Most byte channels a delta or audio filter may have.
const MAX_CHANNELS: usize = 1024;

/// Runs one standard filter over `data`, the block at entry position `pos`.
fn run(f: &Filter, mut data: Vec<u8>, pos: u32) -> Result<Vec<u8>> {
    let channels = || {
        let ch = f.regs[0] as usize;
        if (1..=MAX_CHANNELS).contains(&ch) {
            Ok(ch)
        } else {
            Err(Error::corrupt(format!(
                "RAR {:?} filter channel count {ch}",
                f.kind
            )))
        }
    };
    match f.kind {
        Std::E8 => rar::e8_v3(&mut data, pos, false),
        Std::E8E9 => rar::e8_v3(&mut data, pos, true),
        Std::Itanium => rar::itanium(&mut data, pos),
        Std::Delta => data = rar::delta(&data, channels()?),
        Std::Audio => data = rar::audio(&data, channels()?),
        Std::Rgb => {
            // R0 is the row length plus the 3 bytes of one pixel; R1 the first byte to which
            // the middle byte of each pixel is added back.
            let (r0, first) = (f.regs[0] as usize, f.regs[1] as usize);
            if r0 < 3 || first > 2 {
                return Err(Error::corrupt("RAR RGB filter parameters"));
            }
            data = rar::rgb(&data, r0 - 3, first);
        }
    }
    Ok(data)
}

fn no_tables() -> Error {
    Error::corrupt("RAR data before its code tables")
}

/// Reads the MSB-first fields of a VM filter record.
struct VmReader<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> VmReader<'a> {
    fn new(d: &'a [u8]) -> Self {
        VmReader { d, pos: 0 }
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        if self.pos + n as usize > self.d.len() * 8 {
            return Err(Error::corrupt("RAR VM filter record is truncated"));
        }
        let mut v = 0u32;
        for _ in 0..n {
            let bit = (self.d[self.pos / 8] >> (7 - self.pos % 8)) & 1;
            v = (v << 1) | u32::from(bit);
            self.pos += 1;
        }
        Ok(v)
    }

    /// A variable-width number: a two-bit width selector, then 4, 8, 16 or 32 bits. An
    /// 8-bit value below 16 extends into a negative 32-bit number.
    fn number(&mut self) -> Result<u32> {
        Ok(match self.bits(2)? {
            0 => self.bits(4)?,
            1 => {
                let v = self.bits(8)?;
                if v >= 16 {
                    v
                } else {
                    0xFFFF_FF00 | (v << 4) | self.bits(4)?
                }
            }
            2 => self.bits(16)?,
            _ => self.bits(32)?,
        })
    }

    fn has_bits(&self, n: u32) -> bool {
        self.pos + n as usize <= self.d.len() * 8
    }

    fn bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        (0..n).map(|_| Ok(self.bits(8)? as u8)).collect()
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(drop)
    }
}
