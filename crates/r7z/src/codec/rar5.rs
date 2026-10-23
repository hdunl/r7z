//! RAR 5 decompression (algorithm version 0): LZ77 with canonical Huffman tables, coded in
//! length-delimited blocks, and the fixed filters DELTA, E8, E8E9 and ARM.
//!
//! Each file's packed data is a stream of its own that ends with a block flagged as the
//! last; in a solid unit the window, the code tables, the distance cache and the last
//! match length carry over from one file to the next. One [`Lz5`] decodes a whole unit:
//! [`Lz5::begin`] starts the next file with its packed stream.

use std::collections::VecDeque;
use std::io::{self, Read};

use super::rar::{self, Bits, Huff, NO_SYMBOL};
use crate::error::{Error, Result};

const MAIN: usize = 306;
const DIST: usize = 64;
const LOW: usize = 16;
const REP: usize = 44;
const PRE: usize = 20;
const TABLES: usize = MAIN + DIST + LOW + REP;

/// Longest filter block; longer ones are ignored, as RAR does.
const MAX_FILTER_LEN: u64 = 0x40_0000;
/// Filters that may wait at once.
const MAX_FILTERS: usize = 8192;
/// Output a decoding step aims for before it hands bytes out.
const BATCH: u64 = 1 << 16;

/// A Huffman table and the code lengths it was built from (to count consumed bits).
struct Table {
    huff: Huff,
    lens: Box<[u8]>,
}

impl Table {
    fn new(lens: &[u8]) -> Result<Table> {
        Ok(Table {
            huff: Huff::build(lens)?,
            lens: lens.into(),
        })
    }
}

/// The main, distance, low-distance and repeat-length tables of a block.
struct Tables {
    main: Table,
    dist: Table,
    low: Table,
    rep: Table,
}

/// One file's bit stream, with a count of the bits consumed: blocks are delimited by
/// size, so their ends are bit positions.
struct Input {
    bits: Bits,
    pos: u64,
}

impl Input {
    #[inline]
    fn read(&mut self, k: u32) -> io::Result<u32> {
        self.pos += u64::from(k);
        self.bits.read_bits(k)
    }

    #[inline]
    fn sym(&mut self, t: &Table) -> io::Result<u32> {
        let s = t.huff.decode(&mut self.bits)?;
        if s != NO_SYMBOL {
            self.pos += u64::from(t.lens[s as usize]);
        }
        Ok(s)
    }

    fn align(&mut self) {
        self.bits.align();
        self.pos = (self.pos + 7) & !7;
    }

    /// A filter field: a two-bit byte count less one, then that many bytes, low first.
    fn filter_number(&mut self) -> io::Result<u64> {
        let n = self.read(2)? + 1;
        let mut v = 0u64;
        for i in 0..n {
            v |= u64::from(self.read(8)?) << (8 * i);
        }
        Ok(v)
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Delta(usize),
    E8,
    E8E9,
    Arm,
}

/// A filter waiting for its block to be fully decoded; positions are absolute in the unit.
struct Filter {
    start: u64,
    end: u64,
    kind: Kind,
}

/// A filtered block waiting to be handed out. The window keeps the unfiltered bytes,
/// which later matches refer to.
struct Filtered {
    start: u64,
    data: Vec<u8>,
}

/// Decoder state for one solid unit.
pub struct Lz5 {
    input: Option<Input>,
    /// Bit position in `input` where the current block's data ends.
    block_end: u64,
    in_block: bool,
    last_block: bool,
    win: Vec<u8>,
    mask: usize,
    /// Bytes decoded into the window, and bytes handed out, as absolute positions.
    total: u64,
    delivered: u64,
    /// Where the current file ends, and where it starts.
    end: u64,
    entry_base: u64,
    tables: Option<Box<Tables>>,
    /// Four most recent match distances, the newest first.
    cache: [u64; 4],
    last_len: usize,
    filters: VecDeque<Filter>,
    filtered: VecDeque<Filtered>,
}

impl Lz5 {
    /// A decoder with a window of `win` bytes (a power of two).
    pub fn new(win: usize) -> Lz5 {
        debug_assert!(win.is_power_of_two());
        Lz5 {
            input: None,
            block_end: 0,
            in_block: false,
            last_block: false,
            win: vec![0; win],
            mask: win - 1,
            total: 0,
            delivered: 0,
            end: 0,
            entry_base: 0,
            tables: None,
            cache: [0; 4],
            last_len: 0,
            filters: VecDeque::new(),
            filtered: VecDeque::new(),
        }
    }

    /// Starts the next file: `size` bytes unpacked from the packed stream `src`.
    pub fn begin(&mut self, src: Box<dyn Read + Send>, size: u64) -> Result<()> {
        self.input = Some(Input {
            bits: Bits::new(src),
            pos: 0,
        });
        self.in_block = false;
        self.last_block = false;
        // Filters of the previous file end with it.
        self.filters.clear();
        self.filtered.clear();
        self.delivered = self.total;
        self.entry_base = self.total;
        self.end = self.total + size;
        if size == 0 {
            // An empty file can still carry a block with code tables, which the next file
            // of a solid unit relies on; it must not be skipped.
            if self.ready()? {
                return Err(Error::corrupt("RAR 5 data in an empty file"));
            }
        }
        Ok(())
    }

    /// Reads from the current file; returns 0 at its end.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(b) = self.filtered.front() {
                if self.delivered >= b.start {
                    let off = (self.delivered - b.start) as usize;
                    let n = (b.data.len() - off)
                        .min(out.len())
                        .min((self.end - self.delivered) as usize);
                    out[..n].copy_from_slice(&b.data[off..off + n]);
                    self.delivered += n as u64;
                    if off + n == b.data.len() {
                        self.filtered.pop_front();
                    }
                    return Ok(n);
                }
            }
            // Decode ahead until a sizeable span is ready, so a call hands out more than one
            // symbol's worth of bytes.
            let lim = self.limit();
            let avail = lim - self.delivered;
            let want = out.len().min(1 << 14) as u64;
            let blocked = lim < self.total.min(self.end);
            let room = self.total - self.delivered + 1024 <= self.win.len() as u64;
            if avail > 0 && (avail >= want || blocked || lim == self.end || !room) {
                let start = self.delivered as usize & self.mask;
                let n = (avail as usize).min(out.len()).min(self.win.len() - start);
                out[..n].copy_from_slice(&self.win[start..start + n]);
                self.delivered += n as u64;
                return Ok(n);
            }
            if self.delivered >= self.end {
                return Ok(0);
            }
            self.step()?;
        }
    }

    /// Output that may be handed out from the window now: up to the file end, not into a
    /// filtered block, and not into a filter block that is still being decoded.
    fn limit(&self) -> u64 {
        let mut lim = self.total.min(self.end);
        if let Some(b) = self.filtered.front() {
            lim = lim.min(b.start);
        }
        if let Some(f) = self.filters.front() {
            lim = if self.delivered < f.start {
                lim.min(f.start)
            } else {
                self.delivered
            };
        }
        lim
    }

    /// Decodes at least one symbol, and more until a batch of output is ready.
    fn step(&mut self) -> Result<()> {
        if self.total >= self.end {
            return Err(Error::corrupt(
                "RAR 5 filter block runs past the end of the file",
            ));
        }
        let target = self.total + BATCH.min(self.win.len() as u64 / 4);
        loop {
            if !self.ready()? {
                return Err(Error::corrupt("RAR 5 data ends before the end of the file"));
            }
            self.symbol()?;
            self.apply_filters()?;
            if self.total - self.delivered > self.win.len() as u64 {
                return Err(Error::unsupported(
                    "RAR 5 filter block larger than the decoding window",
                ));
            }
            if self.total >= self.end || self.total >= target {
                return Ok(());
            }
        }
    }

    /// Moves to the next block when the current one is used up. False once the file's
    /// last block is done.
    fn ready(&mut self) -> Result<bool> {
        loop {
            let inp = self
                .input
                .as_mut()
                .ok_or_else(|| Error::corrupt("RAR 5 file not started"))?;
            if inp.bits.overrun() {
                return Err(Error::corrupt("unexpected end of RAR 5 compressed data"));
            }
            if self.in_block {
                if inp.pos < self.block_end {
                    return Ok(true);
                }
                if self.last_block {
                    return Ok(false);
                }
            }
            self.block_header()?;
        }
    }

    /// Reads a block header (byte aligned) and the block's tables when it has them.
    fn block_header(&mut self) -> Result<()> {
        let inp = self
            .input
            .as_mut()
            .ok_or_else(|| Error::corrupt("RAR 5 file not started"))?;
        inp.align();
        let flags = inp.read(8)?;
        let check = inp.read(8)?;
        let count = ((flags >> 3) & 3) + 1;
        if count == 4 {
            return Err(Error::corrupt("RAR 5 block size field"));
        }
        let mut size = 0u64;
        let mut sum = 0x5A ^ flags;
        for i in 0..count {
            let b = inp.read(8)?;
            sum ^= b;
            size |= u64::from(b) << (8 * i);
        }
        if sum & 0xFF != check {
            return Err(Error::corrupt("RAR 5 block header checksum"));
        }
        let last_bits = u64::from(flags & 7) + 1;
        self.block_end = if size == 0 {
            inp.pos
        } else {
            inp.pos + (size - 1) * 8 + last_bits
        };
        self.in_block = true;
        self.last_block = flags & 0x40 != 0;
        if flags & 0x80 != 0 {
            self.read_tables()?;
            let inp = self.input.as_ref().unwrap();
            if inp.pos > self.block_end {
                return Err(Error::corrupt("RAR 5 code tables run past their block"));
            }
        }
        Ok(())
    }

    fn read_tables(&mut self) -> Result<()> {
        let inp = self.input.as_mut().unwrap();
        let mut pre_lens = [0u8; PRE];
        let mut i = 0;
        while i < PRE {
            let l = inp.read(4)? as u8;
            if l == 15 {
                let zeros = inp.read(4)? as usize;
                if zeros == 0 {
                    pre_lens[i] = 15;
                    i += 1;
                } else {
                    // A run of zero lengths, cut at the end of the table.
                    i = (i + zeros + 2).min(PRE);
                }
            } else {
                pre_lens[i] = l;
                i += 1;
            }
        }
        let pre = Table::new(&pre_lens)?;
        let mut lens = [0u8; TABLES];
        let mut i = 0;
        while i < TABLES {
            let sym = inp.sym(&pre)?;
            match sym {
                0..=15 => {
                    lens[i] = sym as u8;
                    i += 1;
                }
                16 | 17 => {
                    if i == 0 {
                        return Err(Error::corrupt("RAR 5 code length repeat without a value"));
                    }
                    let n = if sym == 16 {
                        inp.read(3)? + 3
                    } else {
                        inp.read(7)? + 11
                    } as usize;
                    let v = lens[i - 1];
                    let stop = (i + n).min(TABLES);
                    lens[i..stop].fill(v);
                    i = stop;
                }
                18 | 19 => {
                    let n = if sym == 18 {
                        inp.read(3)? + 3
                    } else {
                        inp.read(7)? + 11
                    } as usize;
                    // `lens` starts zeroed.
                    i = (i + n).min(TABLES);
                }
                _ => return Err(Error::corrupt("bad RAR 5 code length symbol")),
            }
        }
        let (main, rest) = lens.split_at(MAIN);
        let (dist, rest) = rest.split_at(DIST);
        let (low, rep) = rest.split_at(LOW);
        self.tables = Some(Box::new(Tables {
            main: Table::new(main)?,
            dist: Table::new(dist)?,
            low: Table::new(low)?,
            rep: Table::new(rep)?,
        }));
        Ok(())
    }

    #[inline]
    fn put(&mut self, b: u8) {
        self.win[self.total as usize & self.mask] = b;
        self.total += 1;
    }

    /// Copies `len` bytes from `dist` bytes back.
    fn copy(&mut self, dist: u64, len: usize) -> Result<()> {
        if dist == 0 || dist > self.total || dist > self.win.len() as u64 {
            return Err(Error::corrupt("RAR 5 match distance outside the window"));
        }
        let mut src = (self.total - dist) as usize & self.mask;
        let mut dst = self.total as usize & self.mask;
        let w = self.win.len();
        if dist < 32 {
            // Short distances overlap their own output: copy byte by byte.
            for _ in 0..len {
                self.win[dst] = self.win[src];
                src = (src + 1) & self.mask;
                dst = (dst + 1) & self.mask;
            }
        } else {
            // Chunks of at most `dist` bytes read only bytes already written.
            let mut left = len;
            while left > 0 {
                let n = left.min(dist as usize).min(w - src).min(w - dst);
                self.win.copy_within(src..src + n, dst);
                src = (src + n) & self.mask;
                dst = (dst + n) & self.mask;
                left -= n;
            }
        }
        self.total += len as u64;
        Ok(())
    }

    fn symbol(&mut self) -> Result<()> {
        let inp = self.input.as_mut().unwrap();
        let t = self.tables.as_deref().ok_or_else(no_tables)?;
        let sym = inp.sym(&t.main)?;
        match sym {
            0..=255 => self.put(sym as u8),
            256 => self.read_filter()?,
            257 => {
                if self.last_len > 0 {
                    self.copy(self.cache[0], self.last_len)?;
                }
            }
            258..=261 => {
                let idx = (sym - 258) as usize;
                let d = self.cache[idx];
                self.cache.copy_within(0..idx, 1);
                self.cache[0] = d;
                let slot = inp.sym(&t.rep)?;
                if slot == NO_SYMBOL {
                    return Err(Error::corrupt("bad RAR 5 length"));
                }
                let len = slot_length(inp, slot)?;
                self.last_len = len;
                self.copy(d, len)?;
            }
            262..=305 => {
                let mut len = slot_length(inp, sym - 262)?;
                let slot = inp.sym(&t.dist)?;
                let dist = match slot {
                    NO_SYMBOL => return Err(Error::corrupt("bad RAR 5 distance")),
                    0..=3 => 1 + u64::from(slot),
                    _ => {
                        let nb = slot / 2 - 1;
                        let mut d = 1 + (u64::from(2 | (slot & 1)) << nb);
                        if nb >= 4 {
                            if nb > 4 {
                                d += u64::from(inp.read(nb - 4)?) << 4;
                            }
                            let low = inp.sym(&t.low)?;
                            if low == NO_SYMBOL {
                                return Err(Error::corrupt("bad RAR 5 distance"));
                            }
                            d += u64::from(low);
                        } else {
                            d += u64::from(inp.read(nb)?);
                        }
                        d
                    }
                };
                if dist > 0x100 {
                    len += 1;
                    if dist > 0x2000 {
                        len += 1;
                        if dist > 0x4_0000 {
                            len += 1;
                        }
                    }
                }
                self.cache.copy_within(0..3, 1);
                self.cache[0] = dist;
                self.last_len = len;
                self.copy(dist, len)?;
            }
            _ => return Err(Error::corrupt("bad RAR 5 symbol")),
        }
        Ok(())
    }

    /// Reads a filter record (symbol 256) and queues the filter it defines.
    fn read_filter(&mut self) -> Result<()> {
        let inp = self.input.as_mut().unwrap();
        let start = self.total + inp.filter_number()?;
        let len = inp.filter_number()?;
        let kind = match inp.read(3)? {
            0 => Kind::Delta(inp.read(5)? as usize + 1),
            1 => Kind::E8,
            2 => Kind::E8E9,
            3 => Kind::Arm,
            k => return Err(Error::unsupported(format!("RAR 5 filter type {k}"))),
        };
        if len == 0 || len > MAX_FILTER_LEN {
            return Ok(());
        }
        if self.filters.len() >= MAX_FILTERS {
            return Err(Error::corrupt("too many RAR 5 filters"));
        }
        if self.filters.back().is_some_and(|f| start < f.end) {
            return Err(Error::corrupt("RAR 5 filters overlap"));
        }
        self.filters.push_back(Filter {
            start,
            end: start + len,
            kind,
        });
        Ok(())
    }

    /// Runs the filters whose block is fully decoded into blocks for the output.
    fn apply_filters(&mut self) -> Result<()> {
        while self.filters.front().is_some_and(|f| f.end <= self.total) {
            let f = self.filters.pop_front().unwrap();
            let n = (f.end - f.start) as usize;
            let at = f.start as usize & self.mask;
            let mut data = Vec::with_capacity(n);
            let first = n.min(self.win.len() - at);
            data.extend_from_slice(&self.win[at..at + first]);
            data.extend_from_slice(&self.win[..n - first]);
            // Positions given to the filters are relative to the file.
            let pos = (f.start - self.entry_base) as u32;
            match f.kind {
                Kind::E8 => e8(&mut data, pos, false),
                Kind::E8E9 => e8(&mut data, pos, true),
                Kind::Arm => rar::arm(&mut data, pos),
                Kind::Delta(channels) => data = rar::delta(&data, channels),
            }
            self.filtered.push_back(Filtered {
                start: f.start,
                data,
            });
        }
        Ok(())
    }
}

/// The E8 and E8E9 filters of RAR 5: absolute CALL (and JMP) targets back to relative,
/// for addresses within a 16 MiB file. `pos` is the file position of `data[0]`.
fn e8(data: &mut [u8], pos: u32, e9: bool) {
    const SIZE: u32 = 0x100_0000;
    let mut i = 0;
    while i + 4 < data.len() {
        let op = data[i];
        i += 1;
        if op == 0xE8 || (e9 && op == 0xE9) {
            let cur = pos.wrapping_add(i as u32) % SIZE;
            let addr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            let v = if addr & 0x8000_0000 != 0 {
                // A negative address that the offset brings back to the file.
                if addr.wrapping_add(cur) & 0x8000_0000 == 0 {
                    addr.wrapping_add(SIZE)
                } else {
                    addr
                }
            } else if addr < SIZE {
                addr.wrapping_sub(cur)
            } else {
                addr
            };
            data[i..i + 4].copy_from_slice(&v.to_le_bytes());
            i += 4;
        }
    }
}

/// Match length for length slot `slot`: the base of the slot plus its extra bits.
#[inline]
fn slot_length(inp: &mut Input, slot: u32) -> Result<usize> {
    if slot < 8 {
        return Ok(2 + slot as usize);
    }
    let nb = slot / 4 - 1;
    Ok(2 + ((4 | (slot & 3) as usize) << nb) + inp.read(nb)? as usize)
}

fn no_tables() -> Error {
    Error::corrupt("RAR 5 data before its code tables")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_slots() {
        // Slots 0..7 are lengths 2..9; then four slots per extra bit.
        let mut inp = Input {
            bits: Bits::new(Box::new(io::Cursor::new(vec![0u8; 8]))),
            pos: 0,
        };
        assert_eq!(slot_length(&mut inp, 0).unwrap(), 2);
        assert_eq!(slot_length(&mut inp, 7).unwrap(), 9);
        assert_eq!(slot_length(&mut inp, 8).unwrap(), 10);
        assert_eq!(slot_length(&mut inp, 11).unwrap(), 16);
        assert_eq!(slot_length(&mut inp, 12).unwrap(), 18);
        assert_eq!(slot_length(&mut inp, 43).unwrap(), 2 + (7 << 9));
    }

    #[test]
    fn e8_negative_targets() {
        // A negative address that the offset brings back into the file gains the file size.
        let mut d = [0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0];
        e8(&mut d, 0, false);
        assert_eq!(d[1..5], 0x00FF_FFFFu32.to_le_bytes());
        // One that stays negative is left alone.
        let mut d = [0xE8, 0x00, 0xFF, 0xFF, 0xFF, 0];
        e8(&mut d, 0, false);
        assert_eq!(d[1..5], 0xFFFF_FF00u32.to_le_bytes());
        // An address within the file becomes relative to the operand.
        let mut d = [0x90, 0xE8, 0x10, 0x00, 0x00, 0x00, 0];
        e8(&mut d, 0x100, false);
        assert_eq!(d[2..6], (0x10u32.wrapping_sub(0x102)).to_le_bytes());
    }
}
