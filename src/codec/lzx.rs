//! LZX decoder for CAB folders (method 3), after libmspack's `lzxd.c`: verbatim, aligned
//! and uncompressed blocks over a 32 KiB to 2 MiB window, with Huffman trees sent as deltas
//! of the previous block's and the Intel E8 call translation. Each CAB data block is one
//! output frame of at most 32 KiB; blocks and trees run on across frames.

use crate::error::{Error, Result};

const MAIN_MAX: usize = 256 + 50 * 8;
const LENGTH_SYMS: usize = 249;
/// Pretree runs may write a little past a tree's end, as libmspack allows.
const SAFETY: usize = 64;
const FLAG: u32 = 1 << 31;

fn corrupt(what: &str) -> Error {
    Error::corrupt(format!("LZX data error: {what}"))
}

/// `extra_bits[slot]` and `position_base[slot]` for the 50 slots of a 2 MiB window.
fn slot_tables() -> ([u8; 50], [u32; 50]) {
    let mut extra = [0u8; 50];
    let mut base = [0u32; 50];
    let mut b = 0u32;
    for i in 0..50 {
        extra[i] = if i < 4 {
            0
        } else {
            ((i - 2) / 2).min(17) as u8
        };
        base[i] = b;
        b += 1 << extra[i];
    }
    (extra, base)
}

/// Bit reader over one frame: 16-bit little-endian words, most significant bit first;
/// switches to byte reads for uncompressed blocks. Reads past the end yield zero words.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    /// Where word reading (re)started, for 16-bit alignment.
    start: usize,
    buf: u64,
    n: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8], at: usize) -> Self {
        Bits {
            data,
            pos: at,
            start: at,
            buf: 0,
            n: 0,
        }
    }

    #[inline]
    fn ensure(&mut self, k: u32) {
        while self.n < k {
            let w = match self.data.get(self.pos..self.pos + 2) {
                Some(b) => u16::from_le_bytes([b[0], b[1]]),
                None => 0,
            };
            self.pos += 2;
            self.buf |= (w as u64) << (48 - self.n);
            self.n += 16;
        }
    }

    #[inline]
    fn consume(&mut self, k: u32) {
        self.buf <<= k;
        self.n -= k;
    }

    /// Reads `k` (at most 32) bits.
    #[inline]
    fn read(&mut self, k: u32) -> u32 {
        if k == 0 {
            return 0;
        }
        self.ensure(k);
        let v = (self.buf >> (64 - k)) as u32;
        self.consume(k);
        v
    }

    fn consumed_bits(&self) -> usize {
        self.pos * 8 - self.n as usize
    }

    /// Drops 1 to 16 bits to reach a word boundary, then reads bytes from there.
    fn align_for_bytes(&mut self) {
        let rel = self.consumed_bits() - self.start * 8;
        let rel = (rel / 16 + 1) * 16;
        self.pos = self.start + rel / 8;
        self.buf = 0;
        self.n = 0;
    }

    fn bytes(&mut self, k: usize) -> Result<&'a [u8]> {
        let s = self
            .data
            .get(self.pos..self.pos + k)
            .ok_or_else(|| corrupt("uncompressed block is truncated"))?;
        self.pos += k;
        Ok(s)
    }

    /// Resumes word reading at the current byte position.
    fn resume_bits(&mut self) {
        self.start = self.pos;
    }
}

/// A canonical Huffman decoder: a direct table for short codes and a binary tree below
/// it for the rest. Entries are `symbol | length << 16`, or `FLAG | node`.
#[derive(Default)]
struct Huff {
    table: Vec<u32>,
    tree: Vec<u32>,
    bits: u32,
    empty: bool,
}

impl Huff {
    fn build(&mut self, lens: &[u8], bits: u32) -> Result<()> {
        let mut count = [0u32; 17];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        self.bits = bits;
        self.empty = count.iter().all(|&c| c == 0);
        if self.empty {
            return Ok(());
        }
        let mut left = 1i64;
        for &c in &count[1..] {
            left = (left << 1) - c as i64;
            if left < 0 {
                return Err(corrupt("over-subscribed Huffman tree"));
            }
        }
        if left != 0 {
            return Err(corrupt("incomplete Huffman tree"));
        }
        let mut next = [0u32; 17];
        let mut code = 0u32;
        for l in 1..17 {
            code = (code + count[l - 1]) << 1;
            next[l] = code;
        }
        self.table.clear();
        self.table.resize(1 << bits, 0);
        self.tree.clear();
        for (sym, &l) in lens.iter().enumerate() {
            let l = l as u32;
            if l == 0 {
                continue;
            }
            let c = next[l as usize];
            next[l as usize] += 1;
            let leaf = sym as u32 | (l << 16);
            if l <= bits {
                let start = (c << (bits - l)) as usize;
                self.table[start..start + (1 << (bits - l))].fill(leaf);
                continue;
            }
            let prefix = (c >> (l - bits)) as usize;
            let mut node = match self.table[prefix] {
                e if e & FLAG != 0 => (e & !FLAG) as usize,
                _ => {
                    let n = self.new_node();
                    self.table[prefix] = FLAG | n as u32;
                    n
                }
            };
            for b in (0..l - bits).rev() {
                let slot = 2 * node + ((c >> b) & 1) as usize;
                if b == 0 {
                    self.tree[slot] = leaf;
                } else if self.tree[slot] & FLAG != 0 {
                    node = (self.tree[slot] & !FLAG) as usize;
                } else {
                    let n = self.new_node();
                    self.tree[slot] = FLAG | n as u32;
                    node = n;
                }
            }
        }
        Ok(())
    }

    fn new_node(&mut self) -> usize {
        self.tree.extend_from_slice(&[0, 0]);
        self.tree.len() / 2 - 1
    }

    #[inline]
    fn decode(&self, br: &mut Bits) -> u32 {
        br.ensure(16);
        let e = self.table[(br.buf >> (64 - self.bits)) as usize];
        if e & FLAG == 0 {
            br.consume(e >> 16);
            return e & 0xFFFF;
        }
        let mut node = (e & !FLAG) as usize;
        let mut i = self.bits;
        loop {
            let bit = ((br.buf >> (63 - i)) & 1) as usize;
            i += 1;
            let c = self.tree[2 * node + bit];
            if c & FLAG == 0 {
                br.consume(c >> 16);
                return c & 0xFFFF;
            }
            node = (c & !FLAG) as usize;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Verbatim,
    Aligned,
    Uncompressed,
}

pub struct Lzx {
    window: Vec<u8>,
    wpos: usize,
    slots: usize,
    extra: [u8; 50],
    base: [u32; 50],
    r: [u32; 3],
    main_lens: Vec<u8>,
    length_lens: Vec<u8>,
    main: Huff,
    length: Huff,
    aligned: Huff,
    pretree: Huff,
    kind: Kind,
    block_len: u32,
    block_left: u32,
    header_read: bool,
    intel_size: i32,
    intel_started: bool,
    /// Bytes decoded so far in this folder.
    total: u64,
    /// An odd-length uncompressed block ended exactly at a frame end; its padding byte
    /// starts the next frame.
    pad_pending: bool,
}

impl Lzx {
    /// A decoder for a `window_bits` (15..=21) window.
    pub fn new(window_bits: u32) -> Result<Self> {
        let slots = match window_bits {
            15..=19 => 2 * window_bits as usize,
            20 => 42,
            21 => 50,
            _ => {
                return Err(Error::unsupported(format!(
                    "LZX window of 2^{window_bits} bytes"
                )))
            }
        };
        let (extra, base) = slot_tables();
        Ok(Lzx {
            window: vec![0; 1 << window_bits],
            wpos: 0,
            slots,
            extra,
            base,
            r: [1, 1, 1],
            main_lens: vec![0; MAIN_MAX + SAFETY],
            length_lens: vec![0; LENGTH_SYMS + SAFETY],
            main: Huff::default(),
            length: Huff::default(),
            aligned: Huff::default(),
            pretree: Huff::default(),
            kind: Kind::Verbatim,
            block_len: 0,
            block_left: 0,
            header_read: false,
            intel_size: 0,
            intel_started: false,
            total: 0,
            pad_pending: false,
        })
    }

    /// Reads tree lengths `first..last` as deltas through a freshly sent pretree.
    fn read_lengths(
        pretree: &mut Huff,
        lens: &mut [u8],
        first: usize,
        last: usize,
        br: &mut Bits,
    ) -> Result<()> {
        let mut pl = [0u8; 20];
        for l in &mut pl {
            *l = br.read(4) as u8;
        }
        pretree.build(&pl, 6)?;
        if pretree.empty {
            return Err(corrupt("empty pretree"));
        }
        let delta = |old: u8, z: u32| ((old as u32 + 17 - z) % 17) as u8;
        let mut x = first;
        while x < last {
            let z = pretree.decode(br);
            let (run, value) = match z {
                17 => (br.read(4) as usize + 4, 0),
                18 => (br.read(5) as usize + 20, 0),
                19 => {
                    let run = br.read(1) as usize + 4;
                    let z = pretree.decode(br);
                    if z > 16 {
                        return Err(corrupt("bad pretree code"));
                    }
                    (run, delta(lens[x], z))
                }
                z => (1, delta(lens[x], z)),
            };
            let end = (x + run).min(lens.len());
            lens[x..end].fill(value);
            x = end;
        }
        Ok(())
    }

    fn read_block_header(&mut self, br: &mut Bits) -> Result<()> {
        let kind = br.read(3);
        self.block_len = (br.read(16) << 8) | br.read(8);
        self.block_left = self.block_len;
        self.kind = match kind {
            1 => Kind::Verbatim,
            2 => Kind::Aligned,
            3 => Kind::Uncompressed,
            _ => return Err(corrupt("bad block type")),
        };
        match self.kind {
            Kind::Uncompressed => {
                self.intel_started = true;
                br.align_for_bytes();
                let r = br.bytes(12)?;
                for (i, w) in r.chunks_exact(4).enumerate() {
                    self.r[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                }
                br.resume_bits();
            }
            k => {
                if k == Kind::Aligned {
                    let mut al = [0u8; 8];
                    for l in &mut al {
                        *l = br.read(3) as u8;
                    }
                    self.aligned.build(&al, 7)?;
                    if self.aligned.empty {
                        return Err(corrupt("empty aligned offset tree"));
                    }
                }
                let main_syms = 256 + 8 * self.slots;
                Self::read_lengths(&mut self.pretree, &mut self.main_lens, 0, 256, br)?;
                Self::read_lengths(&mut self.pretree, &mut self.main_lens, 256, main_syms, br)?;
                self.main.build(&self.main_lens[..main_syms], 12)?;
                if self.main.empty {
                    return Err(corrupt("empty main tree"));
                }
                if self.main_lens[0xE8] != 0 {
                    self.intel_started = true;
                }
                Self::read_lengths(&mut self.pretree, &mut self.length_lens, 0, LENGTH_SYMS, br)?;
                self.length.build(&self.length_lens[..LENGTH_SYMS], 12)?;
            }
        }
        Ok(())
    }

    /// Decodes `n` bytes of the current verbatim or aligned block into the window.
    fn decode_run(&mut self, br: &mut Bits, n: usize) -> Result<()> {
        let mask = self.window.len() - 1;
        let aligned = self.kind == Kind::Aligned;
        let mut left = n;
        while left > 0 {
            let sym = self.main.decode(br) as usize;
            if sym < 256 {
                self.window[self.wpos] = sym as u8;
                self.wpos = (self.wpos + 1) & mask;
                left -= 1;
                continue;
            }
            let m = sym - 256;
            let mut len = m & 7;
            if len == 7 {
                if self.length.empty {
                    return Err(corrupt("match length without a length tree"));
                }
                len += self.length.decode(br) as usize;
            }
            len += 2;
            let slot = m >> 3;
            let off = match slot {
                0 => self.r[0],
                1 => {
                    self.r.swap(0, 1);
                    self.r[0]
                }
                2 => {
                    self.r.swap(0, 2);
                    self.r[0]
                }
                _ => {
                    let extra = self.extra[slot] as u32;
                    let mut off = self.base[slot] - 2;
                    if aligned && extra >= 3 {
                        off += br.read(extra - 3) << 3;
                        off += self.aligned.decode(br);
                    } else if extra > 0 {
                        off += br.read(extra);
                    } else {
                        off = 1;
                    }
                    self.r = [off, self.r[0], self.r[1]];
                    off
                }
            } as usize;
            if len > left {
                return Err(corrupt("match crosses a block or frame boundary"));
            }
            let decoded = self.total + (n - left) as u64;
            if off == 0 || off > self.window.len() || off as u64 > decoded {
                return Err(corrupt("match offset out of range"));
            }
            let src = (self.wpos + self.window.len() - off) & mask;
            if src + len <= self.window.len() && self.wpos + len <= self.window.len() && off >= len
            {
                self.window.copy_within(src..src + len, self.wpos);
            } else {
                for i in 0..len {
                    self.window[(self.wpos + i) & mask] = self.window[(src + i) & mask];
                }
            }
            self.wpos = (self.wpos + len) & mask;
            left -= len;
        }
        Ok(())
    }

    /// Decodes one frame of `size` bytes (at most 32 KiB) from `data` into `out`.
    pub fn decode_frame(&mut self, data: &[u8], size: usize, out: &mut Vec<u8>) -> Result<()> {
        if size > 1 << 15 {
            return Err(corrupt("frame larger than 32 KiB"));
        }
        let mut br = Bits::new(data, self.pad_pending as usize);
        self.pad_pending = false;
        if !self.header_read {
            self.header_read = true;
            if br.read(1) != 0 {
                self.intel_size = ((br.read(16) << 16) | br.read(16)) as i32;
            }
        }
        let frame_start = self.wpos;
        let mut todo = size;
        while todo > 0 {
            if self.block_left == 0 {
                self.read_block_header(&mut br)?;
                continue;
            }
            let run = (self.block_left as usize).min(todo);
            if self.kind == Kind::Uncompressed {
                let raw = br.bytes(run)?;
                let mask = self.window.len() - 1;
                for (i, &b) in raw.iter().enumerate() {
                    self.window[(self.wpos + i) & mask] = b;
                }
                self.wpos = (self.wpos + run) & mask;
            } else {
                self.decode_run(&mut br, run)?;
            }
            self.block_left -= run as u32;
            self.total += run as u64;
            todo -= run;
            if self.kind == Kind::Uncompressed && self.block_left == 0 {
                if self.block_len & 1 != 0 {
                    if br.pos < data.len() {
                        br.pos += 1;
                    } else {
                        self.pad_pending = true;
                    }
                }
                br.resume_bits();
            }
        }
        if br.consumed_bits() > data.len() * 8 + 16 {
            return Err(corrupt("frame is truncated"));
        }

        out.clear();
        let first = (self.window.len() - frame_start).min(size);
        out.extend_from_slice(&self.window[frame_start..frame_start + first]);
        out.extend_from_slice(&self.window[..size - first]);
        let frame_pos = self.total - size as u64;
        if self.intel_size != 0 && self.intel_started && size > 10 && frame_pos < 1 << 30 {
            self.translate_e8(out, frame_pos as i32);
        }
        Ok(())
    }

    /// Undoes the encoder's E8 (x86 CALL) absolute-address translation.
    fn translate_e8(&self, out: &mut [u8], frame_pos: i32) {
        let size = self.intel_size;
        let end = out.len() - 10;
        let mut i = 0;
        while i < end {
            if out[i] != 0xE8 {
                i += 1;
                continue;
            }
            let cur = frame_pos + i as i32;
            let abs = i32::from_le_bytes([out[i + 1], out[i + 2], out[i + 3], out[i + 4]]);
            if abs >= -cur && abs < size {
                let rel = if abs >= 0 { abs - cur } else { abs + size };
                out[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
            }
            i += 5;
        }
    }
}
