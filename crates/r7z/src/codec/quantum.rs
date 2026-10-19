//! Quantum decoder (CAB method 2), after libmspack's `qtmd.c`: a 16-bit arithmetic coder
//! over seven adaptive frequency models feeding an LZ77 window of 1 KiB to 2 MiB. Raw extra
//! bits for match lengths and offsets are read from the same MSB-first bit stream. Each CAB
//! data block is one frame that restarts the coder; models and window persist through the
//! folder.

use crate::error::{Error, Result};

const POSITION_BASE: [u32; 42] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 393216, 524288, 786432, 1048576, 1572864,
];
const EXTRA_BITS: [u8; 42] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19,
];
const LENGTH_BASE: [u8; 27] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190,
    222, 254,
];
const LENGTH_EXTRA: [u8; 27] = [
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// An adaptive model: symbols sorted by falling frequency, with cumulative frequencies
/// (`cum[0]` is the total, `cum[entries]` is 0).
#[derive(Clone)]
struct Model {
    entries: usize,
    shifts_left: u32,
    sym: [u8; 65],
    cum: [u16; 65],
}

impl Model {
    fn new(start: u8, entries: usize) -> Self {
        let mut m = Model {
            entries,
            shifts_left: 4,
            sym: [0; 65],
            cum: [0; 65],
        };
        for i in 0..=entries {
            m.sym[i] = start.wrapping_add(i as u8);
            m.cum[i] = (entries - i) as u16;
        }
        m
    }

    /// Halves the frequencies; every 50th time also re-sorts symbols by frequency.
    fn rescale(&mut self) {
        let n = self.entries;
        self.shifts_left -= 1;
        if self.shifts_left > 0 {
            for i in (0..n).rev() {
                self.cum[i] >>= 1;
                if self.cum[i] <= self.cum[i + 1] {
                    self.cum[i] = self.cum[i + 1] + 1;
                }
            }
            return;
        }
        self.shifts_left = 50;
        for i in 0..n {
            self.cum[i] = ((self.cum[i] - self.cum[i + 1]) + 1) >> 1;
        }
        // Selection-style exchange sort: the exact (in)stability is part of the format.
        for i in 0..n.saturating_sub(1) {
            for j in i + 1..n {
                if self.cum[i] < self.cum[j] {
                    self.cum.swap(i, j);
                    self.sym.swap(i, j);
                }
            }
        }
        for i in (0..n).rev() {
            self.cum[i] += self.cum[i + 1];
        }
    }
}

/// MSB-first bit reader over one frame; reads past the end yield zeros.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            data,
            pos: 0,
            buf: 0,
            count: 0,
        }
    }

    #[inline]
    fn refill(&mut self) {
        while self.count <= 56 {
            let b = self.data.get(self.pos).copied().unwrap_or(0);
            self.pos += 1;
            self.buf |= (b as u64) << (56 - self.count);
            self.count += 8;
        }
    }

    /// Reads `n` (at most 32) bits.
    #[inline]
    fn read(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        if self.count < n {
            self.refill();
        }
        let v = (self.buf >> (64 - n)) as u32;
        self.buf <<= n;
        self.count -= n;
        v
    }

    /// Bits consumed so far.
    fn consumed(&self) -> usize {
        self.pos * 8 - self.count as usize
    }
}

/// The arithmetic coder registers.
struct Coder {
    high: u32,
    low: u32,
    code: u32,
}

impl Coder {
    fn decode(&mut self, m: &mut Model, bits: &mut Bits) -> u8 {
        let range = ((self.high.wrapping_sub(self.low)) & 0xFFFF) + 1;
        let total = m.cum[0] as u32;
        let target = ((self.code.wrapping_sub(self.low).wrapping_add(1))
            .wrapping_mul(total)
            .wrapping_sub(1)
            / range)
            & 0xFFFF;
        let mut i = 1;
        while i < m.entries && m.cum[i] as u32 > target {
            i += 1;
        }
        let sym = m.sym[i - 1];
        let total = total.max(1);
        self.high = (self.low + (m.cum[i - 1] as u32 * range) / total).wrapping_sub(1) & 0xFFFF;
        self.low = (self.low + (m.cum[i] as u32 * range) / total) & 0xFFFF;
        for c in &mut m.cum[..i] {
            *c += 8;
        }
        if m.cum[0] > 3800 {
            m.rescale();
        }
        loop {
            if (self.low ^ self.high) & 0x8000 != 0 {
                if self.low & 0x4000 != 0 && self.high & 0x4000 == 0 {
                    self.code ^= 0x4000;
                    self.low &= 0x3FFF;
                    self.high |= 0x4000;
                } else {
                    break;
                }
            }
            self.low = (self.low << 1) & 0xFFFF;
            self.high = ((self.high << 1) & 0xFFFF) | 1;
            self.code = ((self.code << 1) & 0xFFFF) | bits.read(1);
        }
        sym
    }
}

pub struct Quantum {
    window: Vec<u8>,
    pos: usize,
    literals: [Model; 4],
    pos3: Model,
    pos4: Model,
    pos_var: Model,
    len_var: Model,
    selector: Model,
}

impl Quantum {
    /// A decoder for a `window_bits` (10..=21) window.
    pub fn new(window_bits: u32) -> Result<Self> {
        if !(10..=21).contains(&window_bits) {
            return Err(Error::unsupported(format!(
                "Quantum window of 2^{window_bits} bytes"
            )));
        }
        let slots = (window_bits * 2) as usize;
        Ok(Quantum {
            window: vec![0; 1 << window_bits],
            pos: 0,
            literals: [
                Model::new(0, 64),
                Model::new(64, 64),
                Model::new(128, 64),
                Model::new(192, 64),
            ],
            pos3: Model::new(0, slots.min(24)),
            pos4: Model::new(0, slots.min(36)),
            pos_var: Model::new(0, slots),
            len_var: Model::new(0, 27),
            selector: Model::new(0, 7),
        })
    }

    /// Decodes one frame of `size` bytes from `data` into `out`.
    pub fn decode_frame(&mut self, data: &[u8], size: usize, out: &mut Vec<u8>) -> Result<()> {
        if size > 1 << 15 {
            return Err(Error::corrupt("Quantum frame larger than 32 KiB"));
        }
        out.clear();
        out.reserve(size);
        let mut bits = Bits::new(data);
        let mut c = Coder {
            high: 0xFFFF,
            low: 0,
            code: 0,
        };
        c.code = bits.read(16);
        let mask = self.window.len() - 1;
        while out.len() < size {
            let sel = c.decode(&mut self.selector, &mut bits);
            if sel < 4 {
                let b = c.decode(&mut self.literals[sel as usize], &mut bits);
                self.window[self.pos] = b;
                self.pos = (self.pos + 1) & mask;
                out.push(b);
            } else {
                let (len, slot) = match sel {
                    4 => (3, c.decode(&mut self.pos3, &mut bits)),
                    5 => (4, c.decode(&mut self.pos4, &mut bits)),
                    6 => {
                        let ls = c.decode(&mut self.len_var, &mut bits) as usize;
                        let extra = bits.read(LENGTH_EXTRA[ls] as u32);
                        let len = LENGTH_BASE[ls] as usize + extra as usize + 5;
                        (len, c.decode(&mut self.pos_var, &mut bits))
                    }
                    _ => return Err(Error::corrupt("Quantum selector out of range")),
                };
                let slot = slot as usize;
                let extra = bits.read(EXTRA_BITS[slot] as u32);
                let dist = POSITION_BASE[slot] as usize + extra as usize + 1;
                if len > size - out.len() {
                    return Err(Error::corrupt(
                        "Quantum match runs past the end of the frame",
                    ));
                }
                if dist > self.window.len() {
                    return Err(Error::corrupt("Quantum match distance exceeds the window"));
                }
                let mut src = (self.pos + self.window.len() - dist) & mask;
                for _ in 0..len {
                    let b = self.window[src];
                    self.window[self.pos] = b;
                    out.push(b);
                    src = (src + 1) & mask;
                    self.pos = (self.pos + 1) & mask;
                }
            }
            if bits.consumed() > data.len() * 8 {
                return Err(Error::corrupt("Quantum frame is truncated"));
            }
        }
        // The coder's last two bits must still lie inside the frame (7-Zip's end check;
        // trailing padding bytes are tolerated).
        if bits.consumed() + 2 > data.len() * 8 {
            return Err(Error::corrupt("Quantum frame is truncated"));
        }
        Ok(())
    }
}
