//! XPRESS Huffman encoder (one chunk of at most 64 KiB), ending with the end-of-data
//! symbol 256 and exact padding, as WIMGAPI writes it and 7-Zip requires.

use super::{canonical_codes, code_lens, Matcher};

enum Item {
    Lit(u8),
    Match { len: usize, dist: usize },
}

/// Bit writer whose 16-bit words are reserved two ahead, so extension bytes land where
/// the decoder's 32-bit window reads them.
struct Writer {
    out: Vec<u8>,
    buf: u64,
    count: u32,
    slot1: usize,
    slot2: usize,
}

impl Writer {
    fn new() -> Self {
        Writer {
            out: vec![0; 4],
            buf: 0,
            count: 0,
            slot1: 0,
            slot2: 2,
        }
    }

    fn bits(&mut self, v: u32, n: u32) {
        if n == 0 {
            return;
        }
        self.buf = (self.buf << n) | v as u64;
        self.count += n;
        if self.count > 16 {
            self.count -= 16;
            let w = (self.buf >> self.count) as u16;
            self.out[self.slot1..self.slot1 + 2].copy_from_slice(&w.to_le_bytes());
            self.slot1 = self.slot2;
            self.slot2 = self.out.len();
            self.out.extend([0, 0]);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        let w = ((self.buf << (16 - self.count)) & 0xFFFF) as u16;
        self.out[self.slot1..self.slot1 + 2].copy_from_slice(&w.to_le_bytes());
        self.out
    }
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 65536);
    let mut m = Matcher::new(data.len());
    let mut items = Vec::new();
    let mut p = 0;
    while p < data.len() {
        match m.find(data, p, 65538, 65535) {
            Some((len, dist)) => {
                for k in p..p + len {
                    m.insert(data, k);
                }
                items.push(Item::Match { len, dist });
                p += len;
            }
            None => {
                m.insert(data, p);
                items.push(Item::Lit(data[p]));
                p += 1;
            }
        }
    }
    let sym = |it: &Item| -> usize {
        match *it {
            Item::Lit(b) => b as usize,
            Item::Match { len, dist } => {
                let bits = 31 - (dist as u32).leading_zeros();
                256 + ((bits as usize) << 4) + (len - 3).min(15)
            }
        }
    };
    let mut freqs = vec![0u32; 512];
    for it in &items {
        freqs[sym(it)] += 1;
    }
    freqs[256] += 1;
    let lens = code_lens(&freqs, 15);
    let codes = canonical_codes(&lens);
    let mut table = vec![0u8; 256];
    for i in 0..256 {
        table[i] = lens[2 * i] | (lens[2 * i + 1] << 4);
    }
    let mut w = Writer::new();
    for it in &items {
        let s = sym(it);
        w.bits(codes[s], lens[s] as u32);
        if let Item::Match { len, dist } = *it {
            let l = len - 3;
            if l >= 15 {
                if l - 15 < 255 {
                    w.out.push((l - 15) as u8);
                } else {
                    w.out.push(255);
                    w.out.extend_from_slice(&(l as u16).to_le_bytes());
                }
            }
            let bits = 31 - (dist as u32).leading_zeros();
            w.bits(dist as u32 - (1 << bits), bits);
        }
    }
    w.bits(codes[256], lens[256] as u32);
    let mut out = table;
    out.extend(w.finish());
    out
}
