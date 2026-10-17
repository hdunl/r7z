//! LZMS encoder: x86 translation, greedy choice among literals, explicit and repeat LZ
//! matches and explicit and repeat delta matches, coded with the adaptive range coder
//! and adaptive Huffman codes the decoder mirrors.

use super::{canonical_codes, code_lens, match_len, Matcher};

const POS_RUNS: [u8; 31] = [
    8, 0, 9, 7, 10, 15, 15, 20, 20, 30, 33, 40, 42, 45, 60, 73, 80, 85, 95, 105, 6, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1,
];
const LEN_EXTRA: [u8; 54] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 16, 30,
];

struct Tables {
    pos_base: Vec<u32>,
    pos_extra: Vec<u8>,
    len_base: Vec<u32>,
}

impl Tables {
    fn new() -> Self {
        let mut pos_extra = Vec::new();
        for (b, &r) in POS_RUNS.iter().enumerate() {
            pos_extra.extend(std::iter::repeat_n(b as u8, r as usize));
        }
        let mut pos_base = Vec::new();
        let mut s = 1u64;
        for &e in &pos_extra {
            pos_base.push(s as u32);
            s += 1 << e;
        }
        let mut len_base = Vec::new();
        let mut s = 1u32;
        for &e in &LEN_EXTRA {
            len_base.push(s);
            s += 1 << e;
        }
        Tables {
            pos_base,
            pos_extra,
            len_base,
        }
    }

    fn pos_slot(&self, v: u32) -> usize {
        self.pos_base.partition_point(|&b| b <= v) - 1
    }

    fn len_slot(&self, v: u32) -> usize {
        self.len_base.partition_point(|&b| b <= v) - 1
    }
}

#[derive(Clone, Copy)]
struct Prob {
    zeros: u32,
    hist: u64,
}

const INIT: Prob = Prob {
    zeros: 48,
    hist: 0x5555_5555,
};

struct Rc {
    low: u64,
    range: u32,
    cache: u16,
    cache_size: u64,
    started: bool,
    out: Vec<u16>,
}

impl Rc {
    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFFFF_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u16;
            let mut c = self.cache;
            loop {
                if self.started {
                    self.out.push(c.wrapping_add(carry));
                }
                self.started = true;
                c = 0xFFFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low >> 16) & 0xFFFF) as u16;
        }
        self.cache_size += 1;
        self.low = (self.low & 0xFFFF) << 16;
    }

    fn bit(&mut self, state: &mut u32, mask: u32, probs: &mut [Prob], bit: u32) {
        let e = &mut probs[*state as usize];
        let prob = e.zeros.clamp(1, 63);
        let bound = (self.range >> 6) * prob;
        if bit == 0 {
            self.range = bound;
        } else {
            self.low += bound as u64;
            self.range -= bound;
        }
        if self.range <= 0xFFFF {
            self.range <<= 16;
            self.shift_low();
        }
        e.zeros = (e.zeros as i32 + (e.hist >> 63) as i32 - bit as i32) as u32;
        e.hist = (e.hist << 1) | bit as u64;
        *state = ((*state << 1) | bit) & mask;
    }
}

/// Bits written MSB first into 16-bit words that the decoder reads from the end.
struct Back {
    words: Vec<u16>,
    buf: u64,
    count: u32,
}

impl Back {
    fn put(&mut self, v: u32, n: u32) {
        if n == 0 {
            return;
        }
        self.buf = (self.buf << n) | (v as u64 & ((1u64 << n) - 1));
        self.count += n;
        while self.count >= 16 {
            self.count -= 16;
            self.words.push((self.buf >> self.count) as u16);
        }
    }
}

struct Code {
    freqs: Vec<u32>,
    lens: Vec<u8>,
    codes: Vec<u32>,
    rebuild: u32,
    left: u32,
}

impl Code {
    fn new(num: usize, rebuild: u32) -> Self {
        let mut c = Code {
            freqs: vec![1; num],
            lens: Vec::new(),
            codes: Vec::new(),
            rebuild,
            left: rebuild,
        };
        c.build();
        c
    }

    fn build(&mut self) {
        self.lens = code_lens(&self.freqs, 15);
        self.codes = canonical_codes(&self.lens);
    }

    fn put(&mut self, w: &mut Back, s: usize) {
        w.put(self.codes[s], self.lens[s] as u32);
        self.freqs[s] += 1;
        self.left -= 1;
        if self.left == 0 {
            self.build();
            for f in &mut self.freqs {
                *f = (*f >> 1) + 1;
            }
            self.left = self.rebuild;
        }
    }
}

enum Choice {
    Lit,
    Lz {
        len: usize,
        rep: Option<usize>,
        dist: u32,
    },
    Delta {
        len: usize,
        rep: Option<usize>,
        power: u32,
        raw: u32,
    },
}

fn delta_len(d: &[u8], p: usize, span: usize, dist: usize, max: usize) -> usize {
    if p < dist + span {
        return 0;
    }
    let mut l = 0;
    while l < max {
        let i = p + l;
        let v = d[i - span]
            .wrapping_add(d[i - dist])
            .wrapping_sub(d[i - dist - span]);
        if d[i] != v {
            break;
        }
        l += 1;
    }
    l
}

pub fn compress(chunk: &[u8]) -> Vec<u8> {
    let t = Tables::new();
    let mut d = chunk.to_vec();
    r7z::codec::lzms::X86Filter::new().apply(&mut d, false);
    let n = d.len();
    let npos = if n < 2 {
        2
    } else {
        t.pos_base
            .partition_point(|&b| b as u64 <= (n - 1) as u64)
            .max(2)
    };

    let mut rc = Rc {
        low: 0,
        range: u32::MAX,
        cache: 0,
        cache_size: 1,
        started: false,
        out: Vec::new(),
    };
    let mut bw = Back {
        words: Vec::new(),
        buf: 0,
        count: 0,
    };
    let mut lit = Code::new(256, 1024);
    let mut lens = Code::new(54, 512);
    let mut pos = Code::new(npos, 1024);
    let mut dpos = Code::new(npos, 1024);
    let mut power_c = Code::new(8, 512);
    let mut main_p = [INIT; 16];
    let mut match_p = [INIT; 32];
    let mut lz_p = [[INIT; 64]; 3];
    let mut delta_p = [[INIT; 64]; 3];
    let (mut main_s, mut match_s) = (0u32, 0u32);
    let mut lz_s = [0u32; 3];
    let mut delta_s = [0u32; 3];
    let mut reps = [1u32, 2, 3, 4];
    let mut dreps = [1u64, 2, 3, 4];
    let mut prev = 0u8;
    let mut m = Matcher::new(n);

    let mut p = 0;
    while p < n {
        let max = (n - p).min(1 << 16);
        let mut best = Choice::Lit;
        let mut best_len = 0usize;
        // LZ repeats (after an LZ match its own offset still heads the queue).
        let shift = (prev == 1) as usize;
        for k in 0..3 {
            let r = reps[k + shift] as usize;
            if r <= p {
                let l = match_len(&d, p - r, p, max);
                if l >= 2 && l > best_len {
                    best_len = l;
                    best = Choice::Lz {
                        len: l,
                        rep: Some(k),
                        dist: r as u32,
                    };
                }
            }
        }
        if let Some((l, dist)) = m.find(&d, p, max, p) {
            if l >= best_len + 2 {
                best_len = l;
                best = Choice::Lz {
                    len: l,
                    rep: None,
                    dist: dist as u32,
                };
            }
        }
        let dshift = (prev == 2) as usize;
        for k in 0..3 {
            let pair = dreps[k + dshift];
            let (power, raw) = ((pair >> 32) as u32, pair as u32);
            let l = delta_len(&d, p, 1 << power, (raw as usize) << power, max);
            if l >= 3 && l > best_len {
                best_len = l;
                best = Choice::Delta {
                    len: l,
                    rep: Some(k),
                    power,
                    raw,
                };
            }
        }
        for power in 0..3u32 {
            for raw in 1..5u32 {
                let l = delta_len(&d, p, 1 << power, (raw as usize) << power, max);
                if l >= 8 && l > best_len + 2 {
                    best_len = l;
                    best = Choice::Delta {
                        len: l,
                        rep: None,
                        power,
                        raw,
                    };
                }
            }
        }
        let advance = match best {
            Choice::Lit => {
                rc.bit(&mut main_s, 15, &mut main_p, 0);
                lit.put(&mut bw, d[p] as usize);
                prev = 0;
                1
            }
            Choice::Lz { len, rep, dist } => {
                rc.bit(&mut main_s, 15, &mut main_p, 1);
                rc.bit(&mut match_s, 31, &mut match_p, 0);
                code_rep(&mut rc, &mut lz_s, &mut lz_p, rep);
                match rep {
                    None => {
                        let s = t.pos_slot(dist);
                        pos.put(&mut bw, s);
                        bw.put(dist - t.pos_base[s], t.pos_extra[s] as u32);
                        reps.copy_within(0..3, 1);
                        reps[0] = dist;
                    }
                    Some(k) => {
                        let k = k + shift;
                        let v = reps[k];
                        reps.copy_within(0..k, 1);
                        reps[0] = v;
                    }
                }
                put_len(&t, &mut lens, &mut bw, len);
                prev = 1;
                len
            }
            Choice::Delta {
                len,
                rep,
                power,
                raw,
            } => {
                rc.bit(&mut main_s, 15, &mut main_p, 1);
                rc.bit(&mut match_s, 31, &mut match_p, 1);
                code_rep(&mut rc, &mut delta_s, &mut delta_p, rep);
                match rep {
                    None => {
                        power_c.put(&mut bw, power as usize);
                        let s = t.pos_slot(raw);
                        dpos.put(&mut bw, s);
                        bw.put(raw - t.pos_base[s], t.pos_extra[s] as u32);
                        dreps.copy_within(0..3, 1);
                        dreps[0] = ((power as u64) << 32) | raw as u64;
                    }
                    Some(k) => {
                        let k = k + dshift;
                        let v = dreps[k];
                        dreps.copy_within(0..k, 1);
                        dreps[0] = v;
                    }
                }
                put_len(&t, &mut lens, &mut bw, len);
                prev = 2;
                len
            }
        };
        for k in p..p + advance {
            m.insert(&d, k);
        }
        p += advance;
    }
    for _ in 0..4 {
        rc.shift_low();
    }
    if bw.count > 0 {
        let pad = 16 - bw.count;
        bw.put(0, pad);
    }
    let mut out: Vec<u8> = rc.out.iter().flat_map(|w| w.to_le_bytes()).collect();
    out.extend(bw.words.iter().rev().flat_map(|w| w.to_le_bytes()));
    out
}

fn code_rep(rc: &mut Rc, st: &mut [u32; 3], probs: &mut [[Prob; 64]; 3], rep: Option<usize>) {
    match rep {
        None => rc.bit(&mut st[0], 63, &mut probs[0], 0),
        Some(k) => {
            rc.bit(&mut st[0], 63, &mut probs[0], 1);
            rc.bit(&mut st[1], 63, &mut probs[1], (k > 0) as u32);
            if k > 0 {
                rc.bit(&mut st[2], 63, &mut probs[2], (k > 1) as u32);
            }
        }
    }
}

fn put_len(t: &Tables, c: &mut Code, w: &mut Back, len: usize) {
    let s = t.len_slot(len as u32);
    c.put(w, s);
    w.put(len as u32 - t.len_base[s], LEN_EXTRA[s] as u32);
}
