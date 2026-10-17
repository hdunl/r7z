//! LZX encoder for WIM chunks: E8 translation, greedy matching with repeat offsets,
//! verbatim, aligned and uncompressed blocks (chosen by `style`), and delta-coded tree
//! lengths using every pretree run code.

use super::{canonical_codes, code_lens, match_len, Matcher};

const E8_SIZE: i32 = 12_000_000;

#[derive(Clone, Copy)]
enum Item {
    Lit(u8),
    /// Main-tree position slot and verbatim offset bits.
    Match {
        len: usize,
        slot: usize,
        extra: u32,
        bits: u32,
    },
}

struct Bits {
    out: Vec<u8>,
    buf: u64,
    count: u32,
}

impl Bits {
    fn put(&mut self, v: u32, n: u32) {
        if n == 0 {
            return;
        }
        self.buf = (self.buf << n) | (v as u64 & ((1 << n) - 1));
        self.count += n;
        while self.count >= 16 {
            self.count -= 16;
            let w = (self.buf >> self.count) as u16;
            self.out.extend_from_slice(&w.to_le_bytes());
        }
    }

    /// Pads to the next word boundary with 1 to 16 zero bits.
    fn align(&mut self) {
        let pad = 16 - self.count % 16;
        self.put(0, pad);
    }

    fn flush(&mut self) {
        if self.count > 0 {
            self.put(0, 16 - self.count);
        }
    }
}

fn slots(window_bits: u32) -> usize {
    if window_bits < 20 {
        2 * window_bits as usize
    } else {
        2 * (17 + (1usize << (window_bits - 18)))
    }
}

fn slot_tables() -> ([u32; 50], [u32; 50]) {
    let mut base = [0u32; 50];
    let mut extra = [0u32; 50];
    let mut b = 0;
    for i in 0..50 {
        extra[i] = if i < 4 { 0 } else { (i as u32 / 2 - 1).min(17) };
        base[i] = b;
        b += 1 << extra[i];
    }
    (base, extra)
}

fn e8_translate(d: &mut [u8]) {
    if d.len() <= 10 {
        return;
    }
    let mut i = 0;
    while i < d.len() - 10 {
        if d[i] == 0xE8 {
            let rel = i32::from_le_bytes(d[i + 1..i + 5].try_into().unwrap());
            let cur = i as i32;
            if rel >= -cur && rel < E8_SIZE {
                let abs = if rel < E8_SIZE - cur {
                    rel + cur
                } else {
                    rel - E8_SIZE
                };
                d[i + 1..i + 5].copy_from_slice(&abs.to_le_bytes());
            }
            i += 5;
        } else {
            i += 1;
        }
    }
}

/// Writes delta-coded lengths `new` (against `prev`) through a pretree.
fn write_lens(bits: &mut Bits, prev: &[u8], new: &[u8]) {
    // (pretree symbol, extra value, extra bit count, optional second symbol)
    let mut syms: Vec<(u32, u32, u32, Option<u32>)> = Vec::new();
    let delta = |i: usize, v: u8| ((prev[i] as u32 + 17 - v as u32) % 17);
    let mut i = 0;
    while i < new.len() {
        let mut run = 1;
        while i + run < new.len() && new[i + run] == new[i] {
            run += 1;
        }
        if new[i] == 0 && run >= 20 {
            let r = run.min(51);
            syms.push((18, (r - 20) as u32, 5, None));
            i += r;
        } else if new[i] == 0 && run >= 4 {
            let r = run.min(19);
            syms.push((17, (r - 4) as u32, 4, None));
            i += r;
        } else if new[i] != 0 && run >= 4 {
            let r = run.min(5);
            syms.push((19, (r - 4) as u32, 1, Some(delta(i, new[i]))));
            i += r;
        } else {
            syms.push((delta(i, new[i]), 0, 0, None));
            i += 1;
        }
    }
    let mut freqs = [0u32; 20];
    for s in &syms {
        freqs[s.0 as usize] += 1;
        if let Some(t) = s.3 {
            freqs[t as usize] += 1;
        }
    }
    let lens = code_lens(&freqs, 15);
    let codes = canonical_codes(&lens);
    for &l in &lens {
        bits.put(l as u32, 4);
    }
    for (s, v, n, t) in syms {
        bits.put(codes[s as usize], lens[s as usize] as u32);
        bits.put(v, n);
        if let Some(t) = t {
            bits.put(codes[t as usize], lens[t as usize] as u32);
        }
    }
}

/// Compresses one chunk. `style` picks block types: 0 verbatim, 1 aligned, 2 mixed
/// (verbatim, aligned and uncompressed blocks of varying sizes).
pub fn compress(chunk: &[u8], window_bits: u32, style: u32) -> Vec<u8> {
    let mut d = chunk.to_vec();
    e8_translate(&mut d);
    let (base, extra_tab) = slot_tables();
    let nslots = slots(window_bits);
    let max_dist = (1usize << window_bits) - 3;
    let mut m = Matcher::new(d.len());
    let mut items: Vec<(usize, Item)> = Vec::new();
    let mut reps = [1usize; 3];
    let mut p = 0;
    while p < d.len() {
        let max_len = 257.min(d.len() - p);
        // Repeat offsets first.
        let mut best: Option<(usize, usize, usize)> = None;
        for (k, &r) in reps.iter().enumerate() {
            if r <= p {
                let l = match_len(&d, p - r, p, max_len);
                if l >= 2 && best.is_none_or(|(bl, _, _)| l > bl) {
                    best = Some((l, k, r));
                }
            }
        }
        let found = m.find(&d, p, max_len, max_dist.min(p));
        let (len, item) = match (best, found) {
            (Some((rl, k, r)), f) if f.is_none_or(|(fl, _)| fl < rl + 2) => {
                reps.swap(0, k);
                debug_assert_eq!(reps[0], r);
                (
                    rl,
                    Item::Match {
                        len: rl,
                        slot: k,
                        extra: 0,
                        bits: 0,
                    },
                )
            }
            (_, Some((fl, dist))) => {
                let formatted = dist as u32 + 2;
                let slot = (0..nslots).rev().find(|&s| base[s] <= formatted).unwrap();
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = dist;
                (
                    fl,
                    Item::Match {
                        len: fl,
                        slot,
                        extra: formatted - base[slot],
                        bits: extra_tab[slot],
                    },
                )
            }
            _ => (1, Item::Lit(d[p])),
        };
        for k in p..p + len {
            m.insert(&d, k);
        }
        items.push((p, item));
        p += len;
    }

    let mut bits = Bits {
        out: Vec::new(),
        buf: 0,
        count: 0,
    };
    let main_syms = 256 + 8 * nslots;
    let mut prev_main = vec![0u8; main_syms];
    let mut prev_len = vec![0u8; 249];
    // Replayed repeat offsets, for uncompressed block headers.
    let mut reps = [1usize; 3];
    let mut i = 0;
    let mut block_no = 0u32;
    while i < items.len() {
        let start = items[i].0;
        let target = match style {
            0 | 1 => 32768,
            _ => [9000, 32768, 3000, 20000][block_no as usize % 4],
        };
        let mut j = i;
        while j < items.len() && items[j].0 < start + target {
            j += 1;
        }
        let end = if j < items.len() { items[j].0 } else { d.len() };
        let size = end - start;
        let kind = match style {
            0 => 1,
            1 => 2,
            _ => [1, 2, 3, 2][block_no as usize % 4],
        };
        // Repeat offsets after this block's items, as the matcher assumed; an
        // uncompressed block hands them to the decoder in its header.
        for (_, it) in &items[i..j] {
            if let Item::Match { slot, extra, .. } = *it {
                if slot < 3 {
                    reps.swap(0, slot);
                } else {
                    let dist = (base[slot] + extra - 2) as usize;
                    reps[2] = reps[1];
                    reps[1] = reps[0];
                    reps[0] = dist;
                }
            }
        }
        bits.put(kind, 3);
        if size == 32768 {
            bits.put(1, 1);
        } else {
            bits.put(0, 1);
            if window_bits >= 16 {
                bits.put((size >> 8) as u32, 16);
                bits.put((size & 0xFF) as u32, 8);
            } else {
                bits.put(size as u32, 16);
            }
        }
        if kind == 3 {
            bits.align();
            for r in reps {
                bits.out.extend_from_slice(&(r as u32).to_le_bytes());
            }
            bits.out.extend_from_slice(&d[start..end]);
            if size % 2 == 1 {
                bits.out.push(0);
            }
        } else {
            let aligned = kind == 2;
            let mut fm = vec![0u32; main_syms];
            let mut fl = vec![0u32; 249];
            let mut fa = [0u32; 8];
            for (_, it) in &items[i..j] {
                match *it {
                    Item::Lit(b) => fm[b as usize] += 1,
                    Item::Match {
                        len,
                        slot,
                        extra,
                        bits: n,
                    } => {
                        fm[256 + slot * 8 + (len - 2).min(7)] += 1;
                        if len - 2 >= 7 {
                            fl[len - 9] += 1;
                        }
                        if aligned && n >= 3 {
                            fa[(extra & 7) as usize] += 1;
                        }
                    }
                }
            }
            let lm = code_lens(&fm, 16);
            let ll = code_lens(&fl, 16);
            let la = code_lens(&fa, 7);
            let (cm, cl, ca) = (
                canonical_codes(&lm),
                canonical_codes(&ll),
                canonical_codes(&la),
            );
            if aligned {
                for &l in &la {
                    bits.put(l as u32, 3);
                }
            }
            write_lens(&mut bits, &prev_main[..256], &lm[..256]);
            write_lens(&mut bits, &prev_main[256..], &lm[256..]);
            // A length tree with no used symbol is sent as all zeros.
            let ll = if fl.iter().all(|&f| f == 0) {
                vec![0u8; 249]
            } else {
                ll
            };
            write_lens(&mut bits, &prev_len, &ll);
            prev_main = lm.clone();
            prev_len = ll.clone();
            for (_, it) in &items[i..j] {
                match *it {
                    Item::Lit(b) => bits.put(cm[b as usize], lm[b as usize] as u32),
                    Item::Match {
                        len,
                        slot,
                        extra,
                        bits: n,
                    } => {
                        let s = 256 + slot * 8 + (len - 2).min(7);
                        bits.put(cm[s], lm[s] as u32);
                        if len - 2 >= 7 {
                            bits.put(cl[len - 9], ll[len - 9] as u32);
                        }
                        if aligned && n >= 3 {
                            bits.put(extra >> 3, n - 3);
                            let a = (extra & 7) as usize;
                            bits.put(ca[a], la[a] as u32);
                        } else {
                            bits.put(extra, n);
                        }
                    }
                }
            }
        }
        i = j;
        block_no += 1;
    }
    bits.flush();
    bits.out
}
