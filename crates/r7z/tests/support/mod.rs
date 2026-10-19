//! Test-only LZH and ARJ writers: a greedy LZ77 matcher, encoders for the static-Huffman
//! block format (`-lh4-`..`-lh7-`, ARJ 1-3), ARJ method 4, `-lh1-`, `-lzs-` and `-lz5-`,
//! and container writers for LZH header levels 0-3 and ARJ. They exist to produce
//! fixtures that 7-Zip can cross-check, since no tool on the test machine writes them.

#![allow(dead_code)]

/// An LZ77 token.
#[derive(Clone, Copy, Debug)]
pub enum Tok {
    Lit(u8),
    Match { len: usize, dist: usize },
}

/// Greedy hash-chain parse with matches of `min..=max_len` bytes up to `window` back.
pub fn parse(data: &[u8], window: usize, min: usize, max_len: usize) -> Vec<Tok> {
    const HBITS: u32 = 15;
    let hash = |p: usize| -> usize {
        let v = u32::from(data[p]) | (u32::from(data[p + 1]) << 8) | (u32::from(data[p + 2]) << 16);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HBITS)) as usize
    };
    let mut head = vec![usize::MAX; 1 << HBITS];
    let mut prev = vec![usize::MAX; data.len()];
    let mut out = Vec::new();
    let mut p = 0;
    let insert = |p: usize, head: &mut Vec<usize>, prev: &mut Vec<usize>| {
        if p + 3 <= data.len() {
            let h = hash(p);
            prev[p] = head[h];
            head[h] = p;
        }
    };
    while p < data.len() {
        let (mut best_len, mut best_dist) = (0, 0);
        if p + 3 <= data.len() {
            let mut cand = head[hash(p)];
            let mut chain = 0;
            while cand != usize::MAX && p - cand <= window && chain < 128 {
                let limit = max_len.min(data.len() - p);
                let mut l = 0;
                while l < limit && data[cand + l] == data[p + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_dist = p - cand;
                    if l == limit {
                        break;
                    }
                }
                cand = prev[cand];
                chain += 1;
            }
        }
        if best_len >= min {
            out.push(Tok::Match {
                len: best_len,
                dist: best_dist,
            });
            for q in p..p + best_len {
                insert(q, &mut head, &mut prev);
            }
            p += best_len;
        } else {
            out.push(Tok::Lit(data[p]));
            insert(p, &mut head, &mut prev);
            p += 1;
        }
    }
    out
}

/// MSB-first bit writer.
#[derive(Default)]
pub struct BitWriter {
    pub out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    pub fn put(&mut self, bits: u32, value: u32) {
        if bits == 0 {
            return;
        }
        debug_assert!(bits <= 32 && (bits == 32 || value >> bits == 0));
        self.acc = (self.acc << bits) | value as u64;
        self.n += bits;
        while self.n >= 8 {
            self.out.push((self.acc >> (self.n - 8)) as u8);
            self.n -= 8;
        }
        self.acc &= (1u64 << self.n) - 1;
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

/// Huffman code lengths limited to `max` bits (frequencies are flattened until they fit).
pub fn code_lengths(freq: &[u32], max: u8) -> Vec<u8> {
    let mut f: Vec<u64> = freq.iter().map(|&x| x as u64).collect();
    loop {
        let lens = huffman_lengths(&f);
        if lens.iter().all(|&l| l <= max) {
            return lens;
        }
        for x in f.iter_mut().filter(|x| **x > 0) {
            *x = x.div_ceil(2);
        }
    }
}

fn huffman_lengths(freq: &[u64]) -> Vec<u8> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let n = freq.len();
    let mut parent = vec![usize::MAX; n];
    let mut heap = BinaryHeap::new();
    for (i, &f) in freq.iter().enumerate() {
        if f > 0 {
            heap.push(Reverse((f, i)));
        }
    }
    let mut lens = vec![0u8; n];
    if heap.len() == 1 {
        let Reverse((_, i)) = heap.pop().unwrap();
        lens[i] = 1;
        return lens;
    }
    while heap.len() > 1 {
        let Reverse((fa, a)) = heap.pop().unwrap();
        let Reverse((fb, b)) = heap.pop().unwrap();
        let id = parent.len();
        parent.push(usize::MAX);
        parent[a] = id;
        parent[b] = id;
        heap.push(Reverse((fa + fb, id)));
    }
    for i in 0..n {
        if freq[i] > 0 {
            let mut d = 0;
            let mut k = i;
            while parent[k] != usize::MAX {
                k = parent[k];
                d += 1;
            }
            lens[i] = d;
        }
    }
    lens
}

/// Canonical MSB-first codes for `lens` (shorter codes first, then by symbol).
pub fn canonical_codes(lens: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 17];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 17];
    let mut code = 0;
    for l in 1..17 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    lens.iter()
        .map(|&l| {
            if l == 0 {
                0
            } else {
                let c = next[l as usize];
                next[l as usize] += 1;
                c
            }
        })
        .collect()
}

const NC: usize = 510;
const NT: usize = 19;

fn pos_code(d: usize) -> usize {
    if d == 0 {
        0
    } else {
        (usize::BITS - d.leading_zeros()) as usize
    }
}

/// A tree to send: either one symbol (zero-length code) or real lengths.
enum Tree {
    Single(usize),
    Lens(Vec<u8>, Vec<u32>),
}

impl Tree {
    fn from_freq(freq: &[u32]) -> Tree {
        let used: Vec<usize> = (0..freq.len()).filter(|&i| freq[i] > 0).collect();
        if used.len() <= 1 {
            return Tree::Single(used.first().copied().unwrap_or(0));
        }
        let lens = code_lengths(freq, 16);
        let codes = canonical_codes(&lens);
        Tree::Lens(lens, codes)
    }

    fn put(&self, w: &mut BitWriter, sym: usize) {
        if let Tree::Lens(l, c) = self {
            assert!(l[sym] > 0, "symbol {sym} has no code");
            w.put(l[sym] as u32, c[sym]);
        }
    }
}

fn write_pt_len(w: &mut BitWriter, lens: &[u8], nbit: u32, special: Option<usize>) {
    let mut n = lens.len();
    while n > 0 && lens[n - 1] == 0 {
        n -= 1;
    }
    w.put(nbit, n as u32);
    let mut i = 0;
    while i < n {
        let k = lens[i] as u32;
        i += 1;
        if k <= 6 {
            w.put(3, k);
        } else {
            w.put(k - 3, (1 << (k - 3)) - 2);
        }
        if special == Some(i) {
            while i < 6 && lens[i] == 0 {
                i += 1;
            }
            w.put(2, (i - 3) as u32);
        }
    }
}

/// Zero runs and lengths of the literal/length tree as code-length symbols (+ extra bits).
fn c_len_symbols(c_len: &[u8]) -> Vec<(usize, u32, u32)> {
    let mut n = c_len.len();
    while n > 0 && c_len[n - 1] == 0 {
        n -= 1;
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let k = c_len[i] as usize;
        i += 1;
        if k != 0 {
            out.push((k + 2, 0, 0));
            continue;
        }
        let mut count = 1;
        while i < n && c_len[i] == 0 {
            i += 1;
            count += 1;
        }
        match count {
            1 | 2 => (0..count).for_each(|_| out.push((0, 0, 0))),
            3..=18 => out.push((1, 4, count as u32 - 3)),
            19 => {
                out.push((0, 0, 0));
                out.push((1, 4, 15));
            }
            _ => out.push((2, 9, count as u32 - 20)),
        }
    }
    out
}

/// The static-Huffman block format with `np` position codes sent in `pbit` bits.
pub fn encode_st1(toks: &[Tok], np: usize, pbit: u32, block: usize) -> Vec<u8> {
    let mut w = BitWriter::default();
    for chunk in toks.chunks(block.min(0xFFFF)) {
        let mut c_freq = vec![0u32; NC];
        let mut p_freq = vec![0u32; np];
        for t in chunk {
            match *t {
                Tok::Lit(b) => c_freq[b as usize] += 1,
                Tok::Match { len, dist } => {
                    c_freq[len + 253] += 1;
                    p_freq[pos_code(dist - 1)] += 1;
                }
            }
        }
        w.put(16, chunk.len() as u32);
        let c = Tree::from_freq(&c_freq);
        match &c {
            Tree::Single(s) => {
                w.put(5, 0);
                w.put(5, 0);
                w.put(9, 0);
                w.put(9, *s as u32);
            }
            Tree::Lens(c_len, _) => {
                let syms = c_len_symbols(c_len);
                let mut t_freq = vec![0u32; NT];
                for &(s, _, _) in &syms {
                    t_freq[s] += 1;
                }
                let t = Tree::from_freq(&t_freq);
                match &t {
                    Tree::Single(s) => {
                        w.put(5, 0);
                        w.put(5, *s as u32);
                    }
                    Tree::Lens(l, _) => write_pt_len(&mut w, l, 5, Some(3)),
                }
                let mut n = c_len.len();
                while n > 0 && c_len[n - 1] == 0 {
                    n -= 1;
                }
                w.put(9, n as u32);
                for (s, nb, v) in syms {
                    t.put(&mut w, s);
                    w.put(nb, v);
                }
            }
        }
        let p = Tree::from_freq(&p_freq);
        match &p {
            Tree::Single(s) => {
                w.put(pbit, 0);
                w.put(pbit, *s as u32);
            }
            Tree::Lens(l, _) => write_pt_len(&mut w, l, pbit, None),
        }
        for t in chunk {
            match *t {
                Tok::Lit(b) => c.put(&mut w, b as usize),
                Tok::Match { len, dist } => {
                    c.put(&mut w, len + 253);
                    let d = dist - 1;
                    let pc = pos_code(d);
                    p.put(&mut w, pc);
                    if pc > 1 {
                        w.put(pc as u32 - 1, (d - (1 << (pc - 1))) as u32);
                    }
                }
            }
        }
    }
    w.finish()
}

/// `-lhN-` with `dict_bits` 12, 13, 15 or 16.
pub fn encode_lh(data: &[u8], dict_bits: u32, block: usize) -> Vec<u8> {
    let toks = parse(data, 1 << dict_bits, 3, 256);
    let (np, pbit) = if dict_bits <= 13 {
        (14, 4)
    } else {
        (dict_bits as usize + 1, 5)
    };
    encode_st1(&toks, np, pbit, block)
}

/// ARJ methods 1-3.
pub fn encode_arj1(data: &[u8], block: usize) -> Vec<u8> {
    encode_st1(&parse(data, 26_624, 3, 256), 17, 5, block)
}

/// ARJ method 4.
pub fn encode_arj4(data: &[u8]) -> Vec<u8> {
    fn gamma(w: &mut BitWriter, v: u32, start: u32, stop: u32) {
        let (mut k, mut plus) = (0, 0u32);
        while start + k < stop && v >= plus + (1 << (start + k)) {
            plus += 1 << (start + k);
            k += 1;
        }
        for _ in 0..k {
            w.put(1, 1);
        }
        if start + k < stop {
            w.put(1, 0);
        }
        w.put(start + k, v - plus);
    }
    let mut w = BitWriter::default();
    for t in parse(data, 15_800, 3, 256) {
        match t {
            Tok::Lit(b) => {
                gamma(&mut w, 0, 0, 7);
                w.put(8, b as u32);
            }
            Tok::Match { len, dist } => {
                gamma(&mut w, len as u32 - 2, 0, 7);
                gamma(&mut w, dist as u32 - 1, 9, 13);
            }
        }
    }
    w.finish()
}

/// `-lzs-`: LArc's 2 KiB LZSS (lengths 2..=17).
pub fn encode_lzs(data: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::default();
    let mut pos = 0usize;
    for t in parse(data, 2048, 3, 17) {
        match t {
            Tok::Lit(b) => {
                w.put(1, 1);
                w.put(8, b as u32);
                pos += 1;
            }
            Tok::Match { len, dist } => {
                let mpos = pos.wrapping_sub(dist).wrapping_sub(17) & 0x7FF;
                w.put(1, 0);
                w.put(11, mpos as u32);
                w.put(4, len as u32 - 2);
                pos += len;
            }
        }
    }
    w.finish()
}

/// `-lz5-`: LArc's 4 KiB LZSS with flag bytes (lengths 3..=18).
pub fn encode_lz5(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut group: Vec<u8> = Vec::new();
    let (mut flags, mut nflags) = (0u8, 0);
    let mut pos = 0usize;
    for t in parse(data, 4096, 3, 18) {
        match t {
            Tok::Lit(b) => {
                flags |= 1 << nflags;
                group.push(b);
                pos += 1;
            }
            Tok::Match { len, dist } => {
                let mpos = pos.wrapping_sub(dist).wrapping_sub(18) & 0xFFF;
                group.push(mpos as u8);
                group.push((((mpos >> 8) as u8) << 4) | (len as u8 - 3));
                pos += len;
            }
        }
        nflags += 1;
        if nflags == 8 {
            out.push(flags);
            out.append(&mut group);
            flags = 0;
            nflags = 0;
        }
    }
    if nflags > 0 {
        out.push(flags);
        out.append(&mut group);
    }
    out
}

/// `-lh1-`: LZHUF adaptive Huffman, 4 KiB window, lengths 3..=60.
pub fn encode_lh1(data: &[u8]) -> Vec<u8> {
    const N_CHAR: usize = 314;
    const T: usize = N_CHAR * 2 - 1;
    const R: usize = T - 1;
    let mut freq = vec![0u32; T + 1];
    let mut son = vec![0usize; T];
    let mut prnt = vec![0usize; T + N_CHAR];
    for i in 0..N_CHAR {
        freq[i] = 1;
        son[i] = i + T;
        prnt[i + T] = i;
    }
    let (mut i, mut j) = (0, N_CHAR);
    while j <= R {
        freq[j] = freq[i] + freq[i + 1];
        son[j] = i;
        prnt[i] = j;
        prnt[i + 1] = j;
        i += 2;
        j += 1;
    }
    freq[T] = 0xFFFF;
    prnt[R] = 0;

    let reconst = |freq: &mut Vec<u32>, son: &mut Vec<usize>, prnt: &mut Vec<usize>| {
        let mut j = 0;
        for i in 0..T {
            if son[i] >= T {
                freq[j] = freq[i].div_ceil(2);
                son[j] = son[i];
                j += 1;
            }
        }
        let mut i = 0;
        for j in N_CHAR..T {
            let f = freq[i] + freq[i + 1];
            freq[j] = f;
            let mut k = j - 1;
            while f < freq[k] {
                k -= 1;
            }
            k += 1;
            freq.copy_within(k..j, k + 1);
            freq[k] = f;
            son.copy_within(k..j, k + 1);
            son[k] = i;
            i += 2;
        }
        for (i, &k) in son.iter().enumerate() {
            prnt[k] = i;
            if k < T {
                prnt[k + 1] = i;
            }
        }
    };
    let update = |c: usize, freq: &mut Vec<u32>, son: &mut Vec<usize>, prnt: &mut Vec<usize>| {
        if freq[R] == 0x8000 {
            reconst(freq, son, prnt);
        }
        let mut c = prnt[c + T];
        loop {
            freq[c] += 1;
            let k = freq[c];
            let mut l = c + 1;
            if k > freq[l] {
                while k > freq[l + 1] {
                    l += 1;
                }
                freq[c] = freq[l];
                freq[l] = k;
                let i = son[c];
                prnt[i] = l;
                if i < T {
                    prnt[i + 1] = l;
                }
                let j = son[l];
                son[l] = i;
                prnt[j] = c;
                if j < T {
                    prnt[j + 1] = c;
                }
                son[c] = j;
                c = l;
            }
            c = prnt[c];
            if c == 0 {
                break;
            }
        }
    };
    let mut plen = [0u8; 64];
    let mut k = 0;
    for (len, n) in [(3u8, 1), (4, 3), (5, 8), (6, 12), (7, 24), (8, 16)] {
        plen[k..k + n].fill(len);
        k += n;
    }
    let pcode = canonical_codes(&plen);
    let mut w = BitWriter::default();
    // A node's bit is its position's parity: sibling pairs sit at (even, odd) slots.
    let emit = |c: usize,
                w: &mut BitWriter,
                freq: &mut Vec<u32>,
                son: &mut Vec<usize>,
                prnt: &mut Vec<usize>| {
        let mut bits = Vec::new();
        let mut k = prnt[c + T];
        loop {
            bits.push((k & 1) as u32);
            k = prnt[k];
            if k == R {
                break;
            }
        }
        for b in bits.iter().rev() {
            w.put(1, *b);
        }
        update(c, freq, son, prnt);
    };
    for t in parse(data, 4096, 3, 60) {
        match t {
            Tok::Lit(b) => emit(b as usize, &mut w, &mut freq, &mut son, &mut prnt),
            Tok::Match { len, dist } => {
                emit(len + 253, &mut w, &mut freq, &mut son, &mut prnt);
                let d = dist - 1;
                let hi = d >> 6;
                w.put(plen[hi] as u32, pcode[hi]);
                w.put(6, (d & 63) as u32);
            }
        }
    }
    w.finish()
}

/// CRC-16/ARC.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// A packed DOS date/time.
pub fn dos_time(y: u32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> u32 {
    ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s / 2)
}

/// One file or directory to store.
pub struct Member {
    /// `/`-separated path.
    pub name: String,
    pub data: Vec<u8>,
    pub is_dir: bool,
    /// Packed DOS time (levels 0/1, ARJ) and Unix time (levels 2/3).
    pub dos_time: u32,
    pub unix_time: u32,
    /// ARJ local header flags (0x10: path separators translated).
    pub arj_flags: u8,
    /// How the name is stored (UTF-8 unless a test needs a legacy code page).
    pub encode: fn(&str) -> Vec<u8>,
}

impl Member {
    pub fn file(name: &str, data: Vec<u8>) -> Member {
        Member {
            name: name.into(),
            data,
            is_dir: false,
            dos_time: dos_time(2024, 5, 6, 7, 8, 10),
            unix_time: 1_700_000_000,
            arj_flags: 0x10,
            encode: |s| s.as_bytes().to_vec(),
        }
    }

    pub fn dir(name: &str) -> Member {
        Member {
            is_dir: true,
            ..Member::file(name, Vec::new())
        }
    }
}

/// Compresses `data` with an LZH method id (`lh0`, `lh5`, ...).
pub fn lzh_compress(method: &str, data: &[u8]) -> Vec<u8> {
    match method {
        "lh0" | "lz4" | "lhd" => data.to_vec(),
        "lh1" => encode_lh1(data),
        "lh4" => encode_lh(data, 12, 4000),
        "lh5" => encode_lh(data, 13, 4000),
        "lh6" => encode_lh(data, 15, 4000),
        "lh7" => encode_lh(data, 16, 4000),
        "lzs" => encode_lzs(data),
        "lz5" => encode_lz5(data),
        m => panic!("no encoder for {m}"),
    }
}

fn split_path(name: &str) -> (&str, &str) {
    match name.rfind('/') {
        Some(i) => (&name[..i + 1], &name[i + 1..]),
        None => ("", name),
    }
}

/// An LZH archive with every member at header `level` using `method` (directories use
/// `-lhd-`).
pub fn write_lzh(members: &[Member], level: u8, method: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for m in members {
        let mid = if m.is_dir { "lhd" } else { method };
        let packed = lzh_compress(mid, &m.data);
        let mid = format!("-{mid}-");
        let crc = crc16(&m.data);
        let size = m.data.len() as u32;
        let (dir, base) = split_path(&m.name);
        let dir_ff: Vec<u8> = (m.encode)(dir)
            .into_iter()
            .map(|b| if b == b'/' { 0xFF } else { b })
            .collect();
        match level {
            0 => {
                let mut name = (m.encode)(&m.name.replace('/', "\\"));
                if m.is_dir {
                    name.push(b'\\');
                }
                let mut h = vec![0u8, 0];
                h.extend_from_slice(mid.as_bytes());
                h.extend_from_slice(&(packed.len() as u32).to_le_bytes());
                h.extend_from_slice(&size.to_le_bytes());
                h.extend_from_slice(&m.dos_time.to_le_bytes());
                h.push(if m.is_dir { 0x10 } else { 0x20 });
                h.push(0);
                h.push(name.len() as u8);
                h.extend_from_slice(&name);
                h.extend_from_slice(&crc.to_le_bytes());
                h[0] = (h.len() - 2) as u8;
                h[1] = h[2..].iter().fold(0u8, |a, &x| a.wrapping_add(x));
                out.extend_from_slice(&h);
            }
            1 => {
                let mut exts: Vec<(u8, Vec<u8>)> = Vec::new();
                if !dir_ff.is_empty() || m.is_dir {
                    let mut d = dir_ff.clone();
                    if m.is_dir {
                        d.extend_from_slice(&(m.encode)(base));
                        d.push(0xFF);
                    }
                    exts.push((0x02, d));
                }
                exts.push((0x50, 0o644u16.to_le_bytes().to_vec()));
                exts.push((0x54, m.unix_time.to_le_bytes().to_vec()));
                let ext_bytes = ext_chain(&exts, 2);
                let fname = (m.encode)(if m.is_dir { "" } else { base });
                let mut h = vec![0u8, 0];
                h.extend_from_slice(mid.as_bytes());
                let skip = packed.len() + ext_bytes.len() - 2;
                h.extend_from_slice(&(skip as u32).to_le_bytes());
                h.extend_from_slice(&size.to_le_bytes());
                h.extend_from_slice(&m.dos_time.to_le_bytes());
                h.push(0x20);
                h.push(1);
                h.push(fname.len() as u8);
                h.extend_from_slice(&fname);
                h.extend_from_slice(&crc.to_le_bytes());
                h.push(b'U');
                // ext_chain starts with the first size field, which ends the base header.
                h.extend_from_slice(&ext_bytes[..2]);
                h[0] = (h.len() - 2) as u8;
                h[1] = h[2..].iter().fold(0u8, |a, &x| a.wrapping_add(x));
                out.extend_from_slice(&h);
                out.extend_from_slice(&ext_bytes[2..]);
            }
            2 | 3 => {
                let width = if level == 2 { 2 } else { 4 };
                let mut exts: Vec<(u8, Vec<u8>)> = vec![(0x00, vec![0, 0])];
                if !m.is_dir {
                    exts.push((0x01, (m.encode)(base)));
                }
                let mut d = dir_ff.clone();
                if m.is_dir {
                    d.extend_from_slice(&(m.encode)(base));
                    d.push(0xFF);
                }
                if !d.is_empty() {
                    exts.push((0x02, d));
                }
                exts.push((0x50, 0o755u16.to_le_bytes().to_vec()));
                let ext_bytes = ext_chain(&exts, width);
                let mut h = Vec::new();
                h.extend_from_slice(&if level == 2 { [0u8, 0] } else { [4u8, 0] });
                h.extend_from_slice(mid.as_bytes());
                h.extend_from_slice(&(packed.len() as u32).to_le_bytes());
                h.extend_from_slice(&size.to_le_bytes());
                h.extend_from_slice(&m.unix_time.to_le_bytes());
                h.push(0x20);
                h.push(level);
                h.extend_from_slice(&crc.to_le_bytes());
                h.push(b'U');
                if level == 3 {
                    h.extend_from_slice(&[0; 4]);
                }
                let crc_at = h.len() + width + 1;
                h.extend_from_slice(&ext_bytes);
                let total = h.len();
                if level == 2 {
                    h[..2].copy_from_slice(&(total as u16).to_le_bytes());
                } else {
                    h[24..28].copy_from_slice(&(total as u32).to_le_bytes());
                }
                let hcrc = crc16(&h);
                h[crc_at..crc_at + 2].copy_from_slice(&hcrc.to_le_bytes());
                out.extend_from_slice(&h);
            }
            _ => panic!("level {level}"),
        }
        out.extend_from_slice(&packed);
    }
    out.push(0);
    out
}

/// The first size field followed by each extended header (`type`, data, next size).
fn ext_chain(exts: &[(u8, Vec<u8>)], width: usize) -> Vec<u8> {
    let size = |e: &(u8, Vec<u8>)| (1 + e.1.len() + width) as u32;
    let put = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes()[..width]);
    let mut v = Vec::new();
    put(&mut v, exts.first().map(size).unwrap_or(0));
    for (k, e) in exts.iter().enumerate() {
        v.push(e.0);
        v.extend_from_slice(&e.1);
        put(&mut v, exts.get(k + 1).map(size).unwrap_or(0));
    }
    v
}

/// Compresses with an ARJ method number.
pub fn arj_compress(method: u8, data: &[u8]) -> Vec<u8> {
    match method {
        0 => data.to_vec(),
        1..=3 => encode_arj1(data, 3000),
        4 => encode_arj4(data),
        m => panic!("ARJ method {m}"),
    }
}

fn arj_block(basic: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0xEA];
    v.extend_from_slice(&(basic.len() as u16).to_le_bytes());
    v.extend_from_slice(basic);
    v.extend_from_slice(&crc32fast::hash(basic).to_le_bytes());
    v.extend_from_slice(&[0, 0]);
    v
}

/// An ARJ archive (MS-DOS host, path separators translated) with every file at `method`.
pub fn write_arj(archive_name: &str, members: &[Member], method: u8, comment: &str) -> Vec<u8> {
    let stamp = dos_time(2024, 5, 6, 7, 8, 10);
    let mut main = vec![30, 11, 1, 0, 0x10, 0, 2, 0];
    main.extend_from_slice(&stamp.to_le_bytes());
    main.extend_from_slice(&stamp.to_le_bytes());
    main.extend_from_slice(&[0; 14]);
    main.extend_from_slice(archive_name.as_bytes());
    main.push(0);
    main.extend_from_slice(comment.as_bytes());
    main.push(0);
    let mut out = arj_block(&main);
    for m in members {
        let meth = if m.is_dir { 0 } else { method };
        let packed = arj_compress(meth, &m.data);
        let (dir, _) = split_path(&m.name);
        let mut b = vec![
            30,
            11,
            1,
            0,
            m.arj_flags,
            meth,
            if m.is_dir { 3 } else { 0 },
            0,
        ];
        b.extend_from_slice(&m.dos_time.to_le_bytes());
        b.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        b.extend_from_slice(&(m.data.len() as u32).to_le_bytes());
        b.extend_from_slice(&crc32fast::hash(&m.data).to_le_bytes());
        b.extend_from_slice(&((m.encode)(dir).len() as u16).to_le_bytes());
        b.extend_from_slice(&(if m.is_dir { 0x10u16 } else { 0x20 }).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&(m.encode)(&m.name));
        b.push(0);
        b.push(0);
        out.extend_from_slice(&arj_block(&b));
        out.extend_from_slice(&packed);
    }
    out.extend_from_slice(&[0x60, 0xEA, 0, 0]);
    out
}

/// Deterministic test data: text-like runs mixed with noise, `n` bytes.
pub fn sample(n: usize, seed: u64) -> Vec<u8> {
    let words: [&[u8]; 12] = [
        b"lorem ",
        b"ipsum ",
        b"dolor ",
        b"sit ",
        b"amet, ",
        b"archive ",
        b"huffman ",
        b"window ",
        b"\n",
        b"LZH ",
        b"ARJ ",
        b"0123456789 ",
    ];
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let mut v = Vec::with_capacity(n + 16);
    while v.len() < n {
        let r = next();
        match r % 16 {
            0 => v.extend((0..(r >> 8) % 40).map(|_| next() as u8)),
            1 => v.extend(std::iter::repeat_n(
                (r >> 8) as u8,
                ((r >> 16) % 300) as usize,
            )),
            _ => v.extend_from_slice(words[((r >> 8) % 12) as usize]),
        }
    }
    v.truncate(n);
    v
}
