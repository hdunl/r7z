//! Test helpers that write WIM files: encoders for XPRESS, LZX and LZMS (greedy LZ77
//! matching with real Huffman codes, so every decoder path is exercised), and a WIM
//! builder for images with directories, alternate streams, reparse points, hard links,
//! several images, solid resources and split sets. The output was validated against
//! 7-Zip (`7z t` checks every blob's SHA-1), which proves the encoders.

#![allow(dead_code)]

pub mod lzms;
pub mod lzx;
pub mod xpress;

use sha1::{Digest, Sha1};

/// Greedy hash-chain match finder over one buffer.
pub struct Matcher {
    head: Vec<u32>,
    prev: Vec<u32>,
    pub chain: usize,
}

const HASH_BITS: u32 = 15;

impl Matcher {
    pub fn new(len: usize) -> Self {
        Matcher {
            head: vec![u32::MAX; 1 << HASH_BITS],
            prev: vec![u32::MAX; len],
            chain: 48,
        }
    }

    fn hash(d: &[u8], p: usize) -> usize {
        let v = (d[p] as u32) | ((d[p + 1] as u32) << 8) | ((d[p + 2] as u32) << 16);
        (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
    }

    pub fn insert(&mut self, d: &[u8], p: usize) {
        if p + 3 <= d.len() {
            let h = Self::hash(d, p);
            self.prev[p] = self.head[h];
            self.head[h] = p as u32;
        }
    }

    /// Longest match at `p` of at least 3 bytes within `max_dist`: `(len, dist)`.
    pub fn find(
        &self,
        d: &[u8],
        p: usize,
        max_len: usize,
        max_dist: usize,
    ) -> Option<(usize, usize)> {
        if p + 3 > d.len() {
            return None;
        }
        let max_len = max_len.min(d.len() - p);
        let mut best: Option<(usize, usize)> = None;
        let mut cand = self.head[Self::hash(d, p)];
        let mut n = 0;
        while cand != u32::MAX && n < self.chain {
            let c = cand as usize;
            if c >= p {
                break;
            }
            let dist = p - c;
            if dist > max_dist {
                break;
            }
            let l = match_len(d, c, p, max_len);
            if l >= 3 && best.is_none_or(|(bl, _)| l > bl) {
                best = Some((l, dist));
                if l == max_len {
                    break;
                }
            }
            cand = self.prev[c];
            n += 1;
        }
        best
    }
}

pub fn match_len(d: &[u8], a: usize, b: usize, max: usize) -> usize {
    let mut l = 0;
    while l < max && b + l < d.len() && d[a + l] == d[b + l] {
        l += 1;
    }
    l
}

/// Canonical codewords for lengths (shorter codes first, by symbol within a length).
pub fn canonical_codes(lens: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 17];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 17];
    let mut code = 0;
    for len in 1..17 {
        code = (code + count[len - 1]) << 1;
        next[len] = code;
    }
    // `code` above starts from count[0] == 0, so next[1] == 0.
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

/// Code lengths for frequencies, limited to `max` bits.
pub fn code_lens(freqs: &[u32], max: u32) -> Vec<u8> {
    let mut lens = vec![0u8; freqs.len()];
    r7z::codec::huffman::lengths_from_freqs(freqs, max, &mut lens);
    lens
}

pub fn sha1(d: &[u8]) -> [u8; 20] {
    Sha1::digest(d).into()
}

/// Compression of one chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Copy,
    Xpress,
    Lzx,
    Lzms,
}

impl Method {
    fn id(self) -> u32 {
        match self {
            Method::Copy => 0,
            Method::Xpress => 1,
            Method::Lzx => 2,
            Method::Lzms => 3,
        }
    }

    fn header_flag(self) -> u32 {
        match self {
            Method::Copy => 0,
            Method::Xpress => 2 | (1 << 17),
            Method::Lzx => 2 | (1 << 18),
            Method::Lzms => 2 | (1 << 19),
        }
    }

    pub fn compress(self, chunk: &[u8], bits: u32, style: u32) -> Vec<u8> {
        match self {
            Method::Copy => chunk.to_vec(),
            Method::Xpress => xpress::compress(chunk),
            Method::Lzx => lzx::compress(chunk, bits, style),
            Method::Lzms => lzms::compress(chunk),
        }
    }
}

/// One file or directory of an image.
#[derive(Clone, Debug, Default)]
pub struct Node {
    /// `/`-separated path below the image root.
    pub path: String,
    /// None for a directory.
    pub data: Option<Vec<u8>>,
    pub attrib: u32,
    /// Creation, last access, last write.
    pub times: [u64; 3],
    pub streams: Vec<(String, Vec<u8>)>,
    /// Reparse tag and data (without the 8-byte header).
    pub reparse: Option<(u32, Vec<u8>)>,
    pub link_group: u64,
}

impl Node {
    pub fn file(path: &str, data: Vec<u8>, mtime: u64) -> Self {
        Node {
            path: path.into(),
            data: Some(data),
            attrib: 0x20,
            times: [mtime - 7_000_000, mtime + 3_000_000, mtime],
            ..Node::default()
        }
    }

    pub fn dir(path: &str, mtime: u64) -> Self {
        Node {
            path: path.into(),
            data: None,
            attrib: 0x10,
            times: [mtime, mtime, mtime],
            ..Node::default()
        }
    }
}

/// How a WIM is written.
#[derive(Clone, Debug)]
pub struct Spec {
    pub images: Vec<Vec<Node>>,
    pub method: Method,
    pub chunk_bits: u32,
    /// Encoder variant (LZX block types).
    pub style: u32,
    /// Solid resources: method, chunk bits and how many resources the blobs are spread
    /// over (all in one solid group).
    pub solid: Option<(Method, u32, usize)>,
    /// Number of parts of a split set.
    pub parts: usize,
    /// Blobs no dentry references (listed as deleted by 7-Zip).
    pub orphans: Vec<Vec<u8>>,
}

impl Spec {
    pub fn new(images: Vec<Vec<Node>>, method: Method) -> Self {
        Spec {
            images,
            method,
            chunk_bits: 15,
            style: 0,
            solid: None,
            parts: 1,
            orphans: Vec::new(),
        }
    }
}

struct Blob {
    hash: [u8; 20],
    data: Vec<u8>,
    refs: u32,
}

fn reshdr(packed: u64, flags: u8, offset: u64, size: u64) -> [u8; 24] {
    let mut r = [0u8; 24];
    r[..8].copy_from_slice(&(packed | ((flags as u64) << 56)).to_le_bytes());
    r[8..16].copy_from_slice(&offset.to_le_bytes());
    r[16..].copy_from_slice(&size.to_le_bytes());
    r
}

/// A non-solid resource: chunk table plus chunks, or the raw data when compression
/// does not help. Returns (bytes, flags).
fn resource(data: &[u8], m: Method, bits: u32, style: u32) -> (Vec<u8>, u8) {
    if m == Method::Copy || data.is_empty() {
        return (data.to_vec(), 0);
    }
    let cs = 1usize << bits;
    let chunks: Vec<Vec<u8>> = data
        .chunks(cs)
        .map(|c| {
            let z = m.compress(c, bits, style);
            if z.len() >= c.len() {
                c.to_vec()
            } else {
                z
            }
        })
        .collect();
    let entry = if data.len() as u64 >= 1 << 32 { 8 } else { 4 };
    let mut out = Vec::new();
    let mut off = 0u64;
    for c in &chunks[..chunks.len() - 1] {
        off += c.len() as u64;
        if entry == 4 {
            out.extend_from_slice(&(off as u32).to_le_bytes());
        } else {
            out.extend_from_slice(&off.to_le_bytes());
        }
    }
    for c in &chunks {
        out.extend_from_slice(c);
    }
    if out.len() >= data.len() {
        return (data.to_vec(), 0);
    }
    (out, 4)
}

/// A solid resource holding `data`.
fn solid_resource(data: &[u8], m: Method, bits: u32, style: u32) -> Vec<u8> {
    let cs = 1usize << bits;
    let chunks: Vec<Vec<u8>> = data
        .chunks(cs)
        .map(|c| {
            let z = m.compress(c, bits, style);
            if z.len() >= c.len() {
                c.to_vec()
            } else {
                z
            }
        })
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&(cs as u32).to_le_bytes());
    out.extend_from_slice(&m.id().to_le_bytes());
    for c in &chunks {
        out.extend_from_slice(&(c.len() as u32).to_le_bytes());
    }
    for c in &chunks {
        out.extend_from_slice(c);
    }
    out
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// A dentry record followed by its stream entries.
fn dentry(node: &Node, name: &str, subdir: u64, hashes: &Hashes) -> Vec<u8> {
    let n = utf16(name);
    let named: Vec<&(String, Vec<u8>)> = node.streams.iter().collect();
    let base = 0x66 + if n.is_empty() { 0 } else { n.len() + 2 };
    let len = base.next_multiple_of(8);
    let mut d = vec![0u8; len];
    d[..8].copy_from_slice(&(len as u64).to_le_bytes());
    d[8..12].copy_from_slice(&node.attrib.to_le_bytes());
    d[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    d[0x10..0x18].copy_from_slice(&subdir.to_le_bytes());
    d[0x28..0x30].copy_from_slice(&node.times[0].to_le_bytes());
    d[0x30..0x38].copy_from_slice(&node.times[1].to_le_bytes());
    d[0x38..0x40].copy_from_slice(&node.times[2].to_le_bytes());
    let main = hashes.main(node);
    if named.is_empty() {
        d[0x40..0x54].copy_from_slice(&main);
    }
    match &node.reparse {
        Some((tag, _)) => d[0x58..0x5C].copy_from_slice(&tag.to_le_bytes()),
        None => d[0x58..0x60].copy_from_slice(&node.link_group.to_le_bytes()),
    }
    let extra = if named.is_empty() { 0 } else { named.len() + 1 };
    d[0x60..0x62].copy_from_slice(&(extra as u16).to_le_bytes());
    d[0x64..0x66].copy_from_slice(&(n.len() as u16).to_le_bytes());
    d[0x66..0x66 + n.len()].copy_from_slice(&n);
    if !named.is_empty() {
        d.extend(stream_entry("", &main));
        for (sname, data) in named {
            d.extend(stream_entry(sname, &hashes.of(data)));
        }
    }
    d
}

fn stream_entry(name: &str, hash: &[u8; 20]) -> Vec<u8> {
    let n = utf16(name);
    let len = (0x26 + n.len() + 2).next_multiple_of(8);
    let mut d = vec![0u8; len];
    d[..8].copy_from_slice(&(len as u64).to_le_bytes());
    d[0x10..0x24].copy_from_slice(hash);
    d[0x24..0x26].copy_from_slice(&(n.len() as u16).to_le_bytes());
    d[0x26..0x26 + n.len()].copy_from_slice(&n);
    d
}

struct Hashes;

impl Hashes {
    fn of(&self, d: &[u8]) -> [u8; 20] {
        if d.is_empty() {
            [0; 20]
        } else {
            sha1(d)
        }
    }

    fn main(&self, node: &Node) -> [u8; 20] {
        match (&node.reparse, &node.data) {
            (Some((_, r)), _) => self.of(r),
            (None, Some(d)) => self.of(d),
            (None, None) => [0; 20],
        }
    }
}

/// The metadata resource of one image: empty security data, an unnamed root and the
/// tree in breadth-first order.
fn metadata(nodes: &[Node]) -> Vec<u8> {
    // Children of each directory path ("" = root), in the given order.
    let mut kids: Vec<(String, Vec<usize>)> = vec![(String::new(), Vec::new())];
    for (i, n) in nodes.iter().enumerate() {
        let parent = n.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        if !kids.iter().any(|(p, _)| p == parent) {
            kids.push((parent.to_string(), Vec::new()));
        }
        kids.iter_mut()
            .find(|(p, _)| p == parent)
            .unwrap()
            .1
            .push(i);
    }
    let children = |p: &str| -> Vec<usize> {
        kids.iter()
            .find(|(k, _)| k == p)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let h = Hashes;
    let mut out = vec![0u8; 8];
    out[..4].copy_from_slice(&8u32.to_le_bytes());
    let root = Node::dir("", 132_000_000_000_000_000);
    // Root list, then each directory's list (BFS); subdir offsets patched afterwards.
    let root_at = out.len();
    out.extend(dentry(&root, "", 0, &h));
    out.extend([0u8; 8]);
    let mut queue: Vec<(usize, String)> = vec![(root_at, String::new())];
    let mut qi = 0;
    while qi < queue.len() {
        let (at, dir) = queue[qi].clone();
        qi += 1;
        let list = out.len() as u64;
        out[at + 0x10..at + 0x18].copy_from_slice(&list.to_le_bytes());
        for i in children(&dir) {
            let n = &nodes[i];
            let name = n.path.rsplit('/').next().unwrap();
            let rec = out.len();
            out.extend(dentry(n, name, 0, &h));
            if n.data.is_none() && n.reparse.is_none() {
                queue.push((rec, n.path.clone()));
            }
        }
        out.extend([0u8; 8]);
    }
    out
}

fn xml(spec: &Spec, total: u64) -> Vec<u8> {
    let mut s = format!("<WIM><TOTALBYTES>{total}</TOTALBYTES>");
    for (i, img) in spec.images.iter().enumerate() {
        let dirs = img.iter().filter(|n| n.data.is_none()).count();
        let files = img.len() - dirs;
        let t = 0x01DC_0000_1234_5678u64 + i as u64 * 10_000_000;
        s.push_str(&format!(
            "<IMAGE INDEX=\"{}\"><DIRCOUNT>{dirs}</DIRCOUNT><FILECOUNT>{files}</FILECOUNT>\
             <CREATIONTIME><HIGHPART>0x{:08X}</HIGHPART><LOWPART>0x{:08X}</LOWPART></CREATIONTIME>\
             <LASTMODIFICATIONTIME><HIGHPART>0x{:08X}</HIGHPART><LOWPART>0x{:08X}</LOWPART></LASTMODIFICATIONTIME>\
             <NAME>image {}</NAME></IMAGE>",
            i + 1,
            t >> 32,
            t as u32,
            (t + 5) >> 32,
            (t + 5) as u32,
            i + 1
        ));
    }
    s.push_str("</WIM>");
    let mut out = vec![0xFF, 0xFE];
    out.extend(utf16(&s));
    out
}

/// Writes the WIM (or the parts of a split set).
pub fn build(spec: &Spec) -> Vec<Vec<u8>> {
    // Unique blobs in first-use order.
    let mut blobs: Vec<Blob> = Vec::new();
    let mut add = |d: &[u8], counted: bool| {
        if d.is_empty() {
            return;
        }
        let hash = sha1(d);
        match blobs.iter_mut().find(|b| b.hash == hash) {
            Some(b) => b.refs += counted as u32,
            None => blobs.push(Blob {
                hash,
                data: d.to_vec(),
                refs: counted as u32,
            }),
        }
    };
    for img in &spec.images {
        for n in img {
            if let Some((_, r)) = &n.reparse {
                add(r, true);
            } else if let Some(d) = &n.data {
                add(d, true);
            }
            for (_, d) in &n.streams {
                add(d, true);
            }
        }
    }
    for o in &spec.orphans {
        add(o, false);
    }
    let parts = spec.parts.max(1);
    let per_part = blobs.len().div_ceil(parts).max(1);
    let total: u64 = blobs.iter().map(|b| b.data.len() as u64).sum();
    let xml = xml(spec, total);
    let flags = match spec.solid {
        Some((m, _, _)) => m.header_flag(),
        None => spec.method.header_flag(),
    };
    let meta_method = match spec.solid {
        Some((m, _, _)) => m,
        None => spec.method,
    };
    let version: u32 = if spec.solid.is_some() { 0xE00 } else { 0x10D00 };
    let mut files = Vec::new();
    let mut boot_meta = [0u8; 24];
    for part in 1..=parts {
        let mut out = vec![0u8; 0xD0];
        let mut table: Vec<u8> = Vec::new();
        let entry = |t: &mut Vec<u8>, r: [u8; 24], refs: u32, hash: &[u8; 20]| {
            t.extend_from_slice(&r);
            t.extend_from_slice(&(part as u16).to_le_bytes());
            t.extend_from_slice(&refs.to_le_bytes());
            t.extend_from_slice(hash);
        };
        let mine: Vec<&Blob> = blobs
            .iter()
            .enumerate()
            .filter(|(i, _)| i / per_part + 1 == part)
            .map(|(_, b)| b)
            .collect();
        match spec.solid {
            Some((m, bits, count)) => {
                // All blobs in one solid group spread over `count` resources.
                let count = count.max(1);
                let per = mine.len().div_ceil(count).max(1);
                let mut bigs = Vec::new();
                let mut smalls = Vec::new();
                let mut group = 0u64;
                for (k, set) in mine.chunks(per).enumerate() {
                    let mut data = Vec::new();
                    for b in set {
                        smalls.push((group + data.len() as u64, b.data.len() as u64, b));
                        data.extend_from_slice(&b.data);
                    }
                    let res = solid_resource(&data, m, bits, spec.style + k as u32);
                    bigs.push(reshdr(res.len() as u64, 0x10, out.len() as u64, 1 << 32));
                    out.extend(res);
                    group += data.len() as u64;
                }
                for r in bigs {
                    entry(&mut table, r, 1, &[0; 20]);
                }
                for (off, size, b) in smalls {
                    entry(&mut table, reshdr(size, 0x10, off, 0), b.refs, &b.hash);
                }
            }
            None => {
                for b in &mine {
                    let (res, fl) = resource(&b.data, spec.method, spec.chunk_bits, spec.style);
                    let r = reshdr(res.len() as u64, fl, out.len() as u64, b.data.len() as u64);
                    out.extend(res);
                    entry(&mut table, r, b.refs, &b.hash);
                }
            }
        }
        if part == 1 {
            for img in &spec.images {
                let meta = metadata(img);
                let (res, fl) = resource(&meta, meta_method, spec.chunk_bits, 0);
                let r = reshdr(
                    res.len() as u64,
                    fl | 2,
                    out.len() as u64,
                    meta.len() as u64,
                );
                if boot_meta == [0; 24] {
                    boot_meta = r;
                }
                out.extend(res);
                entry(&mut table, r, 1, &sha1(&meta));
            }
        }
        let lookup = reshdr(table.len() as u64, 0, out.len() as u64, table.len() as u64);
        out.extend(&table);
        let xr = reshdr(xml.len() as u64, 0, out.len() as u64, xml.len() as u64);
        out.extend(&xml);
        let hd = &mut out[..0xD0];
        hd[..8].copy_from_slice(b"MSWIM\0\0\0");
        hd[8..12].copy_from_slice(&0xD0u32.to_le_bytes());
        hd[12..16].copy_from_slice(&version.to_le_bytes());
        hd[16..20].copy_from_slice(&flags.to_le_bytes());
        let cs = if flags == 0 {
            0
        } else {
            1u32 << spec.chunk_bits
        };
        hd[20..24].copy_from_slice(&cs.to_le_bytes());
        hd[24..40].copy_from_slice(b"r7z-wim-test-gid");
        hd[40..42].copy_from_slice(&(part as u16).to_le_bytes());
        hd[42..44].copy_from_slice(&(parts as u16).to_le_bytes());
        hd[44..48].copy_from_slice(&(spec.images.len() as u32).to_le_bytes());
        hd[48..72].copy_from_slice(&lookup);
        hd[72..96].copy_from_slice(&xr);
        if part == 1 && !spec.images.is_empty() {
            hd[96..120].copy_from_slice(&boot_meta);
            hd[120..124].copy_from_slice(&1u32.to_le_bytes());
        }
        files.push(out);
    }
    files
}

/// Deterministic test data generators.
pub mod data {
    /// xorshift bytes.
    pub fn random(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    /// Text with repetition at many distances.
    pub fn text(n: usize, seed: u64) -> Vec<u8> {
        let words = [
            "wim", "image", "resource", "chunk", "huffman", "literal", "match", "offset", "length",
            "window", "solid", "lzx", "xpress", "lzms", "delta", "repeat", "the", "of", "and",
            "stream", "blob", "dentry", "lookup",
        ];
        let r = random(n, seed);
        let mut out = Vec::with_capacity(n + 16);
        let mut i = 0;
        while out.len() < n {
            let w = words[r[i % r.len()] as usize % words.len()];
            out.extend_from_slice(w.as_bytes());
            out.push(if r[(i + 1) % r.len()] % 11 == 0 {
                b'\n'
            } else {
                b' '
            });
            i += 2;
        }
        out.truncate(n);
        out
    }

    /// x86-like code: CALL/LEA/MOV instructions with repeated targets, which the LZX E8
    /// and LZMS x86 filters translate.
    pub fn x86(n: usize, seed: u64) -> Vec<u8> {
        let r = random(n, seed);
        let mut out = Vec::with_capacity(n + 16);
        let mut i = 0;
        while out.len() < n {
            let pos = out.len() as i32;
            let target = (r[i % n] as i32 % 16) * 64 + 0x1000;
            match r[(i + 1) % n] % 5 {
                0 | 1 => {
                    out.push(0xE8);
                    out.extend_from_slice(&(target - pos - 5).to_le_bytes());
                }
                2 => {
                    out.extend_from_slice(&[0x48, 0x8D, 0x05]);
                    out.extend_from_slice(&(target - pos - 7).to_le_bytes());
                }
                3 => {
                    out.extend_from_slice(&[0xFF, 0x15]);
                    out.extend_from_slice(&(target - pos - 6).to_le_bytes());
                }
                _ => out.extend_from_slice(&[0x55, 0x89, 0xE5, 0x90, r[i % n]]),
            }
            i += 2;
        }
        out.truncate(n);
        out
    }

    /// 16-bit samples: smooth curves that LZMS delta matches compress.
    pub fn samples(n: usize, seed: u64) -> Vec<u8> {
        let r = random(64, seed);
        (0..n)
            .map(|i| {
                let k = i / 2;
                let v = (k as u32 * 3 + (k as u32 / 50) * (r[k % 64] as u32 % 3)) as u16;
                if i % 2 == 0 {
                    v as u8
                } else {
                    (v >> 8) as u8
                }
            })
            .collect()
    }
}
