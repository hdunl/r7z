//! CHM reading: archives made by a small CHM writer in this file (ITSF header, ITSP
//! directory with PMGL and PMGI chunks, a stored section, and an LZX section with its LZXC
//! control data and reset table), a committed fixture, 7-Zip as a cross-check when it is
//! installed, the system's own help files when present, and damaged inputs.
//!
//! The LZX encoder here writes the CAB/CHM bitstream (a 24-bit block length and the E8
//! header bit, unlike the WIM variant in `wimkit`), one block per 32 KiB frame, with
//! verbatim, aligned and uncompressed blocks, and a fresh state at every reset interval.

mod wimkit;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use r7z::format::{self, Archive, Ctx, Flow, OpenRequest, Opened};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Target};
use r7z::Error;
use wimkit::{canonical_codes, code_lens, data, match_len, Matcher};

const FRAME: usize = 0x8000;
const E8_SIZE: i32 = 12_000_000;
const LZX_GUID: &str = "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}";
const STORAGE: &str = "::DataSpace/Storage/MSCompressed/";

// ------------------------------------------------------------------ LZX encoder

struct Bits {
    out: Vec<u8>,
    buf: u64,
    count: u32,
}

impl Bits {
    fn new() -> Self {
        Bits {
            out: Vec::new(),
            buf: 0,
            count: 0,
        }
    }

    fn put(&mut self, v: u32, n: u32) {
        if n == 0 {
            return;
        }
        self.buf = (self.buf << n) | (u64::from(v) & ((1u64 << n) - 1));
        self.count += n;
        while self.count >= 16 {
            self.count -= 16;
            let w = (self.buf >> self.count) as u16;
            self.out.extend_from_slice(&w.to_le_bytes());
        }
    }

    /// Pads to the next 16-bit boundary with 1 to 16 zero bits.
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

/// Window position slots: base offsets, extra bits, slot count and the longest distance.
struct Lz {
    base: [u32; 50],
    extra: [u32; 50],
    slots: usize,
    max_dist: usize,
}

impl Lz {
    fn new(window_bits: u32) -> Lz {
        let (mut base, mut extra) = ([0u32; 50], [0u32; 50]);
        let mut b = 0u32;
        for (i, (bs, ex)) in base.iter_mut().zip(extra.iter_mut()).enumerate() {
            *ex = if i < 4 { 0 } else { (i as u32 / 2 - 1).min(17) };
            *bs = b;
            b += 1 << *ex;
        }
        let slots = if window_bits < 20 {
            2 * window_bits as usize
        } else {
            2 * (17 + (1usize << (window_bits - 18)))
        };
        Lz {
            base,
            extra,
            slots,
            max_dist: (1usize << window_bits) - 3,
        }
    }
}

#[derive(Clone, Copy)]
enum Tok {
    Lit(u8),
    Match {
        len: usize,
        slot: usize,
        extra: u32,
        bits: u32,
    },
}

/// Greedy parse of `d[start..end]` with repeat offsets; matches stay inside the frame.
fn tokenize(
    d: &[u8],
    (start, end): (usize, usize),
    m: &mut Matcher,
    reps: &mut [usize; 3],
    lz: &Lz,
) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut p = start;
    while p < end {
        let max_len = 257.min(end - p);
        let mut best: Option<(usize, usize)> = None;
        for (k, &r) in reps.iter().enumerate() {
            if r <= p {
                let l = match_len(d, p - r, p, max_len);
                if l >= 2 && best.is_none_or(|(bl, _)| l > bl) {
                    best = Some((l, k));
                }
            }
        }
        let found = m.find(d, p, max_len, lz.max_dist.min(p));
        let (len, tok) = match (best, found) {
            (Some((rl, k)), f) if f.is_none_or(|(fl, _)| fl < rl + 2) => {
                reps.swap(0, k);
                (
                    rl,
                    Tok::Match {
                        len: rl,
                        slot: k,
                        extra: 0,
                        bits: 0,
                    },
                )
            }
            (_, Some((fl, dist))) => {
                let formatted = dist as u32 + 2;
                let slot = (0..lz.slots)
                    .rev()
                    .find(|&s| lz.base[s] <= formatted)
                    .unwrap();
                *reps = [dist, reps[0], reps[1]];
                (
                    fl,
                    Tok::Match {
                        len: fl,
                        slot,
                        extra: formatted - lz.base[slot],
                        bits: lz.extra[slot],
                    },
                )
            }
            _ => (1, Tok::Lit(d[p])),
        };
        for k in p..p + len {
            m.insert(d, k);
        }
        toks.push(tok);
        p += len;
    }
    toks
}

/// Writes delta-coded tree lengths `new` (against `prev`) through a pretree.
fn write_lens(bits: &mut Bits, prev: &[u8], new: &[u8]) {
    // (pretree symbol, extra value, extra bit count, optional second symbol)
    let mut syms: Vec<(u32, u32, u32, Option<u32>)> = Vec::new();
    let delta = |i: usize, v: u8| (u32::from(prev[i]) + 17 - u32::from(v)) % 17;
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
        bits.put(u32::from(l), 4);
    }
    for (s, v, n, t) in syms {
        bits.put(codes[s as usize], u32::from(lens[s as usize]));
        bits.put(v, n);
        if let Some(t) = t {
            bits.put(codes[t as usize], u32::from(lens[t as usize]));
        }
    }
}

/// Tree lengths of the previous compressed block, which the next one codes deltas of.
struct Trees {
    main: Vec<u8>,
    length: Vec<u8>,
}

/// One verbatim or aligned block body: trees, then the symbols.
fn compressed_block(bits: &mut Bits, toks: &[Tok], aligned: bool, lz: &Lz, tr: &mut Trees) {
    let main_syms = 256 + 8 * lz.slots;
    let mut fm = vec![0u32; main_syms];
    let mut fl = vec![0u32; 249];
    let mut fa = [0u32; 8];
    for t in toks {
        match *t {
            Tok::Lit(b) => fm[b as usize] += 1,
            Tok::Match {
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
    // A length tree with no used symbol is sent as all zeros.
    let ll = if fl.iter().all(|&f| f == 0) {
        vec![0u8; 249]
    } else {
        code_lens(&fl, 16)
    };
    let la = code_lens(&fa, 7);
    let (cm, cl, ca) = (
        canonical_codes(&lm),
        canonical_codes(&ll),
        canonical_codes(&la),
    );
    if aligned {
        for &l in &la {
            bits.put(u32::from(l), 3);
        }
    }
    write_lens(bits, &tr.main[..256], &lm[..256]);
    write_lens(bits, &tr.main[256..], &lm[256..]);
    write_lens(bits, &tr.length, &ll);
    tr.main = lm.clone();
    tr.length = ll.clone();
    for t in toks {
        match *t {
            Tok::Lit(b) => bits.put(cm[b as usize], u32::from(lm[b as usize])),
            Tok::Match {
                len,
                slot,
                extra,
                bits: n,
            } => {
                let s = 256 + slot * 8 + (len - 2).min(7);
                bits.put(cm[s], u32::from(lm[s]));
                if len - 2 >= 7 {
                    bits.put(cl[len - 9], u32::from(ll[len - 9]));
                }
                if aligned && n >= 3 {
                    bits.put(extra >> 3, n - 3);
                    let a = (extra & 7) as usize;
                    bits.put(ca[a], u32::from(la[a]));
                } else {
                    bits.put(extra, n);
                }
            }
        }
    }
}

/// The encoder's E8 (x86 CALL) translation of one frame, whose first byte is at `base` in
/// the reset interval.
fn e8_translate(f: &mut [u8], base: usize) {
    if f.len() <= 10 {
        return;
    }
    let mut i = 0;
    while i < f.len() - 10 {
        if f[i] != 0xE8 {
            i += 1;
            continue;
        }
        let rel = i32::from_le_bytes([f[i + 1], f[i + 2], f[i + 3], f[i + 4]]);
        let cur = (base + i) as i32;
        if rel >= -cur && rel < E8_SIZE {
            let abs = if rel < E8_SIZE - cur {
                rel + cur
            } else {
                rel - E8_SIZE
            };
            f[i + 1..i + 5].copy_from_slice(&abs.to_le_bytes());
        }
        i += 5;
    }
}

#[derive(Clone, Copy)]
struct LzxStyle {
    /// 0: one verbatim block per frame, 1: one aligned block, 2: several blocks per frame of
    /// all three kinds, uncompressed ones included.
    blocks: u32,
    /// E8 translation on (the header bit and size are sent).
    e8: bool,
    /// The last frame of the section is coded as a whole zero-padded 32 KiB, as Microsoft's
    /// compressor does and 7-Zip requires, instead of at its true size.
    pad_last: bool,
}

/// The blocks of one frame as `(size, kind)`: kind 1 is verbatim, 2 aligned and 3
/// uncompressed. Style 2 cuts frames into several blocks of different kinds.
fn frame_blocks(style: u32, frame_no: usize, size: usize) -> Vec<(usize, u32)> {
    let plan: &[(usize, u32)] = match style {
        0 => &[(usize::MAX, 1)],
        1 => &[(usize::MAX, 2)],
        _ if frame_no.is_multiple_of(2) => &[(1001, 3), (6000, 2), (usize::MAX, 1)],
        _ => &[(4000, 1), (801, 3), (usize::MAX, 2)],
    };
    let mut left = size;
    let mut out = Vec::new();
    for &(n, kind) in plan {
        let n = n.min(left);
        if n == 0 {
            break;
        }
        out.push((n, kind));
        left -= n;
    }
    out
}

/// Compresses one reset interval into its frames (one byte vector each). `first_frame` is
/// the interval's first frame number in the section, which picks the block types.
fn lzx_interval(
    data: &[u8],
    first_frame: usize,
    window_bits: u32,
    style: LzxStyle,
    pad_last: bool,
) -> Vec<Vec<u8>> {
    let mut d = data.to_vec();
    if pad_last && !d.len().is_multiple_of(FRAME) {
        d.resize(d.len().next_multiple_of(FRAME), 0);
    }
    if style.e8 {
        for (k, f) in d.chunks_mut(FRAME).enumerate() {
            e8_translate(f, k * FRAME);
        }
    }
    let lz = Lz::new(window_bits);
    let mut m = Matcher::new(d.len());
    let mut reps = [1usize; 3];
    let mut trees = Trees {
        main: vec![0; 256 + 8 * lz.slots],
        length: vec![0; 249],
    };
    let mut frames = Vec::new();
    for (k, start) in (0..d.len()).step_by(FRAME).enumerate() {
        let end = (start + FRAME).min(d.len());
        let mut bits = Bits::new();
        if k == 0 {
            if style.e8 {
                bits.put(1, 1);
                bits.put((E8_SIZE >> 16) as u32, 16);
                bits.put((E8_SIZE & 0xFFFF) as u32, 16);
            } else {
                bits.put(0, 1);
            }
        }
        let mut at = start;
        for (size, kind) in frame_blocks(style.blocks, first_frame + k, end - start) {
            let toks = tokenize(&d, (at, at + size), &mut m, &mut reps, &lz);
            bits.put(kind, 3);
            bits.put((size >> 8) as u32, 16);
            bits.put((size & 0xFF) as u32, 8);
            if kind == 3 {
                // The repeat offsets the decoder carries on with after the block.
                bits.align();
                for r in reps {
                    bits.out.extend_from_slice(&(r as u32).to_le_bytes());
                }
                bits.out.extend_from_slice(&d[at..at + size]);
                if size % 2 == 1 {
                    bits.out.push(0);
                }
            } else {
                compressed_block(&mut bits, &toks, kind == 2, &lz, &mut trees);
            }
            at += size;
        }
        bits.flush();
        frames.push(bits.out);
    }
    frames
}

// ------------------------------------------------------------------ CHM writer

#[derive(Clone)]
struct Source {
    path: String,
    data: Vec<u8>,
    packed: bool,
}

fn stored(path: &str, data: Vec<u8>) -> Source {
    Source {
        path: path.into(),
        data,
        packed: false,
    }
}

fn packed(path: &str, data: Vec<u8>) -> Source {
    Source {
        path: path.into(),
        data,
        packed: true,
    }
}

#[derive(Clone)]
struct Spec {
    /// ITSF version, 2 or 3.
    version: u32,
    window_bits: u32,
    /// Frames between decoder resets.
    interval: u32,
    style: LzxStyle,
    /// LZXC control data version 1 (sizes in bytes) instead of 2 (32 KiB units).
    ctl_v1: bool,
    /// Directory chunk size.
    chunk: usize,
    /// The transform GUID of the compressed section.
    guid: String,
    /// The directory comes after the content, as in 7-zip.chm.
    dir_last: bool,
    /// Section 0 offsets are file offsets and the header's content offset is 0, as in
    /// 7-zip.chm.
    zero_base: bool,
    dirs: Vec<String>,
    files: Vec<Source>,
    /// Directory entries added as given: name, section, offset, length.
    extra: Vec<(String, u64, u64, u64)>,
}

impl Spec {
    fn new() -> Spec {
        Spec {
            version: 3,
            window_bits: 16,
            interval: 2,
            style: LzxStyle {
                blocks: 0,
                e8: false,
                pad_last: true,
            },
            ctl_v1: false,
            chunk: 0x1000,
            guid: LZX_GUID.into(),
            dir_last: false,
            zero_base: false,
            dirs: Vec::new(),
            files: Vec::new(),
            extra: Vec::new(),
        }
    }

    fn interval_bytes(&self) -> u64 {
        u64::from(self.interval) * FRAME as u64
    }
}

/// A listed file or directory, in directory order, with the bytes it should extract to.
struct Item {
    name: String,
    is_dir: bool,
    section: u64,
    offset: u64,
    data: Vec<u8>,
}

struct Built {
    bytes: Vec<u8>,
    items: Vec<Item>,
    /// File offsets of the control data, reset table, content and name list.
    parts: BTreeMap<&'static str, usize>,
}

/// A directory entry before layout.
struct Dirent {
    name: String,
    section: u64,
    offset: u64,
    len: u64,
    data: Vec<u8>,
}

fn encint(mut v: u64) -> Vec<u8> {
    let mut b = vec![(v & 0x7F) as u8];
    v >>= 7;
    while v > 0 {
        b.push((v & 0x7F) as u8 | 0x80);
        v >>= 7;
    }
    b.reverse();
    b
}

fn le32(out: &mut Vec<u8>, vals: &[u32]) {
    for v in vals {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn le64(out: &mut Vec<u8>, vals: &[u64]) {
    for v in vals {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// The ITSP header and its chunks: PMGL listing chunks, and a PMGI index when there are
/// several.
fn directory(entries: &[(&str, u64, u64, u64)], chunk: usize) -> Vec<u8> {
    const PMGL: usize = 0x14;
    // (entry bytes, offset of each entry, first name)
    let mut listing: Vec<(Vec<u8>, Vec<u16>, String)> = Vec::new();
    let (mut body, mut offs, mut first): (Vec<u8>, Vec<u16>, String) =
        (Vec::new(), Vec::new(), String::new());
    for &(name, section, offset, len) in entries {
        let mut e = encint(name.len() as u64);
        e.extend_from_slice(name.as_bytes());
        e.extend(encint(section));
        e.extend(encint(offset));
        e.extend(encint(len));
        let quickref = |n: usize| 2 + 2 * n.div_ceil(4);
        if !offs.is_empty() && PMGL + body.len() + e.len() + quickref(offs.len() + 1) > chunk {
            listing.push((
                std::mem::take(&mut body),
                std::mem::take(&mut offs),
                std::mem::take(&mut first),
            ));
        }
        assert!(
            PMGL + body.len() + e.len() + quickref(offs.len() + 1) <= chunk,
            "entry {name} does not fit a chunk"
        );
        if offs.is_empty() {
            first = name.to_string();
        }
        offs.push((PMGL + body.len()) as u16);
        body.extend(e);
    }
    if !offs.is_empty() {
        listing.push((body, offs, first));
    }
    let mut chunks: Vec<u8> = Vec::new();
    let count = listing.len();
    for (n, (body, offs, _)) in listing.iter().enumerate() {
        let mut c = b"PMGL".to_vec();
        le32(&mut c, &[(chunk - PMGL - body.len()) as u32, 0]);
        c.extend_from_slice(&(if n == 0 { -1i32 } else { n as i32 - 1 }).to_le_bytes());
        c.extend_from_slice(&(if n + 1 == count { -1i32 } else { n as i32 + 1 }).to_le_bytes());
        c.extend_from_slice(body);
        let refs: Vec<u16> = offs.iter().copied().step_by(4).collect();
        c.resize(chunk - 2 * refs.len() - 2, 0);
        for r in refs.iter().rev() {
            c.extend_from_slice(&r.to_le_bytes());
        }
        c.extend_from_slice(&(offs.len() as u16).to_le_bytes());
        assert_eq!(c.len(), chunk);
        chunks.extend(c);
    }
    let multi = count > 1;
    if multi {
        let mut body = Vec::new();
        for (n, (_, _, first)) in listing.iter().enumerate() {
            body.extend(encint(first.len() as u64));
            body.extend_from_slice(first.as_bytes());
            body.extend(encint(n as u64));
        }
        let mut c = b"PMGI".to_vec();
        le32(&mut c, &[(chunk - 8 - body.len()) as u32]);
        c.extend(body);
        assert!(c.len() + 2 <= chunk, "index does not fit a chunk");
        c.resize(chunk - 2, 0);
        c.extend_from_slice(&(count as u16).to_le_bytes());
        chunks.extend(c);
    }
    let mut h = b"ITSP".to_vec();
    le32(
        &mut h,
        &[1, 0x54, 0x0A, chunk as u32, 2, if multi { 2 } else { 1 }],
    );
    h.extend_from_slice(&(if multi { count as i32 } else { -1 }).to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes());
    h.extend_from_slice(&(count as i32 - 1).to_le_bytes());
    h.extend_from_slice(&(-1i32).to_le_bytes());
    le32(&mut h, &[count as u32 + multi as u32, 0x409]);
    h.extend_from_slice(&[
        0x6A, 0x92, 0x02, 0x5D, 0x2E, 0x21, 0xD0, 0x11, 0x9D, 0xF9, 0x00, 0xA0, 0xC9, 0x22, 0xE6,
        0xEC,
    ]);
    le32(&mut h, &[0x54]);
    for _ in 0..3 {
        h.extend_from_slice(&(-1i32).to_le_bytes());
    }
    assert_eq!(h.len(), 0x54);
    h.extend(chunks);
    h
}

/// Appends a section 0 file and its directory entry.
fn add_meta(
    sec0: &mut Vec<u8>,
    dir: &mut Vec<Dirent>,
    name: String,
    bytes: Vec<u8>,
) -> (usize, usize) {
    let at = (sec0.len(), bytes.len());
    sec0.extend_from_slice(&bytes);
    dir.push(Dirent {
        name,
        section: 0,
        offset: at.0 as u64,
        len: at.1 as u64,
        data: Vec::new(),
    });
    at
}

fn build(spec: &Spec) -> Built {
    let mut sec0: Vec<u8> = Vec::new();
    let mut stream: Vec<u8> = Vec::new();
    let mut dir: Vec<Dirent> = vec![Dirent {
        name: "/".into(),
        section: 0,
        offset: 0,
        len: 0,
        data: Vec::new(),
    }];
    for d in &spec.dirs {
        dir.push(Dirent {
            name: format!("/{d}/"),
            section: 0,
            offset: 0,
            len: 0,
            data: Vec::new(),
        });
    }
    for f in &spec.files {
        let (section, offset) = if f.packed {
            (1, stream.len())
        } else {
            (0, sec0.len())
        };
        dir.push(Dirent {
            name: format!("/{}", f.path),
            section,
            offset: offset as u64,
            len: f.data.len() as u64,
            data: f.data.clone(),
        });
        if f.packed {
            stream.extend_from_slice(&f.data);
        } else {
            sec0.extend_from_slice(&f.data);
        }
    }
    for (name, section, offset, len) in &spec.extra {
        dir.push(Dirent {
            name: name.clone(),
            section: *section,
            offset: *offset,
            len: *len,
            data: Vec::new(),
        });
    }

    let mut meta: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    if spec.files.iter().any(|f| f.packed) {
        let mut content = Vec::new();
        let mut frame_at: Vec<u64> = Vec::new();
        let parts: Vec<&[u8]> = stream.chunks(spec.interval_bytes() as usize).collect();
        let mut frame_no = 0;
        for (n, part) in parts.iter().enumerate() {
            let last = n + 1 == parts.len();
            let pad = last && spec.style.pad_last;
            for f in lzx_interval(part, frame_no, spec.window_bits, spec.style, pad) {
                frame_at.push(content.len() as u64);
                content.extend_from_slice(&f);
                frame_no += 1;
            }
        }
        let mut rt = Vec::new();
        le32(&mut rt, &[2, frame_at.len() as u32, 8, 0x28]);
        le64(
            &mut rt,
            &[stream.len() as u64, content.len() as u64, FRAME as u64],
        );
        le64(&mut rt, &frame_at);
        let unit = if spec.ctl_v1 { 1 } else { FRAME as u64 };
        let mut ctl = Vec::new();
        le32(
            &mut ctl,
            &[
                6,
                u32::from_le_bytes(*b"LZXC"),
                if spec.ctl_v1 { 1 } else { 2 },
                (spec.interval_bytes() / unit) as u32,
                ((1u64 << spec.window_bits) / unit) as u32,
                1,
                0,
            ],
        );
        // Two names: "Uncompressed" and "MSCompressed".
        let mut names = Vec::new();
        names.extend_from_slice(&30u16.to_le_bytes());
        names.extend_from_slice(&2u16.to_le_bytes());
        for n in ["Uncompressed", "MSCompressed"] {
            names.extend_from_slice(&(n.len() as u16).to_le_bytes());
            names.extend(n.encode_utf16().flat_map(u16::to_le_bytes));
            names.extend_from_slice(&0u16.to_le_bytes());
        }
        // Microsoft's writer stores only the first 19 characters of the GUID here.
        let list: Vec<u8> = LZX_GUID
            .encode_utf16()
            .take(19)
            .flat_map(u16::to_le_bytes)
            .collect();
        let transform = format!("{STORAGE}Transform/{}/InstanceData/", spec.guid);
        let mut put = |key: &'static str, name: String, bytes: Vec<u8>| {
            let at = add_meta(&mut sec0, &mut dir, name, bytes);
            meta.insert(key, at);
        };
        put("namelist", "::DataSpace/NameList".into(), names);
        put("list", format!("{STORAGE}Transform/List"), list);
        put(
            "span",
            format!("{STORAGE}SpanInfo"),
            (stream.len() as u64).to_le_bytes().to_vec(),
        );
        put("control", format!("{STORAGE}ControlData"), ctl);
        put("content", format!("{STORAGE}Content"), content);
        put("reset", format!("{transform}ResetTable"), rt);
        dir.push(Dirent {
            name: transform,
            section: 0,
            offset: 0,
            len: 0,
            data: Vec::new(),
        });
    }
    dir.sort_by_key(|e| e.name.to_ascii_lowercase());

    // Lay the file out. Offsets in the directory depend on where section 0 starts, which
    // depends on the directory's size, which is the same for any offsets as long as the
    // chunk count is.
    let header = if spec.version >= 3 { 0x60 } else { 0x58 };
    let make_dir = |shift: u64| {
        let entries: Vec<(&str, u64, u64, u64)> = dir
            .iter()
            .map(|e| {
                let moved = if e.section == 0 && !e.name.ends_with('/') {
                    shift
                } else {
                    0
                };
                (e.name.as_str(), e.section, e.offset + moved, e.len)
            })
            .collect();
        directory(&entries, spec.chunk)
    };
    let dir_len = make_dir(0).len();
    let (dir_off, data_start) = if spec.dir_last {
        (header + 0x18 + sec0.len(), header + 0x18)
    } else {
        (header + 0x18, header + 0x18 + dir_len)
    };
    let dir_bytes = make_dir(if spec.zero_base { data_start as u64 } else { 0 });
    assert_eq!(
        dir_bytes.len(),
        dir_len,
        "directory size changed with offsets"
    );
    let total = header + 0x18 + dir_len + sec0.len();

    let mut f = b"ITSF".to_vec();
    le32(
        &mut f,
        &[spec.version, header as u32, 1, 0x5A96_A85B, 0x409],
    );
    f.extend_from_slice(&[
        0x10, 0xFD, 0x01, 0x7C, 0xAA, 0x7B, 0xD0, 0x11, 0x9E, 0x0C, 0x00, 0xA0, 0xC9, 0x22, 0xE6,
        0xEC, 0x11, 0xFD, 0x01, 0x7C, 0xAA, 0x7B, 0xD0, 0x11, 0x9E, 0x0C, 0x00, 0xA0, 0xC9, 0x22,
        0xE6, 0xEC,
    ]);
    le64(
        &mut f,
        &[header as u64, 0x18, dir_off as u64, dir_len as u64],
    );
    if spec.version >= 3 {
        le64(
            &mut f,
            &[if spec.zero_base { 0 } else { data_start as u64 }],
        );
    }
    assert_eq!(f.len(), header);
    le32(&mut f, &[0x1FE, 0]);
    le64(&mut f, &[total as u64]);
    le32(&mut f, &[0, 0]);
    if spec.dir_last {
        f.extend_from_slice(&sec0);
        f.extend_from_slice(&dir_bytes);
    } else {
        f.extend_from_slice(&dir_bytes);
        f.extend_from_slice(&sec0);
    }
    assert_eq!(f.len(), total);

    let mut parts: BTreeMap<&'static str, usize> =
        meta.iter().map(|(k, v)| (*k, data_start + v.0)).collect();
    parts.insert("itsp", dir_off);
    let items = dir
        .into_iter()
        .filter(|e| e.name.len() > 1 && e.name.starts_with('/'))
        .map(|e| Item {
            is_dir: e.name.ends_with('/'),
            name: e.name.trim_matches('/').to_string(),
            section: e.section,
            offset: e.offset,
            data: e.data,
        })
        .collect();
    Built {
        bytes: f,
        items,
        parts,
    }
}

// ------------------------------------------------------------------ checking

struct Quiet;
impl Callbacks for Quiet {}

/// `(name, is_dir, size, method, block)` as `l -slt` shows an entry.
type Row = (String, bool, u64, String, String);

fn rows(a: &dyn Archive) -> Vec<Row> {
    a.entries()
        .iter()
        .map(|e| {
            (
                e.name.clone(),
                e.is_dir,
                e.size_or_zero(),
                e.method.clone().unwrap_or_default(),
                e.block.map(|b| b.to_string()).unwrap_or_default(),
            )
        })
        .collect()
}

/// 7-Zip's listing order and columns for what `build` wrote: directories first, then
/// files by section, offset and size.
fn expected_rows(b: &Built, spec: &Spec) -> Vec<Row> {
    let mut v: Vec<(usize, &Item)> = b.items.iter().enumerate().collect();
    v.sort_by_key(|(i, it)| (!it.is_dir, it.section, it.offset, it.data.len(), *i));
    v.into_iter()
        .map(|(_, it)| {
            let (method, block) = match (it.is_dir, it.section) {
                (true, _) => (String::new(), String::new()),
                (false, 0) => ("Copy".into(), String::new()),
                (false, _) => (
                    format!("LZX:{}", spec.window_bits),
                    (it.offset / spec.interval_bytes()).to_string(),
                ),
            };
            (
                it.name.clone(),
                it.is_dir,
                it.data.len() as u64,
                method,
                block,
            )
        })
        .collect()
}

fn open(bytes: &[u8]) -> Opened {
    format::open_bytes(bytes.to_vec(), "x.chm", &OpenRequest::default())
        .unwrap_or_else(|e| panic!("open: {e}"))
}

/// Decodes every unit through the handler contract.
fn contents(a: &dyn Archive) -> r7z::Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for u in 0..a.units().len() {
        a.extract_unit(u, &Ctx::default(), &mut |i, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            out.insert(a.entries()[i].name.clone(), v);
            Ok(Flow::Continue)
        })?;
    }
    Ok(out)
}

fn test_archive(a: &dyn Archive) -> r7z::Result<usize> {
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 1,
        target: Target::Test,
        selected: None,
    };
    let rep = extract(a, &opts, &Quiet)?;
    match rep.errors.into_iter().next() {
        Some((_, e)) => Err(e),
        None => Ok(rep.files as usize),
    }
}

/// Opens `b` and checks the listing, the extracted bytes and the unit layout.
fn check(b: &Built, spec: &Spec) {
    let o = open(&b.bytes);
    let a = o.archive();
    assert_eq!(a.format().name, "Chm");
    assert_eq!(rows(a), expected_rows(b, spec));
    let want: BTreeMap<String, Vec<u8>> = b
        .items
        .iter()
        .filter(|it| !it.is_dir && !it.data.is_empty())
        .map(|it| (it.name.clone(), it.data.clone()))
        .collect();
    let got = contents(a).unwrap();
    assert_eq!(got.len(), want.len());
    for (name, data) in &want {
        assert!(got[name] == *data, "{name}: extracted bytes differ");
    }
    // Every file with data is in exactly one unit, in offset order.
    let mut seen = vec![0; a.entries().len()];
    for u in a.units() {
        let offsets: Vec<(u64, u64)> = u
            .entries
            .iter()
            .map(|&i| {
                seen[i] += 1;
                let it = b.items.iter().find(|it| it.name == a.entries()[i].name);
                it.map_or((0, 0), |it| (it.offset, it.data.len() as u64))
            })
            .collect();
        assert!(offsets.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0));
    }
    for (i, e) in a.entries().iter().enumerate() {
        let has_data = !e.is_dir && e.size_or_zero() > 0;
        assert_eq!(seen[i], has_data as usize, "{}", e.name);
    }
    let files = a.entries().iter().filter(|e| !e.is_dir).count();
    assert_eq!(test_archive(a).unwrap(), files);
    assert_eq!(
        a.properties(),
        vec![("Physical Size", b.bytes.len().to_string())]
    );
}

fn html(n: usize, seed: u32) -> Vec<u8> {
    let mut s = String::from("<html><head><title>page</title></head><body><table>\n");
    let mut i = 0u32;
    while s.len() < n {
        s += &format!(
            "<tr><td>row {}</td><td>{:03x}</td></tr>\n",
            (i * 7 + seed) % 40,
            (i * 13 + seed) % 97
        );
        i += 1;
    }
    s.truncate(n);
    s.into_bytes()
}

/// Text made of a few repeated lines, in a pattern the seed picks: it compresses to a
/// small fraction of its size but still needs matches of many lengths and distances.
fn filler(n: usize, seed: usize) -> Vec<u8> {
    let lines = [
        "<p>The quick brown fox jumps over the lazy dog.</p>
",
        "<p>Pack my box with five dozen liquor jugs.</p>
",
        "<li><a href=\"index.htm\">Back to the index</a></li>
",
        "<p>How vexingly quick daft zebras jump!</p>
",
        "<hr>
",
    ];
    let mut out = Vec::with_capacity(n + 64);
    let mut i = seed;
    while out.len() < n {
        out.extend_from_slice(lines[(i * i / 7 + i / 3 + seed) % lines.len()].as_bytes());
        i += 1;
    }
    out.truncate(n);
    out
}

fn sample() -> Spec {
    let mut s = Spec::new();
    s.dirs = ["a", "a/b", "img", "z"].map(String::from).to_vec();
    s.files = vec![
        stored("#SYSTEM", data::random(300, 1)),
        stored("#ITBITS", Vec::new()),
        stored("readme.txt", data::text(1000, 2)),
        packed("index.htm", data::text(5000, 3)),
        packed("a/b/page.htm", html(40000, 4)),
        packed("img/logo.bin", data::random(70000, 5)),
        packed("prog.exe", data::x86(20000, 6)),
        packed("empty.txt", Vec::new()),
        packed("z/zeros.dat", vec![0; 100_000]),
    ];
    s
}

// ------------------------------------------------------------------ tests

#[test]
fn stored_and_compressed_files_round_trip() {
    let spec = sample();
    let b = build(&spec);
    check(&b, &spec);
    let rows = rows(open(&b.bytes).archive());
    // Directories first in directory order, then section 0 files, then LZX ones by offset.
    let names: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        names[..4],
        ["a", "a/b", "img", "z"],
        "directories come first"
    );
    assert_eq!(
        names[4..7],
        ["#SYSTEM", "#ITBITS", "readme.txt"],
        "stored files by offset"
    );
    assert_eq!(rows[4].3, "Copy");
    assert_eq!(rows[7].3, "LZX:16");
    assert_eq!(rows[7].4, "0");
}

#[test]
fn windows_intervals_and_block_styles_decode() {
    let files = vec![
        stored("#SYSTEM", data::random(100, 9)),
        packed("t.htm", html(50_000, 3)),
        packed("p.exe", data::x86(30_000, 8)),
        packed("odd.bin", data::text(32_769, 4)),
        packed("tail.txt", html(12_345, 5)),
    ];
    let mut n = 0u32;
    for window_bits in 15..=21 {
        for interval in [1u32, 2, 3] {
            let mut spec = Spec::new();
            spec.window_bits = window_bits;
            spec.interval = interval;
            spec.version = if n.is_multiple_of(2) { 3 } else { 2 };
            spec.ctl_v1 = n.is_multiple_of(5);
            spec.style = LzxStyle {
                blocks: n % 3,
                e8: n % 4 < 2,
                pad_last: n.is_multiple_of(2),
            };
            spec.files = files.clone();
            n += 1;
            let b = build(&spec);
            check(&b, &spec);
        }
    }
}

#[test]
fn zero_base_and_directory_last_layout_of_7_zip_chm() {
    let mut spec = sample();
    spec.dir_last = true;
    spec.zero_base = true;
    spec.chunk = 0x2000;
    check(&build(&spec), &spec);
    // Each alone.
    spec.zero_base = false;
    check(&build(&spec), &spec);
    spec.dir_last = false;
    spec.zero_base = true;
    check(&build(&spec), &spec);
}

#[test]
fn directory_spread_over_several_chunks_with_an_index() {
    let mut spec = Spec::new();
    for i in 0..60 {
        spec.files.push(packed(
            &format!("section{}/page-{i:03}.htm", i % 5),
            html(300 + i * 7, i as u32),
        ));
        if i % 3 == 0 {
            spec.files.push(stored(
                &format!("raw{i}.dat"),
                data::random(50 + i, i as u64),
            ));
        }
    }
    spec.dirs = (0..5).map(|i| format!("section{i}")).collect();
    spec.chunk = 0x200;
    let b = build(&spec);
    // Several listing chunks and one index chunk.
    let itsp = b.parts["itsp"];
    let chunks = u32::from_le_bytes(b.bytes[itsp + 0x2C..itsp + 0x30].try_into().unwrap());
    assert!(chunks > 3, "{chunks} chunks");
    assert_eq!(
        b.bytes[itsp + 0x54 + (chunks as usize - 1) * 0x200..][..4],
        *b"PMGI"
    );
    check(&b, &spec);
}

#[test]
fn files_that_start_in_one_reset_interval_form_one_unit() {
    // Reset intervals of two frames (64 KiB). Files end on interval boundaries at a, b and
    // d, so each of those is the last file of its unit.
    let iv = 2 * FRAME;
    let mut spec = Spec::new();
    spec.files = vec![
        packed("a", data::text(iv, 1)),
        packed("b", data::text(iv, 2)),
        packed("c", data::text(100, 3)),
        packed("d", data::text(iv - 100, 4)),
        packed("e", data::text(10, 5)),
        packed("f", data::text(100, 6)),
        packed("g", data::text(iv, 7)),
        packed("h", data::text(100, 8)),
    ];
    let b = build(&spec);
    check(&b, &spec);
    let o = open(&b.bytes);
    let a = o.archive();
    let units: Vec<Vec<&str>> = a
        .units()
        .iter()
        .map(|u| {
            u.entries
                .iter()
                .map(|&i| a.entries()[i].name.as_str())
                .collect()
        })
        .collect();
    // a is interval 0, b is 1, c and d are 2, e, f and g start in 3 (g runs on into 4, so
    // the unit decodes 4 as well) and h starts in 4.
    assert_eq!(
        units,
        vec![
            vec!["a"],
            vec!["b"],
            vec!["c", "d"],
            vec!["e", "f", "g"],
            vec!["h"]
        ]
    );
    let numbered: Vec<usize> = a.entries().iter().filter_map(|e| e.block).collect();
    assert_eq!(numbered, [0, 1, 2, 2, 3, 3, 3, 4]);
}

#[test]
fn overlapping_and_out_of_range_entries() {
    let mut spec = Spec::new();
    let page = html(20_000, 1);
    spec.files = vec![
        packed("one.htm", page.clone()),
        packed("two.htm", html(10_000, 2)),
    ];
    // The same bytes under another name, a window into the middle, and a file that starts
    // inside the section but runs past its end.
    spec.extra = vec![
        ("/dup.htm".into(), 1, 0, 20_000),
        ("/part.htm".into(), 1, 5_000, 1_000),
        ("/past.htm".into(), 1, 29_000, 5_000),
        ("/nowhere.htm".into(), 1, 90_000_000, 10),
    ];
    let b = build(&spec);
    let o = open(&b.bytes);
    let a = o.archive();
    // Every file is in exactly one unit even though they overlap.
    let mut seen = vec![0; a.entries().len()];
    for u in a.units() {
        for &i in &u.entries {
            seen[i] += 1;
        }
    }
    assert!(a
        .entries()
        .iter()
        .enumerate()
        .all(|(i, e)| seen[i] == (e.size_or_zero() > 0) as usize));
    // Good files extract; the ones that overrun fail without disturbing the rest.
    let mut ok = BTreeMap::new();
    let mut failed = Vec::new();
    for u in 0..a.units().len() {
        let r = a.extract_unit(u, &Ctx::default(), &mut |i, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            ok.insert(a.entries()[i].name.clone(), v);
            Ok(Flow::Continue)
        });
        if r.is_err() {
            failed.push(u);
        }
    }
    assert_eq!(ok["one.htm"], page);
    assert_eq!(ok["dup.htm"], page);
    assert_eq!(ok["part.htm"], page[5_000..6_000]);
    assert_eq!(ok["two.htm"], html(10_000, 2));
    assert!(!ok.contains_key("past.htm"));
    assert!(!ok.contains_key("nowhere.htm"));
    assert!(!failed.is_empty());
}

#[test]
fn many_overlapping_entries_open_without_quadratic_work() {
    let mut spec = Spec::new();
    spec.chunk = 0x4000;
    spec.files = vec![packed("real.htm", html(40_000, 1))];
    // Fifty thousand names for the first bytes of the section: each overlaps the last, so
    // each needs a unit of its own.
    spec.extra = (0..50_000)
        .map(|i| (format!("/n{i:05}"), 1, 0, 10))
        .collect();
    let b = build(&spec);
    let o = open(&b.bytes);
    let a = o.archive();
    assert_eq!(a.entries().len(), 50_001);
    assert_eq!(a.units().len(), 50_001);
    // Any one of them still extracts.
    let mut first = Vec::new();
    a.extract_unit(a.units().len() / 2, &Ctx::default(), &mut |_, r| {
        r.read_to_end(&mut first).map_err(Error::from)?;
        Ok(Flow::Stop)
    })
    .unwrap();
    assert_eq!(first, html(40_000, 1)[..10]);
}

#[test]
fn empty_files_and_archives_without_a_compressed_section() {
    // Only stored files: no ::DataSpace entries at all.
    let mut spec = Spec::new();
    spec.dirs = vec!["d".into()];
    spec.files = vec![
        stored("d/one", data::text(700, 1)),
        stored("d/none", Vec::new()),
        stored("two", data::random(30, 2)),
    ];
    let b = build(&spec);
    assert!(!b.parts.contains_key("control"));
    check(&b, &spec);
    // Only empty compressed files: an empty section.
    let mut spec = Spec::new();
    spec.files = vec![packed("a", Vec::new()), packed("b", Vec::new())];
    check(&build(&spec), &spec);
    // Nothing at all.
    let spec = Spec::new();
    let b = build(&spec);
    let o = open(&b.bytes);
    assert!(o.archive().entries().is_empty());
}

#[test]
fn unknown_transforms_are_listed_but_not_extracted() {
    let mut spec = sample();
    spec.guid = "{67F6E4A2-60BF-11D2-9B95-00C04F79F6B5}".into();
    let b = build(&spec);
    let o = open(&b.bytes);
    let a = o.archive();
    // The files are listed; only the method is unknown.
    let r = rows(a);
    assert_eq!(r.len(), expected_rows(&b, &spec).len());
    assert!(r.iter().any(|x| x.0 == "index.htm" && x.3.is_empty()));
    // Section 0 still extracts; the other section reports what it is.
    let mut stored_ok = 0;
    for u in 0..a.units().len() {
        let first = a.units()[u].entries[0];
        let r = a.extract_unit(u, &Ctx::default(), &mut |_, r| {
            std::io::copy(r, &mut std::io::sink()).map_err(Error::from)?;
            Ok(Flow::Continue)
        });
        if a.entries()[first].method.as_deref() == Some("Copy") {
            r.unwrap();
            stored_ok += 1;
        } else {
            assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
        }
    }
    assert_eq!(stored_ok, 2);
}

// ------------------------------------------------------------------ damaged archives

fn set32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn set64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn try_open(bytes: Vec<u8>) -> r7z::Result<Opened> {
    format::open_bytes(bytes, "x.chm", &OpenRequest::default())
}

fn try_recover(bytes: Vec<u8>) -> r7z::Result<Opened> {
    format::open_bytes_recover(bytes, "x.chm", &OpenRequest::default())
}

#[test]
fn damaged_headers_and_directories_are_rejected() {
    let mut spec = sample();
    spec.chunk = 0x200;
    let b = build(&spec);
    let itsp = b.parts["itsp"];
    let edit = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut d = b.bytes.clone();
        f(&mut d);
        d
    };

    // A version this reader does not know.
    let d = edit(&|d| set32(d, 4, 9));
    assert!(matches!(try_open(d), Err(Error::Unsupported(_))));
    // Directory pointers outside the file, or without an ITSP header.
    let d = edit(&|d| set64(d, 0x48, u64::MAX));
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    let d = edit(&|d| set64(d, 0x48, 3));
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    let d = edit(&|d| d[itsp] = b'X');
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    // Chunk counts and sizes that cannot be right.
    let d = edit(&|d| set32(d, itsp + 0x2C, u32::MAX));
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    let d = edit(&|d| set32(d, itsp + 0x2C, 1 << 19));
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    for len in [0, 1, 0x15, 0x100000] {
        let d = edit(&|d| set32(d, itsp + 0x10, len));
        assert!(try_open(d).is_err(), "chunk length {len}");
    }
    let d = edit(&|d| set32(d, itsp + 8, 1));
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    // A listing chunk whose free space leaves no room for the header, or runs an entry
    // past the end of the entries.
    let first = itsp + 0x54;
    let d = edit(&|d| set32(d, first + 4, u32::MAX));
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    let d = edit(&|d| d[first + 0x14] = 0xFF);
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    let d = edit(&|d| {
        for b in &mut d[first + 0x14..first + 0x20] {
            *b = 0xFF;
        }
    });
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));

    // Recovery keeps the chunks that are good and says what it skipped.
    let d = edit(&|d| set32(d, first + 4, u32::MAX));
    let o = try_recover(d).unwrap();
    assert!(!o.damage().is_empty());
    let whole = open(&b.bytes).archive().entries().len();
    assert!(o.archive().entries().len() < whole);
    // A directory cut off by the end of the file.
    let d = b.bytes[..first + 0x200 + 7].to_vec();
    assert!(try_open(d.clone()).is_err());
    let o = try_recover(d).unwrap();
    assert!(!o.damage().is_empty());
}

#[test]
fn damaged_compressed_section_metadata() {
    let spec = sample();
    let b = build(&spec);
    let control = b.parts["control"];
    let reset = b.parts["reset"];
    let edit = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut d = b.bytes.clone();
        f(&mut d);
        d
    };
    let extract_all = |o: &Opened| -> Vec<bool> {
        let a = o.archive();
        (0..a.units().len())
            .map(|u| {
                a.extract_unit(u, &Ctx::default(), &mut |_, r| {
                    std::io::copy(r, &mut std::io::sink()).map_err(Error::from)?;
                    Ok(Flow::Continue)
                })
                .is_ok()
            })
            .collect()
    };

    // Window sizes LZX cannot use: listed, not extracted.
    for window in [0u32, 3, 128, 1 << 31] {
        let d = edit(&|d| set32(d, control + 0x10, window));
        let o = try_open(d).unwrap();
        assert!(extract_all(&o).iter().filter(|ok| !**ok).count() > 0);
    }
    // A reset interval of nothing, or not a whole number of frames, is damage.
    let d = edit(&|d| set32(d, control + 0xC, 0));
    assert!(matches!(try_open(d.clone()), Err(Error::Corrupt(_))));
    let o = try_recover(d).unwrap();
    assert!(!o.damage().is_empty());
    let d = edit(&|d| {
        set32(d, control + 8, 1);
        set32(d, control + 0xC, 40_000);
    });
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    // Control data that is not LZXC, or of another version.
    let d = edit(&|d| d[control + 4] = b'Q');
    assert!(try_open(d).is_ok());
    let d = edit(&|d| set32(d, control + 8, 7));
    assert!(try_open(d).is_ok());

    // Reset tables that disagree with the section.
    let cases: [(usize, u64, bool); 5] = [
        (0x4, 0, true),         // no entries
        (0x8, 3, true),         // entry size neither 4 nor 8
        (0x10, u64::MAX, true), // uncompressed length far past the entries
        (0x18, u64::MAX, true), // compressed length past the content
        (0x20, 1 << 14, false), // blocks that are not 32 KiB
    ];
    for (at, v, corrupt) in cases {
        let d = edit(&|d| {
            if at == 0x10 || at == 0x18 || at == 0x20 {
                set64(d, reset + at, v);
            } else {
                set32(d, reset + at, v as u32);
            }
        });
        let r = try_open(d);
        if corrupt {
            assert!(matches!(r, Err(Error::Corrupt(_))), "{at:#x}");
        } else {
            let o = r.unwrap_or_else(|e| panic!("{at:#x}: {e}"));
            assert!(extract_all(&o).iter().any(|ok| !*ok), "{at:#x}");
        }
    }
    // Frame offsets that run backwards.
    let d = edit(&|d| set64(d, reset + 0x28 + 8, u64::MAX));
    assert!(matches!(try_open(d), Err(Error::Corrupt(_))));
    // The content cut short: listed under recovery, but nothing extracts.
    let d = b.bytes[..b.parts["content"] + 100].to_vec();
    assert!(try_open(d.clone()).is_err());
    let o = try_recover(d).unwrap();
    assert!(!o.archive().entries().is_empty());
    assert!(!o.damage().is_empty());
}

// ------------------------------------------------------------------ fixture

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chm/small.chm")
}

/// Two reset intervals (the second a lone frame holding an odd-sized tail), a directory of
/// several chunks with an index, and uncompressed, aligned and verbatim blocks.
fn fixture_spec() -> Spec {
    let mut s = Spec::new();
    s.window_bits = 16;
    s.interval = 2;
    s.chunk = 0x200;
    s.style = LzxStyle {
        blocks: 2,
        e8: true,
        pad_last: true,
    };
    s.dirs = ["docs", "docs/api", "img"].map(String::from).to_vec();
    let mut files = vec![
        stored("#SYSTEM", data::random(240, 11)),
        stored("#ITBITS", Vec::new()),
        stored("readme.txt", html(400, 1)),
        packed("index.htm", html(2_000, 2)),
    ];
    for i in 0..12 {
        files.push(packed(
            &format!("docs/page{i:02}.htm"),
            html(1_500 + 90 * i, i as u32 + 3),
        ));
    }
    files.push(packed("docs/api/big.htm", filler(36_000, 9)));
    files.push(packed("img/prog.bin", data::x86(2_400, 12)));
    files.push(packed("img/noise.bin", data::random(1_000, 13)));
    // Fill the section to two whole frames and an odd tail.
    let used: usize = files
        .iter()
        .filter(|f| f.packed)
        .map(|f| f.data.len())
        .sum();
    let tail = 2 * FRAME + 1_501 - used;
    files.push(packed("docs/api/tail.htm", filler(tail, 5)));
    s.files = files;
    s
}

#[test]
#[ignore = "writes the committed fixture; run it after changing the writer"]
fn write_fixture() {
    let b = build(&fixture_spec());
    fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
    fs::write(fixture_path(), &b.bytes).unwrap();
}

#[test]
fn committed_fixture_matches_what_the_writer_describes() {
    let spec = fixture_spec();
    let model = build(&spec);
    let bytes = fs::read(fixture_path()).expect("fixture is committed");
    assert!(bytes.len() < 20_000, "{} bytes", bytes.len());
    let o = open(&bytes);
    let a = o.archive();
    assert_eq!(rows(a), expected_rows(&model, &spec));
    let got = contents(a).unwrap();
    for it in model
        .items
        .iter()
        .filter(|it| !it.is_dir && !it.data.is_empty())
    {
        assert!(got[&it.name] == it.data, "{}", it.name);
    }
    let files = a.entries().iter().filter(|e| !e.is_dir).count();
    assert_eq!(test_archive(a).unwrap(), files);
}

fn fixture_bytes() -> Vec<u8> {
    fs::read(fixture_path()).expect("fixture is committed")
}

/// Opens and tests damaged bytes; any outcome but a panic is acceptable.
fn try_damaged(data: Vec<u8>) -> r7z::Result<()> {
    let o = try_open(data)?;
    test_archive(o.archive())?;
    Ok(())
}

#[test]
fn truncated_inputs_never_panic() {
    let data = fixture_bytes();
    let full = try_damaged(data.clone());
    assert!(full.is_ok(), "{full:?}");
    let mut listed = 0;
    for len in 0..data.len() {
        let cut = data[..len].to_vec();
        // A shorter file is an error or, never, a different listing of the same files.
        if let Ok(o) = try_open(cut.clone()) {
            listed += 1;
            let _ = test_archive(o.archive());
        }
        let _ = try_recover(cut).map(|o| test_archive(o.archive()));
    }
    // The content and reset table are at the end, so no proper prefix opens.
    assert_eq!(listed, 0);
}

#[test]
fn bit_flips_never_panic() {
    let data = fixture_bytes();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let per = data.len().div_ceil(threads);
    std::thread::scope(|s| {
        for t in 0..threads {
            let data = &data;
            s.spawn(move || {
                for i in (t * per)..((t + 1) * per).min(data.len()) {
                    for bit in [0x01u8, 0x80] {
                        let mut d = data.clone();
                        d[i] ^= bit;
                        let _ = try_damaged(d.clone());
                        let _ = try_recover(d).map(|o| test_archive(o.archive()));
                    }
                }
            });
        }
    });
}

// ------------------------------------------------------------------ against 7-Zip

fn seven_zip() -> Option<PathBuf> {
    let p = std::env::var_os("R7Z_TEST_7Z")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:/Program Files/7-Zip/7z.exe"));
    p.exists().then_some(p)
}

fn tmp(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("r7z-chm-{}-{name}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// What `7z l -slt` shows per entry: path, size, method, block.
fn seven_zip_rows(exe: &Path, file: &Path) -> Vec<(String, String, String, String)> {
    let out = Command::new(exe)
        .args(["l", "-slt"])
        .arg(file)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    let body = text.split("\n----------\n").nth(1).unwrap_or("");
    body.split("\n\n")
        .filter(|b| !b.trim().is_empty())
        .map(|b| {
            let mut m: BTreeMap<String, String> = BTreeMap::new();
            for l in b.lines() {
                if let Some((k, v)) = l.split_once(" = ") {
                    m.insert(k.into(), v.into());
                } else if let Some(k) = l.strip_suffix(" =") {
                    m.insert(k.into(), String::new());
                }
            }
            let get = |k: &str| m.get(k).cloned().unwrap_or_default();
            (
                get("Path").replace('\\', "/"),
                get("Size"),
                get("Method"),
                get("Block"),
            )
        })
        .collect()
}

/// Lists and extracts `file` with both programs and compares them.
fn compare_with_7zip(exe: &Path, file: &Path, what: &str) {
    let o = format::open(file, &OpenRequest::default()).unwrap_or_else(|e| panic!("{what}: {e}"));
    let a = o.archive();
    let ours: Vec<_> = a
        .entries()
        .iter()
        .map(|e| {
            (
                e.name.clone(),
                e.size_or_zero().to_string(),
                e.method.clone().unwrap_or_default(),
                e.block.map(|b| b.to_string()).unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(ours, seven_zip_rows(exe, file), "{what}: listing");

    let out = tmp("x");
    let status = Command::new(exe)
        .arg("x")
        .arg("-y")
        .arg(format!("-o{}", out.display()))
        .arg(file)
        .output()
        .unwrap();
    assert!(status.status.success(), "{what}: 7-Zip failed");
    let got = contents(a).unwrap_or_else(|e| panic!("{what}: {e}"));
    let mut files = 0;
    for e in a.entries() {
        let p = out.join(&e.name);
        if e.is_dir {
            assert!(p.is_dir(), "{what}: {}", e.name);
        } else {
            files += 1;
            let theirs = fs::read(&p).unwrap_or_else(|_| panic!("{what}: 7-Zip has no {}", e.name));
            let ours = got.get(&e.name).cloned().unwrap_or_default();
            assert!(ours == theirs, "{what}: {} differs", e.name);
        }
    }
    assert!(files > 0);
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn built_archives_list_and_extract_like_7zip() {
    let Some(exe) = seven_zip() else {
        eprintln!("skipped: 7-Zip is not installed");
        return;
    };
    let dir = tmp("built");
    // 7-Zip reads ITSF version 3 only, LZXC control data version 2, power-of-two reset
    // intervals and a last frame coded at its full size.
    let mut specs: Vec<(&str, Spec)> = vec![("sample", sample())];
    let mut small = sample();
    small.window_bits = 15;
    small.interval = 1;
    small.style.blocks = 2;
    small.style.e8 = true;
    specs.push(("w15", small));
    let mut big = sample();
    big.window_bits = 21;
    big.interval = 4;
    big.style.blocks = 1;
    specs.push(("w21", big));
    let mut seven = sample();
    seven.dir_last = true;
    seven.zero_base = true;
    seven.chunk = 0x2000;
    specs.push(("like-7-zip.chm", seven));
    specs.push(("fixture", fixture_spec()));
    for (name, spec) in specs {
        let p = dir.join(format!("{name}.chm"));
        fs::write(&p, build(&spec).bytes).unwrap();
        compare_with_7zip(&exe, &p, name);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn committed_fixture_lists_like_7zip() {
    let Some(exe) = seven_zip() else {
        eprintln!("skipped: 7-Zip is not installed");
        return;
    };
    compare_with_7zip(&exe, &fixture_path(), "fixture");
}

#[test]
fn system_help_files_match_7zip() {
    let Some(exe) = seven_zip() else {
        eprintln!("skipped: 7-Zip is not installed");
        return;
    };
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(dir) = exe.parent() {
        files.push(dir.join("7-zip.chm"));
    }
    for dir in ["C:/Windows/Help/mui/0409", "C:/Windows/IME/IMEJP/help"] {
        if let Ok(rd) = fs::read_dir(dir) {
            files.extend(
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("chm"))),
            );
        }
    }
    files.retain(|p| p.is_file());
    for f in &files {
        compare_with_7zip(&exe, f, &f.display().to_string());
    }
    eprintln!("compared {} system help files", files.len());
}
