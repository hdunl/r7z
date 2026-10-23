//! NSIS installers made by a small writer in this file, since no NSIS compiler is on the
//! test machine: a PE loader stub, the first header, a compiled script (instructions,
//! string table, language table) in each string flavor (ANSI NSIS 2, ANSI and UTF-16 NSIS 3,
//! the Unicode fork), and the data in both layouts with each compressor NSIS uses. NSIS's
//! bzip2 differs from bzip2 (one-byte markers, no CRCs), so the writer has its own encoder,
//! which is checked against the bzip2 crate in its standard form. The reader was also
//! checked against real installers and 7-Zip 25.01, which these tests do not need.
//!
//! The fixtures in `tests/fixtures/nsis/` come from `write_fixtures` (run it with
//! `--ignored` to regenerate them); the other tests read them back. 7-Zip 25.01 lists and
//! extracts them with the same bytes; its names differ only for the file named through
//! `$OUTDIR`, where 7-Zip repeats the output folder.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use r7z::format::{self, Archive, Ctx, Flow, OpenRequest, Opened};
use r7z::Error;

// ---------------------------------------------------------------- writer

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codes {
    Ansi2,
    Ansi3,
    Unicode3,
    Park,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codec {
    /// Nothing compressed.
    Copy,
    /// Deflate whose stored blocks lack the length complement (NSIS 2).
    Deflate2,
    /// Standard deflate (NSIS 3).
    Deflate3,
    Bzip2,
    Lzma,
    /// LZMA after the x86 branch filter, flagged by a leading 1.
    LzmaBcj,
}

#[derive(Clone, Copy)]
struct Spec {
    codes: Codes,
    codec: Codec,
    solid: bool,
    /// The header block is stored while files are compressed.
    stored_header: bool,
    /// One file name points outside the string table.
    bad_name: bool,
    /// The instruction table lies outside the header.
    bad_script: bool,
}

const fn spec(codes: Codes, codec: Codec, solid: bool) -> Spec {
    Spec {
        codes,
        codec,
        solid,
        stored_header: false,
        bad_name: false,
        bad_script: false,
    }
}

/// String pieces: text, a variable, a shell folder (two CSIDL bytes), a language string.
enum P<'a> {
    T(&'a str),
    V(u16),
    S(u8, u8),
    L(u16),
}

const VAR_INSTDIR: u16 = 21;
const VAR_OUTDIR: u16 = 22;
const VAR_PLUGINSDIR: u16 = 26;
const VAR_USER0: u16 = 32;

struct Strings {
    codes: Codes,
    bytes: Vec<u8>,
    /// Characters written.
    len: u32,
}

impl Strings {
    fn new(codes: Codes) -> Self {
        let mut s = Strings {
            codes,
            bytes: Vec::new(),
            len: 0,
        };
        s.add(&[]);
        s
    }

    fn unicode(&self) -> bool {
        matches!(self.codes, Codes::Unicode3 | Codes::Park)
    }

    fn unit(&mut self, u: u16) {
        if self.unicode() {
            self.bytes.extend_from_slice(&u.to_le_bytes());
        } else {
            self.bytes.push(u as u8);
        }
        self.len += 1;
    }

    /// A code and its parameter: two bytes, or one UTF-16 unit made of them.
    fn code(&mut self, code: u16, param: [u8; 2]) {
        self.unit(code);
        if self.unicode() {
            self.unit(u16::from_le_bytes(param));
        } else {
            self.unit(param[0] as u16);
            self.unit(param[1] as u16);
        }
    }

    /// Variable and language indexes: 14 bits in two bytes with the top bits set, or (the
    /// fork) 15 bits under the top bit.
    fn index(&self, v: u16) -> [u8; 2] {
        if self.codes == Codes::Park {
            (0x8000 | v).to_le_bytes()
        } else {
            [(v & 0x7F) as u8 | 0x80, ((v >> 7) & 0x7F) as u8 | 0x80]
        }
    }

    /// The codes for language, shell folder and variable.
    fn codes(&self) -> [u16; 3] {
        match self.codes {
            Codes::Ansi2 => [0xFF, 0xFE, 0xFD],
            Codes::Ansi3 | Codes::Unicode3 => [1, 2, 3],
            Codes::Park => [0xE003, 0xE002, 0xE001],
        }
    }

    fn add(&mut self, parts: &[P]) -> u32 {
        let off = self.len;
        let [lang, shell, var] = self.codes();
        for p in parts {
            match p {
                P::T(t) => {
                    for u in t.encode_utf16() {
                        self.unit(u);
                    }
                }
                P::V(v) => self.code(var, self.index(*v)),
                P::L(v) => self.code(lang, self.index(*v)),
                P::S(a, b) => self.code(shell, [*a, *b]),
            }
        }
        self.unit(0);
        off
    }
}

/// A PE image of one section ending at 1024, where the installer data starts.
fn stub() -> Vec<u8> {
    let mut d = vec![0u8; 1024];
    let mut put = |at: usize, v: &[u8]| d[at..at + v.len()].copy_from_slice(v);
    put(0, b"MZ");
    put(0x3C, &0x40u32.to_le_bytes());
    put(0x40, b"PE\0\0");
    let coff = 0x44;
    put(coff, &0x14Cu16.to_le_bytes());
    put(coff + 2, &1u16.to_le_bytes());
    put(coff + 16, &224u16.to_le_bytes());
    put(coff + 18, &0x0102u16.to_le_bytes());
    let opt = coff + 20;
    put(opt, &0x10Bu16.to_le_bytes());
    put(opt + 60, &512u32.to_le_bytes());
    put(opt + 92, &16u32.to_le_bytes());
    let sec = opt + 224;
    put(sec, b".text");
    put(sec + 8, &512u32.to_le_bytes());
    put(sec + 12, &0x1000u32.to_le_bytes());
    put(sec + 16, &512u32.to_le_bytes());
    put(sec + 20, &512u32.to_le_bytes());
    for (i, b) in d[512..].iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    d
}

/// Where the uninstaller's icon goes in the loader, and what it is.
const ICON_AT: usize = 0x300;
const ICON: &[u8] = b"ICON-DATA";

fn noise(n: usize, mut seed: u32) -> Vec<u8> {
    (0..n)
        .map(|_| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (seed >> 16) as u8
        })
        .collect()
}

fn text(lines: usize, tag: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..lines {
        v.extend_from_slice(format!("{tag} line {i}: aaaaabbbbbcccccc {}\r\n", i * i).as_bytes());
    }
    v
}

/// x86-like code with relative calls for the branch filter to convert.
fn code() -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..60u32 {
        v.extend_from_slice(&[0x55, 0x8B, 0xEC, 0xE8]);
        v.extend_from_slice(&(0x1000 + i * 37).to_le_bytes());
        v.extend_from_slice(&[0x5D, 0xC3, 0x90, (i * 13) as u8]);
    }
    v
}

fn deflate(data: &[u8], complement: bool) -> Vec<u8> {
    // A stored block of the first bytes, then a compressed stream for the rest.
    let mut out = Vec::new();
    let split = data.len().min(40);
    if split > 0 {
        out.push(0);
        out.extend_from_slice(&(split as u16).to_le_bytes());
        if complement {
            out.extend_from_slice(&(!(split as u16)).to_le_bytes());
        }
        out.extend_from_slice(&data[..split]);
    }
    let mut e = flate2::write::DeflateEncoder::new(out, flate2::Compression::default());
    e.write_all(&data[split..]).unwrap();
    e.finish().unwrap()
}

fn lzma(data: &[u8], bcj: bool) -> Vec<u8> {
    let mut opts = lzma_rust2::LzmaOptions::with_preset(6);
    opts.dict_size = 1 << 20;
    assert_eq!(opts.get_props(), 0x5D);
    let mut out = Vec::new();
    if bcj {
        out.push(1);
    }
    out.push(0x5D);
    out.extend_from_slice(&opts.dict_size.to_le_bytes());
    let mut w = lzma_rust2::LzmaWriter::new_no_header(out, &opts, true).unwrap();
    if bcj {
        let mut b = lzma_rust2::filter::bcj::BcjWriter::new_x86(w, 0);
        b.write_all(data).unwrap();
        w = b.finish().unwrap();
    } else {
        w.write_all(data).unwrap();
    }
    w.finish().unwrap()
}

/// MSB-first bit writer.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn put(&mut self, bits: u32, v: u32) {
        self.acc = (self.acc << bits) | (v as u64 & ((1u64 << bits) - 1));
        self.n += bits;
        while self.n >= 8 {
            self.n -= 8;
            self.out.push((self.acc >> self.n) as u8);
        }
        self.acc &= (1u64 << self.n) - 1;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

fn bz_crc(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
        }
    }
    !crc
}

/// bzip2's first stage: four equal bytes are followed by a count of further repeats.
fn rle1(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        let run = data[i..].iter().take(259).take_while(|&&x| x == b).count();
        if run >= 4 {
            out.extend_from_slice(&[b; 4]);
            out.push((run - 4) as u8);
        } else {
            out.extend(std::iter::repeat_n(b, run));
        }
        i += run;
    }
    out
}

/// One bzip2 block: BWT by sorting rotations, move-to-front with RUNA/RUNB zero runs, and two
/// identical flat Huffman tables. Returns the block's CRC.
fn bz_block(w: &mut Bits, data: &[u8], nsis: bool) -> u32 {
    let block = rle1(data);
    let n = block.len();
    let mut idx: Vec<usize> = (0..n).collect();
    idx.sort_by(|&a, &b| {
        (0..n)
            .map(|k| block[(a + k) % n])
            .cmp((0..n).map(|k| block[(b + k) % n]))
    });
    let orig = idx.iter().position(|&i| i == 0).unwrap();
    let last: Vec<u8> = idx.iter().map(|&i| block[(i + n - 1) % n]).collect();
    let mut used = [false; 256];
    for &b in &last {
        used[b as usize] = true;
    }
    let mut mtf: Vec<u8> = (0..=255u8).filter(|&b| used[b as usize]).collect();
    let alpha = mtf.len() + 2;
    let mut syms: Vec<u32> = Vec::new();
    let flush = |zeros: &mut usize, syms: &mut Vec<u32>| {
        let mut r = *zeros;
        while r > 0 {
            if r & 1 == 1 {
                syms.push(0);
                r = (r - 1) / 2;
            } else {
                syms.push(1);
                r = (r - 2) / 2;
            }
        }
        *zeros = 0;
    };
    let mut zeros = 0;
    for &b in &last {
        let j = mtf.iter().position(|&x| x == b).unwrap();
        if j == 0 {
            zeros += 1;
            continue;
        }
        flush(&mut zeros, &mut syms);
        mtf.remove(j);
        mtf.insert(0, b);
        syms.push(j as u32 + 1);
    }
    flush(&mut zeros, &mut syms);
    syms.push(alpha as u32 - 1);
    let crc = bz_crc(data);
    if nsis {
        w.put(8, 0x31);
    } else {
        w.put(24, 0x31_4159);
        w.put(24, 0x26_5359);
        w.put(32, crc);
        w.put(1, 0);
    }
    w.put(24, orig as u32);
    let group = |i: usize| (0..16).any(|j| used[i * 16 + j]);
    let used16 = (0..16)
        .filter(|&i| group(i))
        .fold(0, |m, i| m | (0x8000 >> i));
    w.put(16, used16);
    for i in (0..16).filter(|&i| group(i)) {
        let m = (0..16)
            .filter(|&j| used[i * 16 + j])
            .fold(0, |m, j| m | (0x8000 >> j));
        w.put(16, m);
    }
    let mut len = 1;
    while (1 << len) < alpha {
        len += 1;
    }
    let selectors = syms.len().div_ceil(50);
    w.put(3, 2);
    w.put(15, selectors as u32);
    for _ in 0..selectors {
        w.put(1, 0);
    }
    for _ in 0..2 {
        w.put(5, len);
        for _ in 0..alpha {
            w.put(1, 0);
        }
    }
    for &s in &syms {
        w.put(len, s);
    }
    crc
}

/// bzip2 in blocks of 500 bytes; NSIS's form when `nsis`, else the standard stream.
fn bzip2(data: &[u8], nsis: bool) -> Vec<u8> {
    let mut w = Bits::default();
    if !nsis {
        for &b in b"BZh9" {
            w.put(8, b as u32);
        }
    }
    let mut combined = 0u32;
    for chunk in data.chunks(500) {
        combined = combined.rotate_left(1) ^ bz_block(&mut w, chunk, nsis);
    }
    if nsis {
        w.put(8, 0x17);
    } else {
        w.put(24, 0x17_7245);
        w.put(24, 0x38_5090);
        w.put(32, combined);
    }
    w.finish()
}

fn compress(codec: Codec, data: &[u8]) -> Vec<u8> {
    match codec {
        Codec::Copy => data.to_vec(),
        Codec::Deflate2 => deflate(data, false),
        Codec::Deflate3 => deflate(data, true),
        Codec::Bzip2 => bzip2(data, true),
        Codec::Lzma => lzma(data, false),
        Codec::LzmaBcj => lzma(data, true),
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A built installer and what it should list: names in order, with their contents.
struct Built {
    bytes: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
    /// Offsets of the data blocks, as the reader names unnamed ones.
    offsets: Vec<u32>,
}

const README_TIME: u64 = 0x01D9_0A0B_1234_5678;

fn build(spec: &Spec) -> Built {
    let mut st = Strings::new(spec.codes);
    let pfd = st.add(&[P::T("ProgramFilesDir")]);
    let pf_default = st.add(&[P::T("C:\\Program Files")]);
    let plugin = st.add(&[P::V(VAR_PLUGINSDIR), P::T("\\plugin.dll")]);
    let instdir = st.add(&[P::V(VAR_INSTDIR)]);
    let readme = st.add(&[P::T("readme.txt")]);
    let bin = st.add(&[P::V(VAR_INSTDIR), P::T("\\bin")]);
    let tool = st.add(&[P::T("tool.exe")]);
    let empty = st.add(&[P::T("empty.dat")]);
    let sysdir = st.add(&[P::S(0x25, 0x25)]);
    let other = st.add(&[P::V(VAR_INSTDIR), P::T("\\other")]);
    let vendor = st.add(&[P::S(0x80 | pfd as u8, pf_default as u8), P::T("\\Vendor")]);
    let settings = st.add(&[P::V(VAR_OUTDIR), P::T("\\conf\\settings.ini")]);
    let notes = st.add(&[P::V(VAR_USER0), P::T("\\notes.txt")]);
    let uninst = st.add(&[P::V(VAR_INSTDIR), P::T("\\uninst.exe")]);
    let caption = st.add(&[P::T("Setup: "), P::L(3)]);

    let loader = stub();
    let mut icon = Vec::new();
    put_u32(&mut icon, ICON.len() as u32);
    put_u32(&mut icon, ICON_AT as u32);
    icon.extend_from_slice(ICON);
    put_u32(&mut icon, 0);
    let mut uninstaller = b"\x01\0\0\0\xEF\xBE\xAD\xDENullsoftInst".to_vec();
    uninstaller.extend_from_slice(&text(4, "uninstaller"));
    // plugin, readme, tool, empty, settings, notes, icon, uninstaller data.
    let blocks: Vec<Vec<u8>> = vec![
        noise(700, 7),
        text(30, "readme"),
        code(),
        Vec::new(),
        text(3, "[settings]"),
        text(2, "notes"),
        icon.clone(),
        uninstaller.clone(),
    ];
    let compressed = |k: usize, raw: &[u8]| -> Option<Vec<u8>> {
        // Like makensis: kept stored when compression does not pay, and the noise always.
        if spec.codec == Codec::Copy || k == 0 {
            return None;
        }
        Some(compress(spec.codec, raw)).filter(|c| c.len() < raw.len())
    };
    let mut encoded: Vec<Vec<u8>> = Vec::new();
    let mut offsets = Vec::new();
    let mut at = 0u32;
    for (k, raw) in blocks.iter().enumerate() {
        offsets.push(at);
        let mut b = Vec::new();
        match (spec.solid, compressed(k, raw)) {
            (false, Some(c)) => {
                put_u32(&mut b, c.len() as u32 | 0x8000_0000);
                b.extend_from_slice(&c);
            }
            _ => {
                put_u32(&mut b, raw.len() as u32);
                b.extend_from_slice(raw);
            }
        }
        at += b.len() as u32;
        encoded.push(b);
    }
    let off = |k: usize| offsets[k];

    let none = u32::MAX;
    let file = |name: u32, k: usize, time: Option<u64>| {
        let (lo, hi) = time.map_or((none, none), |t| (t as u32, (t >> 32) as u32));
        [20, 0x0500_0090, name, off(k), lo, hi, 0]
    };
    let set_out = |path: u32| [11, path, 1, 0, 0, 0, 0];
    let entries: Vec<[u32; 7]> = vec![
        [13, 0, 1, 0, 0, 0, 0],
        file(plugin, 0, None),
        set_out(instdir),
        file(readme, 1, Some(README_TIME)),
        file(readme, 1, Some(README_TIME)),
        set_out(bin),
        file(tool, 2, None),
        file(if spec.bad_name { 0x00FF_FFFF } else { empty }, 3, None),
        [11, other, 0, 0, 0, 0, 0],
        file(tool, 2, None),
        set_out(sysdir),
        file(tool, 2, None),
        set_out(vendor),
        file(settings, 4, None),
        file(notes, 5, None),
        [62, uninst, off(6), icon.len() as u32, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0],
    ];

    let fixed = 300;
    let entries_at = fixed;
    let strings_at = entries_at + 28 * entries.len();
    let lang_at = strings_at + st.bytes.len();
    let mut lang = Vec::new();
    lang.extend_from_slice(&1033u16.to_le_bytes());
    put_u32(&mut lang, 0);
    put_u32(&mut lang, 0);
    for s in [caption, 0, 0, 0] {
        put_u32(&mut lang, s);
    }
    let mut header = vec![0u8; fixed];
    let tables = [
        (fixed, 0),
        (fixed, 0),
        (
            if spec.bad_script { 1 << 20 } else { entries_at },
            entries.len(),
        ),
        (strings_at, 0),
        (lang_at, 1),
        (lang_at + lang.len(), 0),
        (0, 0),
        (0, 0),
    ];
    for (i, (o, n)) in tables.iter().enumerate() {
        header[4 + 8 * i..8 + 8 * i].copy_from_slice(&(*o as u32).to_le_bytes());
        header[8 + 8 * i..12 + 8 * i].copy_from_slice(&(*n as u32).to_le_bytes());
    }
    header[100..104].copy_from_slice(&(lang.len() as u32).to_le_bytes());
    for e in &entries {
        for v in e {
            put_u32(&mut header, *v);
        }
    }
    header.extend_from_slice(&st.bytes);
    header.extend_from_slice(&lang);

    let mut data = Vec::new();
    if spec.solid {
        let mut raw = Vec::new();
        put_u32(&mut raw, header.len() as u32);
        raw.extend_from_slice(&header);
        for b in &encoded {
            raw.extend_from_slice(b);
        }
        data = compress(spec.codec, &raw);
    } else {
        if spec.codec == Codec::Copy || spec.stored_header {
            put_u32(&mut data, header.len() as u32);
            data.extend_from_slice(&header);
        } else {
            let c = compress(spec.codec, &header);
            put_u32(&mut data, c.len() as u32 | 0x8000_0000);
            data.extend_from_slice(&c);
        }
        for b in &encoded {
            data.extend_from_slice(b);
        }
    }
    let mut bytes = loader.clone();
    put_u32(&mut bytes, 0);
    put_u32(&mut bytes, 0xDEAD_BEEF);
    bytes.extend_from_slice(b"NullsoftInst");
    put_u32(&mut bytes, header.len() as u32);
    put_u32(&mut bytes, (28 + data.len() + 4) as u32);
    bytes.extend_from_slice(&data);
    let crc = crc32fast::hash(&bytes[1024..]);
    put_u32(&mut bytes, crc);

    let mut patched = loader;
    patched[ICON_AT..ICON_AT + ICON.len()].copy_from_slice(ICON);
    patched.extend_from_slice(&uninstaller);
    let empty_name = if spec.bad_name {
        format!("[{}]", off(3))
    } else {
        "bin/empty.dat".into()
    };
    let files = vec![
        ("$PLUGINSDIR/plugin.dll".to_string(), blocks[0].clone()),
        ("readme.txt".into(), blocks[1].clone()),
        ("bin/tool.exe".into(), blocks[2].clone()),
        ("$SYSDIR/tool.exe".into(), blocks[2].clone()),
        (empty_name, Vec::new()),
        (
            "$PROGRAMFILES/Vendor/conf/settings.ini".into(),
            blocks[4].clone(),
        ),
        // A name starting with a user variable is joined to the output folder, as 7-Zip
        // does; `$OUTDIR` is replaced by the folder (7-Zip repeats it).
        (
            "$PROGRAMFILES/Vendor/$_0_/notes.txt".into(),
            blocks[5].clone(),
        ),
        ("uninst.exe".into(), patched),
    ];
    Built {
        bytes,
        files,
        offsets,
    }
}

// ---------------------------------------------------------------- helpers

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/nsis")
        .join(name)
}

/// The committed fixtures and how they were made.
const FIXTURES: [(&str, Spec); 3] = [
    (
        "nsis2-ansi-deflate.bin",
        spec(Codes::Ansi2, Codec::Deflate2, false),
    ),
    (
        "nsis3-unicode-solid-lzma.bin",
        spec(Codes::Unicode3, Codec::Lzma, true),
    ),
    (
        "nsis3-ansi-solid-bzip2.bin",
        spec(Codes::Ansi3, Codec::Bzip2, true),
    ),
];

fn open(bytes: Vec<u8>) -> r7z::Result<Opened> {
    format::open_bytes(bytes, "setup.exe", &OpenRequest::default())
}

fn prop(a: &dyn Archive, key: &str) -> Option<String> {
    a.properties()
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// Every entry's bytes, by decoding every unit; failed units are left out.
fn contents(a: &dyn Archive) -> (Vec<Option<Vec<u8>>>, Vec<Error>) {
    let mut out = vec![None; a.entries().len()];
    let mut errors = Vec::new();
    for u in 0..a.units().len() {
        let r = a.extract_unit(u, &Ctx::default(), &mut |i, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            out[i] = Some(v);
            Ok(Flow::Continue)
        });
        if let Err(e) = r {
            errors.push(e);
        }
    }
    (out, errors)
}

/// Opens `bytes` and checks the listing and every file against `built`.
fn check(bytes: Vec<u8>, built: &Built, what: &str) -> Opened {
    let o = open(bytes).unwrap_or_else(|e| panic!("{what}: {e}"));
    let a = o.archive();
    assert_eq!(a.format().name, "Nsis", "{what}");
    let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
    let want: Vec<&str> = built.files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, want, "{what}");
    let (got, errors) = contents(a);
    assert!(errors.is_empty(), "{what}: {errors:?}");
    for ((name, data), got) in built.files.iter().zip(got) {
        assert_eq!(got.as_deref(), Some(&data[..]), "{what}: {name}");
    }
    o
}

// ---------------------------------------------------------------- tests

#[test]
#[ignore]
fn write_fixtures() {
    for (name, spec) in FIXTURES {
        fs::write(fixture(name), build(&spec).bytes).unwrap();
    }
}

#[test]
fn fixtures_list_and_extract() {
    for (name, spec) in FIXTURES {
        let bytes = fs::read(fixture(name)).unwrap();
        let o = check(bytes, &build(&spec), name);
        let a = o.archive();
        assert_eq!(
            prop(a, "Solid").as_deref(),
            Some(if spec.solid { "+" } else { "-" })
        );
        let readme = &a.entries()[1];
        assert_eq!(readme.mtime, Some(README_TIME), "{name}");
        assert!(a.damage().is_empty(), "{name}: {:?}", a.damage());
    }
}

#[test]
fn every_flavor_and_codec() {
    let cases = [
        (Codes::Ansi2, Codec::Deflate2, false, "NSIS-2", "Deflate"),
        (Codes::Ansi2, Codec::Lzma, false, "NSIS-2", "LZMA:20"),
        (Codes::Ansi3, Codec::Bzip2, false, "NSIS-3", "BZip2"),
        (Codes::Ansi3, Codec::Deflate3, true, "NSIS-3", "Deflate"),
        (
            Codes::Unicode3,
            Codec::Deflate3,
            false,
            "NSIS-3 Unicode",
            "Deflate",
        ),
        (
            Codes::Unicode3,
            Codec::Bzip2,
            true,
            "NSIS-3 Unicode",
            "BZip2",
        ),
        (
            Codes::Unicode3,
            Codec::LzmaBcj,
            false,
            "NSIS-3 Unicode",
            "LZMA:20 BCJ",
        ),
        (
            Codes::Unicode3,
            Codec::LzmaBcj,
            true,
            "NSIS-3 Unicode",
            "LZMA:20 BCJ",
        ),
        (
            Codes::Unicode3,
            Codec::Copy,
            false,
            "NSIS-3 Unicode",
            "Copy",
        ),
        (
            Codes::Park,
            Codec::Deflate2,
            false,
            "NSIS-Park Unicode",
            "Deflate",
        ),
        (
            Codes::Park,
            Codec::Lzma,
            true,
            "NSIS-Park Unicode",
            "LZMA:20",
        ),
    ];
    for (codes, codec, solid, sub, method) in cases {
        let what = format!("{codes:?} {codec:?} solid={solid}");
        let built = build(&spec(codes, codec, solid));
        let o = check(built.bytes.clone(), &built, &what);
        let a = o.archive();
        assert_eq!(prop(a, "SubType").as_deref(), Some(sub), "{what}");
        assert_eq!(prop(a, "Method").as_deref(), Some(method), "{what}");
        assert_eq!(
            prop(a, "Embedded Stub Size").as_deref(),
            Some("1024"),
            "{what}"
        );
        // Stored files have known sizes; the noise is always stored in the block layout.
        let plugin = &a.entries()[0];
        let want = (!solid).then_some(700);
        assert_eq!(plugin.size, want, "{what}");
        if codec == Codec::Copy {
            let uninst = a.entries().last().unwrap();
            assert_eq!(uninst.size, Some(built.files[7].1.len() as u64), "{what}");
        }
    }
}

#[test]
fn stored_header_with_compressed_files() {
    for codec in [Codec::Deflate3, Codec::Lzma, Codec::Bzip2] {
        let built = build(&Spec {
            stored_header: true,
            ..spec(Codes::Unicode3, codec, false)
        });
        check(built.bytes.clone(), &built, &format!("{codec:?}"));
    }
}

#[test]
fn unreadable_names_keep_a_generic_name() {
    let built = build(&Spec {
        bad_name: true,
        ..spec(Codes::Ansi3, Codec::Lzma, false)
    });
    let o = check(built.bytes.clone(), &built, "bad name");
    let damage = o.archive().damage();
    assert!(
        damage
            .iter()
            .any(|d| d.contains("1 file names could not be read")),
        "{damage:?}"
    );
}

#[test]
fn unreadable_script_lists_blocks_by_position() {
    for solid in [false, true] {
        let built = build(&Spec {
            bad_script: true,
            ..spec(Codes::Unicode3, Codec::Deflate3, solid)
        });
        let o = open(built.bytes.clone()).unwrap();
        let a = o.archive();
        let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
        let want: Vec<String> = built.offsets.iter().map(|o| format!("[{o}]")).collect();
        assert_eq!(names, want, "solid={solid}");
        let (got, errors) = contents(a);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(got[1].as_deref(), Some(&built.files[1].1[..]));
        assert!(
            a.damage().iter().any(|d| d.contains("listed by position")),
            "{:?}",
            a.damage()
        );
    }
}

#[test]
fn truncated_data_is_reported() {
    let built = build(&spec(Codes::Unicode3, Codec::Deflate3, false));
    let cut = built.bytes.len() - 30;
    let o = open(built.bytes[..cut].to_vec()).unwrap();
    let a = o.archive();
    assert!(
        a.damage().iter().any(|d| d.contains("truncated")),
        "{:?}",
        a.damage()
    );
    let (got, errors) = contents(a);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(got.last().unwrap().is_none());
    assert_eq!(got[1].as_deref(), Some(&built.files[1].1[..]));
}

#[test]
fn plain_executable_is_not_an_installer() {
    assert!(open(stub()).is_err());
    let mut bytes = build(&spec(Codes::Ansi2, Codec::Copy, false)).bytes;
    bytes[1024 + 8] ^= 0x20;
    assert!(open(bytes).is_err());
}

#[test]
fn bzip2_writer_matches_the_standard_decoder() {
    let mut data = text(40, "bzip2");
    data.extend_from_slice(&noise(300, 3));
    data.extend_from_slice(&[b'z'; 600]);
    let standard = bzip2(&data, false);
    let mut out = Vec::new();
    bzip2::read::BzDecoder::new(&standard[..])
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, data);
}

/// Opens damaged bytes and decodes what opens; any outcome but a panic is acceptable.
fn try_damaged(bytes: Vec<u8>) {
    if let Ok(o) = open(bytes) {
        for lvl in &o.levels {
            let _ = contents(&*lvl.archive);
        }
    }
}

#[test]
fn truncated_inputs_never_panic() {
    for (name, _) in FIXTURES {
        let bytes = fs::read(fixture(name)).unwrap();
        for len in 0..bytes.len() {
            try_damaged(bytes[..len].to_vec());
        }
    }
}

#[test]
fn bit_flips_never_panic() {
    for (name, _) in FIXTURES {
        let bytes = fs::read(fixture(name)).unwrap();
        for i in 0..bytes.len() {
            for bit in [0x01, 0x80] {
                let mut d = bytes.clone();
                d[i] ^= bit;
                try_damaged(d);
            }
        }
    }
}
