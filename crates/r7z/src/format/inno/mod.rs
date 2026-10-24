//! Inno Setup installers (5.5 to 6.7), read-only.
//!
//! An installer is Inno's setup loader, a small PE executable, with the setup program and
//! the setup data appended. The loader finds them through an offset table stored as its
//! RCDATA resource 11111: an ID, a table version (1 up to 6.4, 2 with 64-bit offsets
//! since 6.5) and the file offsets of the setup header data (`setup-0`) and the file data
//! (`setup-1`), ending with a CRC32 of the table.
//!
//! `setup-0` starts with a 64-byte ID, `Inno Setup Setup Data (x.y.z)`, which names the
//! format; 6.5 and later follow it with an encryption header and its CRC32. Then come two
//! compressed blocks, each a CRC32-checked size and flag, then the data in 4 KiB pieces
//! that each start with their CRC32, LZMA-compressed. The first block holds the setup
//! header and the entries of every script section, each a record written as its string
//! fields (a 32-bit byte length and the bytes, UTF-16LE in Unicode installers) and then
//! the rest of the record as raw memory. The record layouts change between releases, so
//! `layouts.rs`, generated from Inno's own record definitions, gives the sizes and the
//! offsets of the fields read here for each format ID. The second block holds the file
//! location entries: where each file's data is, its size, hash and time.
//!
//! File data is stored in chunks, each starting with `zlb\x1a` and compressed with the
//! installer's method (stored, zlib, bzip2, LZMA or LZMA2) when its entry says so. A solid
//! installer has one chunk, which makes it one unit; otherwise each file is a chunk.
//! Executables may have their x86 CALL and JMP targets made absolute in 64 KiB blocks,
//! which is undone here. Every file is checked against its SHA-256 or SHA-1 hash.
//!
//! Names are the [Files] entries' destinations with their leading constant written as a
//! folder: `{app}\bin\tool.exe` is listed as `app/bin/tool.exe`. A file installed only for
//! some languages has them added to its name when another entry has the same destination.
//! The uninstaller, which Setup builds from itself, and external files are not listed.
//! Encrypted file data and installers whose data is in separate `setup-N.bin` files are
//! listed but not extracted.

mod layouts;

use std::collections::HashMap;
use std::io::{self, Read};

use lzma_rust2::{Lzma2Reader, LzmaReader};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::data::{Input, Slice};
use super::{Archive, CodePage, Columns, Ctx, Entry, EntryFn, Flow, Format, OpenOptions, Unit};
use crate::error::{Error, Result};

use layouts::LAYOUTS;

/// A payload format: recognized in a PE file by the loader's offset table
/// (see `format::payload_format`).
pub const FORMAT: Format = Format {
    name: "Inno",
    aliases: &[],
    extensions: &[],
    signatures: &[],
    detect: Some(looks_like_inno),
    write: false,
    stream: false,
    sequential: false,
    open,
};

/// The ID that starts the loader's offset table.
const TABLE_ID: &[u8; 12] = b"rDlPtS\xCD\xE6\xD7\x7B\x0B\x2A";
const SETUP_ID_LEN: usize = 64;
const CHUNK_ID: &[u8; 4] = b"zlb\x1a";
/// The loader and its resources lie well within this many bytes of the file's start.
const SCAN: usize = 4 << 20;
/// Setup header blocks are small; wizard images make them a few MiB at most.
const MAX_BLOCK: u64 = 256 << 20;
/// Largest LZMA dictionary a chunk decoder allocates, whatever its header claims.
const MAX_DICT: u64 = 1 << 30;
/// The x86 call filter works on blocks of this size from the start of each file.
const CALL_BLOCK: usize = 1 << 16;

/// The sizes of one record: its string fields, and the raw bytes after them.
#[derive(Clone, Copy)]
pub(super) struct Rec {
    pub strings: u8,
    pub fixed: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Hash {
    Sha256,
    Sha1,
}

/// Offsets in a file location entry.
pub(super) struct Loc {
    pub size: u16,
    pub first_slice: u16,
    pub start: u16,
    pub start64: bool,
    pub suboffset: u16,
    pub original: u16,
    pub compressed: u16,
    pub hash: u16,
    pub hash_kind: Hash,
    pub time: u16,
    pub flags: u16,
    pub flags_len: u16,
    pub call: Option<u8>,
    pub encrypted: Option<u8>,
    pub chunk_compressed: Option<u8>,
}

/// One setup data format: the record sizes and field offsets this reader needs.
pub(super) struct Layout {
    pub id: &'static str,
    pub unicode: bool,
    /// Size of the encryption header after the ID (6.5 and later), else 0.
    pub enc_header: u16,
    /// Compressed block headers hold a 64-bit size.
    pub block64: bool,
    pub header: Rec,
    /// Offsets in the setup header of the entry counts: languages, custom messages,
    /// permissions, types, components, tasks, directories, signing keys, files and file
    /// locations.
    pub counts: [Option<u16>; 10],
    pub compress: u16,
    /// The records before the files, in the order of `counts`.
    pub skip: [Rec; 8],
    pub file: Rec,
    pub file_location: u16,
    pub file_attribs: u16,
    pub file_type: Option<u16>,
    /// Index of the Languages string among a file entry's strings.
    pub file_languages: u8,
    pub loc: Loc,
}

const FILES: usize = 8;
const LOCATIONS: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Stored,
    Zlib,
    Bzip2,
    Lzma,
    Lzma2,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Stored => "Copy",
            Method::Zlib => "Deflate",
            Method::Bzip2 => "BZip2",
            Method::Lzma => "LZMA",
            Method::Lzma2 => "LZMA2",
        }
    }
}

/// Where a file's data is.
struct Location {
    first_slice: i32,
    start: u64,
    suboffset: u64,
    size: u64,
    packed: u64,
    hash: Vec<u8>,
    hash_kind: Hash,
    mtime: u64,
    call: bool,
    encrypted: bool,
    compressed: bool,
}

pub struct Inno {
    file: Slice,
    /// File offset of the embedded file data, or 0 when it is in `setup-N.bin` files.
    data_at: u64,
    version: String,
    method: Method,
    app: String,
    locations: Vec<Location>,
    /// For each entry, its location.
    items: Vec<usize>,
    entries: Vec<Entry>,
    units: Vec<Unit>,
}

/// True when `file` holds what looks like the offset table of Inno's setup loader: its ID
/// and a known table version. Reads bytes only, without the CRC check that opening does,
/// so the Explorer menu links no checksum code.
pub fn looks_like_inno(file: &[u8]) -> bool {
    let head = &file[..file.len().min(SCAN)];
    file.starts_with(b"MZ")
        && head
            .windows(TABLE_ID.len() + 4)
            .any(|w| w.starts_with(TABLE_ID) && matches!(w[12..], [1 | 2, 0, 0, 0]))
}

/// The offsets of `setup-0` and `setup-1` from the loader's offset table.
fn find_table(file: &[u8]) -> Option<(u64, u64)> {
    let head = &file[..file.len().min(SCAN)];
    let mut from = 0;
    while let Some(i) = head[from..]
        .windows(TABLE_ID.len())
        .position(|w| w == TABLE_ID)
    {
        let at = from + i;
        if let Some(t) = parse_table(&file[at..]) {
            return Some(t);
        }
        from = at + 1;
    }
    None
}

fn parse_table(t: &[u8]) -> Option<(u64, u64)> {
    let u32_at = |p: usize| Some(u32::from_le_bytes(t.get(p..p + 4)?.try_into().ok()?));
    let u64_at = |p: usize| Some(u64::from_le_bytes(t.get(p..p + 8)?.try_into().ok()?));
    let crc = |n: usize| Some(crc32fast::hash(t.get(..n)?));
    // Version 1 has 32-bit fields; version 2 (6.5 and later) 64-bit offsets, aligned.
    let (crc_at, off0, off1) = match u32_at(12)? {
        1 => (40, u64::from(u32_at(32)?), u64::from(u32_at(36)?)),
        2 => (60, u64_at(40)?, u64_at(48)?),
        _ => return None,
    };
    (crc(crc_at)? == u32_at(crc_at)?).then_some((off0, off1))
}

fn u32_at(d: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        d.get(p..p + 4).ok_or_else(short)?.try_into().unwrap(),
    ))
}

fn u64_at(d: &[u8], p: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        d.get(p..p + 8).ok_or_else(short)?.try_into().unwrap(),
    ))
}

fn short() -> Error {
    Error::corrupt("Inno Setup data is truncated")
}

/// Reads one compressed block at `at`: returns its decoded bytes and where it ends.
fn read_block(d: &[u8], at: usize, block64: bool) -> Result<(Vec<u8>, usize)> {
    let hlen = if block64 { 9 } else { 5 };
    let crc = u32_at(d, at)?;
    let h = d.get(at + 4..at + 4 + hlen).ok_or_else(short)?;
    if crc32fast::hash(h) != crc {
        return Err(Error::corrupt("Inno Setup block header CRC mismatch"));
    }
    let stored = if block64 {
        u64::from_le_bytes(h[..8].try_into().unwrap())
    } else {
        u64::from(u32::from_le_bytes(h[..4].try_into().unwrap()))
    };
    if stored > MAX_BLOCK {
        return Err(Error::corrupt("Inno Setup block is implausibly large"));
    }
    let compressed = h[hlen - 1] != 0;
    let start = at + 4 + hlen;
    let end = start + stored as usize;
    let body = d.get(start..end).ok_or_else(short)?;
    let mut raw = Vec::with_capacity(body.len());
    for piece in body.chunks(4 + 4096) {
        if piece.len() < 5 {
            return Err(Error::corrupt("Inno Setup block piece is truncated"));
        }
        let (crc, data) = piece.split_at(4);
        if crc32fast::hash(data) != u32::from_le_bytes(crc.try_into().unwrap()) {
            return Err(Error::corrupt("Inno Setup block CRC mismatch"));
        }
        raw.extend_from_slice(data);
    }
    if !compressed {
        return Ok((raw, end));
    }
    if raw.len() < 5 {
        return Err(short());
    }
    let dict = u32::from_le_bytes(raw[1..5].try_into().unwrap()).min(MAX_DICT as u32);
    let lz = LzmaReader::new_with_props(&raw[5..], u64::MAX, raw[0], dict, None)
        .map_err(|_| Error::corrupt("invalid LZMA properties in an Inno Setup block"))?;
    let mut out = Vec::new();
    // Inno writes no end marker: the block ends with its input, so a decoder error past
    // the last whole symbol is the normal end.
    let _ = lz.take(MAX_BLOCK).read_to_end(&mut out);
    Ok((out, end))
}

/// A cursor over a decoded block.
struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let b = self
            .d
            .get(self.p..self.p + n)
            .ok_or_else(|| Error::corrupt("Inno Setup entries run past their block"))?;
        self.p += n;
        Ok(b)
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let n = u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()) as usize;
        self.bytes(n)
    }

    /// Reads one record: its strings and its raw bytes.
    fn record(&mut self, r: Rec) -> Result<(Vec<&'a [u8]>, &'a [u8])> {
        let mut s = Vec::with_capacity(r.strings as usize);
        for _ in 0..r.strings {
            s.push(self.string()?);
        }
        Ok((s, self.bytes(r.fixed as usize)?))
    }
}

/// Decodes a stored string: UTF-16LE in Unicode installers, else the ANSI code page.
fn text(b: &[u8], unicode: bool, page: CodePage) -> String {
    if unicode {
        let (units, _) = b.as_chunks::<2>();
        String::from_utf16_lossy(
            &units
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        )
    } else {
        page.decode(b)
    }
}

/// A destination such as `{app}\bin\tool.exe` as `app/bin/tool.exe`: constants become
/// folders named after them.
fn dest_name(dest: &str) -> String {
    let mut out = Vec::new();
    for part in dest.split(['\\', '/']) {
        let part = part.trim();
        if part.is_empty() || part == "." {
            continue;
        }
        let name = match part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
            Some(c) => c.replace(':', "_"),
            None => part.to_string(),
        };
        out.push(name);
    }
    out.join("/")
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let file = input.into_mem()?;
    let (off0, off1) = find_table(&file).ok_or(Error::NotArchive)?;
    let d: &[u8] = &file;
    let at = usize::try_from(off0).map_err(|_| short())?;
    let id_bytes = d.get(at..at + SETUP_ID_LEN).ok_or_else(short)?;
    let id_len = id_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(SETUP_ID_LEN);
    let id = String::from_utf8_lossy(&id_bytes[..id_len]).into_owned();
    let lay = LAYOUTS.iter().find(|l| l.id == id).ok_or_else(|| {
        Error::unsupported(match id.strip_prefix("Inno Setup Setup Data ") {
            Some(v) => format!("Inno Setup data format {v}"),
            None => "Inno Setup data with an unknown ID".to_string(),
        })
    })?;
    let mut p = at + SETUP_ID_LEN;
    if lay.enc_header > 0 {
        let crc = u32_at(d, p)?;
        let h = d
            .get(p + 4..p + 4 + lay.enc_header as usize)
            .ok_or_else(short)?;
        if crc32fast::hash(h) != crc {
            return Err(Error::corrupt("Inno Setup encryption header CRC mismatch"));
        }
        if h[0] == 2 {
            return Err(Error::unsupported(
                "Inno Setup installers whose setup data is encrypted",
            ));
        }
        p += 4 + lay.enc_header as usize;
    }
    let (b1, next) = read_block(d, p, lay.block64)?;
    let (b2, _) = read_block(d, next, lay.block64)?;
    let page = opts
        .code_page
        .or_else(|| CodePage::from_number(1252))
        .unwrap_or(CodePage::UTF8);

    let mut c = Cur { d: &b1, p: 0 };
    let (hs, hf) = c.record(lay.header)?;
    let count = |k: usize| -> Result<usize> {
        match lay.counts[k] {
            None => Ok(0),
            Some(o) => usize::try_from(u32_at(hf, o as usize)? as i32)
                .map_err(|_| Error::corrupt("negative Inno Setup entry count")),
        }
    };
    let method = match hf.get(lay.compress as usize) {
        Some(0) => Method::Stored,
        Some(1) => Method::Zlib,
        Some(2) => Method::Bzip2,
        Some(3) => Method::Lzma,
        Some(4) => Method::Lzma2,
        _ => return Err(Error::corrupt("unknown Inno Setup compression method")),
    };
    let app = hs
        .get(1)
        .map(|s| text(s, lay.unicode, page))
        .unwrap_or_default();

    for k in 0..FILES {
        for _ in 0..count(k)? {
            c.record(lay.skip[k])?;
        }
    }

    struct FileRec {
        name: String,
        langs: String,
        loc: usize,
        attrib: u32,
    }
    let n_locs = count(LOCATIONS)?;
    let mut files = Vec::new();
    for _ in 0..count(FILES)? {
        let (s, f) = c.record(lay.file)?;
        let loc = u32_at(f, lay.file_location as usize)? as i32;
        let uninst = lay
            .file_type
            .is_some_and(|o| f.get(o as usize).is_some_and(|&t| t == 1));
        if loc < 0 || uninst {
            continue;
        }
        let loc = loc as usize;
        if loc >= n_locs {
            return Err(Error::corrupt(
                "Inno Setup file entry points past the locations",
            ));
        }
        let dest = s
            .get(1)
            .map(|b| text(b, lay.unicode, page))
            .unwrap_or_default();
        let langs = s
            .get(lay.file_languages as usize)
            .map(|b| text(b, lay.unicode, page))
            .unwrap_or_default();
        files.push(FileRec {
            name: dest_name(&dest),
            langs,
            loc,
            attrib: u32_at(f, lay.file_attribs as usize)?,
        });
    }

    let l = &lay.loc;
    if n_locs > b2.len() / l.size as usize {
        return Err(Error::corrupt(
            "Inno Setup file locations run past their block",
        ));
    }
    let mut locations = Vec::with_capacity(n_locs);
    let mut c2 = Cur { d: &b2, p: 0 };
    for _ in 0..n_locs {
        let r = c2.bytes(l.size as usize)?;
        let flags = r
            .get(l.flags as usize..(l.flags + l.flags_len) as usize)
            .ok_or_else(short)?;
        let bit = |b: Option<u8>| {
            b.is_some_and(|b| {
                flags
                    .get(b as usize / 8)
                    .is_some_and(|x| x & (1 << (b % 8)) != 0)
            })
        };
        let hash_len = match l.hash_kind {
            Hash::Sha256 => 32,
            Hash::Sha1 => 20,
        };
        locations.push(Location {
            first_slice: u32_at(r, l.first_slice as usize)? as i32,
            start: if l.start64 {
                u64_at(r, l.start as usize)?
            } else {
                u64::from(u32_at(r, l.start as usize)?)
            },
            suboffset: u64_at(r, l.suboffset as usize)?,
            size: u64_at(r, l.original as usize)?,
            packed: u64_at(r, l.compressed as usize)?,
            hash: r
                .get(l.hash as usize..l.hash as usize + hash_len)
                .ok_or_else(short)?
                .to_vec(),
            hash_kind: l.hash_kind,
            mtime: u64_at(r, l.time as usize)?,
            call: bit(l.call),
            encrypted: bit(l.encrypted),
            compressed: bit(l.chunk_compressed),
        });
    }

    // Names shared by entries for different languages get the languages added.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for f in &files {
        *seen.entry(f.name.clone()).or_default() += 1;
    }
    let mut entries = Vec::with_capacity(files.len());
    let mut items = Vec::with_capacity(files.len());
    let mut chunks: HashMap<(i32, u64), usize> = HashMap::new();
    let mut units: Vec<Unit> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        let loc = &locations[f.loc];
        let mut name = f.name.clone();
        if seen[&f.name] > 1 && !f.langs.is_empty() {
            name = with_suffix(&name, &f.langs);
        }
        let key = (loc.first_slice, loc.start);
        let unit = *chunks.entry(key).or_insert_with(|| {
            units.push(Unit {
                entries: Vec::new(),
                encrypted: loc.encrypted,
            });
            units.len() - 1
        });
        units[unit].entries.push(i);
        entries.push(Entry {
            name,
            is_dir: false,
            size: Some(loc.size),
            packed_size: None,
            mtime: Some(loc.mtime),
            ctime: None,
            atime: None,
            attrib: Some(f.attrib),
            crc: None,
            method: Some(method.name().to_string()),
            encrypted: loc.encrypted,
            is_anti: false,
            block: Some(unit),
            link: None,
            comment: None,
            raw_name: None,
        });
        items.push(f.loc);
    }
    // Within a chunk, files are decoded in the order of their data; the chunk's packed
    // size is put on its first file, as 7-Zip does for a solid block.
    for u in &mut units {
        u.entries
            .sort_by_key(|&e| (locations[items[e]].suboffset, e));
        for (k, &e) in u.entries.iter().enumerate() {
            let packed = if k == 0 {
                locations[items[e]].packed
            } else {
                0
            };
            entries[e].packed_size = Some(packed);
        }
    }
    let version = id
        .trim_start_matches("Inno Setup Setup Data (")
        .replace(") (u)", "")
        .trim_end_matches(')')
        .to_string();
    Ok(Box::new(Inno {
        file,
        data_at: off1,
        version,
        method,
        app,
        locations,
        items,
        entries,
        units,
    }))
}

/// `name` with ` (suffix)` before its extension.
fn with_suffix(name: &str, suffix: &str) -> String {
    let base = name.rsplit_once('/').map_or(0, |(d, _)| d.len() + 1);
    match name[base..].rfind('.') {
        Some(dot) if dot > 0 => {
            format!("{} ({suffix}){}", &name[..base + dot], &name[base + dot..])
        }
        _ => format!("{name} ({suffix})"),
    }
}

impl Inno {
    /// A reader over the decoded bytes of `loc`'s chunk, from its start.
    fn open_chunk(&self, loc: &Location, chunk_len: u64) -> Result<Box<dyn Read + Send>> {
        if self.data_at == 0 {
            return Err(Error::unsupported(
                "Inno Setup installers with their data in setup-N.bin files",
            ));
        }
        if loc.encrypted {
            return Err(Error::unsupported("encrypted Inno Setup files"));
        }
        let at = self.data_at.checked_add(loc.start).ok_or_else(short)?;
        let id = self.file.sub(at..at + 4)?;
        if id[..] != CHUNK_ID[..] {
            return Err(Error::corrupt("Inno Setup chunk has no zlb ID"));
        }
        let end = (at + 4).checked_add(loc.packed).ok_or_else(short)?;
        let packed = self.file.sub(at + 4..end)?;
        if !loc.compressed {
            return Ok(Box::new(packed.reader()));
        }
        let dict_cap = chunk_len.clamp(4096, MAX_DICT) as u32;
        Ok(match self.method {
            Method::Stored => Box::new(packed.reader()),
            Method::Zlib => Box::new(flate2::read::ZlibDecoder::new(packed.reader())),
            Method::Bzip2 => Box::new(bzip2::read::BzDecoder::new(packed.reader())),
            Method::Lzma => {
                let props = packed.get(..5).ok_or_else(short)?;
                let dict = u32::from_le_bytes(props[1..5].try_into().unwrap()).min(dict_cap);
                let rest = packed.sub(5..packed.len() as u64)?;
                Box::new(
                    LzmaReader::new_with_props(rest.reader(), u64::MAX, props[0], dict, None)
                        .map_err(|_| Error::corrupt("invalid LZMA properties in an Inno chunk"))?,
                )
            }
            Method::Lzma2 => {
                let prop = *packed.first().ok_or_else(short)?;
                if prop > 40 {
                    return Err(Error::corrupt("invalid LZMA2 dictionary in an Inno chunk"));
                }
                let dict = if prop == 40 {
                    u32::MAX
                } else {
                    (2 | u32::from(prop & 1)) << (prop / 2 + 11)
                };
                let rest = packed.sub(1..packed.len() as u64)?;
                Box::new(Lzma2Reader::new(rest.reader(), dict.min(dict_cap), None))
            }
        })
    }
}

impl Archive for Inno {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let u = &self.units[unit];
        let chunk_len = u
            .entries
            .iter()
            .map(|&e| {
                let l = &self.locations[self.items[e]];
                l.suboffset.saturating_add(l.size)
            })
            .max()
            .unwrap_or(0);
        let mut dec: Option<(Box<dyn Read + Send>, u64)> = None;
        for &e in &u.entries {
            let loc = &self.locations[self.items[e]];
            if dec.as_ref().is_none_or(|(_, pos)| *pos > loc.suboffset) {
                dec = Some((self.open_chunk(loc, chunk_len)?, 0));
            }
            let (r, pos) = dec.as_mut().unwrap();
            let gap = loc.suboffset - *pos;
            if super::data::skip(&mut **r, gap)? != gap {
                return Err(Error::corrupt("Inno Setup chunk ends before a file"));
            }
            *pos = loc.suboffset;
            let body = Exact {
                inner: &mut **r,
                left: loc.size,
            };
            let mut v = Verify::new(Uncall::new(body, loc.call), loc);
            let flow = f(e, &mut v)?;
            let mut sink = [0u8; 1 << 14];
            while v.read(&mut sink).map_err(Error::from_codec)? > 0 {}
            *pos = loc.suboffset.saturating_add(loc.size);
            if flow == Flow::Stop {
                break;
            }
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![
            ("SubType", format!("Inno Setup {}", self.version)),
            ("Method", self.method.name().to_string()),
            (
                "Solid",
                if self.units.len() < self.entries.len() {
                    "+"
                } else {
                    "-"
                }
                .to_string(),
            ),
        ];
        if !self.app.is_empty() {
            p.push(("Title", self.app.clone()));
        }
        p
    }

    fn columns(&self) -> Columns {
        Columns {
            method: true,
            block: true,
            ..Columns::default()
        }
    }

    fn verifies_data(&self) -> bool {
        true
    }
}

/// Exactly `left` bytes of `inner`; ending early is corrupt data.
struct Exact<'a> {
    inner: &'a mut (dyn Read + Send),
    left: u64,
}

impl Read for Exact<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Inno Setup chunk ends inside a file",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Undoes Inno's x86 call filter, which made the targets of E8 and E9 instructions
/// absolute within each 64 KiB block of a file. A target is converted only when its high
/// byte is 0x00 or 0xFF; that byte is inverted when the 24-bit offset is negative.
struct Uncall<R> {
    inner: R,
    on: bool,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    addr: u32,
}

impl<R: Read> Uncall<R> {
    fn new(inner: R, on: bool) -> Self {
        Uncall {
            inner,
            on,
            buf: if on { vec![0; CALL_BLOCK] } else { Vec::new() },
            pos: 0,
            len: 0,
            addr: 0,
        }
    }
}

impl<R: Read> Read for Uncall<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if !self.on {
            return self.inner.read(out);
        }
        if self.pos == self.len {
            let mut n = 0;
            while n < CALL_BLOCK {
                let k = self.inner.read(&mut self.buf[n..])?;
                if k == 0 {
                    break;
                }
                n += k;
            }
            if n == 0 {
                return Ok(0);
            }
            uncall(&mut self.buf[..n], self.addr);
            self.addr = self.addr.wrapping_add(n as u32);
            self.pos = 0;
            self.len = n;
        }
        let k = out.len().min(self.len - self.pos);
        out[..k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
        self.pos += k;
        Ok(k)
    }
}

fn uncall(b: &mut [u8], base: u32) {
    if b.len() < 5 {
        return;
    }
    let end = b.len() - 4;
    let mut i = 0;
    while i < end {
        if b[i] != 0xE8 && b[i] != 0xE9 {
            i += 1;
            continue;
        }
        i += 1;
        if b[i + 3] == 0 || b[i + 3] == 0xFF {
            let addr = base.wrapping_add(i as u32 + 4) & 0xFF_FFFF;
            let rel = (u32::from(b[i]) | u32::from(b[i + 1]) << 8 | u32::from(b[i + 2]) << 16)
                .wrapping_sub(addr);
            if rel & 0x80_0000 != 0 {
                b[i + 3] = !b[i + 3];
            }
            b[i..i + 3].copy_from_slice(&rel.to_le_bytes()[..3]);
        }
        i += 4;
    }
}

enum Hasher {
    Sha256(Sha256),
    Sha1(Sha1),
}

/// Checks a file's hash once all of it has been read.
struct Verify<'a, R> {
    inner: R,
    hasher: Option<Hasher>,
    want: &'a [u8],
}

impl<'a, R: Read> Verify<'a, R> {
    fn new(inner: R, loc: &'a Location) -> Self {
        let hasher = match loc.hash_kind {
            Hash::Sha256 => Hasher::Sha256(Sha256::new()),
            Hash::Sha1 => Hasher::Sha1(Sha1::new()),
        };
        Verify {
            inner,
            hasher: Some(hasher),
            want: &loc.hash,
        }
    }
}

impl<R: Read> Read for Verify<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        match (n, &mut self.hasher) {
            (0, h @ Some(_)) => {
                let got = match h.take().unwrap() {
                    Hasher::Sha256(h) => h.finalize().to_vec(),
                    Hasher::Sha1(h) => h.finalize().to_vec(),
                };
                if got != self.want {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Inno Setup file hash mismatch",
                    ));
                }
            }
            (_, Some(Hasher::Sha256(h))) => h.update(&buf[..n]),
            (_, Some(Hasher::Sha1(h))) => h.update(&buf[..n]),
            (_, None) => {}
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_become_folders() {
        assert_eq!(dest_name("{app}\\bin\\tool.exe"), "app/bin/tool.exe");
        assert_eq!(dest_name("{code:GetDir}\\x.txt"), "code_GetDir/x.txt");
        assert_eq!(
            with_suffix("app/readme.txt", "german"),
            "app/readme (german).txt"
        );
        assert_eq!(with_suffix("app/README", "de"), "app/README (de)");
    }

    #[test]
    fn call_filter_round_trip() {
        // E8 with a forward 24-bit target, encoded as Inno does: target + position.
        let mut b = vec![0x90, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90];
        let addr = 2 + 4; // the operand starts at 2; the next instruction at 6
        let enc = 0x10u32 + addr;
        b[2..5].copy_from_slice(&enc.to_le_bytes()[..3]);
        uncall(&mut b, 0);
        assert_eq!(b, [0x90, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90]);
    }
}
