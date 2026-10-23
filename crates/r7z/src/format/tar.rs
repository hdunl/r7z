//! tar: ustar, GNU (long names, old sparse, base-256 numbers) and pax (extended headers,
//! sparse 0.1/1.0) for reading; ustar + pax extensions for writing.
//!
//! Over random-access bytes every entry is its own unit. Inside a compressor the archive is
//! scanned once while the decoded bytes are kept in memory (up to the budget); if they fit,
//! extraction reads from memory instead of decompressing a second time.

use std::collections::HashMap;
use std::io::{self, Read, Write};

use super::data::{self, Input, Opener, Slice};
use super::{
    Archive, CodePage, Ctx, Entry, EntryFn, Flow, Format, Link, NameCoding, OpenOptions, Signature,
    Unit,
};
use crate::error::{Error, Result};
use crate::ops::create::Item;
use crate::sevenz::attr;
use crate::util::codepage;
use crate::util::time::{filetime_to_unix, unix_to_filetime};

#[path = "tar_update.rs"]
mod rewrite;

/// Carries out an update: rewrites the tar stream from `open` into `tmp`, compressed with
/// `compress` when given.
pub fn update(
    open: Opener,
    tmp: &std::path::Path,
    plan: &crate::ops::update::Plan,
    compress: Option<super::write::Compressor>,
    opts: &super::write::WriteOptions,
    progress: &dyn crate::ops::create::Progress,
) -> Result<crate::ops::update::Outcome> {
    rewrite::update(open, tmp, plan, compress, opts, progress)
}

pub const FORMAT: Format = Format {
    name: "tar",
    aliases: &["ustar", "pax", "gnutar"],
    extensions: &["tar", "ova"],
    signatures: &[Signature::at(257, b"ustar")],
    detect: Some(|h| h.len() >= 512 && checksum_ok(&h[..512])),
    write: true,
    stream: false,
    sequential: true,
    open,
};

const BLOCK: usize = 512;

/// Where an entry's bytes live in the tar stream, possibly as a sparse map.
#[derive(Clone, Debug)]
struct DataRef {
    offset: u64,
    /// Bytes stored in the archive.
    stored: u64,
    /// (logical offset, length) segments; empty for ordinary files.
    sparse: Vec<(u64, u64)>,
    /// Inline data (symlink targets).
    inline: Option<Vec<u8>>,
}

pub struct Tar {
    entries: Vec<Entry>,
    refs: Vec<Option<DataRef>>,
    units: Vec<Unit>,
    source: Source,
    end: u64,
    /// Recovery opens: headers skipped and where the data stopped.
    notes: Vec<String>,
    coding: Option<NameCoding>,
}

enum Source {
    Mem(Slice),
    Stream(Opener),
}

fn octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        // GNU base-256: big-endian two's complement, first byte's top bit is the marker.
        if field[0] & 0x40 != 0 {
            return None; // negative
        }
        let mut v: u64 = (field[0] & 0x3F) as u64;
        for &b in &field[1..] {
            v = v.checked_mul(256)?.checked_add(b as u64)?;
        }
        return Some(v);
    }
    let s: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ' || b == 0)
        .take_while(|&b| (b'0'..=b'7').contains(&b))
        .collect();
    if s.is_empty() {
        return Some(0);
    }
    let mut v = 0u64;
    for b in s {
        v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

fn checksum_ok(h: &[u8]) -> bool {
    let Some(stored) = octal(&h[148..156]) else {
        return false;
    };
    if h.iter().all(|&b| b == 0) {
        return false;
    }
    let mut unsigned = 0u64;
    let mut signed = 0i64;
    for (i, &b) in h[..BLOCK].iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += b as u64;
        signed += b as i8 as i64;
    }
    stored == unsigned || stored as i64 == signed
}

fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

fn text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b.iter().map(|&c| c as char).collect(),
    }
}

/// Parses pax `len key=value\n` records.
fn pax_records(data: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    let mut p = 0;
    while p < data.len() {
        let Some(sp) = data[p..].iter().position(|&b| b == b' ') else {
            break;
        };
        let Some(len) = std::str::from_utf8(&data[p..p + sp])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            break;
        };
        if len <= sp + 1 || p + len > data.len() {
            break;
        }
        let rec = &data[p + sp + 1..p + len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            out.insert(text(&rec[..eq]), rec[eq + 1..].to_vec());
        }
        p += len;
    }
    out
}

/// A pax time `seconds[.fraction]` as FILETIME.
fn pax_time(v: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(v).ok()?;
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = secs.parse().ok()?;
    let mut ticks = 0u64;
    for (i, c) in frac.chars().take(7).enumerate() {
        ticks += c.to_digit(10)? as u64 * 10u64.pow(6 - i as u32);
    }
    Some(unix_to_filetime(secs).saturating_add(ticks))
}

/// Reads a tar stream sequentially, tracking the absolute position.
struct Cursor<'a> {
    r: &'a mut dyn Read,
    pos: u64,
    /// Decoded bytes kept for random access, while under budget.
    cache: Option<Vec<u8>>,
    budget: u64,
    /// Recovery: notes on damage worked around; `None` fails on damage instead.
    lenient: Option<Vec<String>>,
    /// Link targets that are not UTF-8, by entry index, decoded with the names later.
    legacy_links: Vec<(usize, Vec<u8>)>,
}

impl Cursor<'_> {
    fn read_block(&mut self, buf: &mut [u8; BLOCK]) -> Result<bool> {
        let mut n = 0;
        while n < BLOCK {
            let k = data::read_some(self.r, &mut buf[n..])?;
            if k == 0 {
                break;
            }
            n += k;
        }
        self.keep(&buf[..n]);
        self.pos += n as u64;
        if n == 0 {
            return Ok(false);
        }
        if n < BLOCK {
            return Err(Error::corrupt("tar header truncated"));
        }
        Ok(true)
    }

    fn keep(&mut self, b: &[u8]) {
        if let Some(c) = &mut self.cache {
            if (c.len() + b.len()) as u64 > self.budget {
                self.cache = None;
            } else {
                c.extend_from_slice(b);
            }
        }
    }

    fn read_vec(&mut self, n: u64) -> Result<Vec<u8>> {
        if n > 64 << 20 {
            return Err(Error::corrupt("tar extended header is implausibly large"));
        }
        let padded = (n as usize).div_ceil(BLOCK) * BLOCK;
        let mut v = vec![0u8; padded];
        data::read_exact(self.r, &mut v)?;
        self.keep(&v);
        self.pos += padded as u64;
        v.truncate(n as usize);
        Ok(v)
    }

    /// Skips up to `n` bytes; returns how many were there.
    fn skip_some(&mut self, n: u64) -> Result<u64> {
        if self.cache.is_some() {
            let mut buf = vec![0u8; 1 << 16];
            let mut left = n;
            while left > 0 {
                let k = data::read_some(self.r, &mut buf[..left.min(1 << 16) as usize])?;
                if k == 0 {
                    break;
                }
                self.keep(&buf[..k]);
                left -= k as u64;
            }
            self.pos += n - left;
            return Ok(n - left);
        }
        let got = data::skip(self.r, n)?;
        self.pos += got;
        Ok(got)
    }

    fn note(&mut self, msg: String) {
        if let Some(n) = &mut self.lenient {
            n.push(msg);
        }
    }

    fn skip(&mut self, n: u64) -> Result<()> {
        if self.cache.is_some() {
            let mut buf = vec![0u8; 1 << 16];
            let mut left = n;
            while left > 0 {
                let k = data::read_some(self.r, &mut buf[..left.min(1 << 16) as usize])?;
                if k == 0 {
                    return Err(Error::corrupt("tar data truncated"));
                }
                self.keep(&buf[..k]);
                left -= k as u64;
            }
        } else if data::skip(self.r, n)? != n {
            return Err(Error::corrupt("tar data truncated"));
        }
        self.pos += n;
        Ok(())
    }
}

#[derive(Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    pax: HashMap<String, Vec<u8>>,
}

/// Where a record's bytes sit in the stream, for rewriting it (see `tar_update`).
#[derive(Clone, Copy, Debug)]
enum Span {
    /// An entry: its extension headers and main header (`start..data`), its data
    /// (`data..end`, padded to whole blocks).
    Entry {
        index: usize,
        start: u64,
        data: u64,
        end: u64,
    },
    /// A pax global header, which applies to the entries after it.
    Global { start: u64, end: u64 },
}

impl Span {
    fn end(&self) -> u64 {
        match *self {
            Span::Entry { end, .. } | Span::Global { end, .. } => end,
        }
    }
}

fn parse(
    cur: &mut Cursor<'_>,
    spans: Option<&mut Vec<Span>>,
) -> Result<(Vec<Entry>, Vec<Option<DataRef>>)> {
    let mut entries = Vec::new();
    let mut refs = Vec::new();
    match parse_into(cur, &mut entries, &mut refs, spans) {
        Ok(()) => Ok((entries, refs)),
        // Recovery keeps the entries before the damage.
        Err(e) if cur.lenient.is_some() && !matches!(e, Error::Cancelled) => {
            if entries.is_empty() && matches!(e, Error::NotArchive) {
                return Err(e);
            }
            cur.note(format!(
                "reading stopped at offset {}: {}",
                cur.pos,
                match &e {
                    Error::Corrupt(m) => m.clone(),
                    other => other.to_string(),
                }
            ));
            Ok((entries, refs))
        }
        Err(e) => Err(e),
    }
}

/// Finds the next valid header after a damaged one (recovery). Damage in an earlier stream
/// can shift everything after it by any number of bytes, so the search slides one byte at
/// a time, checking the `ustar` magic before the checksum. Returns false at the end of
/// the data.
fn resync(cur: &mut Cursor<'_>, h: &mut [u8; BLOCK]) -> Result<bool> {
    let from = cur.pos - BLOCK as u64;
    let mut window = *h;
    let mut byte = [0u8; 1];
    loop {
        if data::read_some(cur.r, &mut byte)? == 0 {
            cur.note(format!(
                "the header at offset {from} is damaged and no valid header follows it"
            ));
            return Ok(false);
        }
        cur.keep(&byte);
        cur.pos += 1;
        window.copy_within(1.., 0);
        window[BLOCK - 1] = byte[0];
        if window[257..262] == *b"ustar" && checksum_ok(&window) {
            *h = window;
            cur.note(format!(
                "the header at offset {from} is damaged; skipped {} bytes to the next valid header",
                cur.pos - BLOCK as u64 - from
            ));
            return Ok(true);
        }
    }
}

fn parse_into(
    cur: &mut Cursor<'_>,
    entries: &mut Vec<Entry>,
    refs: &mut Vec<Option<DataRef>>,
    mut spans: Option<&mut Vec<Span>>,
) -> Result<()> {
    let mut global: HashMap<String, Vec<u8>> = HashMap::new();
    let mut pend = Pending::default();
    let mut h = [0u8; BLOCK];
    // Where the current record starts: its first extension header, or its main header.
    let mut record_start: Option<u64> = None;
    loop {
        let header_at = cur.pos;
        if !cur.read_block(&mut h)? {
            break;
        }
        if h.iter().all(|&b| b == 0) {
            // End of archive: one or two zero blocks (both count toward the physical
            // size). Drain the rest to verify the compressed container's checksum.
            let mut second = [0u8; BLOCK];
            let mut n = 0;
            while n < BLOCK {
                let k = data::read_some(cur.r, &mut second[n..])?;
                if k == 0 {
                    break;
                }
                n += k;
            }
            if n == BLOCK && second.iter().all(|&b| b == 0) {
                cur.pos += BLOCK as u64;
            }
            let mut rest = [0u8; 1 << 14];
            while data::read_some(cur.r, &mut rest)? > 0 {}
            break;
        }
        if !checksum_ok(&h) {
            if cur.lenient.is_some() {
                // What came before this header no longer applies to whatever follows.
                pend = Pending::default();
                if !resync(cur, &mut h)? {
                    break;
                }
            } else if entries.is_empty() {
                return Err(Error::NotArchive);
            } else {
                return Err(Error::corrupt(format!(
                    "tar header checksum mismatch at offset {}",
                    cur.pos - BLOCK as u64
                )));
            }
        }
        let typ = h[156];
        let mut size = octal(&h[124..136]).ok_or_else(|| Error::corrupt("bad tar size field"))?;
        match typ {
            b'L' => {
                pend.long_name = Some(cstr(&cur.read_vec(size)?).to_vec());
                record_start.get_or_insert(header_at);
                continue;
            }
            b'K' => {
                pend.long_link = Some(cstr(&cur.read_vec(size)?).to_vec());
                record_start.get_or_insert(header_at);
                continue;
            }
            b'x' | b'X' => {
                let recs = pax_records(&cur.read_vec(size)?);
                pend.pax.extend(recs);
                record_start.get_or_insert(header_at);
                continue;
            }
            b'g' => {
                global.extend(pax_records(&cur.read_vec(size)?));
                if let Some(spans) = spans.as_deref_mut() {
                    spans.push(Span::Global {
                        start: header_at,
                        end: cur.pos,
                    });
                }
                continue;
            }
            _ => {}
        }
        let mut pax = global.clone();
        pax.extend(std::mem::take(&mut pend.pax));
        let magic = &h[257..263];
        let is_ustar = magic == b"ustar\0";
        let is_gnu = magic == b"ustar ";
        let mut name_bytes = cstr(&h[0..100]).to_vec();
        if is_ustar && h[345] != 0 {
            let mut full = cstr(&h[345..500]).to_vec();
            full.push(b'/');
            full.extend_from_slice(&name_bytes);
            name_bytes = full;
        }
        if let Some(n) = pend.long_name.take() {
            name_bytes = n;
        }
        if let Some(p) = pax.get("path") {
            name_bytes = p.clone();
        }
        let mut link_bytes = cstr(&h[157..257]).to_vec();
        if let Some(l) = pend.long_link.take() {
            link_bytes = l;
        }
        if let Some(l) = pax.get("linkpath") {
            link_bytes = l.clone();
        }
        if let Some(s) = pax
            .get("size")
            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
        {
            size = s;
        }
        let mode = octal(&h[100..108]).unwrap_or(0) as u32 & 0o7777;
        let mut name = text(&name_bytes);
        // Names that are not UTF-8 come from old writers using a local code page.
        let legacy_name = std::str::from_utf8(&name_bytes)
            .is_err()
            .then_some(name_bytes);
        if std::str::from_utf8(&link_bytes).is_err() && matches!(typ, b'1' | b'2') {
            cur.legacy_links.push((entries.len(), link_bytes.clone()));
        }
        let mut is_dir = typ == b'5' || (name.ends_with('/') && matches!(typ, b'0' | 0));
        if typ == b'D' {
            is_dir = true; // GNU dump directory: the data lists names; skip it.
        }
        while name.ends_with('/') && name.len() > 1 {
            name.pop();
        }
        while let Some(rest) = name.strip_prefix("./") {
            name = rest.to_string();
        }
        let mtime = pax
            .get("mtime")
            .and_then(|v| pax_time(v))
            .or_else(|| octal(&h[136..148]).map(|t| unix_to_filetime(t as i64)));
        let atime = pax.get("atime").and_then(|v| pax_time(v)).or_else(|| {
            if is_gnu {
                octal(&h[345..357])
                    .filter(|&t| t > 0)
                    .map(|t| unix_to_filetime(t as i64))
            } else {
                None
            }
        });
        let ctime = pax.get("ctime").and_then(|v| pax_time(v)).or_else(|| {
            if is_gnu {
                octal(&h[357..369])
                    .filter(|&t| t > 0)
                    .map(|t| unix_to_filetime(t as i64))
            } else {
                None
            }
        });
        let mut a = attr::UNIX_EXTENSION | (mode << 16);
        let kind_bits = match typ {
            b'5' | b'D' => 0o040000,
            b'2' => 0o120000,
            b'3' => 0o020000,
            b'4' => 0o060000,
            b'6' => 0o010000,
            _ => 0o100000,
        };
        a |= kind_bits << 16;
        if is_dir {
            a |= attr::DIRECTORY;
        }
        let mut e = Entry {
            name,
            is_dir,
            size: Some(if is_dir { 0 } else { size }),
            packed_size: Some(if is_dir { 0 } else { size }),
            mtime,
            atime,
            ctime,
            attrib: Some(a),
            raw_name: legacy_name,
            ..Default::default()
        };
        let mut dref = None;
        match typ {
            b'1' => {
                e.link = Some(Link::Hard(
                    text(&link_bytes).trim_start_matches("./").to_string(),
                ));
                e.size = Some(0);
                if size > 0 {
                    // pax permits data on hard links; keep it as a regular file.
                    e.link = None;
                    e.size = Some(size);
                    dref = Some(DataRef {
                        offset: 0,
                        stored: size,
                        sparse: Vec::new(),
                        inline: None,
                    });
                }
            }
            b'2' => {
                let target = text(&link_bytes);
                e.size = Some(target.len() as u64);
                e.packed_size = Some(0);
                dref = Some(DataRef {
                    offset: 0,
                    stored: 0,
                    sparse: Vec::new(),
                    inline: Some(target.clone().into_bytes()),
                });
                e.link = Some(Link::Symbolic(target));
            }
            b'3' | b'4' | b'6' | b'V' => {
                e.size = Some(0);
                if typ == b'V' {
                    // Volume label: listed by 7-Zip as an entry; it has no data.
                    e.packed_size = Some(0);
                }
            }
            b'S' => {
                // Old GNU sparse: map in the header (and extension blocks), real size at 483.
                let mut map = Vec::new();
                let mut push = |b: &[u8]| -> Result<()> {
                    let off = octal(&b[..12]).ok_or_else(|| Error::corrupt("bad sparse map"))?;
                    let len = octal(&b[12..24]).ok_or_else(|| Error::corrupt("bad sparse map"))?;
                    if off != 0 || len != 0 {
                        map.push((off, len));
                    }
                    Ok(())
                };
                for i in 0..4 {
                    push(&h[386 + i * 24..386 + (i + 1) * 24])?;
                }
                let mut extended = h[482] != 0;
                let real = octal(&h[483..495]).ok_or_else(|| Error::corrupt("bad sparse size"))?;
                let mut ext = [0u8; BLOCK];
                while extended {
                    if !cur.read_block(&mut ext)? {
                        return Err(Error::corrupt("sparse map truncated"));
                    }
                    for i in 0..21 {
                        push(&ext[i * 24..(i + 1) * 24])?;
                    }
                    extended = ext[504] != 0;
                }
                e.size = Some(real);
                dref = Some(DataRef {
                    offset: 0,
                    stored: size,
                    sparse: map,
                    inline: None,
                });
            }
            _ if is_dir => {}
            _ => {
                let major = pax.get("GNU.sparse.major").map(|v| text(v));
                let real = pax
                    .get("GNU.sparse.realsize")
                    .or_else(|| pax.get("GNU.sparse.size"))
                    .and_then(|v| std::str::from_utf8(v).ok()?.parse::<u64>().ok());
                if let Some(n) = pax.get("GNU.sparse.name") {
                    e.name = text(n).trim_end_matches('/').to_string();
                    e.raw_name = None;
                }
                if major.as_deref() == Some("1") {
                    // Sparse 1.0: the map is decimal text at the start of the data.
                    let (map, used) = read_sparse10(cur, size)?;
                    e.size = Some(real.unwrap_or(size));
                    dref = Some(DataRef {
                        offset: 0,
                        stored: size - used,
                        sparse: map,
                        inline: None,
                    });
                    size -= used;
                } else if let Some(m) = pax.get("GNU.sparse.map") {
                    let nums: Vec<u64> = text(m)
                        .split(',')
                        .filter_map(|x| x.trim().parse().ok())
                        .collect();
                    let map = nums
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| (c[0], c[1]))
                        .collect();
                    e.size = Some(real.unwrap_or(size));
                    dref = Some(DataRef {
                        offset: 0,
                        stored: size,
                        sparse: map,
                        inline: None,
                    });
                } else {
                    dref = Some(DataRef {
                        offset: 0,
                        stored: size,
                        sparse: Vec::new(),
                        inline: None,
                    });
                }
            }
        }
        // Every header type is followed by `size` bytes (padded), even when they carry
        // nothing r7z extracts (directories, devices).
        let at = cur.pos;
        let padded = size.div_ceil(BLOCK as u64) * BLOCK as u64;
        if cur.lenient.is_some() {
            let got = cur.skip_some(padded)?;
            if got < padded {
                // Cut off: keep what is there; extraction reports the entry as partial.
                if let Some(d) = &mut dref {
                    if d.inline.is_none() {
                        d.offset = at;
                        d.stored = got.min(size);
                    }
                }
                cur.note(format!(
                    "{}: the data ends inside this entry ({} of {size} bytes present)",
                    e.name,
                    got.min(size)
                ));
                entries.push(e);
                refs.push(dref);
                break;
            }
        } else {
            cur.skip(padded)?;
        }
        if let Some(d) = &mut dref {
            if d.inline.is_none() {
                d.offset = at;
                d.stored = size;
            }
        }
        let start = record_start.take().unwrap_or(header_at);
        if let Some(spans) = spans.as_deref_mut() {
            spans.push(Span::Entry {
                index: entries.len(),
                start,
                data: at,
                end: cur.pos,
            });
        }
        entries.push(e);
        refs.push(dref);
    }
    Ok(())
}

/// Reads a sparse 1.0 map (decimal lines, padded to a block) from the start of an entry's
/// `size` data bytes. Returns the map and the bytes it occupied, which never exceed `size`.
fn read_sparse10(cur: &mut Cursor<'_>, size: u64) -> Result<(Vec<(u64, u64)>, u64)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut nums: Vec<u64> = Vec::new();
    let mut want: Option<usize> = None;
    let mut consumed = 0u64;
    let mut block = [0u8; BLOCK];
    loop {
        if consumed >= size {
            return Err(Error::corrupt("sparse map runs past the data"));
        }
        if !cur.read_block(&mut block)? {
            return Err(Error::corrupt("sparse map truncated"));
        }
        consumed += BLOCK as u64;
        if consumed > size {
            return Err(Error::corrupt("sparse map runs past the data"));
        }
        buf.extend_from_slice(&block);
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let v: u64 = std::str::from_utf8(&line[..line.len() - 1])
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::corrupt("bad sparse map number"))?;
            if want.is_none() {
                if v > 1 << 20 {
                    return Err(Error::corrupt("sparse map too large"));
                }
                want = Some(v as usize * 2);
            } else {
                nums.push(v);
            }
            if want == Some(nums.len()) {
                let map = nums
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| (c[0], c[1]))
                    .collect();
                return Ok((map, consumed));
            }
        }
    }
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let lenient = opts.recover.then(Vec::new);
    let notes: Vec<String>;
    let links: Vec<(usize, Vec<u8>)>;
    let (mut entries, mut refs, source, end) = match input {
        Input::Mem(s) => {
            let mut r = s.reader();
            let mut cur = Cursor {
                r: &mut r,
                pos: 0,
                cache: None,
                budget: 0,
                lenient,
                legacy_links: Vec::new(),
            };
            let (e, refs) = parse(&mut cur, None)?;
            let end = cur.pos;
            notes = cur.lenient.take().unwrap_or_default();
            links = std::mem::take(&mut cur.legacy_links);
            (e, refs, Source::Mem(s), end)
        }
        Input::Stream { open, size_hint } => {
            let mut r = open()?;
            // Beyond this the archive is decompressed a second time for extraction rather
            // than held in memory.
            let budget = data::memory_budget().min(1 << 30);
            let mut cur = Cursor {
                r: &mut *r,
                pos: 0,
                cache: Some(Vec::with_capacity(
                    size_hint.unwrap_or(0).min(budget) as usize
                )),
                budget,
                lenient,
                legacy_links: Vec::new(),
            };
            let (e, refs) = parse(&mut cur, None)?;
            let end = cur.pos;
            notes = cur.lenient.take().unwrap_or_default();
            links = std::mem::take(&mut cur.legacy_links);
            let src = match cur.cache.take() {
                Some(v) => Source::Mem(Slice::from_vec(v)),
                None => Source::Stream(open),
            };
            (e, refs, src, end)
        }
        volume @ Input::Volume(_) => return open(Input::Mem(volume.into_mem()?), opts),
    };
    if entries.is_empty() && (end == 0 || opts.recover) {
        return Err(Error::NotArchive);
    }
    let coding = decode_legacy(&mut entries, &mut refs, &links, opts.code_page);
    let with_data: Vec<usize> = (0..entries.len()).filter(|&i| refs[i].is_some()).collect();
    let units = match source {
        Source::Mem(_) => with_data
            .iter()
            .map(|&i| Unit {
                entries: vec![i],
                encrypted: false,
            })
            .collect(),
        Source::Stream(_) => vec![Unit {
            entries: with_data,
            encrypted: false,
        }],
    };
    Ok(Box::new(Tar {
        entries,
        refs,
        units,
        source,
        end,
        notes,
        coding,
    }))
}

/// Decodes the names (`Entry::raw_name`) and link targets that are not UTF-8 with one code
/// page for the whole archive.
fn decode_legacy(
    entries: &mut [Entry],
    refs: &mut [Option<DataRef>],
    links: &[(usize, Vec<u8>)],
    forced: Option<CodePage>,
) -> Option<NameCoding> {
    let texts = || {
        entries
            .iter()
            .filter_map(|e| e.raw_name.as_deref())
            .chain(links.iter().map(|(_, l)| l.as_slice()))
    };
    texts().next()?;
    let coding = codepage::choose(forced, texts());
    for e in entries.iter_mut() {
        if let Some(raw) = &e.raw_name {
            let mut name = coding.page.decode(raw);
            while name.ends_with('/') && name.len() > 1 {
                name.pop();
            }
            while let Some(rest) = name.strip_prefix("./") {
                name = rest.to_string();
            }
            e.name = name;
        }
    }
    for (i, raw) in links {
        let target = coding.page.decode(raw);
        let e = &mut entries[*i];
        match &mut e.link {
            Some(Link::Hard(t)) => *t = target.trim_start_matches("./").to_string(),
            Some(Link::Symbolic(t)) => {
                e.size = Some(target.len() as u64);
                if let Some(d) = &mut refs[*i] {
                    d.inline = Some(target.clone().into_bytes());
                }
                *t = target;
            }
            None => {}
        }
    }
    Some(coding)
}

/// Expands a sparse file: zeros between the stored segments.
struct SparseReader<R: Read> {
    inner: R,
    map: Vec<(u64, u64)>,
    seg: usize,
    pos: u64,
    size: u64,
}

impl<R: Read> Read for SparseReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        while self.seg < self.map.len() && self.map[self.seg].0 + self.map[self.seg].1 <= self.pos {
            self.seg += 1;
        }
        let (off, len) = self.map.get(self.seg).copied().unwrap_or((self.size, 0));
        if self.pos < off {
            let n = ((off.min(self.size) - self.pos) as usize).min(buf.len());
            buf[..n].fill(0);
            self.pos += n as u64;
            return Ok(n);
        }
        let n = ((off + len - self.pos) as usize).min(buf.len());
        let k = self.inner.read(&mut buf[..n])?;
        if k == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sparse data truncated",
            ));
        }
        self.pos += k as u64;
        Ok(k)
    }
}

impl Tar {
    fn entry_reader<'a>(&self, i: usize, raw: Box<dyn Read + 'a>) -> Box<dyn Read + 'a> {
        let d = self.refs[i].as_ref().unwrap();
        if let Some(b) = &d.inline {
            return Box::new(io::Cursor::new(b.clone()));
        }
        let raw = raw.take(d.stored);
        if d.sparse.is_empty() {
            Box::new(raw)
        } else {
            Box::new(SparseReader {
                inner: raw,
                map: d.sparse.clone(),
                seg: 0,
                pos: 0,
                size: self.entries[i].size_or_zero(),
            })
        }
    }
}

impl Archive for Tar {
    fn name_coding(&self) -> Option<NameCoding> {
        self.coding
    }

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
        match &self.source {
            Source::Mem(s) => {
                for &i in &self.units[unit].entries {
                    let d = self.refs[i].as_ref().unwrap();
                    let bytes =
                        s.sub(d.offset..d.offset + if d.inline.is_some() { 0 } else { d.stored })?;
                    let mut r = self.entry_reader(i, Box::new(&bytes[..]));
                    if f(i, &mut r)? == Flow::Stop {
                        break;
                    }
                }
                Ok(())
            }
            Source::Stream(open) => {
                let mut r = open()?;
                let mut pos = 0u64;
                let list = &self.units[unit].entries;
                for (k, &i) in list.iter().enumerate() {
                    let d = self.refs[i].as_ref().unwrap();
                    if d.inline.is_none() {
                        if d.offset < pos || data::skip(&mut *r, d.offset - pos)? != d.offset - pos
                        {
                            return Err(Error::corrupt("tar data truncated"));
                        }
                        pos = d.offset;
                    }
                    let flow = {
                        let mut er = self.entry_reader(i, Box::new(&mut *r));
                        let flow = f(i, &mut er)?;
                        data::skip(&mut er, u64::MAX)?;
                        flow
                    };
                    if d.inline.is_none() {
                        pos += d.stored;
                    }
                    if flow == Flow::Stop && k + 1 < list.len() {
                        return Ok(());
                    }
                }
                // Read to the end so the outer stream's checksum is verified.
                data::skip(&mut *r, u64::MAX)?;
                Ok(())
            }
        }
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        vec![("Physical Size", self.end.to_string())]
    }

    fn damage(&self) -> Vec<String> {
        self.notes.clone()
    }
}

// ---------------------------------------------------------------------------------------
// Writing

/// Writes a tar stream of `items` to `out`.
pub struct TarWriter<W: Write> {
    out: W,
    pub written: u64,
}

fn put_octal(field: &mut [u8], v: u64) -> bool {
    let digits = field.len() - 1;
    let s = format!("{v:0digits$o}");
    if s.len() > digits {
        return false;
    }
    field[..digits].copy_from_slice(s.as_bytes());
    field[digits] = 0;
    true
}

fn pax_record(out: &mut Vec<u8>, key: &str, value: &str) {
    let body = format!(" {key}={value}\n");
    let mut len = body.len() + 1;
    loop {
        let total = len.to_string().len() + body.len();
        if total == len {
            break;
        }
        len = total;
    }
    out.extend_from_slice(format!("{len}{body}").as_bytes());
}

fn split_ustar(name: &[u8]) -> Option<(&[u8], &[u8])> {
    if name.len() <= 100 {
        return Some((&[], name));
    }
    // Split at a '/' so that prefix <= 155 and name <= 100.
    for (i, &b) in name.iter().enumerate() {
        if b == b'/' && i <= 155 && name.len() - i - 1 <= 100 && name.len() - i - 1 > 0 {
            return Some((&name[..i], &name[i + 1..]));
        }
    }
    None
}

impl<W: Write> TarWriter<W> {
    pub fn new(out: W) -> Self {
        TarWriter { out, written: 0 }
    }

    fn write(&mut self, b: &[u8]) -> Result<()> {
        self.out.write_all(b)?;
        self.written += b.len() as u64;
        Ok(())
    }

    fn header(&mut self, name: &str, typ: u8, size: u64, item: &Item) -> Result<()> {
        let mode = match item.attrib {
            Some(a) if a & attr::UNIX_EXTENSION != 0 => (a >> 16) & 0o7777,
            Some(a) if a & attr::READONLY != 0 => {
                if item.is_dir {
                    0o555
                } else {
                    0o444
                }
            }
            _ => {
                if item.is_dir {
                    0o755
                } else {
                    0o644
                }
            }
        };
        let mtime_ft = item.mtime.unwrap_or(0);
        let mtime = filetime_to_unix(mtime_ft).max(0) as u64;
        let nb = name.as_bytes();
        let needs_pax_name = !name.is_ascii() || split_ustar(nb).is_none();
        let needs_pax_size = size >= 0o77777777777;
        let mut h = [0u8; BLOCK];
        if needs_pax_name || needs_pax_size {
            let mut recs = Vec::new();
            if needs_pax_name {
                pax_record(&mut recs, "path", name);
            }
            if needs_pax_size {
                pax_record(&mut recs, "size", &size.to_string());
            }
            if mtime_ft != 0 {
                let ticks = mtime_ft % 10_000_000;
                if ticks != 0 {
                    pax_record(&mut recs, "mtime", &format!("{mtime}.{ticks:07}"));
                }
            }
            let short: String = format!(
                "PaxHeaders/{}",
                name.rsplit('/')
                    .next()
                    .unwrap_or(name)
                    .chars()
                    .filter(|c| c.is_ascii() && *c != '\0')
                    .take(80)
                    .collect::<String>()
            );
            self.raw_header(short.as_bytes(), &[], b'x', recs.len() as u64, 0o644, mtime)?;
            self.write(&recs)?;
            self.pad(recs.len() as u64)?;
        }
        let (prefix, short): (Vec<u8>, Vec<u8>) = match split_ustar(nb) {
            Some((p, n)) if !needs_pax_name => (p.to_vec(), n.to_vec()),
            _ => (
                Vec::new(),
                nb.iter()
                    .copied()
                    .filter(|&b| b.is_ascii())
                    .take(100)
                    .collect(),
            ),
        };
        h[..short.len()].copy_from_slice(&short);
        h[345..345 + prefix.len()].copy_from_slice(&prefix);
        let size_field = if needs_pax_size { 0 } else { size };
        self.fill(&mut h, typ, size_field, mode, mtime)?;
        self.write(&h)
    }

    fn raw_header(
        &mut self,
        name: &[u8],
        prefix: &[u8],
        typ: u8,
        size: u64,
        mode: u32,
        mtime: u64,
    ) -> Result<()> {
        let mut h = [0u8; BLOCK];
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name[..n]);
        h[345..345 + prefix.len().min(155)].copy_from_slice(&prefix[..prefix.len().min(155)]);
        self.fill(&mut h, typ, size, mode, mtime)?;
        self.write(&h)
    }

    fn fill(
        &mut self,
        h: &mut [u8; BLOCK],
        typ: u8,
        size: u64,
        mode: u32,
        mtime: u64,
    ) -> Result<()> {
        put_octal(&mut h[100..108], mode as u64);
        put_octal(&mut h[108..116], 0);
        put_octal(&mut h[116..124], 0);
        if !put_octal(&mut h[124..136], size) {
            return Err(Error::Other("tar entry too large".into()));
        }
        if !put_octal(&mut h[136..148], mtime) {
            put_octal(&mut h[136..148], 0);
        }
        h[156] = typ;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| b as u64).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        Ok(())
    }

    fn pad(&mut self, n: u64) -> Result<()> {
        let rem = (n % BLOCK as u64) as usize;
        if rem != 0 {
            self.write(&[0u8; BLOCK][..BLOCK - rem])?;
        }
        Ok(())
    }

    /// Adds a directory entry.
    pub fn add_dir(&mut self, item: &Item) -> Result<()> {
        let name = format!("{}/", item.name.trim_end_matches('/'));
        self.header(&name, b'5', 0, item)
    }

    /// Adds a file, copying exactly `item.size` bytes from `data` (shorter input is
    /// zero-padded so the archive stays consistent; the caller reports it).
    pub fn add_file(
        &mut self,
        item: &Item,
        data: &mut dyn Read,
        progress: &dyn Fn(u64),
    ) -> Result<u64> {
        self.header(&item.name, b'0', item.size, item)?;
        let mut left = item.size;
        let mut buf = vec![0u8; 1 << 20];
        let mut got = 0u64;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let n = match data.read(&mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Other(format!("reading {}: {e}", item.src.display()))),
            };
            self.write(&buf[..n])?;
            progress(n as u64);
            left -= n as u64;
            got += n as u64;
        }
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            buf[..n].fill(0);
            self.write(&buf[..n])?;
            left -= n as u64;
        }
        self.pad(item.size)?;
        Ok(got)
    }

    pub fn finish(mut self) -> Result<W> {
        self.write(&[0u8; BLOCK * 2])?;
        self.out.flush()?;
        Ok(self.out)
    }
}
