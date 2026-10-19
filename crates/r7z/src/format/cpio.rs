//! cpio archives: old binary (both byte orders), portable ASCII (`070707`), new ASCII
//! (`070701`) and new CRC (`070702`). Opens from a sequential stream too, since cpio usually
//! arrives inside gzip or xz (rpm payloads); the whole archive is one unit.

use std::collections::HashMap;
use std::io::{self, Read};

use super::data::{read_exact, skip};
use super::{Archive, Ctx, Entry, EntryFn, Flow, Format, Input, Link, OpenOptions, Opener};
use super::{Signature, Slice, Unit};
use crate::error::{Error, Result};
use crate::util::time::unix_to_filetime;

pub const FORMAT: Format = Format {
    name: "Cpio",
    aliases: &[],
    extensions: &["cpio"],
    signatures: &[
        Signature::at(0, b"07070"),
        Signature::at(0, &[0xC7, 0x71]),
        Signature::at(0, &[0x71, 0xC7]),
    ],
    detect: Some(detect),
    write: false,
    stream: false,
    sequential: true,
    open,
};

const TRAILER: &[u8] = b"TRAILER!!!";
/// Longest accepted name field; real archives stay far below (PATH_MAX is 4096).
const MAX_NAME: usize = 1 << 16;
/// Longest symbolic link target read into the listing.
const MAX_LINK: u64 = 1 << 16;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    BinLe,
    BinBe,
    Odc,
    Newc,
    Crc,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::BinLe => "Binary LE",
            Kind::BinBe => "Binary BE",
            Kind::Odc => "Portable ASCII",
            Kind::Newc => "New ASCII",
            Kind::Crc => "New CRC",
        }
    }

    /// Alignment of names and data, relative to the archive start.
    fn align(self) -> u64 {
        match self {
            Kind::BinLe | Kind::BinBe => 2,
            Kind::Odc => 1,
            Kind::Newc | Kind::Crc => 4,
        }
    }

    fn header_len(self) -> usize {
        match self {
            Kind::BinLe | Kind::BinBe => 26,
            Kind::Odc => 76,
            Kind::Newc | Kind::Crc => 110,
        }
    }

    fn of(magic: &[u8]) -> Option<Kind> {
        match magic {
            [0xC7, 0x71, ..] => Some(Kind::BinLe),
            [0x71, 0xC7, ..] => Some(Kind::BinBe),
            [b'0', b'7', b'0', b'7', b'0', b'7', ..] => Some(Kind::Odc),
            [b'0', b'7', b'0', b'7', b'0', b'1', ..] => Some(Kind::Newc),
            [b'0', b'7', b'0', b'7', b'0', b'2', ..] => Some(Kind::Crc),
            _ => None,
        }
    }
}

/// The fields of one header that matter for listing and extraction.
#[derive(Clone, Debug)]
struct Header {
    kind: Kind,
    ino: u32,
    dev: (u32, u32),
    mode: u32,
    nlink: u32,
    mtime: u64,
    size: u64,
    name_size: usize,
    check: u32,
}

fn hex(b: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(b).ok()?;
    u32::from_str_radix(s, 16)
        .ok()
        .filter(|_| !s.starts_with(['+', '-']))
}

fn oct(b: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(b).ok()?;
    u64::from_str_radix(s, 8)
        .ok()
        .filter(|_| !s.starts_with(['+', '-']))
}

/// Parses a fixed-size header (`h` holds exactly `kind.header_len()` bytes).
fn parse_header(kind: Kind, h: &[u8]) -> Option<Header> {
    match kind {
        Kind::BinLe | Kind::BinBe => {
            let w = |i: usize| {
                let b = [h[2 * i], h[2 * i + 1]];
                u32::from(if kind == Kind::BinLe {
                    u16::from_le_bytes(b)
                } else {
                    u16::from_be_bytes(b)
                })
            };
            Some(Header {
                kind,
                dev: (0, w(1)),
                ino: w(2),
                mode: w(3),
                nlink: w(6),
                mtime: u64::from((w(8) << 16) | w(9)),
                name_size: w(10) as usize,
                size: u64::from((w(11) << 16) | w(12)),
                check: 0,
            })
        }
        Kind::Odc => {
            let f = |at: usize, len: usize| oct(&h[at..at + len]);
            Some(Header {
                kind,
                dev: (0, f(6, 6)? as u32),
                ino: f(12, 6)? as u32,
                mode: f(18, 6)? as u32,
                nlink: f(36, 6)? as u32,
                mtime: f(48, 11)?,
                name_size: f(59, 6)? as usize,
                size: f(65, 11)?,
                check: 0,
            })
        }
        Kind::Newc | Kind::Crc => {
            let f = |i: usize| hex(&h[6 + 8 * i..14 + 8 * i]);
            Some(Header {
                kind,
                ino: f(0)?,
                mode: f(1)?,
                nlink: f(4)?,
                mtime: u64::from(f(5)?),
                size: u64::from(f(6)?),
                dev: (f(7)?, f(8)?),
                name_size: f(11)? as usize,
                check: f(12)?,
            })
        }
    }
}

fn detect(head: &[u8]) -> bool {
    let Some(kind) = Kind::of(head) else {
        return false;
    };
    let n = kind.header_len();
    head.len() >= n
        && parse_header(kind, &head[..n])
            .is_some_and(|h| h.name_size > 0 && h.name_size <= MAX_NAME)
}

/// One parsed member.
struct Rec {
    hdr: Header,
    name: String,
    data_offset: u64,
    link_target: Option<String>,
}

/// The archive bytes being parsed, with the absolute position reached.
struct Scan<'a> {
    src: ScanSrc<'a>,
    pos: u64,
}

enum ScanSrc<'a> {
    Mem(&'a Slice),
    Stream(&'a mut dyn Read),
}

impl Scan<'_> {
    fn truncated() -> Error {
        Error::corrupt("unexpected end of cpio archive")
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        match &mut self.src {
            ScanSrc::Mem(m) => {
                let end = self.pos + buf.len() as u64;
                if end > m.len() as u64 {
                    return Err(Self::truncated());
                }
                buf.copy_from_slice(&m[self.pos as usize..end as usize]);
            }
            ScanSrc::Stream(r) => read_exact(*r, buf)?,
        }
        self.pos += buf.len() as u64;
        Ok(())
    }

    fn skip(&mut self, n: u64) -> Result<()> {
        let ok = match &mut self.src {
            ScanSrc::Mem(m) => self.pos.checked_add(n).is_some_and(|e| e <= m.len() as u64),
            ScanSrc::Stream(r) => skip(*r, n)? == n,
        };
        if !ok {
            return Err(Self::truncated());
        }
        self.pos += n;
        Ok(())
    }

    fn align(&mut self, a: u64) -> Result<()> {
        let pad = self.pos.next_multiple_of(a) - self.pos;
        self.skip(pad)
    }

    fn at_end(&self) -> bool {
        matches!(self.src, ScanSrc::Mem(m) if self.pos >= m.len() as u64)
    }
}

/// Walks the archive up to and including the trailer.
fn scan(src: ScanSrc<'_>) -> Result<(Vec<Rec>, u64)> {
    let mut s = Scan { src, pos: 0 };
    let mut recs = Vec::new();
    loop {
        let start = s.pos;
        if start == 0 && s.at_end() {
            return Err(Error::NotArchive);
        }
        let mut magic = [0u8; 6];
        s.read(&mut magic[..2])
            .map_err(|_| Error::corrupt("cpio archive has no TRAILER!!! entry"))?;
        let used = if magic[0] == b'0' { 6 } else { 2 };
        s.read(&mut magic[2..used])?;
        let bad = || {
            if start == 0 {
                Error::NotArchive
            } else {
                Error::corrupt(format!("bad cpio header at offset {start}"))
            }
        };
        let kind = Kind::of(&magic[..used]).ok_or_else(bad)?;
        let mut h = vec![0u8; kind.header_len()];
        h[..used].copy_from_slice(&magic[..used]);
        s.read(&mut h[used..])?;
        let hdr = parse_header(kind, &h).ok_or_else(bad)?;
        if hdr.name_size == 0 || hdr.name_size > MAX_NAME {
            return Err(Error::corrupt("bad cpio name length"));
        }
        let mut name = vec![0u8; hdr.name_size];
        s.read(&mut name)?;
        s.align(kind.align())?;
        if let Some(z) = name.iter().position(|&b| b == 0) {
            name.truncate(z);
        }
        let data_offset = s.pos;
        let link_target = if name != TRAILER && hdr.mode & S_IFMT == S_IFLNK && hdr.size <= MAX_LINK
        {
            let mut t = vec![0u8; hdr.size as usize];
            s.read(&mut t)?;
            Some(String::from_utf8_lossy(&t).into_owned())
        } else {
            s.skip(hdr.size)?;
            None
        };
        s.align(kind.align())?;
        if name == TRAILER {
            return Ok((recs, s.pos));
        }
        recs.push(Rec {
            hdr,
            name: String::from_utf8_lossy(&name).into_owned(),
            data_offset,
            link_target,
        });
    }
}

enum Source {
    Mem(Slice),
    Stream(Opener),
}

pub struct Cpio {
    source: Source,
    kind: Kind,
    entries: Vec<Entry>,
    /// Per entry: data offset and, for the CRC format, the stored byte sum.
    data: Vec<(u64, Option<u32>)>,
    units: Vec<Unit>,
    physical_size: u64,
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let (source, (recs, physical_size)) = match input {
        Input::Mem(m) => {
            let parsed = scan(ScanSrc::Mem(&m))?;
            (Source::Mem(m), parsed)
        }
        Input::Stream { open, .. } => {
            let parsed = scan(ScanSrc::Stream(&mut *open()?))?;
            (Source::Stream(open), parsed)
        }
    };
    let kind = recs.first().map_or(Kind::Newc, |r| r.hdr.kind);
    Ok(Box::new(Cpio::new(source, kind, recs, physical_size)))
}

/// The member that carries the data of a new-ASCII hard link set: the last one with data.
fn hard_link_targets(recs: &[Rec]) -> Vec<Option<usize>> {
    let mut groups: HashMap<(u32, u32, u32), Vec<usize>> = HashMap::new();
    for (i, r) in recs.iter().enumerate() {
        let h = &r.hdr;
        if matches!(h.kind, Kind::Newc | Kind::Crc) && h.nlink > 1 && h.mode & S_IFMT != S_IFDIR {
            groups.entry((h.dev.0, h.dev.1, h.ino)).or_default().push(i);
        }
    }
    let mut target = vec![None; recs.len()];
    for members in groups.values() {
        let Some(&data) = members.iter().rev().find(|&&i| recs[i].hdr.size > 0) else {
            continue;
        };
        for &i in members {
            if i != data && recs[i].hdr.size == 0 {
                target[i] = Some(data);
            }
        }
    }
    target
}

impl Cpio {
    fn new(source: Source, kind: Kind, recs: Vec<Rec>, physical_size: u64) -> Self {
        let targets = hard_link_targets(&recs);
        let mut entries = Vec::with_capacity(recs.len());
        let mut data = Vec::with_capacity(recs.len());
        let mut unit = Unit::default();
        for (i, r) in recs.iter().enumerate() {
            let h = &r.hdr;
            let is_dir = h.mode & S_IFMT == S_IFDIR;
            let mode = h.mode & 0xFFFF;
            let mut e = Entry {
                name: r.name.clone(),
                is_dir,
                size: Some(if is_dir { 0 } else { h.size }),
                packed_size: Some(if is_dir {
                    0
                } else {
                    h.size.next_multiple_of(h.kind.align())
                }),
                mtime: Some(unix_to_filetime(h.mtime as i64)),
                attrib: Some(0x8000 | (mode << 16) | if is_dir { 0x10 } else { 0 }),
                link: r.link_target.clone().map(Link::Symbolic),
                ..Default::default()
            };
            if let Some(t) = targets[i] {
                e.size = Some(recs[t].hdr.size);
                e.packed_size = Some(0);
                e.link = Some(Link::Hard(recs[t].name.clone()));
            } else if !is_dir && h.size > 0 {
                unit.entries.push(i);
            }
            entries.push(e);
            data.push((r.data_offset, (h.kind == Kind::Crc).then_some(h.check)));
        }
        Cpio {
            source,
            kind,
            entries,
            data,
            units: if unit.entries.is_empty() {
                Vec::new()
            } else {
                vec![unit]
            },
            physical_size,
        }
    }
}

/// Verifies the new-CRC format's checksum (the 32-bit sum of the data bytes) once the
/// entry's last byte has been read.
struct SumReader<R> {
    inner: R,
    left: u64,
    sum: u32,
    want: Option<u32>,
}

impl<R: Read> Read for SumReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(want) = self.want {
            for &b in &buf[..n] {
                self.sum = self.sum.wrapping_add(u32::from(b));
            }
            self.left = self.left.saturating_sub(n as u64);
            if self.left == 0 && self.sum != want {
                self.want = None;
                return Err(Error::Checksum("cpio entry checksum".into()).into_io());
            }
        }
        Ok(n)
    }
}

impl Archive for Cpio {
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
        let unit = &self.units[unit];
        let size_of = |i: usize| self.entries[i].size_or_zero();
        match &self.source {
            Source::Mem(m) => {
                for &i in &unit.entries {
                    let (off, want) = self.data[i];
                    let slice = m.sub(off..off + size_of(i))?;
                    let mut r = SumReader {
                        inner: slice.reader(),
                        left: size_of(i),
                        sum: 0,
                        want,
                    };
                    if f(i, &mut r)? == Flow::Stop {
                        break;
                    }
                }
            }
            Source::Stream(open) => {
                let mut r = open()?;
                let mut pos = 0u64;
                for &i in &unit.entries {
                    let (off, want) = self.data[i];
                    let gap = off - pos;
                    if skip(&mut *r, gap)? != gap {
                        return Err(Error::corrupt("unexpected end of cpio archive"));
                    }
                    let size = size_of(i);
                    let mut take = SumReader {
                        inner: (&mut *r).take(size),
                        left: size,
                        sum: 0,
                        want,
                    };
                    if f(i, &mut take)? == Flow::Stop {
                        break;
                    }
                    let rest = take.inner.limit();
                    if skip(&mut take.inner, rest)? != rest {
                        return Err(Error::corrupt("unexpected end of cpio archive"));
                    }
                    pos = off + size;
                }
            }
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Physical Size", self.physical_size.to_string()),
            ("SubType", self.kind.name().into()),
        ]
    }
}
