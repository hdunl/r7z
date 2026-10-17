//! ARJ archives: a main header, then one local header plus data per entry, each header
//! protected by CRC32. One unit per entry; entry data is checked by the extractor's CRC32.

use std::io::Read;

use super::{
    Archive, CodePage, Columns, Ctx, Entry, EntryFn, Format, Input, NameCoding, OpenOptions,
    Signature, Slice, Unit,
};
use crate::codec::lzh::{arj_fast_reader, arj_reader};
use crate::error::{Error, Result};
use crate::util::codepage;
use crate::util::time::dos_datetime_to_filetime as dos_to_filetime;
use crate::util::time::format_filetime;

pub static FORMAT: Format = Format {
    name: "Arj",
    aliases: &[],
    extensions: &["arj"],
    signatures: &[Signature::at(0, &[0x60, 0xEA])],
    detect: Some(looks_like_arj),
    write: false,
    stream: false,
    sequential: false,
    open,
};

/// Basic headers are at most this long.
const MAX_BASIC: usize = 2600;
/// Fixed part of a basic header, before the extra data and the names.
const FIXED: usize = 30;

mod flag {
    pub const GARBLED: u8 = 0x01;
    pub const VOLUME: u8 = 0x04;
    pub const EXTFILE: u8 = 0x08;
}

const TYPE_DIR: u8 = 3;
const HOST_MSDOS: u8 = 0;
const HOST_UNIX: u8 = 2;
const HOST_WIN95: u8 = 10;

/// The main header's size is sane and its CRC matches.
fn looks_like_arj(head: &[u8]) -> bool {
    matches!(basic_header(head, 0), Ok(Some(_)))
}

fn u16_at(d: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([d[p], d[p + 1]])
}

fn u32_at(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(d[p..p + 4].try_into().unwrap())
}

/// The basic header at `off` (`None` for the end-of-archive marker) and the offset just
/// past its extended headers.
fn basic_header(d: &[u8], off: usize) -> Result<Option<(&[u8], usize)>> {
    let short = || Error::corrupt("ARJ header is truncated");
    let fixed = d.get(off..off + 4).ok_or_else(short)?;
    if fixed[..2] != [0x60, 0xEA] {
        return Err(Error::corrupt("ARJ header signature not found"));
    }
    let size = u16_at(fixed, 2) as usize;
    if size == 0 {
        return Ok(None);
    }
    if !(FIXED..=MAX_BASIC).contains(&size) {
        return Err(Error::corrupt("bad ARJ header size"));
    }
    let start = off + 4;
    let basic = d.get(start..start + size).ok_or_else(short)?;
    let crc = d.get(start + size..start + size + 4).ok_or_else(short)?;
    if crc32fast::hash(basic) != u32_at(crc, 0) {
        return Err(Error::corrupt("ARJ header CRC mismatch"));
    }
    let mut p = start + size + 4;
    loop {
        let n = u16_at(d.get(p..p + 2).ok_or_else(short)?, 0) as usize;
        p += 2;
        if n == 0 {
            break;
        }
        let ext = d.get(p..p + n + 4).ok_or_else(short)?;
        if crc32fast::hash(&ext[..n]) != u32_at(ext, n) {
            return Err(Error::corrupt("ARJ extended header CRC mismatch"));
        }
        p += n + 4;
    }
    Ok(Some((basic, p)))
}

/// A NUL-terminated string at `p` (to the end if unterminated) and the offset after it.
fn c_string(b: &[u8], p: usize) -> (&[u8], usize) {
    let rest = b.get(p..).unwrap_or(&[]);
    let n = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    (&rest[..n], p + n + 1)
}

struct Item {
    flags: u8,
    method: u8,
    offset: u64,
    packed: u64,
    size: u64,
}

pub struct Arj {
    data: Slice,
    entries: Vec<Entry>,
    items: Vec<Item>,
    units: Vec<Unit>,
    archive_name: String,
    comment: String,
    host: u8,
    ctime: Option<u64>,
    mtime: Option<u64>,
    physical_size: u64,
    coding: Option<NameCoding>,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    Ok(Box::new(Arj::parse(input.into_mem()?, opts.code_page)?))
}

impl Arj {
    fn parse(data: Slice, code_page: Option<CodePage>) -> Result<Arj> {
        let d: &[u8] = &data;
        let (main, mut off) = basic_header(d, 0)?.ok_or(Error::NotArchive)?;
        let first = (main[0] as usize).clamp(FIXED, main.len());
        let (name, p) = c_string(main, first);
        let (comment, _) = c_string(main, p);
        // Names and comments as stored, decoded once the code page is known.
        let mut texts: Vec<(&[u8], &[u8])> = Vec::new();
        let (host, ctime, mtime) = (
            main[3],
            dos_to_filetime(u32_at(main, 8)),
            dos_to_filetime(u32_at(main, 12)),
        );

        let mut entries = Vec::new();
        let mut items = Vec::new();
        let mut units = Vec::new();
        let physical_size = loop {
            let Some((b, data_start)) = basic_header(d, off)? else {
                break off as u64 + 4;
            };
            let first = b[0] as usize;
            if first < FIXED || first > b.len() {
                return Err(Error::corrupt("bad ARJ header size"));
            }
            let (host, flags, method, ftype) = (b[3], b[4], b[5], b[6]);
            let packed = u32_at(b, 12) as u64;
            let size = u32_at(b, 16) as u64;
            let mode = u16_at(b, 26) as u32;
            let (raw_name, p) = c_string(b, first);
            let (raw_comment, _) = c_string(b, p);
            let is_dir = ftype == TYPE_DIR;
            texts.push((raw_name, raw_comment));
            let mut attrib = match host {
                HOST_MSDOS | HOST_WIN95 => mode,
                HOST_UNIX => 0x8000 | (mode << 16),
                _ => 0,
            };
            if is_dir {
                attrib |= 0x10;
            }
            let index = entries.len();
            if !is_dir && size > 0 {
                units.push(Unit {
                    entries: vec![index],
                    encrypted: false,
                });
            }
            entries.push(Entry {
                is_dir,
                size: Some(if is_dir { 0 } else { size }),
                packed_size: Some(packed),
                mtime: dos_to_filetime(u32_at(b, 8)),
                attrib: Some(attrib),
                crc: Some(u32_at(b, 20)),
                method: Some(method.to_string()),
                encrypted: flags & flag::GARBLED != 0,
                ..Entry::default()
            });
            items.push(Item {
                flags,
                method,
                offset: data_start as u64,
                packed,
                size,
            });
            off = data_start
                .checked_add(packed as usize)
                .ok_or_else(|| Error::corrupt("bad ARJ header"))?;
        };
        let all = || {
            [name, comment]
                .into_iter()
                .chain(texts.iter().flat_map(|&(n, c)| [n, c]))
        };
        let coding = all()
            .any(|t| !t.is_ascii())
            .then(|| codepage::choose(code_page, all()));
        let page = coding.map_or(CodePage::CP437, |c| c.page);
        for (e, &(n, c)) in entries.iter_mut().zip(&texts) {
            e.name = page
                .decode(n)
                .replace('\\', "/")
                .trim_end_matches('/')
                .to_string();
            e.raw_name = (!n.is_ascii()).then(|| n.to_vec());
            e.comment = (!c.is_empty()).then(|| page.decode(c));
        }
        let archive_name = page.decode(name);
        let comment = page.decode(comment);
        Ok(Arj {
            coding,
            data,
            entries,
            items,
            units,
            archive_name,
            comment,
            host,
            ctime,
            mtime,
            physical_size,
        })
    }

    fn reader(&self, i: usize) -> Result<Box<dyn Read>> {
        let it = &self.items[i];
        let name = &self.entries[i].name;
        if it.flags & flag::GARBLED != 0 {
            return Err(Error::unsupported(format!(
                "{name}: garbled (encrypted) ARJ entry"
            )));
        }
        if it.flags & (flag::VOLUME | flag::EXTFILE) != 0 {
            return Err(Error::unsupported(format!(
                "{name}: entry spans ARJ volumes"
            )));
        }
        let src = self.data.sub(it.offset..it.offset + it.packed)?;
        Ok(match it.method {
            0 => {
                if it.packed < it.size {
                    return Err(Error::corrupt("stored ARJ data is shorter than the file"));
                }
                Box::new(src.sub(0..it.size)?.reader())
            }
            1..=3 => Box::new(arj_reader(src, it.size)),
            4 => Box::new(arj_fast_reader(src, it.size)),
            m => return Err(Error::unsupported(format!("ARJ method {m}"))),
        })
    }
}

impl Archive for Arj {
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
        let i = self.units[unit].entries[0];
        let mut r = self.reader(i)?;
        f(i, &mut r)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![("Physical Size", self.physical_size.to_string())];
        if !self.archive_name.is_empty() {
            p.push(("Name", self.archive_name.clone()));
        }
        if let Some(t) = self.ctime {
            p.push(("Created", format_filetime(t)));
        }
        if let Some(t) = self.mtime {
            p.push(("Modified", format_filetime(t)));
        }
        const HOSTS: [&str; 12] = [
            "MSDOS", "PRIMOS", "UNIX", "AMIGA", "MAC", "OS/2", "APPLE GS", "ATARI ST", "NEXT",
            "VAX VMS", "WIN95", "WIN32",
        ];
        let host = HOSTS
            .get(self.host as usize)
            .map_or_else(|| self.host.to_string(), |h| h.to_string());
        p.push(("Host OS", host));
        if !self.comment.is_empty() {
            p.push(("Comment", self.comment.clone()));
        }
        p
    }

    fn columns(&self) -> Columns {
        Columns {
            crc: true,
            method: true,
            encrypted: true,
            block: false,
        }
    }

    /// Garbled entries cannot be decoded with any password, so do not ask for one.
    fn has_encrypted_data(&self) -> bool {
        false
    }
}
