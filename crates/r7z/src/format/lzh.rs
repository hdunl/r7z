//! LZH/LHA archives: header levels 0-3, one unit per entry. Each entry carries a CRC16 of
//! its data, checked by the entry reader (so [`Archive::verifies_data`] is true).

use std::io::{self, Read};

use super::{
    Archive, CodePage, Columns, Ctx, Entry, EntryFn, Format, Input, NameCoding, OpenOptions,
    Signature, Slice, Unit,
};
use crate::codec::lzh::{crc16, lh1_reader, lh_reader, lz5_reader, lzs_reader};
use crate::error::{Error, Result};
use crate::util::codepage;
use crate::util::time::{dos_datetime_to_filetime as dos_to_filetime, unix_to_filetime};

pub const FORMAT: Format = Format {
    name: "Lzh",
    aliases: &["lha"],
    extensions: &["lzh", "lha"],
    signatures: &[Signature::at(2, b"-lh")],
    detect: Some(looks_like_lzh),
    write: false,
    stream: false,
    sequential: false,
    open,
};

/// A plausible first header: `-l??-` method id and a known header level.
fn looks_like_lzh(head: &[u8]) -> bool {
    head.len() >= 21 && is_method(&head[2..7]) && head[20] <= 3
}

fn is_method(m: &[u8]) -> bool {
    m[0] == b'-' && m[1] == b'l' && m[4] == b'-'
}

/// Where an entry's data lives and how it is coded.
struct Item {
    method: [u8; 5],
    offset: u64,
    packed: u64,
    size: u64,
    crc: u16,
}

pub struct Lzh {
    data: Slice,
    entries: Vec<Entry>,
    items: Vec<Item>,
    units: Vec<Unit>,
    physical_size: u64,
    coding: Option<NameCoding>,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    Ok(Box::new(Lzh::parse(input.into_mem()?, opts.code_page)?))
}

fn u16_at(d: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([d[p], d[p + 1]])
}

fn u32_at(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(d[p..p + 4].try_into().unwrap())
}

fn truncated() -> Error {
    Error::corrupt("LZH header is truncated")
}

/// Fields collected from one header and its extended headers.
#[derive(Default)]
struct Header {
    level: u8,
    name: Vec<u8>,
    dir: Option<Vec<u8>>,
    file_name: Option<Vec<u8>>,
    unix_time: Option<u32>,
    unix_mode: Option<u16>,
    sizes64: Option<(u64, u64)>,
    /// Offset and value of the header CRC16 (extended header 0x00).
    header_crc: Option<(usize, u16)>,
}

impl Header {
    fn extension(&mut self, kind: u8, data: &[u8]) {
        match kind {
            0x01 => self.file_name = Some(data.to_vec()),
            0x02 => self.dir = Some(data.to_vec()),
            0x42 if data.len() >= 16 => {
                let packed = u64::from_le_bytes(data[..8].try_into().unwrap());
                let size = u64::from_le_bytes(data[8..16].try_into().unwrap());
                self.sizes64 = Some((packed, size));
            }
            0x50 if data.len() >= 2 => self.unix_mode = Some(u16_at(data, 0)),
            0x54 if data.len() >= 4 => self.unix_time = Some(u32_at(data, 0)),
            _ => {}
        }
    }

    /// `dir/name` as stored, with the 0xFF directory separators turned into `/`. A `\`
    /// can be the second byte of a Shift-JIS character, so it is left for after decoding.
    fn raw_path(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        if let Some(d) = &self.dir {
            raw.extend_from_slice(d);
            if !raw.is_empty() && !matches!(raw.last(), Some(b'/' | 0xFF)) {
                raw.push(b'/');
            }
        }
        raw.extend_from_slice(self.file_name.as_deref().unwrap_or(&self.name));
        for b in &mut raw {
            if *b == 0xFF {
                *b = b'/';
            }
        }
        raw
    }
}

/// A decoded path with `\` separators turned into `/`, without a trailing slash.
fn clean_path(s: String) -> String {
    s.replace('\\', "/").trim_end_matches('/').to_string()
}

/// Walks a chain of extended headers starting at `p` whose first size is `next`; sizes are
/// `width` bytes and count the whole extended header. Returns the end offset.
fn read_extensions(
    d: &[u8],
    mut p: usize,
    mut next: usize,
    width: usize,
    limit: usize,
    h: &mut Header,
) -> Result<usize> {
    let mut count = 0;
    while next != 0 {
        count += 1;
        if next < 1 + width || count > 1024 {
            return Err(Error::corrupt("bad LZH extended header"));
        }
        let end = p
            .checked_add(next)
            .filter(|&e| e <= limit)
            .ok_or_else(truncated)?;
        let data = &d[p + 1..end - width];
        if d[p] == 0 && data.len() >= 2 {
            h.header_crc = Some((p + 1, u16_at(data, 0)));
        }
        h.extension(d[p], data);
        next = if width == 2 {
            u16_at(d, end - 2) as usize
        } else {
            u32_at(d, end - 4) as usize
        };
        p = end;
    }
    Ok(p)
}

/// Levels 2 and 3 may carry a CRC16 of the whole header taken with the CRC field zeroed.
fn check_header_crc(header: &[u8], off: usize, h: &Header) -> Result<()> {
    let Some((at, want)) = h.header_crc else {
        return Ok(());
    };
    let at = at - off;
    let crc = crc16(crc16(crc16(0, &header[..at]), &[0, 0]), &header[at + 2..]);
    if crc != want {
        return Err(Error::corrupt("LZH header CRC mismatch"));
    }
    Ok(())
}

impl Lzh {
    fn parse(data: Slice, code_page: Option<CodePage>) -> Result<Lzh> {
        let d: &[u8] = &data;
        let mut entries = Vec::new();
        // Paths as stored, decoded once the code page is known.
        let mut paths = Vec::new();
        let mut items = Vec::new();
        let mut units = Vec::new();
        let mut off = 0usize;
        let physical_size = loop {
            if off >= d.len() {
                break d.len() as u64;
            }
            // A zero byte ends the archive, unless it is the low byte of a level-2 header
            // size (7-Zip reads those too).
            if d[off] == 0 && !looks_like_lzh(&d[off..]) {
                break off as u64 + 1;
            }
            if d.len() - off < 22 {
                return Err(truncated());
            }
            if !is_method(&d[off + 2..off + 7]) {
                return Err(if entries.is_empty() {
                    Error::NotArchive
                } else {
                    Error::corrupt("bad LZH header")
                });
            }
            let b = &d[off..];
            let mut method = [0u8; 5];
            method.copy_from_slice(&b[2..7]);
            let mut packed = u32_at(b, 7) as u64;
            let mut size = u32_at(b, 11) as u64;
            let stamp = u32_at(b, 15);
            let mut h = Header {
                level: b[20],
                ..Header::default()
            };
            let (crc, data_start) = match h.level {
                0 | 1 => {
                    let hsize = b[0] as usize + 2;
                    if hsize > b.len() {
                        return Err(truncated());
                    }
                    let sum = b[2..hsize].iter().fold(0u8, |a, &x| a.wrapping_add(x));
                    if sum != b[1] {
                        return Err(Error::corrupt("LZH header checksum mismatch"));
                    }
                    let nlen = b[21] as usize;
                    if 22 + nlen + 2 > hsize {
                        return Err(Error::corrupt("bad LZH header"));
                    }
                    h.name = b[22..22 + nlen].to_vec();
                    let crc = u16_at(b, 22 + nlen);
                    let rest = &b[24 + nlen..hsize];
                    if h.level == 0 {
                        // LHa for UNIX: 'U', mtime, mode, uid, gid.
                        if rest.len() >= 7 && rest[0] == b'U' {
                            h.unix_mode = Some(u16_at(rest, 5));
                        }
                        (crc, off + hsize)
                    } else {
                        if rest.len() < 3 {
                            return Err(Error::corrupt("bad LZH header"));
                        }
                        let next = u16_at(rest, 1) as usize;
                        let end = read_extensions(d, off + hsize, next, 2, d.len(), &mut h)?;
                        let ext_len = (end - off - hsize) as u64;
                        packed = packed
                            .checked_sub(ext_len)
                            .ok_or_else(|| Error::corrupt("bad LZH header"))?;
                        (crc, end)
                    }
                }
                2 => {
                    let hsize = u16_at(b, 0) as usize;
                    if hsize < 26 {
                        return Err(Error::corrupt("bad LZH header"));
                    }
                    if hsize > b.len() {
                        return Err(truncated());
                    }
                    let next = u16_at(b, 24) as usize;
                    read_extensions(d, off + 26, next, 2, off + hsize, &mut h)?;
                    check_header_crc(&d[off..off + hsize], off, &h)?;
                    (u16_at(b, 21), off + hsize)
                }
                3 => {
                    if b.len() < 32 {
                        return Err(truncated());
                    }
                    let hsize = u32_at(b, 24) as usize;
                    if u16_at(b, 0) != 4 || hsize < 32 {
                        return Err(Error::corrupt("bad LZH header"));
                    }
                    if hsize > b.len() {
                        return Err(truncated());
                    }
                    let next = u32_at(b, 28) as usize;
                    read_extensions(d, off + 32, next, 4, off + hsize, &mut h)?;
                    check_header_crc(&d[off..off + hsize], off, &h)?;
                    (u16_at(b, 21), off + hsize)
                }
                l => return Err(Error::unsupported(format!("LZH header level {l}"))),
            };
            if let Some((p, s)) = h.sizes64 {
                packed = p;
                size = s;
            }
            let is_dir = &method == b"-lhd-";
            // 7-Zip's rule: an explicit Unix time, else the level 2/3 Unix stamp, else DOS.
            let mtime = match h.unix_time {
                Some(t) => Some(unix_to_filetime(t as i64)),
                None if h.level >= 2 => Some(unix_to_filetime(stamp as i64)),
                None => dos_to_filetime(stamp),
            };
            let index = entries.len();
            if !is_dir && size > 0 {
                units.push(Unit {
                    entries: vec![index],
                    encrypted: false,
                });
            }
            paths.push(h.raw_path());
            entries.push(Entry {
                is_dir,
                size: Some(if is_dir { 0 } else { size }),
                packed_size: Some(packed),
                mtime,
                attrib: h.unix_mode.map(|m| 0x8000 | ((m as u32) << 16)),
                method: Some(String::from_utf8_lossy(&method).into_owned()),
                ..Entry::default()
            });
            items.push(Item {
                method,
                offset: data_start as u64,
                packed,
                size,
                crc,
            });
            off = (data_start as u64)
                .checked_add(packed)
                .filter(|&e| e <= usize::MAX as u64)
                .ok_or_else(|| Error::corrupt("bad LZH header"))? as usize;
        };
        let physical_size = physical_size.min(d.len() as u64);
        let coding = paths
            .iter()
            .any(|p| !p.is_ascii())
            .then(|| codepage::choose(code_page, paths.iter().map(Vec::as_slice)));
        let page = coding.map_or(CodePage::CP437, |c| c.page);
        for (e, p) in entries.iter_mut().zip(paths) {
            e.name = clean_path(page.decode(&p));
            e.raw_name = (!p.is_ascii()).then_some(p);
        }
        Ok(Lzh {
            data,
            entries,
            items,
            units,
            physical_size,
            coding,
        })
    }

    fn reader(&self, i: usize) -> Result<Box<dyn Read + '_>> {
        let it = &self.items[i];
        let src = self.data.sub(it.offset..it.offset + it.packed)?;
        let size = it.size;
        let r: Box<dyn Read> = match &it.method[1..4] {
            b"lh0" | b"lz4" => {
                if it.packed < size {
                    return Err(Error::corrupt("stored LZH data is shorter than the file"));
                }
                Box::new(src.sub(0..size)?.reader())
            }
            b"lh1" => Box::new(lh1_reader(src, size)),
            b"lh4" => Box::new(lh_reader(src, size, 12)),
            b"lh5" => Box::new(lh_reader(src, size, 13)),
            b"lh6" => Box::new(lh_reader(src, size, 15)),
            b"lh7" => Box::new(lh_reader(src, size, 16)),
            b"lzs" => Box::new(lzs_reader(src, size)),
            b"lz5" => Box::new(lz5_reader(src, size)),
            _ => {
                return Err(Error::unsupported(format!(
                    "LZH method {}",
                    String::from_utf8_lossy(&it.method)
                )))
            }
        };
        Ok(Box::new(Crc16Check {
            inner: r,
            crc: 0,
            left: size,
            want: it.crc,
            name: &self.entries[i].name,
        }))
    }
}

/// Passes data through and fails the read that delivers the last byte if the CRC16 differs.
struct Crc16Check<'a, R> {
    inner: R,
    crc: u16,
    left: u64,
    want: u16,
    name: &'a str,
}

impl<R: Read> Read for Crc16Check<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.crc = crc16(self.crc, &buf[..n]);
        self.left = self.left.saturating_sub(n as u64);
        if n > 0 && self.left == 0 && self.crc != self.want {
            return Err(Error::Checksum(format!(
                "{} (expected CRC16 {:04X}, got {:04X})",
                self.name, self.want, self.crc
            ))
            .into_io());
        }
        Ok(n)
    }
}

impl Archive for Lzh {
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
        vec![("Physical Size", self.physical_size.to_string())]
    }

    fn columns(&self) -> Columns {
        Columns {
            method: true,
            ..Columns::default()
        }
    }

    fn verifies_data(&self) -> bool {
        true
    }
}
