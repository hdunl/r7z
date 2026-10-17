//! zip: reading (Stored, Deflate, Deflate64, BZip2, LZMA, Zstandard, xz; ZIP64; UTF-8 and
//! OEM names; ZipCrypto and WinZip AES) and writing (Stored/Deflate, ZIP64, UTF-8 names,
//! NTFS timestamps, WinZip AES-256).
//!
//! Every entry is its own unit, so extraction decodes entries in parallel. Writing
//! compresses small files concurrently in memory and streams large ones through the
//! parallel Deflate encoder.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use rayon::prelude::*;

use super::data::{data_err, Input, Slice};
use super::write::{deflate_level, WriteOptions};
use super::{
    Archive, CodePage, Columns, Ctx, Entry, EntryFn, Format, NameCoding, OpenOptions, Signature,
    Unit,
};
use crate::codec::pcompress::{deflate_chunk, ParDeflate};
use crate::codec::zipcrypt::{wz_aes_encrypt, WzAesReader, ZipCryptoReader};
use crate::error::{Error, Result};
use crate::ops::create::{temp_path, Item, Progress, Summary};
use crate::sevenz::attr;
use crate::util::codepage;
use crate::util::time::{dos_to_filetime, filetime_to_dos, unix_to_filetime};

pub static FORMAT: Format = Format {
    name: "zip",
    aliases: &["zipx", "jar"],
    extensions: &[
        "zip", "z01", "zipx", "jar", "xpi", "odt", "ods", "odp", "docx", "xlsx", "pptx", "epub",
        "ipa", "apk", "appx", "nupkg", "whl", "vsix",
    ],
    signatures: &[
        Signature::at(0, b"PK\x03\x04"),
        Signature::at(0, b"PK\x05\x06"),
        Signature::at(0, b"PK\x06\x06"),
        Signature::at(0, b"PK\x07\x08PK"),
        Signature::at(0, b"PK00PK"),
    ],
    detect: None,
    write: true,
    stream: false,
    sequential: false,
    open,
};

const LOCAL_SIG: u32 = 0x0403_4B50;
const CENTRAL_SIG: u32 = 0x0201_4B50;
const EOCD_SIG: u32 = 0x0605_4B50;
const EOCD64_SIG: u32 = 0x0606_4B50;
const LOCATOR_SIG: u32 = 0x0706_4B50;

const FLAG_ENCRYPTED: u16 = 1;
const FLAG_DESCRIPTOR: u16 = 8;
const FLAG_STRONG: u16 = 0x40;
const FLAG_UTF8: u16 = 0x800;

#[derive(Clone, Copy, Debug)]
struct AesInfo {
    strength: u8,
    vendor: u16,
    method: u16,
}

#[derive(Clone, Debug)]
struct ZEntry {
    local_offset: u64,
    method: u16,
    flags: u16,
    packed: u64,
    crc: u32,
    dos_time: u16,
    aes: Option<AesInfo>,
}

pub struct Zip {
    data: Slice,
    entries: Vec<Entry>,
    z: Vec<ZEntry>,
    units: Vec<Unit>,
    comment: Option<String>,
    offset: u64,
    coding: Option<NameCoding>,
}

fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([b[p], b[p + 1]])
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn u64le(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}

fn method_name(m: u16) -> String {
    match m {
        0 => "Store".into(),
        1 => "Shrink".into(),
        6 => "Implode".into(),
        8 => "Deflate".into(),
        9 => "Deflate64".into(),
        12 => "BZip2".into(),
        14 => "LZMA".into(),
        93 => "ZSTD".into(),
        95 => "xz".into(),
        96 => "Jpeg".into(),
        97 => "WavPack".into(),
        98 => "PPMd".into(),
        n => format!("#{n}"),
    }
}

fn find_eocd(d: &[u8]) -> Option<usize> {
    if d.len() < 22 {
        return None;
    }
    let lo = d.len().saturating_sub(22 + 65535);
    (lo..=d.len() - 22)
        .rev()
        .find(|&p| u32le(d, p) == EOCD_SIG && p + 22 + u16le(d, p + 20) as usize <= d.len())
}

#[path = "zip_recover.rs"]
mod recover;

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let data = input.into_mem()?;
    if opts.recover {
        return recover::open(data, opts.code_page);
    }
    Ok(Box::new(open_central(&data, opts.code_page)?))
}

/// Opens through the end-of-central-directory record.
fn open_central(data: &Slice, code_page: Option<CodePage>) -> Result<Zip> {
    let d: &[u8] = data;
    let eocd = find_eocd(d).ok_or_else(|| {
        if d.starts_with(b"PK\x03\x04") {
            Error::corrupt("zip central directory not found (truncated archive?)")
        } else {
            Error::NotArchive
        }
    })?;
    if u16le(d, eocd + 4) != 0 && u16le(d, eocd + 4) != 0xFFFF {
        return Err(Error::unsupported("multi-volume zip archives"));
    }
    let mut count = u16le(d, eocd + 10) as u64;
    let mut cd_size = u32le(d, eocd + 12) as u64;
    let mut cd_off = u32le(d, eocd + 16) as u64;
    let clen = u16le(d, eocd + 20) as usize;
    let comment = (clen > 0).then(|| &d[eocd + 22..eocd + 22 + clen]);
    let mut cd_end = eocd as u64;
    if eocd >= 20 && u32le(d, eocd - 20) == LOCATOR_SIG {
        let z64 = u64le(d, eocd - 20 + 8) as usize;
        // The record may sit before its recorded offset (SFX stub); look just before the
        // locator if the recorded offset is wrong.
        let at = if z64 + 56 <= d.len() && u32le(d, z64) == EOCD64_SIG {
            Some(z64)
        } else {
            (0..eocd - 20)
                .rev()
                .take(1 << 16)
                .find(|&p| p + 56 <= d.len() && u32le(d, p) == EOCD64_SIG)
        };
        if let Some(z) = at {
            count = u64le(d, z + 32);
            cd_size = u64le(d, z + 40);
            cd_off = u64le(d, z + 48);
            cd_end = z as u64;
        }
    }
    // Data before the archive (an SFX stub) shifts every offset.
    let actual = cd_end
        .checked_sub(cd_size)
        .ok_or_else(|| Error::corrupt("zip central directory size is invalid"))?;
    let cd_start = if cd_off.checked_add(4).is_some_and(|e| e <= d.len() as u64)
        && u32le(d, cd_off as usize) == CENTRAL_SIG
    {
        cd_off
    } else {
        actual
    };
    let delta = cd_start.wrapping_sub(cd_off);
    if count > d.len() as u64 / 46 + 1 {
        return Err(Error::corrupt("zip entry count exceeds archive size"));
    }
    let offset = if delta < cd_start { delta } else { 0 };
    let cd = d.get(cd_start as usize..).unwrap_or_default();
    from_central(data, cd, count, delta, comment, offset, code_page)
}

/// Builds the archive from `count` central directory records at the start of `cd`; local
/// header offsets are shifted by `delta`. Names and comments without the UTF-8 flag or a
/// Unicode extra field are decoded with `code_page`, or with the page detected from all of
/// them.
fn from_central(
    data: &Slice,
    cd: &[u8],
    count: u64,
    delta: u64,
    comment: Option<&[u8]>,
    offset: u64,
    code_page: Option<CodePage>,
) -> Result<Zip> {
    let d = cd;
    let mut entries = Vec::with_capacity(count as usize);
    let mut z = Vec::with_capacity(count as usize);
    // Per entry: the name and comment bytes still to decode with a legacy code page.
    let mut legacy: Vec<[Option<&[u8]>; 2]> = Vec::with_capacity(count as usize);
    let mut p = 0usize;
    for _ in 0..count {
        if p + 46 > d.len() || u32le(d, p) != CENTRAL_SIG {
            return Err(Error::corrupt("zip central directory entry is damaged"));
        }
        let made_by = u16le(d, p + 4);
        let flags = u16le(d, p + 8);
        let method = u16le(d, p + 10);
        let dos_time = u16le(d, p + 12);
        let dos_date = u16le(d, p + 14);
        let crc = u32le(d, p + 16);
        let mut packed = u32le(d, p + 20) as u64;
        let mut size = u32le(d, p + 24) as u64;
        let nlen = u16le(d, p + 28) as usize;
        let xlen = u16le(d, p + 30) as usize;
        let clen = u16le(d, p + 32) as usize;
        let ext_attr = u32le(d, p + 38);
        let mut local = u32le(d, p + 42) as u64;
        let end = p + 46 + nlen + xlen + clen;
        if end > d.len() {
            return Err(Error::corrupt("zip central directory entry is truncated"));
        }
        let raw_name = &d[p + 46..p + 46 + nlen];
        let extra = &d[p + 46 + nlen..p + 46 + nlen + xlen];
        let fcomment = &d[p + 46 + nlen + xlen..end];
        let unicode = flags & FLAG_UTF8 != 0;
        let mut name = unicode.then(|| String::from_utf8_lossy(raw_name).into_owned());
        let mut ucomment = unicode.then(|| String::from_utf8_lossy(fcomment).into_owned());
        let mut mtime = dos_to_filetime(dos_date, dos_time);
        let (mut atime, mut ctime) = (None, None);
        let mut aes = None;
        let mut have_ntfs = false;
        let mut x = 0usize;
        while x + 4 <= extra.len() {
            let id = u16le(extra, x);
            let len = u16le(extra, x + 2) as usize;
            let Some(body) = extra.get(x + 4..x + 4 + len) else {
                break;
            };
            match id {
                0x0001 => {
                    let mut q = 0;
                    let mut take = |v: &mut u64| {
                        if *v == 0xFFFF_FFFF && q + 8 <= body.len() {
                            *v = u64le(body, q);
                            q += 8;
                        }
                    };
                    take(&mut size);
                    take(&mut packed);
                    take(&mut local);
                }
                0x000A if body.len() >= 32 => {
                    let mut q = 4;
                    while q + 4 <= body.len() {
                        let tag = u16le(body, q);
                        let sz = u16le(body, q + 2) as usize;
                        if tag == 1 && sz >= 24 && q + 4 + 24 <= body.len() {
                            have_ntfs = true;
                            let t = |o| Some(u64le(body, q + 4 + o)).filter(|&v| v != 0);
                            mtime = t(0).or(mtime);
                            atime = t(8);
                            ctime = t(16);
                        }
                        q += 4 + sz;
                    }
                }
                0x5455 if body.len() >= 5 && body[0] & 1 != 0 && !have_ntfs => {
                    mtime = Some(unix_to_filetime(u32le(body, 1) as i32 as i64));
                }
                // Info-ZIP Unicode path and comment: UTF-8 text, valid while the CRC of the
                // legacy bytes still matches.
                0x7075 if body.len() >= 5 && body[0] == 1 && !unicode => {
                    if u32le(body, 1) == crc32fast::hash(raw_name) {
                        name = Some(String::from_utf8_lossy(&body[5..]).into_owned());
                    }
                }
                0x6375 if body.len() >= 5 && body[0] == 1 && !unicode => {
                    if u32le(body, 1) == crc32fast::hash(fcomment) {
                        ucomment = Some(String::from_utf8_lossy(&body[5..]).into_owned());
                    }
                }
                0x9901 if body.len() >= 7 => {
                    aes = Some(AesInfo {
                        vendor: u16le(body, 0),
                        strength: body[4],
                        method: u16le(body, 5),
                    });
                }
                _ => {}
            }
            x += 4 + len;
        }
        let host = made_by >> 8;
        let mut attrib = ext_attr & 0xFFFF;
        let unix_mode = ext_attr >> 16;
        if matches!(host, 3 | 19) && unix_mode != 0 {
            attrib = (attrib & 0xFFFF) | attr::UNIX_EXTENSION | (unix_mode << 16);
            if unix_mode & 0o170000 == 0o040000 {
                attrib |= attr::DIRECTORY;
            }
        }
        let encrypted = flags & FLAG_ENCRYPTED != 0;
        let real_method = aes.map(|a| a.method).unwrap_or(method);
        let mut m = method_name(real_method);
        if encrypted {
            m = match aes {
                Some(a) => format!("AES-{} {m}", 64 + 64 * a.strength as u32),
                None if flags & FLAG_STRONG != 0 => format!("Strong {m}"),
                None => format!("ZipCrypto {m}"),
            };
        }
        legacy.push([
            name.is_none().then_some(raw_name),
            (ucomment.is_none() && !fcomment.is_empty()).then_some(fcomment),
        ]);
        entries.push(Entry {
            name: name.unwrap_or_default(),
            is_dir: attrib & attr::DIRECTORY != 0,
            size: Some(size),
            packed_size: Some(packed),
            mtime,
            atime,
            ctime,
            attrib: Some(attrib),
            // AE-2 stores no CRC; the AES tag authenticates the data instead.
            crc: if aes.is_some_and(|a| a.vendor == 2) {
                None
            } else {
                Some(crc)
            },
            method: Some(m),
            encrypted,
            comment: ucomment.filter(|c| !c.is_empty()),
            ..Default::default()
        });
        z.push(ZEntry {
            local_offset: local.wrapping_add(delta),
            method,
            flags,
            packed,
            crc,
            dos_time,
            aes,
        });
        p = end;
    }
    let texts = || legacy.iter().flatten().copied().chain([comment]).flatten();
    let coding = texts()
        .any(|t| !t.is_ascii())
        .then(|| codepage::choose(code_page, texts()));
    // With only ASCII left to decode, every page gives the same text.
    let page = coding.map_or(CodePage::CP437, |c| c.page);
    for (e, &[n, c]) in entries.iter_mut().zip(&legacy) {
        if let Some(n) = n {
            e.name = page.decode(n);
            e.raw_name = (!n.is_ascii()).then(|| n.to_vec());
        }
        if let Some(c) = c {
            e.comment = Some(page.decode(c));
        }
        e.is_dir |= e.name.ends_with(['/', '\\']);
        let trimmed = e.name.trim_end_matches(['/', '\\']).len();
        e.name.truncate(trimmed);
    }
    let comment = comment.map(|c| page.decode(c));
    let units = (0..entries.len())
        .filter(|&i| !entries[i].is_dir)
        .map(|i| Unit {
            entries: vec![i],
            encrypted: entries[i].encrypted,
        })
        .collect();
    Ok(Zip {
        data: data.clone(),
        entries,
        z,
        units,
        comment,
        offset,
        coding,
    })
}

impl Zip {
    fn raw(&self, i: usize) -> Result<&[u8]> {
        let ze = &self.z[i];
        let d: &[u8] = &self.data;
        let lo = ze.local_offset as usize;
        if lo.checked_add(30).is_none_or(|e| e > d.len()) || u32le(d, lo) != LOCAL_SIG {
            return Err(Error::corrupt(format!(
                "{}: local header not found",
                self.entries[i].name
            )));
        }
        let start = lo + 30 + u16le(d, lo + 26) as usize + u16le(d, lo + 28) as usize;
        let end = (start as u64)
            .checked_add(ze.packed)
            .filter(|&e| e <= d.len() as u64)
            .ok_or_else(|| Error::corrupt("archive is truncated (entry data past end of file)"))?;
        Ok(&d[start..end as usize])
    }

    fn reader<'a>(&'a self, i: usize, password: Option<&str>) -> Result<Box<dyn Read + 'a>> {
        let ze = &self.z[i];
        let raw = self.raw(i)?;
        let mut method = ze.method;
        let size = self.entries[i].size_or_zero();
        let src: Box<dyn Read + 'a> = if ze.flags & FLAG_ENCRYPTED != 0 {
            let pw = password.ok_or(Error::PasswordRequired)?.as_bytes();
            if let Some(a) = ze.aes {
                method = a.method;
                Box::new(WzAesReader::new(raw, pw, a.strength)?)
            } else if ze.flags & FLAG_STRONG != 0 {
                return Err(Error::unsupported("PKWARE strong encryption"));
            } else {
                let check = if ze.flags & FLAG_DESCRIPTOR != 0 {
                    (ze.dos_time >> 8) as u8
                } else {
                    (ze.crc >> 24) as u8
                };
                Box::new(ZipCryptoReader::new(raw, pw, check)?)
            }
        } else {
            Box::new(raw)
        };
        Ok(match method {
            0 => src,
            8 => Box::new(flate2::read::DeflateDecoder::new(src)),
            9 => Box::new(deflate64::Deflate64Decoder::new(src)),
            12 => Box::new(bzip2::read::BzDecoder::new(src)),
            14 => {
                let mut src = src;
                let mut h = [0u8; 9];
                super::data::read_exact(&mut src, &mut h)?;
                if u16le(&h, 2) != 5 {
                    return Err(Error::corrupt("zip LZMA properties size is not 5"));
                }
                let dict = u32le(&h, 5);
                // Bit 1 means an end marker terminates the stream.
                let usize_ = if ze.flags & 2 != 0 { u64::MAX } else { size };
                Box::new(
                    lzma_rust2::LzmaReader::new_with_props(src, usize_, h[4], dict, None)
                        .map_err(data_err)?,
                )
            }
            93 => Box::new(super::stream::ZstdReader::new(src)),
            95 => Box::new(lzma_rust2::XzReader::new(src, true)),
            98 => {
                let mut src = src;
                let mut h = [0u8; 2];
                super::data::read_exact(&mut src, &mut h)?;
                let v = u16::from_le_bytes(h);
                let order = (v & 0xF) as u32 + 1;
                let mem = (((v >> 4) & 0xFF) as u32 + 1) << 20;
                let restore = ppmd_rust::RestoreMethod::from(v >> 12);
                if restore == ppmd_rust::RestoreMethod::Unsupported {
                    return Err(Error::unsupported("PPMd restore method"));
                }
                Box::new(
                    ppmd_rust::Ppmd8Decoder::new(src, order, mem, restore)
                        .map_err(|e| Error::corrupt(format!("PPMd: {e}")))?,
                )
            }
            m => {
                return Err(Error::unsupported(format!(
                    "zip compression method {}",
                    method_name(m)
                )))
            }
        })
    }
}

impl Archive for Zip {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let i = self.units[unit].entries[0];
        let mut r = self.reader(i, ctx.password.as_deref())?;
        f(i, &mut r)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![("Physical Size", self.data.len().to_string())];
        if self.offset > 0 {
            p.push(("Offset", self.offset.to_string()));
        }
        if let Some(c) = &self.comment {
            p.push(("Comment", c.clone()));
        }
        p
    }

    fn name_coding(&self) -> Option<NameCoding> {
        self.coding
    }

    fn columns(&self) -> Columns {
        Columns {
            crc: true,
            method: true,
            encrypted: true,
            block: false,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Writing

/// Files up to this size are compressed in memory, many at once.
const IN_MEMORY: u64 = 16 << 20;

struct Written {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    crc: u32,
    size: u64,
    packed: u64,
    offset: u64,
    dos: (u16, u16),
    ext_attr: u32,
    host: u16,
    ntfs: Option<[u64; 3]>,
    aes: bool,
    is_dir: bool,
}

fn host_and_attr(it: &Item) -> (u16, u32) {
    match it.attrib {
        Some(a) if a & attr::UNIX_EXTENSION != 0 => (3, (a & 0xFFFF0000) | (a & 0x3F)),
        Some(a) => (0, a & 0xFFFF),
        None => (0, if it.is_dir { attr::DIRECTORY } else { 0 }),
    }
}

fn ntfs_extra(t: &[u64; 3]) -> Vec<u8> {
    let mut x = Vec::with_capacity(36);
    x.extend_from_slice(&0x000Au16.to_le_bytes());
    x.extend_from_slice(&32u16.to_le_bytes());
    x.extend_from_slice(&0u32.to_le_bytes());
    x.extend_from_slice(&1u16.to_le_bytes());
    x.extend_from_slice(&24u16.to_le_bytes());
    for v in t {
        x.extend_from_slice(&v.to_le_bytes());
    }
    x
}

fn aes_extra(method: u16, vendor: u16) -> Vec<u8> {
    let mut x = vec![0x01, 0x99, 7, 0];
    x.extend_from_slice(&vendor.to_le_bytes());
    x.extend_from_slice(b"AE");
    x.push(3);
    x.extend_from_slice(&method.to_le_bytes());
    x
}

fn version_needed(w: &Written, zip64: bool) -> u16 {
    if w.aes {
        51
    } else if zip64 {
        45
    } else if w.method == 8 || w.is_dir {
        20
    } else {
        10
    }
}

/// An in-memory file ready to write: method, CRC, unpacked size, stored body.
type Encoded = (u16, u32, u64, Vec<u8>);

/// Encodes one in-memory file: compressed (or stored, when that is smaller) and encrypted.
fn encode_small(data: &[u8], level: u32, password: Option<&str>) -> Result<(u16, u32, Vec<u8>)> {
    let crc = crc32fast::hash(data);
    let (method, mut body) = if level == 0 || data.is_empty() {
        (0u16, data.to_vec())
    } else {
        let c = deflate_chunk(&[], data, level, true)?;
        if c.len() < data.len() {
            (8, c)
        } else {
            (0, data.to_vec())
        }
    };
    if let Some(pw) = password {
        body = wz_aes_encrypt(&body, pw.as_bytes())?;
    }
    Ok((method, crc, body))
}

fn local_header(out: &mut dyn Write, w: &Written, zip64: bool, aes_vendor: u16) -> Result<()> {
    let mut h = Vec::with_capacity(30 + w.name.len() + 64);
    h.extend_from_slice(&LOCAL_SIG.to_le_bytes());
    h.extend_from_slice(&version_needed(w, zip64).to_le_bytes());
    h.extend_from_slice(&w.flags.to_le_bytes());
    h.extend_from_slice(&(if w.aes { 99 } else { w.method }).to_le_bytes());
    h.extend_from_slice(&w.dos.1.to_le_bytes());
    h.extend_from_slice(&w.dos.0.to_le_bytes());
    h.extend_from_slice(&w.crc.to_le_bytes());
    if zip64 {
        h.extend_from_slice(&u32::MAX.to_le_bytes());
        h.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        h.extend_from_slice(&(w.packed as u32).to_le_bytes());
        h.extend_from_slice(&(w.size as u32).to_le_bytes());
    }
    let mut extra = Vec::new();
    if zip64 {
        extra.extend_from_slice(&[1, 0, 16, 0]);
        extra.extend_from_slice(&w.size.to_le_bytes());
        extra.extend_from_slice(&w.packed.to_le_bytes());
    }
    if let Some(t) = &w.ntfs {
        extra.extend_from_slice(&ntfs_extra(t));
    }
    if w.aes {
        extra.extend_from_slice(&aes_extra(w.method, aes_vendor));
    }
    h.extend_from_slice(&(w.name.len() as u16).to_le_bytes());
    h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    h.extend_from_slice(&w.name);
    h.extend_from_slice(&extra);
    out.write_all(&h)?;
    Ok(())
}

/// AE-2 (no CRC) for files under 20 bytes, AE-1 otherwise, as WinZip recommends.
fn aes_vendor(w: &Written) -> u16 {
    if w.size < 20 {
        2
    } else {
        1
    }
}

pub fn write(
    archive: &Path,
    items: &[Item],
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<Summary> {
    let tmp = temp_path(archive);
    let file = File::create(&tmp)
        .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp.display())))?;
    let res = write_to(file, items, opts, progress);
    match res {
        Ok((file, mut s)) => {
            s.archive_bytes = file.metadata()?.len();
            let _ = file.sync_all();
            drop(file);
            if archive.exists() {
                std::fs::remove_file(archive)?;
            }
            std::fs::rename(&tmp, archive)?;
            Ok(s)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn base_written(it: &Item, opts: &WriteOptions) -> Written {
    let mut name = it.name.replace('\\', "/");
    if it.is_dir && !name.ends_with('/') {
        name.push('/');
    }
    let mut flags = 0u16;
    if !name.is_ascii() {
        flags |= FLAG_UTF8;
    }
    if opts.password.is_some() && !it.is_dir {
        flags |= FLAG_ENCRYPTED;
    }
    let (host, ext_attr) = host_and_attr(it);
    let mtime = if opts.store_mtime { it.mtime } else { None };
    let ntfs = mtime.map(|m| {
        [
            m,
            if opts.store_atime {
                it.atime.unwrap_or(0)
            } else {
                0
            },
            if opts.store_ctime {
                it.ctime.unwrap_or(0)
            } else {
                0
            },
        ]
    });
    Written {
        name: name.into_bytes(),
        flags,
        method: 0,
        crc: 0,
        size: 0,
        packed: 0,
        offset: 0,
        dos: mtime.map(filetime_to_dos).unwrap_or((0x21, 0)),
        ext_attr,
        host,
        ntfs,
        aes: opts.password.is_some() && !it.is_dir,
        is_dir: it.is_dir,
    }
}

fn write_to(
    file: File,
    items: &[Item],
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<(File, Summary)> {
    let level = deflate_level(opts.level);
    let level = if opts.store { 0 } else { level };
    let pw = opts.password.as_deref();
    let mut out = BufWriter::with_capacity(1 << 20, file);
    let mut pos = 0u64;
    let mut written: Vec<Written> = Vec::with_capacity(items.len());
    let mut s = Summary {
        threads_used: opts.threads,
        ..Default::default()
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.threads.max(1))
        .build()
        .map_err(|e| Error::Other(e.to_string()))?;
    let mut i = 0;
    while i < items.len() {
        let it = &items[i];
        if !it.is_dir && it.size > IN_MEMORY {
            match stream_large(&mut out, &mut pos, it, opts, level, progress)? {
                Some(w) => {
                    s.files += 1;
                    s.input_bytes += w.size;
                    written.push(w);
                }
                None => s.skipped += 1,
            }
            i += 1;
            continue;
        }
        // A batch of consecutive directories and small files, files compressed concurrently.
        let start = i;
        let mut acc = 0u64;
        while i < items.len()
            && (items[i].is_dir || items[i].size <= IN_MEMORY)
            && (acc == 0 || acc + items[i].size <= 256 << 20)
        {
            acc += items[i].size;
            i += 1;
        }
        let batch: Vec<Option<Result<Encoded>>> = pool.install(|| {
            items[start..i]
                .par_iter()
                .map(|it| {
                    if it.is_dir {
                        return Some(Ok((0, 0, 0, Vec::new())));
                    }
                    let data = match std::fs::read(&it.src) {
                        Ok(d) => d,
                        Err(e) => {
                            progress.warn(&format!("cannot read {}: {e}", it.src.display()));
                            return None;
                        }
                    };
                    progress.add(data.len() as u64);
                    if progress.cancelled() {
                        return Some(Err(Error::Cancelled));
                    }
                    Some(
                        encode_small(&data, level, pw)
                            .map(|(m, c, b)| (m, c, data.len() as u64, b)),
                    )
                })
                .collect()
        });
        for (it, r) in items[start..i].iter().zip(batch) {
            let Some(r) = r else {
                s.skipped += 1;
                continue;
            };
            let (method, crc, size, body) = r?;
            let mut w = base_written(it, opts);
            w.offset = pos;
            if it.is_dir {
                s.dirs += 1;
            } else {
                w.method = method;
                w.size = size;
                w.packed = body.len() as u64;
                w.crc = if w.aes && aes_vendor(&w) == 2 { 0 } else { crc };
                s.files += 1;
                s.input_bytes += size;
            }
            let zip64 = w.size >= 0xFFFF_FFFF || w.packed >= 0xFFFF_FFFF;
            let mut hdr = Vec::new();
            local_header(&mut hdr, &w, zip64, aes_vendor(&w))?;
            out.write_all(&hdr)?;
            out.write_all(&body)?;
            pos += hdr.len() as u64 + body.len() as u64;
            written.push(w);
        }
    }
    let cd_start = pos;
    let mut cd = Vec::new();
    for w in &written {
        let zip64_size = w.size >= 0xFFFF_FFFF || w.packed >= 0xFFFF_FFFF;
        let zip64_off = w.offset >= 0xFFFF_FFFF;
        let mut extra = Vec::new();
        if zip64_size || zip64_off {
            let mut body = Vec::new();
            if zip64_size {
                body.extend_from_slice(&w.size.to_le_bytes());
                body.extend_from_slice(&w.packed.to_le_bytes());
            }
            if zip64_off {
                body.extend_from_slice(&w.offset.to_le_bytes());
            }
            extra.extend_from_slice(&1u16.to_le_bytes());
            extra.extend_from_slice(&(body.len() as u16).to_le_bytes());
            extra.extend_from_slice(&body);
        }
        if let Some(t) = &w.ntfs {
            extra.extend_from_slice(&ntfs_extra(t));
        }
        if w.aes {
            extra.extend_from_slice(&aes_extra(w.method, aes_vendor(w)));
        }
        cd.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
        cd.extend_from_slice(&(63u16 | (w.host << 8)).to_le_bytes());
        cd.extend_from_slice(&version_needed(w, zip64_size || zip64_off).to_le_bytes());
        cd.extend_from_slice(&w.flags.to_le_bytes());
        cd.extend_from_slice(&(if w.aes { 99 } else { w.method }).to_le_bytes());
        cd.extend_from_slice(&w.dos.1.to_le_bytes());
        cd.extend_from_slice(&w.dos.0.to_le_bytes());
        cd.extend_from_slice(&w.crc.to_le_bytes());
        let (p32, s32) = if zip64_size {
            (u32::MAX, u32::MAX)
        } else {
            (w.packed as u32, w.size as u32)
        };
        cd.extend_from_slice(&p32.to_le_bytes());
        cd.extend_from_slice(&s32.to_le_bytes());
        cd.extend_from_slice(&(w.name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&w.ext_attr.to_le_bytes());
        cd.extend_from_slice(&(if zip64_off { u32::MAX } else { w.offset as u32 }).to_le_bytes());
        cd.extend_from_slice(&w.name);
        cd.extend_from_slice(&extra);
    }
    out.write_all(&cd)?;
    let cd_size = cd.len() as u64;
    let n = written.len() as u64;
    let need64 = n >= 0xFFFF || cd_start >= 0xFFFF_FFFF || cd_size >= 0xFFFF_FFFF;
    if need64 {
        let z64 = cd_start + cd_size;
        let mut r = Vec::with_capacity(76);
        r.extend_from_slice(&EOCD64_SIG.to_le_bytes());
        r.extend_from_slice(&44u64.to_le_bytes());
        r.extend_from_slice(&63u16.to_le_bytes());
        r.extend_from_slice(&45u16.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&n.to_le_bytes());
        r.extend_from_slice(&n.to_le_bytes());
        r.extend_from_slice(&cd_size.to_le_bytes());
        r.extend_from_slice(&cd_start.to_le_bytes());
        r.extend_from_slice(&LOCATOR_SIG.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&z64.to_le_bytes());
        r.extend_from_slice(&1u32.to_le_bytes());
        out.write_all(&r)?;
    }
    let mut e = Vec::with_capacity(22);
    e.extend_from_slice(&EOCD_SIG.to_le_bytes());
    e.extend_from_slice(&0u32.to_le_bytes());
    let n16 = n.min(0xFFFF) as u16;
    e.extend_from_slice(&n16.to_le_bytes());
    e.extend_from_slice(&n16.to_le_bytes());
    e.extend_from_slice(&(cd_size.min(0xFFFF_FFFF) as u32).to_le_bytes());
    e.extend_from_slice(&(cd_start.min(0xFFFF_FFFF) as u32).to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    out.write_all(&e)?;
    out.flush()?;
    let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    Ok((file, s))
}

/// Writes a large file: local header with placeholders, data through the parallel Deflate
/// encoder (and AES), then patches sizes and CRC in place.
fn stream_large(
    out: &mut BufWriter<File>,
    pos: &mut u64,
    it: &Item,
    opts: &WriteOptions,
    level: u32,
    progress: &dyn Progress,
) -> Result<Option<Written>> {
    let mut f = match File::open(&it.src) {
        Ok(f) => f,
        Err(e) => {
            progress.warn(&format!("cannot open {}: {e}", it.src.display()));
            return Ok(None);
        }
    };
    let mut w = base_written(it, opts);
    w.method = if level == 0 { 0 } else { 8 };
    w.offset = *pos;
    w.size = it.size;
    let zip64 = it.size >= 0xFFFF_0000;
    let vendor = 1u16;
    let mut hdr = Vec::new();
    local_header(&mut hdr, &w, zip64, vendor)?;
    out.write_all(&hdr)?;
    let data_start = *pos + hdr.len() as u64;

    // Encryption needs the whole compressed body for its tag; stream through a counting
    // writer that encrypts as it goes.
    let mut enc = match opts.password.as_deref() {
        Some(pw) => {
            let mut salt = [0u8; 16];
            getrandom::fill(&mut salt)
                .map_err(|e| Error::Other(format!("random source failed: {e}")))?;
            let (aes, pv) = crate::codec::zipcrypt::WzAes::new(pw.as_bytes(), &salt, 3)?;
            out.write_all(&salt)?;
            out.write_all(&pv)?;
            Some(aes)
        }
        None => None,
    };
    let mut sink = EncSink {
        out: &mut *out,
        aes: enc.as_mut(),
        written: 0,
        buf: Vec::with_capacity(1 << 16),
    };
    let mut crc = crc32fast::Hasher::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    {
        let mut deflater = None;
        let target: &mut dyn Write = if w.method == 8 {
            deflater.insert(ParDeflate::new(&mut sink, level, opts.threads))
        } else {
            &mut sink
        };
        loop {
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Other(format!("reading {}: {e}", it.src.display()))),
            };
            crc.update(&buf[..n]);
            total += n as u64;
            progress.add(n as u64);
            if progress.cancelled() {
                return Err(Error::Cancelled);
            }
            target.write_all(&buf[..n])?;
        }
        if let Some(d) = deflater {
            d.finish()?;
        }
    }
    sink.flush_buf()?;
    let mut packed = sink.written;
    if let Some(aes) = enc {
        out.write_all(&aes.tag())?;
        packed += 28;
    }
    w.size = total;
    w.packed = packed;
    w.crc = crc.finalize();
    if !zip64 && (w.size >= 0xFFFF_FFFF || w.packed >= 0xFFFF_FFFF) {
        return Err(Error::Other(format!(
            "{} grew past 4 GiB while being read",
            it.src.display()
        )));
    }
    // Patch the local header.
    let end = data_start + packed;
    out.seek(SeekFrom::Start(w.offset))?;
    let mut fixed = Vec::new();
    local_header(&mut fixed, &w, zip64, vendor)?;
    out.write_all(&fixed)?;
    out.seek(SeekFrom::Start(end))?;
    *pos = end;
    Ok(Some(w))
}

/// Counts bytes written and encrypts them with WinZip AES when active.
struct EncSink<'a, W: Write> {
    out: &'a mut W,
    aes: Option<&'a mut crate::codec::zipcrypt::WzAes>,
    written: u64,
    buf: Vec<u8>,
}

impl<W: Write> EncSink<'_, W> {
    fn flush_buf(&mut self) -> io::Result<()> {
        if let Some(a) = self.aes.as_mut() {
            a.encrypt(&mut self.buf);
        }
        self.out.write_all(&self.buf)?;
        self.written += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }
}

impl<W: Write> Write for EncSink<'_, W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= 1 << 16 {
            self.flush_buf()?;
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
