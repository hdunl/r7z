//! Virtual Hard Disk (`.vhd`) images: fixed, dynamic and differencing disks, as Windows and
//! Hyper-V write them. The raw disk is the one entry. A differencing disk reads its
//! unallocated sectors from its parent, which is found next to it through the parent
//! locator; without the parent the archive does not open.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::data::{Input, ReadAt, Slice};
use super::disk::{be32, be64, bytes, read_vec, Cached, ImageArchive, Window};
use super::{Archive, Format, OpenOptions, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "VHD",
    aliases: &["vpc"],
    extensions: &["vhd"],
    signatures: &[Signature::at(0, b"conectix")],
    // Fixed disks have no signature at the start (only the footer at the end), so a `.vhd`
    // name is enough to try them; `open` checks the footer.
    detect: Some(|_| true),
    write: false,
    stream: false,
    sequential: true,
    open,
};

const FOOTER: u64 = 512;
const FIXED: u32 = 2;
const DYNAMIC: u32 = 3;
const DIFFERENCING: u32 = 4;
/// Parent chains deeper than this are refused (a loop through the file names, say).
const MAX_DEPTH: u32 = 8;
const NO_BLOCK: u32 = 0xFFFF_FFFF;

/// The fields of a footer that the reader needs.
struct Footer {
    kind: u32,
    data_offset: u64,
    size: u64,
}

fn has_cookie(b: &[u8]) -> bool {
    b.starts_with(b"conectix")
}

fn parse_footer(f: &[u8]) -> Result<Footer> {
    if !has_cookie(f) {
        return Err(Error::corrupt("VHD footer cookie is missing"));
    }
    let stored = be32(f, 64)?;
    let sum = f
        .iter()
        .enumerate()
        .filter(|(i, _)| !(64..68).contains(i))
        .fold(0u32, |a, (_, b)| a.wrapping_add(u32::from(*b)));
    if !sum != stored {
        return Err(Error::corrupt("VHD footer checksum does not match"));
    }
    Ok(Footer {
        kind: be32(f, 60)?,
        data_offset: be64(f, 16)?,
        size: be64(f, 48)?,
    })
}

/// The stem of an archive's file name (`disk.vhd` → `disk`).
pub fn stem(name: &str) -> &str {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rsplit_once('.') {
        Some((s, _)) if !s.is_empty() => s,
        _ => base,
    }
}

/// A dynamic disk: the block allocation table maps each block of the disk to its place in
/// the file. A differencing disk reads the sectors its bitmap does not mark from `parent`.
struct Dynamic {
    file: Arc<dyn ReadAt>,
    /// Page-cached view of the file for the allocation table.
    table: Cached,
    bat: u64,
    block: u64,
    /// Bytes of sector bitmap that start each allocated block.
    bitmap: u64,
    size: u64,
    parent: Option<Arc<dyn ReadAt>>,
}

impl Dynamic {
    fn sector_from_parent(&self, at: u64, buf: &mut [u8]) -> Result<()> {
        match &self.parent {
            Some(p) => p.read_at(at, buf),
            None => {
                buf.fill(0);
                Ok(())
            }
        }
    }
}

impl ReadAt for Dynamic {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        super::data::check_range(offset, buf.len(), self.size)?;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let index = at / self.block;
            let inside = at % self.block;
            let n = (self.block - inside).min((buf.len() - done) as u64) as usize;
            let mut entry = [0u8; 4];
            self.table.read_at(self.bat + index * 4, &mut entry)?;
            let sector = u32::from_be_bytes(entry);
            let out = &mut buf[done..done + n];
            if sector == NO_BLOCK {
                match &self.parent {
                    Some(_) => self.sector_from_parent(at, out)?,
                    None => out.fill(0),
                }
            } else {
                let base = u64::from(sector) * 512;
                if self.parent.is_none() {
                    self.file.read_at(base + self.bitmap + inside, out)?;
                } else {
                    // Differencing: a sector whose bitmap bit is clear lives in the parent.
                    let mut pos = 0usize;
                    while pos < n {
                        let s_at = at + pos as u64;
                        let s_in = s_at % self.block;
                        let sec = s_in / 512;
                        let room = (512 - s_in % 512).min((n - pos) as u64) as usize;
                        let mut byte = [0u8; 1];
                        self.file.read_at(base + sec / 8, &mut byte)?;
                        let set = byte[0] >> (7 - sec % 8) & 1 == 1;
                        let chunk = &mut out[pos..pos + room];
                        if set {
                            self.file.read_at(base + self.bitmap + s_in, chunk)?;
                        } else {
                            self.sector_from_parent(s_at, chunk)?;
                        }
                        pos += room;
                    }
                }
            }
            done += n;
        }
        Ok(())
    }
}

/// The file name of a differencing disk's parent, from its parent locator entries (Windows
/// relative or absolute paths; the name is looked up next to the child).
fn parent_name(src: &dyn ReadAt, hdr: &[u8]) -> Result<Option<String>> {
    for i in 0..8 {
        let at = 576 + i * 24;
        let code = bytes::<4>(hdr, at)?;
        if &code != b"W2ru" && &code != b"W2ku" {
            continue;
        }
        // Platform data length (8), then platform data offset (16).
        let len = be32(hdr, at + 8)? as usize;
        let off = be64(hdr, at + 16)?;
        if len == 0 || len > 4096 {
            continue;
        }
        let raw = read_vec(src, off, len)?;
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let path = String::from_utf16_lossy(&units);
        let name = path.rsplit(['\\', '/']).next().unwrap_or("").to_string();
        if !name.is_empty() {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// Opens the disk in `src`. `dir` is where a differencing disk finds its parent.
/// A disk's method (`Fixed`, `Dynamic`, `Differencing`), the readable disk and its properties.
type Parsed = (&'static str, Arc<dyn ReadAt>, Vec<(&'static str, String)>);

fn open_disk(src: Arc<dyn ReadAt>, dir: Option<&Path>, depth: u32) -> Result<Parsed> {
    let len = src.size();
    if len < FOOTER {
        return Err(Error::NotArchive);
    }
    let tail = read_vec(&*src, len - FOOTER, FOOTER as usize)?;
    let head = if has_cookie(&tail) {
        Vec::new()
    } else {
        read_vec(&*src, 0, FOOTER as usize)?
    };
    let footer = if has_cookie(&tail) {
        parse_footer(&tail)?
    } else if has_cookie(&head) {
        parse_footer(&head)?
    } else {
        return Err(Error::NotArchive);
    };
    match footer.kind {
        FIXED => {
            if footer.size > len - FOOTER {
                return Err(Error::corrupt("VHD fixed disk is longer than the file"));
            }
            let disk: Arc<dyn ReadAt> = Arc::new(Window::new(src, 0, footer.size));
            Ok(("Fixed", disk, Vec::new()))
        }
        DYNAMIC | DIFFERENCING => {
            let at = footer.data_offset;
            let hdr = read_vec(&*src, at, 1024)?;
            if !hdr.starts_with(b"cxsparse") {
                return Err(Error::corrupt("VHD dynamic header cookie is missing"));
            }
            let bat = be64(&hdr, 16)?;
            let entries = u64::from(be32(&hdr, 28)?);
            let block = u64::from(be32(&hdr, 32)?);
            if !block.is_power_of_two() || !(512..=1 << 30).contains(&block) {
                return Err(Error::corrupt("VHD block size is not a valid power of two"));
            }
            let blocks = footer.size.div_ceil(block);
            if blocks > entries || bat.checked_add(entries * 4).is_none_or(|e| e > len) {
                return Err(Error::corrupt(
                    "VHD block allocation table is past the end of the file",
                ));
            }
            let sectors = block / 512;
            let bitmap = sectors.div_ceil(8).div_ceil(512) * 512;
            let mut props = vec![("Block Size", block.to_string())];
            let parent = if footer.kind == DIFFERENCING {
                let name = parent_name(&*src, &hdr)?;
                let found = match (name, dir) {
                    (Some(n), Some(d)) if depth < MAX_DEPTH => {
                        let p: PathBuf = d.join(&n);
                        if p.is_file() {
                            Some((n, p))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                let Some((n, p)) = found else {
                    return Err(Error::unsupported(
                        "differencing VHD: its parent disk was not found next to it",
                    ));
                };
                let parent_src: Arc<dyn ReadAt> = Arc::new(Slice::map_file(&p)?);
                let (_, pd, _) = open_disk(parent_src, p.parent(), depth + 1)?;
                props.push(("Parent", n));
                Some(pd)
            } else {
                None
            };
            let dynamic = Dynamic {
                file: src.clone(),
                table: Cached::new(src),
                bat,
                block,
                bitmap,
                size: footer.size,
                parent,
            };
            let method = if footer.kind == DIFFERENCING {
                "Differencing"
            } else {
                "Dynamic"
            };
            Ok((method, Arc::new(dynamic), props))
        }
        _ => Err(Error::corrupt("unknown VHD disk type")),
    }
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let src = input.volume()?;
    let dir = opts.path.as_deref().and_then(Path::parent);
    let (method, disk, mut props) = open_disk(src, dir, 0)?;
    props.insert(0, ("Method", method.to_string()));
    let name = format!("{}.mbr", stem(&opts.name));
    Ok(ImageArchive::boxed(&FORMAT, disk, name, props))
}
