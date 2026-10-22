//! VMware virtual disks (`.vmdk`): sparse extents (monolithic sparse, and stream-optimized
//! with zlib-compressed grains), and text descriptors that name flat, sparse and zero extents
//! next to them. The raw disk is the one entry. A descriptor's extent files are found beside
//! the descriptor, so a descriptor nested in another archive cannot be opened.

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};

use flate2::read::ZlibDecoder;

use super::data::{check_range, Input, ReadAt, Slice};
use super::disk::{le32, le64, read_vec, Cached, Concat, ImageArchive, Window, Zeros};
use super::{Archive, Format, OpenOptions, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "VMDK",
    aliases: &[],
    extensions: &["vmdk"],
    signatures: &[
        Signature::at(0, b"KDMV"),
        Signature::at(0, b"# Disk DescriptorFile"),
    ],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

const SECTOR: u64 = 512;
const GD_AT_END: u64 = u64::MAX;
const COMPRESSED: u32 = 0x1_0000;
/// Descriptors are text; anything larger than this is not one.
const MAX_DESCRIPTOR: usize = 1 << 20;
/// Extents that nest (a sparse file named by a descriptor) are followed this deep.
const MAX_NEST: u32 = 2;

/// A sparse extent: a grain directory of grain tables of grain addresses.
struct Sparse {
    file: Arc<dyn ReadAt>,
    /// Page-cached view of the file for the directory and tables.
    table: Cached,
    gd_at: u64,
    grain: u64,
    gtes: u64,
    compressed: bool,
    size: u64,
    /// The last grain decompressed, so a sequential reader decodes each grain once.
    last: Mutex<Option<(u64, Arc<[u8]>)>>,
}

impl Sparse {
    fn open(file: Arc<dyn ReadAt>) -> Result<(Self, String)> {
        let head = read_vec(&*file, 0, SECTOR as usize)?;
        if !head.starts_with(b"KDMV") {
            return Err(Error::NotArchive);
        }
        let flags = le32(&head, 8)?;
        let capacity = le64(&head, 12)?;
        let grain = le64(&head, 20)?;
        let mut gd = le64(&head, 56)?;
        let gtes = u64::from(le32(&head, 44)?);
        if gd == GD_AT_END {
            // A stream-optimized file keeps its real directory in a footer: a copy of the
            // header, 1024 bytes before the end of the file.
            let len = file.size();
            if len < 2 * SECTOR {
                return Err(Error::corrupt("VMDK footer is missing"));
            }
            let footer = read_vec(&*file, len - 2 * SECTOR, SECTOR as usize)?;
            if !footer.starts_with(b"KDMV") {
                return Err(Error::corrupt("VMDK footer is missing"));
            }
            gd = le64(&footer, 56)?;
        }
        if capacity == 0
            || !grain.is_power_of_two()
            || grain < 8
            || !gtes.is_power_of_two()
            || gtes > 4096
            || gd == GD_AT_END
        {
            return Err(Error::corrupt("VMDK sparse header is not valid"));
        }
        let size = capacity
            .checked_mul(SECTOR)
            .ok_or_else(|| Error::corrupt("VMDK capacity is not valid"))?;
        let kind = if flags & COMPRESSED != 0 {
            "streamOptimized"
        } else {
            "monolithicSparse"
        };
        let compressed = flags & COMPRESSED != 0;
        let table = Cached::new(file.clone());
        Ok((
            Sparse {
                file,
                table,
                gd_at: gd
                    .checked_mul(SECTOR)
                    .ok_or_else(|| Error::corrupt("VMDK directory is past the end of the file"))?,
                grain,
                gtes,
                compressed,
                size,
                last: Mutex::new(None),
            },
            kind.to_string(),
        ))
    }

    fn grain_bytes(&self) -> u64 {
        self.grain * SECTOR
    }

    /// The grain's data, decompressed (stream-optimized files). A grain is a marker (its
    /// sector and compressed size) followed by zlib data.
    fn grain_data(&self, index: u64, at: u64) -> Result<Arc<[u8]>> {
        let mut last = self.last.lock().unwrap();
        if let Some((i, data)) = last.as_ref() {
            if *i == index {
                return Ok(data.clone());
            }
        }
        let size = u64::from(le32(&read_vec(&self.table, at, 12)?, 8)?);
        if size > self.grain_bytes() + 64 {
            return Err(Error::corrupt("VMDK compressed grain is too large"));
        }
        let raw = read_vec(&self.table, at + 12, size as usize)?;
        let mut out = Vec::with_capacity(self.grain_bytes() as usize);
        ZlibDecoder::new(&raw[..])
            .take(self.grain_bytes())
            .read_to_end(&mut out)
            .map_err(|e| Error::corrupt(format!("VMDK compressed grain: {e}")))?;
        out.resize(self.grain_bytes() as usize, 0);
        let data: Arc<[u8]> = out.into();
        *last = Some((index, data.clone()));
        Ok(data)
    }
}

impl ReadAt for Sparse {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        let gb = self.grain_bytes();
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let g = at / gb;
            let within = at % gb;
            let n = (gb - within).min((buf.len() - done) as u64) as usize;
            let out = &mut buf[done..done + n];
            let table_no = g / self.gtes;
            let gte_no = g % self.gtes;
            let gt = u64::from(le32(
                &read_vec(&self.table, self.gd_at + 4 * table_no, 4)?,
                0,
            )?);
            let sector = if gt == 0 {
                0
            } else {
                u64::from(le32(
                    &read_vec(&self.table, gt * SECTOR + 4 * gte_no, 4)?,
                    0,
                )?)
            };
            // 0 and 1 are grains that were never written, and read as zeros.
            if sector <= 1 {
                out.fill(0);
            } else if self.compressed {
                let data = self.grain_data(g, sector * SECTOR)?;
                out.copy_from_slice(&data[within as usize..within as usize + n]);
            } else {
                self.file.read_at(sector * SECTOR + within, out)?;
            }
            done += n;
        }
        Ok(())
    }
}

/// Opens the descriptor's extents, which are named relative to the descriptor's folder.
fn descriptor_disk(text: &str, dir: Option<&Path>, depth: u32) -> Result<Arc<dyn ReadAt>> {
    let mut parts: Vec<Arc<dyn ReadAt>> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !(line.starts_with("RW ")
            || line.starts_with("RDONLY ")
            || line.starts_with("NOACCESS "))
        {
            continue;
        }
        let (head, rest) = line.split_once('"').unwrap_or((line, ""));
        let mut fields = head.split_whitespace();
        let _access = fields.next();
        let sectors: u64 = fields
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::corrupt("VMDK extent line has no size"))?;
        let kind = fields.next().unwrap_or("");
        let name = rest.split('"').next().unwrap_or("");
        let tail = rest.split_once('"').map(|(_, t)| t.trim()).unwrap_or("");
        let len = sectors
            .checked_mul(SECTOR)
            .ok_or_else(|| Error::corrupt("VMDK extent is too large"))?;
        if kind == "ZERO" {
            parts.push(Arc::new(Zeros(len)));
            continue;
        }
        let Some(dir) = dir else {
            return Err(Error::unsupported(
                "VMDK descriptor: its extent files must be next to it, which is not available here",
            ));
        };
        let path = dir.join(name);
        let file: Arc<dyn ReadAt> = Arc::new(
            Slice::map_file(&path)
                .map_err(|_| Error::unsupported(format!("VMDK extent {name:?} was not found")))?,
        );
        match kind {
            "FLAT" => {
                let offset: u64 = tail
                    .split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                let base = offset
                    .checked_mul(SECTOR)
                    .ok_or_else(|| Error::corrupt("VMDK extent offset is not valid"))?;
                parts.push(Arc::new(Window::new(file, base, len)));
            }
            "SPARSE" if depth < MAX_NEST => {
                let (sparse, _) = Sparse::open(file)?;
                parts.push(Arc::new(sparse));
            }
            _ => {
                return Err(Error::unsupported(format!(
                    "VMDK extent type {kind:?} is not supported"
                )))
            }
        }
    }
    if parts.is_empty() {
        return Err(Error::corrupt("VMDK descriptor has no extents"));
    }
    Ok(Arc::new(Concat::new(parts)))
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let src: Arc<dyn ReadAt> = input.volume()?;
    let dir = opts.path.as_deref().and_then(Path::parent);
    let head = read_vec(&*src, 0, (src.size() as usize).min(21))?;
    let (disk, kind): (Arc<dyn ReadAt>, String) = if head.starts_with(b"KDMV") {
        let (sparse, kind) = Sparse::open(src)?;
        (Arc::new(sparse), kind)
    } else if head.starts_with(b"# Disk DescriptorFile") {
        let text_bytes = read_vec(&*src, 0, (src.size() as usize).min(MAX_DESCRIPTOR))?;
        let text = String::from_utf8_lossy(&text_bytes);
        let kind = text
            .lines()
            .find_map(|l| {
                l.strip_prefix("createType=\"")
                    .map(|v| v.trim_end_matches('"').to_string())
            })
            .unwrap_or_else(|| "descriptor".to_string());
        (descriptor_disk(&text, dir, 0)?, kind)
    } else {
        return Err(Error::NotArchive);
    };
    let stem = super::vhd::stem(&opts.name).to_string();
    Ok(ImageArchive::boxed(
        &FORMAT,
        disk,
        format!("{stem}.mbr"),
        vec![("Type", kind)],
    ))
}
