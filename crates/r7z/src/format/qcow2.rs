//! QEMU copy-on-write disk images (`.qcow2`, version 2 and 3): the two-level cluster table,
//! uncompressed clusters and zlib-compressed ones (raw deflate streams inside a cluster), and
//! zero clusters. A backing file is not followed: its clusters are reported as an error
//! when a read needs them, and the header's backing name is listed.

use std::io::Read;
use std::sync::{Arc, Mutex};

use flate2::read::DeflateDecoder;

use super::data::{check_range, Input, ReadAt};
use super::disk::{be32, be64, read_vec, Cached, ImageArchive};
use super::{Archive, Format, OpenOptions, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "QCOW2",
    aliases: &["qcow"],
    extensions: &["qcow2", "qcow"],
    signatures: &[Signature::at(0, &[0x51, 0x46, 0x49, 0xFB])],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

/// Bits of a table entry: the copied flag (63), the compressed flag (62), and the zero
/// flag (bit 0 of a version 3 cluster entry).
const COMPRESSED: u64 = 1 << 62;
const ZERO: u64 = 1;
const OFFSET: u64 = 0x00FF_FFFF_FFFF_FE00;
/// Largest L1 table and backing name this reader reads.
const MAX_BACKING: u64 = 1023;
const MAX_CLUSTER_BITS: u32 = 21;
const MIN_CLUSTER_BITS: u32 = 9;

struct Header {
    version: u32,
    backing_offset: u64,
    backing_size: u64,
    cluster_bits: u32,
    size: u64,
    crypt: u32,
    l1_size: u64,
    l1_offset: u64,
    incompatible: u64,
    compression_type: u8,
}

fn parse_header(b: &[u8]) -> Result<Header> {
    let version = be32(b, 4)?;
    if version != 2 && version != 3 {
        return Err(Error::unsupported(format!("QCOW2 version {version}")));
    }
    let (incompatible, compression_type) = if version == 3 {
        (be64(b, 72)?, b.get(104).copied().unwrap_or(0))
    } else {
        (0, 0)
    };
    Ok(Header {
        version,
        backing_offset: be64(b, 8)?,
        backing_size: u64::from(be32(b, 16)?),
        cluster_bits: be32(b, 20)?,
        size: be64(b, 24)?,
        crypt: be32(b, 32)?,
        l1_size: u64::from(be32(b, 36)?),
        l1_offset: be64(b, 40)?,
        incompatible,
        compression_type,
    })
}

/// The disk: cluster `c` is found through L1 entry `c / per` and L2 entry `c % per`.
struct Qcow2 {
    file: Arc<dyn ReadAt>,
    /// Page-cached view of the file for the tables.
    table: Cached,
    cluster_bits: u32,
    l1_offset: u64,
    l1_size: u64,
    size: u64,
    version3: bool,
    /// The backing file's name, when the image has one.
    backing: Option<String>,
    /// The last compressed cluster decoded.
    last: Mutex<Option<(u64, Arc<[u8]>)>>,
}

impl Qcow2 {
    fn cluster(&self) -> u64 {
        1 << self.cluster_bits
    }

    /// The cluster's bytes, decoded from its compressed form.
    fn decompress(&self, index: u64, entry: u64) -> Result<Arc<[u8]>> {
        let mut last = self.last.lock().unwrap();
        if let Some((i, data)) = last.as_ref() {
            if *i == index {
                return Ok(data.clone());
            }
        }
        // The compressed size is stored in the sectors above the offset; the offset is the
        // bits below them.
        let shift = 62 - (self.cluster_bits - 8);
        let mask = (1u64 << (self.cluster_bits - 8)) - 1;
        let sectors = ((entry >> shift) & mask) + 1;
        let offset = entry & ((1u64 << shift) - 1);
        let len = (sectors * 512).saturating_sub(offset & 511);
        let raw = read_vec(&*self.file, offset, len as usize)?;
        let mut out = Vec::with_capacity(self.cluster() as usize);
        DeflateDecoder::new(&raw[..])
            .take(self.cluster())
            .read_to_end(&mut out)
            .map_err(|e| Error::corrupt(format!("QCOW2 compressed cluster: {e}")))?;
        out.resize(self.cluster() as usize, 0);
        let data: Arc<[u8]> = out.into();
        *last = Some((index, data.clone()));
        Ok(data)
    }
}

impl ReadAt for Qcow2 {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        let cluster = self.cluster();
        let per = cluster / 8;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let index = at / cluster;
            let within = at % cluster;
            let n = (cluster - within).min((buf.len() - done) as u64) as usize;
            let out = &mut buf[done..done + n];
            let l1_index = index / per;
            let l2_index = index % per;
            let l1 = if l1_index < self.l1_size {
                be64(&read_vec(&self.table, self.l1_offset + 8 * l1_index, 8)?, 0)?
            } else {
                0
            };
            let l2_table = l1 & OFFSET;
            let entry = if l2_table == 0 {
                0
            } else {
                be64(&read_vec(&self.table, l2_table + 8 * l2_index, 8)?, 0)?
            };
            if entry & COMPRESSED != 0 {
                let data = self.decompress(index, entry)?;
                out.copy_from_slice(&data[within as usize..within as usize + n]);
            } else if entry & ZERO != 0 && self.version3 {
                out.fill(0);
            } else if entry & OFFSET == 0 {
                match &self.backing {
                    Some(name) => {
                        return Err(Error::unsupported(format!(
                            "QCOW2 cluster is not stored in this image; its backing file {name:?} is not followed"
                        )))
                    }
                    None => out.fill(0),
                }
            } else {
                self.file.read_at((entry & OFFSET) + within, out)?;
            }
            done += n;
        }
        Ok(())
    }
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let file: Arc<dyn ReadAt> = input.volume()?;
    if file.size() < 72 {
        return Err(Error::NotArchive);
    }
    let head = read_vec(&*file, 0, 104)?;
    if !head.starts_with(&[0x51, 0x46, 0x49, 0xFB]) {
        return Err(Error::NotArchive);
    }
    let h = parse_header(&head)?;
    if h.crypt != 0 {
        return Err(Error::unsupported("encrypted QCOW2 image"));
    }
    if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&h.cluster_bits) {
        return Err(Error::corrupt("QCOW2 cluster size is not valid"));
    }
    if h.version == 3 && h.incompatible & (1 << 3) != 0 && h.compression_type != 0 {
        return Err(Error::unsupported("QCOW2 with zstd-compressed clusters"));
    }
    if h.l1_offset
        .checked_add(h.l1_size.saturating_mul(8))
        .is_none_or(|end| end > file.size())
    {
        return Err(Error::corrupt("QCOW2 L1 table is past the end of the file"));
    }
    let backing = if h.backing_offset != 0 && h.backing_size > 0 {
        let n = h.backing_size.min(MAX_BACKING);
        let raw = read_vec(&*file, h.backing_offset, n as usize)?;
        Some(String::from_utf8_lossy(&raw).into_owned())
    } else {
        None
    };
    let mut props = vec![
        ("Version", h.version.to_string()),
        ("Cluster Size", (1u64 << h.cluster_bits).to_string()),
    ];
    if let Some(b) = &backing {
        props.push(("Backing File", b.clone()));
    }
    let disk = Qcow2 {
        table: Cached::new(file.clone()),
        file,
        cluster_bits: h.cluster_bits,
        l1_offset: h.l1_offset,
        l1_size: h.l1_size,
        size: h.size,
        version3: h.version == 3,
        backing,
        last: Mutex::new(None),
    };
    let stem = super::vhd::stem(&opts.name).to_string();
    Ok(ImageArchive::boxed(
        &FORMAT,
        Arc::new(disk),
        format!("{stem}.mbr"),
        props,
    ))
}
