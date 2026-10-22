//! Hyper-V virtual disks (`.vhdx`): the header that is current, the region table, the
//! metadata items (block size, disk size, sector size), and the block allocation table that
//! places each block of the disk in the file. A block the table does not place reads as zeros.
//! A differencing disk, or one whose log still holds changes, is refused with a clear error:
//! r7z does not replay logs or follow parents yet.

use std::sync::Arc;

use super::data::{Input, ReadAt};
use super::disk::{le16, le32, le64, read_vec, Cached, ImageArchive};
use super::{Archive, Format, OpenOptions, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "VHDX",
    aliases: &[],
    extensions: &["vhdx"],
    signatures: &[Signature::at(0, b"vhdxfile")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

const HEADER_AT: [u64; 2] = [0x1_0000, 0x2_0000];
const REGION_AT: [u64; 2] = [0x3_0000, 0x4_0000];
const HEADER_SIZE: usize = 4096;
const REGION_SIZE: usize = 65536;
const MAX_BLOCK: u64 = 1 << 28;

/// A GUID in the byte order the format stores it: the first three fields little-endian.
const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

const BAT_GUID: [u8; 16] = guid(
    0x2DC2_7766,
    0xF623,
    0x4200,
    [0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08],
);
const METADATA_GUID: [u8; 16] = guid(
    0x8B7C_A206,
    0x4790,
    0x4B9A,
    [0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E],
);
const FILE_PARAMETERS: [u8; 16] = guid(
    0xCAA1_6737,
    0xFA36,
    0x4D43,
    [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B],
);
const DISK_SIZE: [u8; 16] = guid(
    0x2FA5_4224,
    0xCD1B,
    0x4876,
    [0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8],
);
const SECTOR_SIZE: [u8; 16] = guid(
    0x8141_BF1D,
    0xA96F,
    0x4347,
    [0xAD, 0xF6, 0xC4, 0xE2, 0xFF, 0xD2, 0x9A, 0x83],
);
const PARENT_LOCATOR: [u8; 16] = guid(
    0xA8D3_5F2D,
    0xB30B,
    0x454D,
    [0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C],
);

/// CRC-32C (Castagnoli), which the header and region checksums use.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A buffer whose checksum field (at 4) is zeroed for checking.
fn checksum_ok(buf: &[u8]) -> bool {
    let Ok(stored) = le32(buf, 4) else {
        return false;
    };
    let mut copy = buf.to_vec();
    copy[4..8].fill(0);
    crc32c(&copy) == stored
}

/// The current header: the valid one with the higher sequence number.
struct Header {
    log_guid: [u8; 16],
    log_length: u32,
}

fn current_header(src: &dyn ReadAt) -> Result<Header> {
    let mut best: Option<(u64, Header)> = None;
    for at in HEADER_AT {
        let buf = read_vec(src, at, HEADER_SIZE)?;
        if !buf.starts_with(b"head") || !checksum_ok(&buf) {
            continue;
        }
        let seq = le64(&buf, 8)?;
        if best.as_ref().is_none_or(|(s, _)| seq > *s) {
            let mut log_guid = [0u8; 16];
            log_guid.copy_from_slice(&buf[48..64]);
            best = Some((
                seq,
                Header {
                    log_guid,
                    log_length: le32(&buf, 68)?,
                },
            ));
        }
    }
    best.map(|(_, h)| h)
        .ok_or_else(|| Error::corrupt("VHDX headers are both damaged"))
}

/// Where the BAT and the metadata items are.
struct Region {
    bat: (u64, u64),
    metadata: (u64, u64),
}

fn region_table(src: &dyn ReadAt) -> Result<Region> {
    for at in REGION_AT {
        let buf = read_vec(src, at, REGION_SIZE)?;
        if !buf.starts_with(b"regi") || !checksum_ok(&buf) {
            continue;
        }
        let count = le32(&buf, 8)? as usize;
        let mut bat = None;
        let mut metadata = None;
        for i in 0..count.min((REGION_SIZE - 16) / 32) {
            let e = 16 + 32 * i;
            let id = &buf[e..e + 16];
            let file_at = le64(&buf, e + 16)?;
            let len = u64::from(le32(&buf, e + 24)?);
            if id == BAT_GUID {
                bat = Some((file_at, len));
            } else if id == METADATA_GUID {
                metadata = Some((file_at, len));
            }
        }
        if let (Some(bat), Some(metadata)) = (bat, metadata) {
            return Ok(Region { bat, metadata });
        }
    }
    Err(Error::corrupt("VHDX region table is missing or damaged"))
}

/// The metadata items the reader needs.
struct Meta {
    block: u64,
    disk: u64,
    sector: u64,
    has_parent: bool,
}

fn metadata(src: &dyn ReadAt, (at, len): (u64, u64)) -> Result<Meta> {
    if len > 1 << 20 {
        return Err(Error::corrupt("VHDX metadata region is too large"));
    }
    let buf = read_vec(src, at, len as usize)?;
    if !buf.starts_with(b"metadata") {
        return Err(Error::corrupt(
            "VHDX metadata region is missing its signature",
        ));
    }
    let count = usize::from(le16(&buf, 10)?);
    let mut block = None;
    let mut disk = None;
    let mut sector = None;
    let mut has_parent = false;
    for i in 0..count.min((buf.len() - 32) / 32) {
        let e = 32 + 32 * i;
        let id = &buf[e..e + 16];
        let item = le32(&buf, e + 16)? as usize;
        let item_len = le32(&buf, e + 20)? as usize;
        let value = buf
            .get(item..item.saturating_add(item_len))
            .ok_or_else(|| Error::corrupt("VHDX metadata item is past its region"))?;
        if id == FILE_PARAMETERS {
            block = Some(u64::from(le32(value, 0)?));
            has_parent = le32(value, 4)? & 2 != 0;
        } else if id == DISK_SIZE {
            disk = Some(le64(value, 0)?);
        } else if id == SECTOR_SIZE {
            sector = Some(u64::from(le32(value, 0)?));
        } else if id == PARENT_LOCATOR {
            has_parent = true;
        }
    }
    let (Some(block), Some(disk), Some(sector)) = (block, disk, sector) else {
        return Err(Error::corrupt("VHDX metadata is incomplete"));
    };
    if !block.is_power_of_two() || !(1 << 20..=MAX_BLOCK).contains(&block) {
        return Err(Error::corrupt("VHDX block size is not valid"));
    }
    if sector != 512 && sector != 4096 {
        return Err(Error::corrupt("VHDX logical sector size is not valid"));
    }
    Ok(Meta {
        block,
        disk,
        sector,
        has_parent,
    })
}

/// The disk: each block of the virtual disk is found through the allocation table.
struct Disk {
    file: Arc<dyn ReadAt>,
    /// Page-cached view of the file for the allocation table.
    table: Cached,
    bat: u64,
    block: u64,
    /// Blocks of the virtual disk per sector bitmap block (the table interleaves them).
    chunk_ratio: u64,
    size: u64,
}

impl ReadAt for Disk {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        super::data::check_range(offset, buf.len(), self.size)?;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let block = at / self.block;
            let within = at % self.block;
            let n = (self.block - within).min((buf.len() - done) as u64) as usize;
            let index = block + block / self.chunk_ratio;
            let mut e = [0u8; 8];
            self.table.read_at(self.bat + index * 8, &mut e)?;
            let entry = u64::from_le_bytes(e);
            let state = entry & 7;
            let out = &mut buf[done..done + n];
            // 6 is fully present and 7 partially present; the latter only occurs in
            // differencing disks, which are refused, so both read from the file.
            if state == 6 || state == 7 {
                let file_at = (entry >> 20) << 20;
                self.file.read_at(file_at + within, out)?;
            } else {
                out.fill(0);
            }
            done += n;
        }
        Ok(())
    }
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let src: Arc<dyn ReadAt> = input.volume()?;
    if src.size() < 0x4_0000 + REGION_SIZE as u64 {
        return Err(Error::NotArchive);
    }
    if !read_vec(&*src, 0, 8)?.starts_with(b"vhdxfile") {
        return Err(Error::NotArchive);
    }
    let header = current_header(&*src)?;
    if header.log_guid != [0; 16] && header.log_length != 0 {
        return Err(Error::unsupported(
            "VHDX log has changes that were not written back (the disk was not closed cleanly)",
        ));
    }
    let region = region_table(&*src)?;
    let meta = metadata(&*src, region.metadata)?;
    if meta.has_parent {
        return Err(Error::unsupported(
            "differencing VHDX: its parent disk is not opened by r7z",
        ));
    }
    let chunk_ratio = (1u64 << 23) * meta.sector / meta.block;
    let blocks = meta.disk.div_ceil(meta.block);
    if blocks > 0 {
        let last = (blocks - 1) + (blocks - 1) / chunk_ratio;
        if region.bat.0.saturating_add((last + 1) * 8) > src.size() || region.bat.1 < (last + 1) * 8
        {
            return Err(Error::corrupt(
                "VHDX block allocation table is past the end of the file",
            ));
        }
    }
    let disk: Arc<dyn ReadAt> = Arc::new(Disk {
        table: Cached::new(src.clone()),
        file: src,
        bat: region.bat.0,
        block: meta.block,
        chunk_ratio,
        size: meta.disk,
    });
    let props = vec![
        ("Block Size", meta.block.to_string()),
        ("Sector Size", meta.sector.to_string()),
    ];
    let stem = super::vhd::stem(&opts.name).to_string();
    Ok(ImageArchive::boxed(
        &FORMAT,
        disk,
        format!("{stem}.mbr"),
        props,
    ))
}
