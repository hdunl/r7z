//! MBR partition tables: the four primary entries of the first sector, and the logical
//! partitions of an extended one, found by walking its chain of EBRs. Partitions are listed
//! in table order, as 7-Zip numbers them.

use std::sync::Arc;

use super::data::{Input, ReadAt};
use super::disk::{le32, read_vec, Part, Partitions};
use super::{Archive, Format, OpenOptions, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "MBR",
    aliases: &[],
    extensions: &[],
    signatures: &[Signature::at(510, &[0x55, 0xAA])],
    detect: Some(looks_like_mbr),
    write: false,
    stream: false,
    sequential: true,
    open,
};

const SECTOR: u64 = 512;
const TABLE: usize = 446;
/// Logical partitions are followed through at most this many EBRs.
const MAX_LOGICAL: usize = 128;

/// Status, type, first LBA and sector count of primary entry `i`.
fn slot(sector: &[u8], i: usize) -> Result<(u8, u8, u32, u32)> {
    let e = TABLE + i * 16;
    Ok((
        sector[e],
        sector[e + 4],
        le32(sector, e + 8)?,
        le32(sector, e + 12)?,
    ))
}

fn is_extended(typ: u8) -> bool {
    matches!(typ, 0x05 | 0x0F | 0x85)
}

/// A sector that holds a plausible partition table: every status byte is 0x00 or 0x80, and
/// some entry is in use with a size.
fn looks_like_mbr(head: &[u8]) -> bool {
    if head.len() < 512 {
        return false;
    }
    let mut any = false;
    for i in 0..4 {
        let Ok((status, typ, _, sectors)) = slot(head, i) else {
            return false;
        };
        if status != 0x00 && status != 0x80 {
            return false;
        }
        if typ != 0 {
            if sectors == 0 {
                return false;
            }
            any = true;
        }
    }
    any
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let disk: Arc<dyn ReadAt> = input.volume()?;
    if disk.size() < SECTOR {
        return Err(Error::NotArchive);
    }
    let sector = read_vec(&*disk, 0, SECTOR as usize)?;
    if sector[510..512] != [0x55, 0xAA] {
        return Err(Error::NotArchive);
    }
    let mut parts = Vec::new();
    for i in 0..4 {
        let (_, typ, start, sectors) = slot(&sector, i)?;
        if typ == 0 || sectors == 0 {
            continue;
        }
        if is_extended(typ) {
            logical(&disk, u64::from(start), &mut parts)?;
        } else {
            parts.push(Part {
                label: None,
                start: u64::from(start) * SECTOR,
                len: u64::from(sectors) * SECTOR,
            });
        }
    }
    Partitions::boxed(&FORMAT, disk, parts, Vec::new())
}

/// Lists the logical partitions of the extended partition whose first sector is `base`
/// (an LBA), following the EBR chain. An EBR's first entry is a logical partition, relative
/// to that EBR; its second, when of an extended type, points to the next EBR, relative to
/// `base`.
fn logical(disk: &Arc<dyn ReadAt>, base: u64, parts: &mut Vec<Part>) -> Result<()> {
    let mut ebr = base;
    for _ in 0..MAX_LOGICAL {
        let at = ebr
            .checked_mul(SECTOR)
            .ok_or_else(|| Error::corrupt("MBR extended partition is past the end of the disk"))?;
        if at.saturating_add(SECTOR) > disk.size() {
            break;
        }
        let sector = read_vec(&**disk, at, SECTOR as usize)?;
        if sector[510..512] != [0x55, 0xAA] {
            break;
        }
        let (_, typ, start, sectors) = slot(&sector, 0)?;
        if typ != 0 && sectors != 0 {
            parts.push(Part {
                label: None,
                start: (ebr + u64::from(start)) * SECTOR,
                len: u64::from(sectors) * SECTOR,
            });
        }
        let (_, next_typ, next, _) = slot(&sector, 1)?;
        if !is_extended(next_typ) || next == 0 {
            break;
        }
        ebr = base + u64::from(next);
    }
    Ok(())
}
