//! GUID partition tables: the header at LBA 1 (or the backup at the end of the disk) and the
//! partition entries it points to. Partitions are named by index and label, as 7-Zip names
//! them.

use std::sync::Arc;

use super::data::{Input, ReadAt};
use super::disk::{guid_text, le32, le64, read_vec, Part, Partitions};
use super::{Archive, Format, OpenOptions, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "GPT",
    aliases: &[],
    extensions: &[],
    signatures: &[Signature::at(512, b"EFI PART")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

const SECTOR: u64 = 512;
/// Partition entry sizes this reader accepts (the spec uses 128).
const MIN_ENTRY: usize = 128;
const MAX_ENTRY: usize = 4096;
const MAX_ENTRIES: u64 = 1 << 16;

/// The header fields the reader uses, after its CRC32 checks out.
struct Header {
    guid: [u8; 16],
    entries_lba: u64,
    count: u64,
    entry_size: usize,
    array_crc: u32,
}

fn parse_header(sector: &[u8]) -> Result<Header> {
    if !sector.starts_with(b"EFI PART") {
        return Err(Error::corrupt("GPT header signature is missing"));
    }
    let size = le32(sector, 12)? as usize;
    if !(92..=SECTOR as usize).contains(&size) {
        return Err(Error::corrupt("GPT header size is not valid"));
    }
    let mut h = sector[..size].to_vec();
    let stored = le32(&h, 16)?;
    h[16..20].fill(0);
    if crc32fast::hash(&h) != stored {
        return Err(Error::corrupt("GPT header checksum does not match"));
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&sector[56..72]);
    Ok(Header {
        guid,
        entries_lba: le64(sector, 72)?,
        count: u64::from(le32(sector, 80)?),
        entry_size: le32(sector, 84)? as usize,
        array_crc: le32(sector, 88)?,
    })
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let disk: Arc<dyn ReadAt> = input.volume()?;
    let size = disk.size();
    if size < 2 * SECTOR {
        return Err(Error::NotArchive);
    }
    let primary = read_vec(&*disk, SECTOR, SECTOR as usize)?;
    if !primary.starts_with(b"EFI PART") {
        return Err(Error::NotArchive);
    }
    // A damaged primary header is replaced by the backup at the end of the disk.
    let header = match parse_header(&primary) {
        Ok(h) => h,
        Err(e) => {
            let last = size / SECTOR - 1;
            let backup = read_vec(&*disk, last * SECTOR, SECTOR as usize)?;
            parse_header(&backup).map_err(|_| e)?
        }
    };
    if header.count > MAX_ENTRIES
        || !(MIN_ENTRY..=MAX_ENTRY).contains(&header.entry_size)
        || header.entry_size % 8 != 0
    {
        return Err(Error::corrupt("GPT partition entries are not valid"));
    }
    let table_len = header.count as usize * header.entry_size;
    let table = read_vec(
        &*disk,
        header
            .entries_lba
            .checked_mul(SECTOR)
            .ok_or_else(|| Error::corrupt("GPT partition table is past the end of the disk"))?,
        table_len,
    )?;
    if crc32fast::hash(&table) != header.array_crc {
        return Err(Error::corrupt(
            "GPT partition array checksum does not match",
        ));
    }
    let mut parts = Vec::new();
    for e in table.chunks_exact(header.entry_size) {
        if e[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = le64(e, 32)?;
        let last = le64(e, 40)?;
        if last < first {
            continue;
        }
        let units: Vec<u16> = e[56..MIN_ENTRY]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let label = String::from_utf16_lossy(&units);
        parts.push(Part {
            label: (!label.is_empty()).then_some(label),
            start: first.saturating_mul(SECTOR),
            len: (last - first + 1).saturating_mul(SECTOR),
        });
    }
    let props = vec![("ID", guid_text(&header.guid))];
    Partitions::boxed(&FORMAT, disk, parts, props)
}
