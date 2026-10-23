//! Catalog records: folders and files, read in leaf order. Thread records are skipped, since
//! each folder and file record names its parent and its own name in its key.

use super::be::{utf16be, Be};
use super::btree::split_key;
use super::volume::{ForkData, Volume};
use crate::error::{Error, Result};

/// CNID of the root folder, whose children are the top level of the volume.
pub const ROOT: u32 = 2;
/// CNIDs below this are reserved for the system files and are not listed.
const FIRST_USER_ID: u32 = 16;
/// Upper bound on catalog records read, against damaged trees.
const MAX_RECORDS: usize = 4_000_000;
const MAX_NAME: usize = 255;
const FOLDER: u16 = 1;
const FILE: u16 = 2;
const THREAD_FOLDER: u16 = 3;
const THREAD_FILE: u16 = 4;
/// Sizes of the folder and file record data.
const FOLDER_LEN: usize = 88;
const FILE_LEN: usize = 248;

/// A folder or file record, with the parent and name from its key.
pub struct Record {
    pub cnid: u32,
    pub parent: u32,
    pub name: String,
    pub is_dir: bool,
    /// BSD mode bits (file type and permissions).
    pub mode: u16,
    /// HFS+ dates: seconds since 1904-01-01 UTC.
    pub created: u32,
    pub modified: u32,
    pub accessed: u32,
    pub file_type: [u8; 4],
    pub creator: [u8; 4],
    /// The link number of a hard link (its `iNode<n>` data file), for BSD info.
    pub special: u32,
    pub data: ForkData,
    pub rsrc: ForkData,
}

/// Every folder and file record of the catalog that is a user item.
pub fn read(volume: &Volume) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    volume.catalog().for_each_record(&*volume.src(), |rec| {
        if let Some(r) = parse(rec.bytes)? {
            if out.len() >= MAX_RECORDS {
                return Err(Error::corrupt("the HFS+ catalog has too many records"));
            }
            out.push(r);
        }
        Ok(())
    })?;
    Ok(out)
}

fn parse(rec: &[u8]) -> Result<Option<Record>> {
    let (key, data) = split_key(rec)?;
    let mut k = Be::at(key, 2);
    let parent = k.u32()?;
    let name_len = usize::from(k.u16()?);
    if name_len > MAX_NAME {
        return Err(Error::corrupt("HFS+ catalog name is too long"));
    }
    let name = utf16be(k.take(2 * name_len)?);
    let (is_dir, len) = match Be::at(data, 0).u16()? {
        FOLDER => (true, FOLDER_LEN),
        FILE => (false, FILE_LEN),
        THREAD_FOLDER | THREAD_FILE => return Ok(None),
        other => {
            return Err(Error::corrupt(format!(
                "unknown HFS+ catalog record type {other}"
            )))
        }
    };
    if data.len() < len {
        return Err(Error::corrupt("HFS+ catalog record is truncated"));
    }
    let cnid = Be::at(data, 8).u32()?;
    if cnid < FIRST_USER_ID {
        return Ok(None);
    }
    let mut r = Record {
        cnid,
        parent,
        name,
        is_dir,
        mode: Be::at(data, 42).u16()?,
        created: Be::at(data, 12).u32()?,
        modified: Be::at(data, 16).u32()?,
        accessed: Be::at(data, 24).u32()?,
        file_type: [0; 4],
        creator: [0; 4],
        special: Be::at(data, 44).u32()?,
        data: ForkData::default(),
        rsrc: ForkData::default(),
    };
    if !is_dir {
        r.file_type.copy_from_slice(Be::at(data, 48).take(4)?);
        r.creator.copy_from_slice(Be::at(data, 52).take(4)?);
        r.data = ForkData::parse(Be::at(data, 88).take(80)?)?;
        r.rsrc = ForkData::parse(Be::at(data, 168).take(80)?)?;
    }
    Ok(Some(r))
}
