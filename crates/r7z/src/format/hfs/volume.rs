//! The volume header, and the mapping from a fork's bytes to allocation blocks. A fork's
//! extents are its eight inline extents, then records of the extents overflow B-tree keyed by
//! fork type, file ID and the number of blocks before each record.

use std::sync::Arc;

use super::be::Be;
use super::btree::BTree;
use crate::error::{Error, Result};
use crate::format::ReadAt;

/// Byte offset and length of the volume header.
const HEADER_AT: u64 = 1024;
const HEADER_LEN: usize = 512;
/// CNIDs of the system files, which key their forks in the overflow tree.
const EXTENTS_FILE: u32 = 3;
const CATALOG_FILE: u32 = 4;
const ATTRIBUTES_FILE: u32 = 8;
/// Fork types in overflow keys.
pub const DATA_FORK: u8 = 0x00;
pub const RSRC_FORK: u8 = 0xFF;
/// Allocation block sizes accepted: multiples of 512 up to 1 MiB.
const MIN_BLOCK: u64 = 512;
const MAX_BLOCK: u64 = 1 << 20;

/// A run of allocation blocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extent {
    pub start: u32,
    pub count: u32,
}

/// An `HFSPlusForkData` record: the logical size and the first eight extents.
#[derive(Clone, Copy, Debug, Default)]
pub struct ForkData {
    pub logical_size: u64,
    pub total_blocks: u32,
    pub extents: [Extent; 8],
}

impl ForkData {
    /// Parses the 80-byte record.
    pub fn parse(b: &[u8]) -> Result<ForkData> {
        let mut r = Be::at(b, 0);
        let logical_size = r.u64()?;
        r.skip(4)?; // clump size
        let total_blocks = r.u32()?;
        let mut extents = [Extent::default(); 8];
        for e in &mut extents {
            *e = read_extent(&mut r)?;
        }
        Ok(ForkData {
            logical_size,
            total_blocks,
            extents,
        })
    }
}

fn read_extent(r: &mut Be<'_>) -> Result<Extent> {
    Ok(Extent {
        start: r.u32()?,
        count: r.u32()?,
    })
}

/// A fork's bytes, as the byte ranges of the volume that hold them.
#[derive(Clone, Debug, Default)]
pub struct Fork {
    size: u64,
    runs: Vec<Run>,
}

/// `len` bytes at byte `phys` of the volume hold the fork's bytes from `logical` on.
#[derive(Clone, Copy, Debug)]
struct Run {
    logical: u64,
    phys: u64,
    len: u64,
}

impl Fork {
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The `(offset, length)` byte ranges of the volume that hold the fork, in order.
    pub fn ranges(&self) -> Vec<(u64, u64)> {
        self.runs.iter().map(|r| (r.phys, r.len)).collect()
    }

    /// Fills `buf` with the fork's bytes from `pos`.
    pub fn read_at(&self, src: &dyn ReadAt, pos: u64, mut buf: &mut [u8]) -> Result<()> {
        let end = pos
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.size)
            .ok_or_else(|| Error::corrupt("read past the end of an HFS+ fork"))?;
        let mut at = pos;
        while at < end {
            let i = self.runs.partition_point(|r| r.logical + r.len <= at);
            let run = self
                .runs
                .get(i)
                .filter(|r| r.logical <= at)
                .ok_or_else(|| Error::corrupt("HFS+ fork has a gap"))?;
            let within = at - run.logical;
            let n = (run.len - within).min(end - at) as usize;
            let (head, tail) = buf.split_at_mut(n);
            src.read_at(run.phys + within, head)?;
            buf = tail;
            at += n as u64;
        }
        Ok(())
    }
}

/// The volume geometry and the fork resolution that needs it.
pub struct Layout {
    src: Arc<dyn ReadAt>,
    block_size: u64,
    total_blocks: u64,
}

impl Layout {
    /// The fork with `data`'s size, found through its extents. `overflow` is the extents
    /// overflow tree, when the volume has one.
    fn fork(
        &self,
        overflow: Option<&BTree>,
        file_id: u32,
        fork_type: u8,
        data: &ForkData,
    ) -> Result<Fork> {
        let size = data.logical_size;
        let need = size.div_ceil(self.block_size);
        let mut extents = Vec::new();
        let mut blocks = 0u64;
        let mut batch = data.extents;
        loop {
            let mut ended = false;
            for e in batch {
                if e.count == 0 {
                    ended = true;
                    break;
                }
                if u64::from(e.start) + u64::from(e.count) > self.total_blocks {
                    return Err(Error::corrupt("HFS+ extent is past the end of the volume"));
                }
                blocks += u64::from(e.count);
                extents.push(e);
            }
            if ended || blocks >= need || blocks >= u64::from(data.total_blocks) {
                break;
            }
            let Some(tree) = overflow else { break };
            match overflow_record(tree, &*self.src, fork_type, file_id, blocks as u32)? {
                Some(next) => batch = next,
                None => break,
            }
        }
        if blocks < need {
            return Err(Error::corrupt(
                "HFS+ fork's extents end before its logical size",
            ));
        }
        let mut runs = Vec::new();
        let mut logical = 0u64;
        for e in extents {
            if logical == size {
                break;
            }
            let len = (u64::from(e.count) * self.block_size).min(size - logical);
            runs.push(Run {
                logical,
                phys: u64::from(e.start) * self.block_size,
                len,
            });
            logical += len;
        }
        Ok(Fork { size, runs })
    }
}

/// The eight extents of the overflow record for a fork starting at block `start`.
fn overflow_record(
    tree: &BTree,
    src: &dyn ReadAt,
    fork_type: u8,
    file_id: u32,
    start: u32,
) -> Result<Option<[Extent; 8]>> {
    let Some(data) = tree.find(src, extent_key, &(fork_type, file_id, start))? else {
        return Ok(None);
    };
    let mut r = Be::at(&data, 0);
    let mut out = [Extent::default(); 8];
    for e in &mut out {
        *e = read_extent(&mut r)?;
    }
    Ok(Some(out))
}

/// `(fork type, file ID, start block)` of an extents overflow key.
fn extent_key(key: &[u8]) -> Result<(u8, u32, u32)> {
    let mut r = Be::at(key, 0);
    if r.u16()? != 10 {
        return Err(Error::corrupt("HFS+ extents overflow key has the wrong length"));
    }
    let fork = r.u8()?;
    r.skip(1)?;
    Ok((fork, r.u32()?, r.u32()?))
}

/// An opened HFS+ or HFSX volume.
pub struct Volume {
    layout: Layout,
    version: u16,
    overflow: Option<BTree>,
    catalog: BTree,
    attributes: Option<BTree>,
}

impl Volume {
    /// Reads the volume header and the B-trees it names. Fails with `NotArchive` when the
    /// header is not an HFS+ or HFSX one.
    pub fn open(src: Arc<dyn ReadAt>) -> Result<Volume> {
        if src.size() < HEADER_AT + HEADER_LEN as u64 {
            return Err(Error::NotArchive);
        }
        let mut h = [0u8; HEADER_LEN];
        src.read_at(HEADER_AT, &mut h)?;
        let mut r = Be::at(&h, 0);
        let signature = r.take(2)?;
        let version = r.u16()?;
        match (signature, version) {
            (b"H+", 4) | (b"HX", 5) => {}
            (b"BD", _) => {
                return Err(Error::unsupported(
                    "HFS wrapper volumes (HFS+ inside HFS) are not supported",
                ))
            }
            _ => return Err(Error::NotArchive),
        }
        let block_size = u64::from(Be::at(&h, 40).u32()?);
        let total_blocks = u64::from(Be::at(&h, 44).u32()?);
        if block_size % MIN_BLOCK != 0 || !(MIN_BLOCK..=MAX_BLOCK).contains(&block_size) {
            return Err(Error::corrupt(format!(
                "HFS+ allocation block size {block_size} is not valid"
            )));
        }
        if total_blocks == 0 {
            return Err(Error::corrupt("HFS+ volume has no allocation blocks"));
        }
        let layout = Layout {
            src,
            block_size,
            total_blocks,
        };
        let src: &dyn ReadAt = &*layout.src;

        let extents = ForkData::parse(&h[192..272])?;
        let overflow = if extents.logical_size == 0 {
            None
        } else {
            let fork = layout.fork(None, EXTENTS_FILE, DATA_FORK, &extents)?;
            Some(BTree::open(src, fork)?)
        };
        let catalog = ForkData::parse(&h[272..352])?;
        let catalog = BTree::open(
            src,
            layout.fork(overflow.as_ref(), CATALOG_FILE, DATA_FORK, &catalog)?,
        )?;
        let attributes = ForkData::parse(&h[352..432])?;
        let attributes = if attributes.logical_size == 0 {
            None
        } else {
            let fork = layout.fork(overflow.as_ref(), ATTRIBUTES_FILE, DATA_FORK, &attributes)?;
            Some(BTree::open(src, fork)?)
        };
        Ok(Volume {
            layout,
            version,
            overflow,
            catalog,
            attributes,
        })
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn block_size(&self) -> u64 {
        self.layout.block_size
    }

    pub fn src(&self) -> Arc<dyn ReadAt> {
        self.layout.src.clone()
    }

    pub fn catalog(&self) -> &BTree {
        &self.catalog
    }

    pub fn attributes(&self) -> Option<&BTree> {
        self.attributes.as_ref()
    }

    /// Reads `buf.len()` bytes of the attributes file from `pos`.
    pub fn read_attributes(&self, pos: u64, buf: &mut [u8]) -> Result<()> {
        let tree = self
            .attributes
            .as_ref()
            .ok_or_else(|| Error::corrupt("HFS+ attribute data without an attributes file"))?;
        tree.read_at(&*self.layout.src, pos, buf)
    }

    /// The fork of file `file_id` (its data or resource fork, by `fork_type`) with `data`'s
    /// size and first extents.
    pub fn fork(&self, file_id: u32, fork_type: u8, data: &ForkData) -> Result<Fork> {
        self.layout
            .fork(self.overflow.as_ref(), file_id, fork_type, data)
    }
}
