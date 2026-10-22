//! ext2, ext3 and ext4 file systems: the superblock and group descriptors, inodes with their
//! block maps (indirect blocks, or extent trees), inline data, and the linear directory
//! blocks that name the inodes. Hashed (htree) directories are read through their leaf
//! blocks, which the format keeps in linear form. Symbolic links are listed with their
//! targets; devices, FIFOs and sockets are left out.

use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;

use super::data::{Input, ReadAt};
use super::disk::{le16, le32, read_runs, read_vec, u8_at, Cached, Run, RunReader};
use super::{Archive, Ctx, Entry, EntryFn, Format, Link, OpenOptions, Signature, Unit};
use crate::error::{Error, Result};
use crate::sevenz::attr;
use crate::util::time::unix_to_filetime;

pub const FORMAT: Format = Format {
    name: "Ext",
    aliases: &["ext2", "ext3", "ext4"],
    extensions: &[],
    signatures: &[Signature::at(1080, &[0x53, 0xEF])],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

const ROOT_INO: u32 = 2;
const EXTENTS_FL: u32 = 0x0008_0000;
const INLINE_FL: u32 = 0x1000_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const MAX_DEPTH: u16 = 5;
const MAX_DIR: u64 = 64 << 20;
const MAX_BLOCKS: u64 = 1 << 24;
const MAX_TARGET: u64 = 4096;
const MAX_ENTRIES: usize = 1 << 20;
/// Inode mode file types.
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;
const S_IFMT: u16 = 0xF000;

pub struct Ext {
    vol: Arc<dyn ReadAt>,
    /// Page-cached view of the volume for inode tables and group descriptors.
    meta: Cached,
    block: u64,
    inodes_per_group: u64,
    first_data_block: u64,
    inode_size: u64,
    desc_size: u64,
    is64: bool,
    entries: Vec<Entry>,
    /// The inode number of each entry.
    inodes: Vec<u32>,
    units: Vec<Unit>,
    props: Vec<(&'static str, String)>,
}

/// The data of an inode: its bytes, inline, or runs of blocks.
enum Content {
    Inline(Vec<u8>),
    Runs { runs: Vec<Run>, size: u64 },
}

impl Ext {
    fn read_inode(&self, ino: u32) -> Result<Vec<u8>> {
        if ino == 0 {
            return Err(Error::corrupt("ext inode number 0"));
        }
        let n = u64::from(ino - 1);
        let group = n / self.inodes_per_group;
        let index = n % self.inodes_per_group;
        let desc_at = (self.first_data_block + 1) * self.block + group * self.desc_size;
        let desc = read_vec(&self.meta, desc_at, self.desc_size as usize)?;
        let lo = u64::from(le32(&desc, 8)?);
        let hi = if self.is64 {
            u64::from(le32(&desc, 0x28)?)
        } else {
            0
        };
        let table = lo | (hi << 32);
        let at = table
            .checked_mul(self.block)
            .and_then(|t| t.checked_add(index * self.inode_size))
            .ok_or_else(|| Error::corrupt("ext inode table is past the end of the volume"))?;
        read_vec(&self.meta, at, self.inode_size as usize)
    }

    /// The data of an inode, as inline bytes or as runs of blocks.
    fn content(&self, inode: &[u8]) -> Result<Content> {
        let mode = le16(inode, 0)?;
        let size_lo = u64::from(le32(inode, 4)?);
        let size = if mode & S_IFMT == S_IFREG {
            size_lo | (u64::from(le32(inode, 0x6C)?) << 32)
        } else {
            size_lo
        };
        let flags = le32(inode, 0x20)?;
        let map = &inode[0x28..0x28 + 60];
        if flags & INLINE_FL != 0 {
            return Ok(Content::Inline(self.inline_data(inode, size)?));
        }
        if mode & S_IFMT == S_IFLNK && size < 60 && le32(inode, 0x1C)? == 0 {
            // A fast symbolic link keeps its target in the block map.
            return Ok(Content::Inline(map[..size as usize].to_vec()));
        }
        let runs = if flags & EXTENTS_FL != 0 {
            let mut out = Vec::new();
            self.extent_runs(map, &mut out, 0)?;
            out.sort_by_key(|r| r.at);
            let mut end = 0u64;
            for r in &out {
                if r.at < end {
                    return Err(Error::corrupt("ext extents overlap"));
                }
                end = r.at + r.len;
            }
            out
        } else {
            self.block_runs(map, size)?
        };
        Ok(Content::Runs { runs, size })
    }

    /// Inline data: the first 60 bytes live in the block map, the rest in the `system.data`
    /// extended attribute kept after the inode's fixed fields.
    fn inline_data(&self, inode: &[u8], size: u64) -> Result<Vec<u8>> {
        let mut out = inode[0x28..0x28 + 60].to_vec();
        if size as usize > out.len() {
            let start = 128 + usize::from(le16(inode, 0x80)?);
            if start + 4 <= inode.len() && le32(inode, start)? == 0xEA02_0000 {
                let first = start + 4;
                let mut at = first;
                while at + 16 <= inode.len() {
                    let name_len = usize::from(u8_at(inode, at)?);
                    let name_index = u8_at(inode, at + 1)?;
                    if name_len == 0 && name_index == 0 && le32(inode, at)? == 0 {
                        break;
                    }
                    let value_at = first + usize::from(le16(inode, at + 2)?);
                    let value_size = le32(inode, at + 8)? as usize;
                    let name = inode.get(at + 16..at + 16 + name_len).unwrap_or(&[]);
                    if name_index == 7 && name == b"data" {
                        let v = inode
                            .get(value_at..value_at + value_size)
                            .ok_or_else(|| Error::corrupt("ext inline data is past the inode"))?;
                        out.extend_from_slice(v);
                        break;
                    }
                    at += (16 + name_len + 3) & !3;
                }
            }
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// Runs of a block-mapped file: twelve direct pointers, then single, double and triple
    /// indirect blocks. A zero pointer is a hole.
    fn block_runs(&self, map: &[u8], size: u64) -> Result<Vec<Run>> {
        let nblocks = size.div_ceil(self.block);
        if nblocks > MAX_BLOCKS {
            return Err(Error::corrupt("ext file is too large to map"));
        }
        let mut blocks: Vec<u64> = Vec::new();
        for i in 0..12 {
            self.walk_ptr(u64::from(le32(map, 4 * i)?), 0, nblocks, &mut blocks)?;
        }
        self.walk_ptr(u64::from(le32(map, 48)?), 1, nblocks, &mut blocks)?;
        self.walk_ptr(u64::from(le32(map, 52)?), 2, nblocks, &mut blocks)?;
        self.walk_ptr(u64::from(le32(map, 56)?), 3, nblocks, &mut blocks)?;
        let mut runs: Vec<Run> = Vec::new();
        for (i, &b) in blocks.iter().enumerate() {
            let at = i as u64 * self.block;
            let phys = (b != 0).then(|| b * self.block);
            if let Some(last) = runs.last_mut() {
                let contiguous = match (last.phys, phys) {
                    (None, None) => true,
                    (Some(p), Some(q)) => p + last.len == q,
                    _ => false,
                };
                if contiguous && last.at + last.len == at {
                    last.len += self.block;
                    continue;
                }
            }
            runs.push(Run {
                at,
                len: self.block,
                phys,
            });
        }
        Ok(runs)
    }

    /// Appends the data blocks under `ptr`, a block at `level` (0: a data block).
    fn walk_ptr(&self, ptr: u64, level: u32, nblocks: u64, out: &mut Vec<u64>) -> Result<()> {
        if out.len() as u64 >= nblocks {
            return Ok(());
        }
        if level == 0 {
            out.push(ptr);
            return Ok(());
        }
        let per = self.block / 4;
        if ptr == 0 {
            let span = per.saturating_pow(level).min(nblocks - out.len() as u64);
            out.extend(std::iter::repeat_n(0, span as usize));
            return Ok(());
        }
        let buf = read_vec(&self.meta, ptr * self.block, self.block as usize)?;
        for i in 0..per {
            if out.len() as u64 >= nblocks {
                break;
            }
            self.walk_ptr(
                u64::from(le32(&buf, 4 * i as usize)?),
                level - 1,
                nblocks,
                out,
            )?;
        }
        Ok(())
    }

    /// Runs of an extent tree: the leaves of a node are its extents, and an index node points
    /// at child nodes one level down.
    fn extent_runs(&self, node: &[u8], out: &mut Vec<Run>, depth: u16) -> Result<()> {
        if le16(node, 0)? != EXTENT_MAGIC {
            return Err(Error::corrupt("ext extent node is missing its magic"));
        }
        let count = usize::from(le16(node, 2)?);
        let level = le16(node, 6)?;
        if level > MAX_DEPTH || (depth != 0 && level + 1 != depth) {
            return Err(Error::corrupt("ext extent tree is damaged"));
        }
        let count = count.min((node.len() - 12) / 12);
        for i in 0..count {
            let e = 12 + 12 * i;
            if level == 0 {
                let block = u64::from(le32(node, e)?);
                let mut len = u64::from(le16(node, e + 4)?);
                let start = (u64::from(le16(node, e + 6)?) << 32) | u64::from(le32(node, e + 8)?);
                // Lengths above 32768 mark an extent that was allocated but not written.
                let unwritten = len > 32768;
                if unwritten {
                    len -= 32768;
                }
                if len == 0 {
                    continue;
                }
                out.push(Run {
                    at: block * self.block,
                    len: len * self.block,
                    phys: (!unwritten).then(|| start * self.block),
                });
            } else {
                let child = (u64::from(le16(node, e + 8)?) << 32) | u64::from(le32(node, e + 4)?);
                let buf = read_vec(&self.meta, child * self.block, self.block as usize)?;
                self.extent_runs(&buf, out, level)?;
            }
        }
        Ok(())
    }

    /// The bytes of a directory or a link, read whole.
    fn read_all(&self, c: Content, limit: u64) -> Result<Vec<u8>> {
        match c {
            Content::Inline(v) => Ok(v),
            Content::Runs { runs, size } => {
                if size > limit {
                    return Err(Error::corrupt("ext file is too large to read whole"));
                }
                let mut out = vec![0u8; size as usize];
                read_runs(&*self.vol, &runs, 0, &mut out)?;
                Ok(out)
            }
        }
    }
}

/// The entries of a linear directory block: inode number and name, skipping deleted ones.
fn dir_entries(data: &[u8]) -> Result<Vec<(u32, String)>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= data.len() {
        let ino = le32(data, at)?;
        let rec_len = usize::from(le16(data, at + 4)?);
        let name_len = usize::from(u8_at(data, at + 6)?);
        if rec_len < 8 || rec_len % 4 != 0 || at + rec_len > data.len() {
            return Err(Error::corrupt("ext directory entry is damaged"));
        }
        if ino != 0 && 8 + name_len <= rec_len {
            let name = String::from_utf8_lossy(&data[at + 8..at + 8 + name_len]).into_owned();
            out.push((ino, name));
        }
        at += rec_len;
    }
    Ok(out)
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let vol: Arc<dyn ReadAt> = input.volume()?;
    if vol.size() < 2048 {
        return Err(Error::NotArchive);
    }
    let sb = read_vec(&*vol, 1024, 1024)?;
    if le16(&sb, 56)? != 0xEF53 {
        return Err(Error::NotArchive);
    }
    let log = le32(&sb, 24)?;
    if log > 6 {
        return Err(Error::corrupt("ext block size is not valid"));
    }
    let block = 1024u64 << log;
    let inodes_per_group = u64::from(le32(&sb, 40)?);
    let first_data_block = u64::from(le32(&sb, 20)?);
    let rev = le32(&sb, 76)?;
    let inode_size = if rev >= 1 {
        u64::from(le16(&sb, 88)?)
    } else {
        128
    };
    let incompat = le32(&sb, 96)?;
    let is64 = incompat & 0x80 != 0;
    let desc_size = if is64 {
        u64::from(le16(&sb, 0xFE)?).max(32)
    } else {
        32
    };
    if inodes_per_group == 0
        || !(128..=4096).contains(&inode_size)
        || !inode_size.is_power_of_two()
        || desc_size > 1024
    {
        return Err(Error::corrupt("ext superblock is not valid"));
    }
    let mut fs = Ext {
        meta: Cached::new(vol.clone()),
        vol,
        block,
        inodes_per_group,
        first_data_block,
        inode_size,
        desc_size,
        is64,
        entries: Vec::new(),
        inodes: Vec::new(),
        units: Vec::new(),
        props: vec![
            (
                "Version",
                if incompat & 0x0004 != 0 {
                    "ext3/ext4"
                } else {
                    "ext2"
                }
                .to_string(),
            ),
            ("Block Size", block.to_string()),
        ],
    };
    let mut seen = HashSet::from([ROOT_INO]);
    let mut todo: Vec<(String, u32)> = vec![(String::new(), ROOT_INO)];
    while let Some((prefix, dir)) = todo.pop() {
        let inode = fs.read_inode(dir)?;
        let inline = le32(&inode, 0x20)? & INLINE_FL != 0;
        let content = fs.content(&inode)?;
        let data = fs.read_all(content, MAX_DIR)?;
        // An inline directory starts with its parent's inode number, then its entries.
        let body = if inline {
            &data[4.min(data.len())..]
        } else {
            &data[..]
        };
        for (ino, name) in dir_entries(body)? {
            if name == "." || name == ".." {
                continue;
            }
            if fs.entries.len() >= MAX_ENTRIES {
                break;
            }
            let child = fs.read_inode(ino)?;
            let mode = le16(&child, 0)?;
            let kind = mode & S_IFMT;
            if kind != S_IFDIR && kind != S_IFREG && kind != S_IFLNK {
                continue;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let is_dir = kind == S_IFDIR;
            if is_dir && seen.insert(ino) {
                todo.push((path.clone(), ino));
            }
            let (size, link) = match kind {
                S_IFDIR => (None, None),
                S_IFLNK => {
                    let c = fs.content(&child)?;
                    let target = fs.read_all(c, MAX_TARGET)?;
                    let target = String::from_utf8_lossy(&target).into_owned();
                    (Some(target.len() as u64), Some(Link::Symbolic(target)))
                }
                _ => {
                    let c = fs.content(&child)?;
                    let size = match c {
                        Content::Inline(ref v) => v.len() as u64,
                        Content::Runs { size, .. } => size,
                    };
                    (Some(size), None)
                }
            };
            let stamp = |at: usize| -> Result<Option<u64>> {
                Ok(Some(unix_to_filetime(i64::from(le32(&child, at)?))))
            };
            let idx = fs.entries.len();
            fs.entries.push(Entry {
                name: path,
                is_dir,
                size,
                attrib: Some(attr::UNIX_EXTENSION | (u32::from(mode) << 16)),
                atime: stamp(8)?,
                ctime: stamp(12)?,
                mtime: stamp(16)?,
                link,
                ..Default::default()
            });
            fs.inodes.push(ino);
            if !is_dir {
                fs.units.push(Unit {
                    entries: vec![idx],
                    encrypted: false,
                });
            }
        }
    }
    Ok(Box::new(fs))
}

impl Archive for Ext {
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
        let entry = &self.entries[i];
        if let Some(Link::Symbolic(target)) = &entry.link {
            let mut r = Cursor::new(target.clone().into_bytes());
            f(i, &mut r)?;
            return Ok(());
        }
        let inode = self.read_inode(self.inodes[i])?;
        let mut reader: Box<dyn std::io::Read + Send> = match self.content(&inode)? {
            Content::Inline(v) => Box::new(Cursor::new(v)),
            Content::Runs { runs, size } => Box::new(RunReader::new(self.vol.clone(), runs, size)),
        };
        f(i, &mut *reader)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.props.clone()
    }

    fn verifies_data(&self) -> bool {
        true
    }
}
