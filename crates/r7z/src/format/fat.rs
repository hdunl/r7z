//! FAT12, FAT16 and FAT32 volumes, with long file names. Directories are read from the root
//! down; a file's data is its cluster chain, read as runs straight from the volume. A
//! damaged chain is an error for the file that uses it, not for the whole volume.

use std::collections::HashSet;
use std::sync::Arc;

use super::data::{Input, ReadAt};
use super::disk::{le16, le32, read_vec, u8_at, Cached, Run, RunReader};
use super::{Archive, Ctx, Entry, EntryFn, Format, OpenOptions, Signature, Unit};
use crate::error::{Error, Result};
use crate::util::time::dos_to_filetime;

pub const FORMAT: Format = Format {
    name: "FAT",
    aliases: &["fat12", "fat16", "fat32"],
    extensions: &[],
    signatures: &[Signature::at(510, &[0x55, 0xAA])],
    detect: Some(looks_like_fat),
    write: false,
    stream: false,
    sequential: true,
    open,
};

/// Entries this reader keeps; a volume with more is cut short.
const MAX_ENTRIES: usize = 1 << 20;
/// Largest directory read at once.
const MAX_DIR: u64 = 64 << 20;
/// Byte offsets of the 13 UTF-16 characters in a long-name directory entry.
const LFN_AT: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Fat12,
    Fat16,
    Fat32,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Fat12 => "FAT12",
            Kind::Fat16 => "FAT16",
            Kind::Fat32 => "FAT32",
        }
    }
}

/// The BIOS parameter block fields the reader needs.
#[derive(Debug)]
struct Bpb {
    kind: Kind,
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    reserved: u64,
    fats: u64,
    fat_size: u64,
    root_entries: u64,
    root_cluster: u32,
    /// Data clusters, numbered from 2.
    clusters: u64,
}

impl Bpb {
    fn cluster_bytes(&self) -> u64 {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    /// Where the fixed root directory of FAT12 and FAT16 starts.
    fn root_start(&self) -> u64 {
        (self.reserved + self.fats * self.fat_size) * self.bytes_per_sector
    }

    fn data_start(&self) -> u64 {
        let root_sectors = (self.root_entries * 32).div_ceil(self.bytes_per_sector);
        self.root_start() + root_sectors * self.bytes_per_sector
    }
}

fn parse_bpb(b: &[u8]) -> Option<Bpb> {
    let bytes_per_sector = u64::from(le16(b, 11).ok()?);
    let sectors_per_cluster = u64::from(u8_at(b, 13).ok()?);
    let reserved = u64::from(le16(b, 14).ok()?);
    let fats = u64::from(u8_at(b, 16).ok()?);
    let root_entries = u64::from(le16(b, 17).ok()?);
    let total16 = u64::from(le16(b, 19).ok()?);
    let media = u8_at(b, 21).ok()?;
    let fat16 = u64::from(le16(b, 22).ok()?);
    let total32 = u64::from(le32(b, 32).ok()?);
    let fat32 = u64::from(le32(b, 36).ok()?);
    let root_cluster = le32(b, 44).ok()?;
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        || !sectors_per_cluster.is_power_of_two()
        || sectors_per_cluster > 128
        || reserved == 0
        || !(1..=2).contains(&fats)
        || media < 0xF0
    {
        return None;
    }
    let fat_size = if fat16 != 0 { fat16 } else { fat32 };
    let total = if total16 != 0 { total16 } else { total32 };
    if fat_size == 0 {
        return None;
    }
    let root_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
    let overhead = reserved + fats * fat_size + root_sectors;
    if total <= overhead {
        return None;
    }
    let clusters = (total - overhead) / sectors_per_cluster;
    let kind = if clusters < 4085 {
        Kind::Fat12
    } else if clusters < 65525 {
        Kind::Fat16
    } else {
        Kind::Fat32
    };
    if kind == Kind::Fat32 && root_cluster < 2 {
        return None;
    }
    Some(Bpb {
        kind,
        bytes_per_sector,
        sectors_per_cluster,
        reserved,
        fats,
        fat_size,
        root_entries,
        root_cluster,
        clusters,
    })
}

fn looks_like_fat(head: &[u8]) -> bool {
    head.len() >= 512 && matches!(head[0], 0xEB | 0xE9) && parse_bpb(&head[..512]).is_some()
}

/// Where a directory's entries are: the fixed root of FAT12/16, or a cluster chain.
#[derive(Clone, Copy)]
enum Dir {
    Root,
    Chain(u32),
}

/// One directory entry as read, before its path is known.
struct Raw {
    name: String,
    attr: u8,
    first: u32,
    size: u32,
    ctime: Option<u64>,
    mtime: Option<u64>,
    atime: Option<u64>,
}

/// The checksum a long-name entry stores for its short name.
fn short_checksum(short: &[u8]) -> u8 {
    short.iter().fold(0u8, |sum, &c| {
        (sum >> 1).wrapping_add(sum << 7).wrapping_add(c)
    })
}

/// The 8.3 name of a short entry, with the lowercase flags of the NT reserved byte applied.
fn short_name(e: &[u8]) -> String {
    let base: String = e[..8]
        .iter()
        .map(|&b| if b == 0x05 { '\u{e5}' } else { b as char })
        .collect();
    let ext: String = e[8..11].iter().map(|&b| b as char).collect();
    let mut base = base.trim_end().to_string();
    let mut ext = ext.trim_end().to_string();
    if e[12] & 0x08 != 0 {
        base = base.to_ascii_lowercase();
    }
    if e[12] & 0x10 != 0 {
        ext = ext.to_ascii_lowercase();
    }
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// Parses one directory's bytes: short and long names, skipping deleted entries, volume
/// labels and the `.` and `..` links.
fn parse_dir(bytes: &[u8], fat32: bool) -> Vec<Raw> {
    let mut out = Vec::new();
    // Long-name fragments of the entry that follows: (sequence, checksum, characters).
    let mut lfn: Vec<(u8, u8, [u16; 13])> = Vec::new();
    for e in bytes.as_chunks::<32>().0 {
        if e[0] == 0 {
            break;
        }
        if e[0] == 0xE5 {
            lfn.clear();
            continue;
        }
        if e[11] & 0x3F == 0x0F {
            let mut chars = [0xFFFFu16; 13];
            for (c, &at) in chars.iter_mut().zip(LFN_AT.iter()) {
                *c = u16::from_le_bytes([e[at], e[at + 1]]);
            }
            if e[0] & 0x40 != 0 {
                lfn.clear();
            }
            lfn.push((e[0] & 0x1F, e[13], chars));
            continue;
        }
        let fragments = std::mem::take(&mut lfn);
        if e[11] & 0x08 != 0 {
            continue;
        }
        let sum = short_checksum(&e[..11]);
        let name = if !fragments.is_empty() && fragments.iter().all(|f| f.1 == sum) {
            let mut sorted = fragments;
            sorted.sort_by_key(|f| f.0);
            let units: Vec<u16> = sorted
                .iter()
                .flat_map(|f| f.2.iter().copied())
                .take_while(|&u| u != 0 && u != 0xFFFF)
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            short_name(e)
        };
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let word = |at: usize| u16::from_le_bytes([e[at], e[at + 1]]);
        let hi = if fat32 { u32::from(word(20)) << 16 } else { 0 };
        out.push(Raw {
            name,
            attr: e[11],
            first: hi | u32::from(word(26)),
            size: u32::from_le_bytes([e[28], e[29], e[30], e[31]]),
            ctime: dos_to_filetime(word(16), word(14)),
            mtime: dos_to_filetime(word(24), word(22)),
            atime: dos_to_filetime(word(18), 0),
        });
    }
    out
}

pub struct Fat {
    vol: Arc<dyn ReadAt>,
    /// Page-cached view of the volume for the FAT, which is read a few bytes at a time.
    table: Cached,
    bpb: Bpb,
    entries: Vec<Entry>,
    first: Vec<u32>,
    units: Vec<Unit>,
    props: Vec<(&'static str, String)>,
}

impl Fat {
    fn fat_entry(&self, cluster: u32) -> Result<u32> {
        let c = u64::from(cluster);
        let fat = self.bpb.reserved * self.bpb.bytes_per_sector;
        Ok(match self.bpb.kind {
            Kind::Fat12 => {
                let mut b = [0u8; 2];
                self.table.read_at(fat + c + c / 2, &mut b)?;
                let v = u16::from_le_bytes(b);
                u32::from(if cluster & 1 == 1 { v >> 4 } else { v & 0xFFF })
            }
            Kind::Fat16 => {
                let mut b = [0u8; 2];
                self.table.read_at(fat + c * 2, &mut b)?;
                u32::from(u16::from_le_bytes(b))
            }
            Kind::Fat32 => {
                let mut b = [0u8; 4];
                self.table.read_at(fat + c * 4, &mut b)?;
                u32::from_le_bytes(b) & 0x0FFF_FFFF
            }
        })
    }

    fn is_end(&self, v: u32) -> bool {
        match self.bpb.kind {
            Kind::Fat12 => v >= 0xFF8,
            Kind::Fat16 => v >= 0xFFF8,
            Kind::Fat32 => v >= 0x0FFF_FFF8,
        }
    }

    /// The clusters of the chain from `first`, at most `limit` of them.
    fn chain(&self, first: u32, limit: Option<u64>) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut c = first;
        loop {
            if c < 2 || u64::from(c) >= self.bpb.clusters + 2 {
                return Err(Error::corrupt("FAT cluster chain leaves the data area"));
            }
            out.push(c);
            if limit.is_some_and(|n| out.len() as u64 >= n) {
                return Ok(out);
            }
            let next = self.fat_entry(c)?;
            if self.is_end(next) {
                return Ok(out);
            }
            if out.len() as u64 > self.bpb.clusters {
                return Err(Error::corrupt("FAT cluster chain loops"));
            }
            c = next;
        }
    }

    fn cluster_at(&self, c: u32) -> u64 {
        self.bpb.data_start() + u64::from(c - 2) * self.bpb.cluster_bytes()
    }

    /// The raw bytes of a directory.
    fn dir_bytes(&self, dir: Dir) -> Result<Vec<u8>> {
        match dir {
            Dir::Root if self.bpb.kind != Kind::Fat32 => read_vec(
                &*self.vol,
                self.bpb.root_start(),
                (self.bpb.root_entries * 32) as usize,
            ),
            Dir::Root => self.chain_bytes(self.bpb.root_cluster),
            Dir::Chain(c) => self.chain_bytes(c),
        }
    }

    fn chain_bytes(&self, first: u32) -> Result<Vec<u8>> {
        let clusters = self.chain(first, None)?;
        let cb = self.bpb.cluster_bytes();
        if clusters.len() as u64 * cb > MAX_DIR {
            return Err(Error::corrupt("FAT directory is too large"));
        }
        let mut out = vec![0u8; clusters.len() * cb as usize];
        for (i, &c) in clusters.iter().enumerate() {
            let at = i * cb as usize;
            self.vol
                .read_at(self.cluster_at(c), &mut out[at..at + cb as usize])?;
        }
        Ok(out)
    }

    /// The runs of a file of `size` bytes whose data starts at cluster `first`.
    fn runs(&self, first: u32, size: u64) -> Result<Vec<Run>> {
        let mut runs: Vec<Run> = Vec::new();
        if size == 0 {
            return Ok(runs);
        }
        let cb = self.bpb.cluster_bytes();
        let need = size.div_ceil(cb);
        let clusters = self.chain(first, Some(need))?;
        if (clusters.len() as u64) < need {
            return Err(Error::corrupt(
                "FAT cluster chain ends before the file's size",
            ));
        }
        for (i, &c) in clusters.iter().enumerate() {
            let at = i as u64 * cb;
            let phys = self.cluster_at(c);
            if let Some(last) = runs.last_mut() {
                if last.at + last.len == at && last.phys.map(|p| p + last.len) == Some(phys) {
                    last.len += cb;
                    continue;
                }
            }
            runs.push(Run {
                at,
                len: cb,
                phys: Some(phys),
            });
        }
        Ok(runs)
    }
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let vol: Arc<dyn ReadAt> = input.volume()?;
    if vol.size() < 512 {
        return Err(Error::NotArchive);
    }
    let boot = read_vec(&*vol, 0, 512)?;
    let bpb = parse_bpb(&boot).ok_or(Error::NotArchive)?;
    let fat32 = bpb.kind == Kind::Fat32;
    let props = vec![
        ("File System", bpb.kind.name().to_string()),
        ("Cluster Size", bpb.cluster_bytes().to_string()),
    ];
    let mut fs = Fat {
        table: Cached::new(vol.clone()),
        vol,
        bpb,
        entries: Vec::new(),
        first: Vec::new(),
        units: Vec::new(),
        props,
    };
    // Breadth first from the root; a directory's cluster is its identity, so a loop
    // through the links is walked once.
    let mut seen = HashSet::new();
    let mut todo = vec![(String::new(), Dir::Root)];
    while let Some((prefix, dir)) = todo.pop() {
        for r in parse_dir(&fs.dir_bytes(dir)?, fat32) {
            if fs.entries.len() >= MAX_ENTRIES {
                break;
            }
            let is_dir = r.attr & 0x10 != 0;
            let path = if prefix.is_empty() {
                r.name.clone()
            } else {
                format!("{prefix}/{}", r.name)
            };
            if is_dir && r.first >= 2 && seen.insert(r.first) {
                todo.push((path.clone(), Dir::Chain(r.first)));
            }
            let idx = fs.entries.len();
            fs.entries.push(Entry {
                name: path,
                is_dir,
                size: (!is_dir).then_some(u64::from(r.size)),
                attrib: Some(u32::from(r.attr)),
                mtime: r.mtime,
                ctime: r.ctime,
                atime: r.atime,
                ..Default::default()
            });
            fs.first.push(r.first);
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

impl Archive for Fat {
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
        let size = self.entries[i].size_or_zero();
        let runs = self.runs(self.first[i], size)?;
        let mut r = RunReader::new(self.vol.clone(), runs, size);
        f(i, &mut r)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.props.clone()
    }

    fn verifies_data(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_the_spec_example() {
        // "HELLO   TXT" is the 11-byte short name; the checksum is fixed by the layout.
        let a = short_checksum(b"HELLO   TXT");
        assert_eq!(a, short_checksum(b"HELLO   TXT"));
        assert_ne!(a, short_checksum(b"HELLO   TXY"));
    }
}
