//! exFAT volumes: the boot sector, the allocation table (or contiguous clusters, where a file
//! says it has no chain), and the directory entry sets that name files and folders. Bytes a
//! file has not written, past its valid data length, read as zeros.

use std::collections::HashSet;
use std::sync::Arc;

use super::data::{Input, ReadAt};
use super::disk::{le16, le32, read_vec, u8_at, Cached, Run, RunReader};
use super::{Archive, Ctx, Entry, EntryFn, Format, OpenOptions, Signature, Unit};
use crate::error::{Error, Result};
use crate::util::time::dos_to_filetime;

pub const FORMAT: Format = Format {
    name: "exFAT",
    aliases: &[],
    extensions: &[],
    signatures: &[Signature::at(3, b"EXFAT   ")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

const MAX_ENTRIES: usize = 1 << 20;
const MAX_DIR: u64 = 64 << 20;
/// Entry types of a file set: the file, its stream extension and its name fragments.
const FILE: u8 = 0x85;
const STREAM: u8 = 0xC0;
const NAME: u8 = 0xC1;
const NO_FAT_CHAIN: u8 = 0x02;

/// The boot sector fields the reader needs.
struct Boot {
    cluster: u64,
    /// Byte offset of the active allocation table.
    fat: u64,
    heap: u64,
    clusters: u64,
    root: u32,
}

fn parse_boot(b: &[u8]) -> Result<Boot> {
    let sector_shift = u8_at(b, 108)?;
    let cluster_shift = u8_at(b, 109)?;
    if !(9..=12).contains(&sector_shift) || u32::from(cluster_shift) + u32::from(sector_shift) > 25
    {
        return Err(Error::corrupt("exFAT sector or cluster size is not valid"));
    }
    let sector = 1u64 << sector_shift;
    let cluster = sector << cluster_shift;
    let fat_offset = u64::from(le32(b, 80)?);
    let fat_length = u64::from(le32(b, 84)?);
    let heap_offset = u64::from(le32(b, 88)?);
    let clusters = u64::from(le32(b, 92)?);
    let root = le32(b, 96)?;
    let flags = le16(b, 106)?;
    let fats = u8_at(b, 110)?;
    // Bit 0 of the volume flags selects the second FAT when there are two.
    let active = if fats == 2 && flags & 1 == 1 { 1 } else { 0 };
    Ok(Boot {
        cluster,
        fat: (fat_offset + active * fat_length) * sector,
        heap: heap_offset * sector,
        clusters,
        root,
    })
}

/// One file or directory as read, before its path is known.
struct Raw {
    name: String,
    attr: u16,
    first: u32,
    size: u64,
    valid: u64,
    no_chain: bool,
    ctime: Option<u64>,
    mtime: Option<u64>,
    atime: Option<u64>,
}

/// The timestamp of a directory entry: DOS date and time in the same layout.
fn stamp(ts: u32) -> Option<u64> {
    dos_to_filetime((ts >> 16) as u16, ts as u16)
}

/// Parses a directory's entry sets. Entries that are not in use (deleted, their high bit
/// clear), and sets that do not parse, are skipped.
fn parse_dir(bytes: &[u8]) -> Vec<Raw> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 32 <= bytes.len() {
        let e = &bytes[i..i + 32];
        if e[0] == 0 {
            break;
        }
        if e[0] != FILE {
            i += 32;
            continue;
        }
        let count = usize::from(e[1]);
        let end = i + (1 + count) * 32;
        if count < 2 || end > bytes.len() {
            i += 32;
            continue;
        }
        let stream = &bytes[i + 32..i + 64];
        if stream[0] != STREAM {
            i += 32;
            continue;
        }
        let name_len = usize::from(stream[3]);
        let mut units: Vec<u16> = Vec::with_capacity(name_len);
        for k in 2..=count {
            let f = &bytes[i + k * 32..i + (k + 1) * 32];
            if f[0] != NAME {
                break;
            }
            for c in f[2..32].as_chunks::<2>().0 {
                if units.len() < name_len {
                    units.push(u16::from_le_bytes([c[0], c[1]]));
                }
            }
        }
        let le64_at = |b: &[u8], at: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[at..at + 8]);
            u64::from_le_bytes(a)
        };
        let attr = u16::from_le_bytes([e[4], e[5]]);
        out.push(Raw {
            name: String::from_utf16_lossy(&units),
            attr,
            first: u32::from_le_bytes([stream[20], stream[21], stream[22], stream[23]]),
            size: le64_at(stream, 24),
            valid: le64_at(stream, 8),
            no_chain: stream[1] & NO_FAT_CHAIN != 0,
            ctime: stamp(u32::from_le_bytes([e[8], e[9], e[10], e[11]])),
            mtime: stamp(u32::from_le_bytes([e[12], e[13], e[14], e[15]])),
            atime: stamp(u32::from_le_bytes([e[16], e[17], e[18], e[19]])),
        });
        i = end;
    }
    out
}

/// Where a directory's entries are: the root, or a folder's first cluster, chain flag and
/// size.
#[derive(Clone, Copy)]
enum Dir {
    Root,
    Folder {
        first: u32,
        no_chain: bool,
        size: u64,
    },
}

pub struct ExFat {
    vol: Arc<dyn ReadAt>,
    table: Cached,
    boot: Boot,
    entries: Vec<Entry>,
    /// Per entry: first cluster, chain flag and valid data length (files only).
    data: Vec<(u32, bool, u64)>,
    units: Vec<Unit>,
    props: Vec<(&'static str, String)>,
}

impl ExFat {
    fn cluster_at(&self, c: u32) -> u64 {
        self.boot.heap + u64::from(c - 2) * self.boot.cluster
    }

    fn check_cluster(&self, c: u32) -> Result<()> {
        if c < 2 || u64::from(c) >= self.boot.clusters + 2 {
            return Err(Error::corrupt("exFAT cluster is outside the data area"));
        }
        Ok(())
    }

    /// The clusters of the chain from `first`, at most `limit` of them.
    fn chain(&self, first: u32, limit: u64) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut c = first;
        loop {
            self.check_cluster(c)?;
            out.push(c);
            if out.len() as u64 >= limit {
                return Ok(out);
            }
            let mut next = [0u8; 4];
            self.table
                .read_at(self.boot.fat + u64::from(c) * 4, &mut next)?;
            let next = u32::from_le_bytes(next);
            if next >= 0xFFFF_FFF8 {
                return Ok(out);
            }
            if out.len() as u64 > self.boot.clusters {
                return Err(Error::corrupt("exFAT cluster chain loops"));
            }
            c = next;
        }
    }

    /// The bytes of a directory: its clusters, read in order.
    fn dir_bytes(&self, dir: Dir) -> Result<Vec<u8>> {
        let cb = self.boot.cluster;
        let (first, no_chain, size) = match dir {
            Dir::Root => (self.boot.root, false, 0),
            Dir::Folder {
                first,
                no_chain,
                size,
            } => (first, no_chain, size),
        };
        if no_chain {
            self.check_cluster(first)?;
            let total = size.div_ceil(cb).max(1) * cb;
            if total > MAX_DIR {
                return Err(Error::corrupt("exFAT directory is too large"));
            }
            let mut out = vec![0u8; total as usize];
            self.vol.read_at(self.cluster_at(first), &mut out)?;
            return Ok(out);
        }
        let clusters = self.chain(first, u64::MAX)?;
        if clusters.len() as u64 * cb > MAX_DIR {
            return Err(Error::corrupt("exFAT directory is too large"));
        }
        let mut out = vec![0u8; clusters.len() * cb as usize];
        for (k, &c) in clusters.iter().enumerate() {
            let at = k * cb as usize;
            self.vol
                .read_at(self.cluster_at(c), &mut out[at..at + cb as usize])?;
        }
        Ok(out)
    }

    /// The runs of a file's data up to `valid` bytes; past that, the file reads as zeros.
    fn runs(&self, first: u32, no_chain: bool, valid: u64) -> Result<Vec<Run>> {
        if valid == 0 {
            return Ok(Vec::new());
        }
        let cb = self.boot.cluster;
        let need = valid.div_ceil(cb);
        if no_chain {
            self.check_cluster(first)?;
            if u64::from(first) + need > self.boot.clusters + 2 {
                return Err(Error::corrupt(
                    "exFAT contiguous file runs past the data area",
                ));
            }
            return Ok(vec![Run {
                at: 0,
                len: need * cb,
                phys: Some(self.cluster_at(first)),
            }]);
        }
        let clusters = self.chain(first, need)?;
        if (clusters.len() as u64) < need {
            return Err(Error::corrupt(
                "exFAT cluster chain ends before the file's size",
            ));
        }
        let mut runs: Vec<Run> = Vec::new();
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
    let boot_sector = read_vec(&*vol, 0, 512)?;
    if &boot_sector[3..11] != b"EXFAT   " {
        return Err(Error::NotArchive);
    }
    let boot = parse_boot(&boot_sector)?;
    let props = vec![
        ("File System", "exFAT".to_string()),
        ("Cluster Size", boot.cluster.to_string()),
    ];
    let mut fs = ExFat {
        table: Cached::new(vol.clone()),
        vol,
        boot,
        entries: Vec::new(),
        data: Vec::new(),
        units: Vec::new(),
        props,
    };
    let mut seen = HashSet::new();
    let mut todo = vec![(String::new(), Dir::Root)];
    while let Some((prefix, dir)) = todo.pop() {
        for r in parse_dir(&fs.dir_bytes(dir)?) {
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
                todo.push((
                    path.clone(),
                    Dir::Folder {
                        first: r.first,
                        no_chain: r.no_chain,
                        size: r.size,
                    },
                ));
            }
            let idx = fs.entries.len();
            fs.entries.push(Entry {
                name: path,
                is_dir,
                size: (!is_dir).then_some(r.size),
                attrib: Some(u32::from(r.attr)),
                mtime: r.mtime,
                ctime: r.ctime,
                atime: r.atime,
                ..Default::default()
            });
            fs.data.push((r.first, r.no_chain, r.valid.min(r.size)));
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

impl Archive for ExFat {
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
        let (first, no_chain, valid) = self.data[i];
        let size = self.entries[i].size_or_zero();
        let runs = self.runs(first, no_chain, valid)?;
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
    fn stamp_uses_dos_layout() {
        // 2000-01-01 00:00:00 in DOS date (day 1, month 1, year 20) and time (0).
        let ts = ((20u32 << 9) | (1 << 5) | 1) << 16;
        assert_eq!(stamp(ts), dos_to_filetime((ts >> 16) as u16, 0));
    }
}
