//! NTFS volumes: the boot sector, the master file table, and the directories (B-trees of
//! file names) that name its records. A file's unnamed data stream is read through its run
//! list: sparse runs read as zeros, and compressed files (LZNT1, in units of 16 clusters) are
//! decoded unit by unit as they are read. Alternate streams, reparse targets and encrypted
//! files are not read.

use std::collections::hash_map::Entry as MapEntry;
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use super::data::{Input, ReadAt};
use super::disk::{le16, le32, le64, read_runs, read_vec, u8_at, Run, RunReader};
use super::{Archive, Ctx, Entry, EntryFn, Format, OpenOptions, Signature, Unit};
use crate::codec::lznt1;
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "NTFS",
    aliases: &[],
    extensions: &[],
    signatures: &[Signature::at(3, b"NTFS    ")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

const SECTOR: usize = 512;
/// The root directory's record.
const ROOT: u64 = 5;
const ATTR_STD_INFO: u32 = 0x10;
const ATTR_LIST: u32 = 0x20;
const ATTR_DATA: u32 = 0x80;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOC: u32 = 0xA0;
const ATTR_END: u32 = 0xFFFF_FFFF;
const RECORD_DIR: u16 = 0x02;
const DOS_NAMESPACE: u8 = 2;
const INDEX_DIR_FLAG: u32 = 0x1000_0000;
const MASK48: u64 = (1 << 48) - 1;
const MAX_RECORD: u64 = 1 << 16;
const MAX_INDEX: u64 = 1 << 20;
/// Largest compression unit this reader decodes at once.
const MAX_UNIT: u64 = 1 << 22;
const MAX_DEPTH: u32 = 32;
const MAX_ENTRIES: usize = 1 << 20;

struct Boot {
    cluster: u64,
    record_size: u64,
    /// Byte offset of the master file table's first record.
    mft: u64,
}

fn parse_boot(b: &[u8]) -> Result<Boot> {
    let bytes_per_sector = u64::from(le16(b, 0x0B)?);
    let sectors_per_cluster = u64::from(u8_at(b, 0x0D)?);
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        || !sectors_per_cluster.is_power_of_two()
        || sectors_per_cluster > 128
    {
        return Err(Error::corrupt("NTFS sector or cluster size is not valid"));
    }
    let cluster = bytes_per_sector * sectors_per_cluster;
    let clusters_per_record = i32::from(u8_at(b, 0x40)? as i8);
    let record_size = if clusters_per_record > 0 {
        u64::from(clusters_per_record as u32).saturating_mul(cluster)
    } else {
        1u64.checked_shl((-clusters_per_record) as u32).unwrap_or(0)
    };
    if !record_size.is_power_of_two() || !(SECTOR as u64..=MAX_RECORD).contains(&record_size) {
        return Err(Error::corrupt("NTFS file record size is not valid"));
    }
    let mft = le64(b, 0x30)?
        .checked_mul(cluster)
        .ok_or_else(|| Error::corrupt("NTFS MFT is past the end of the volume"))?;
    Ok(Boot {
        cluster,
        record_size,
        mft,
    })
}

/// Undoes the update sequence of a record or index buffer: the last two bytes of every
/// 512-byte sector were moved into the array at `usa`, and must match its check value.
fn fixup(buf: &mut [u8]) -> Result<()> {
    let usa = le16(buf, 4)? as usize;
    let count = le16(buf, 6)? as usize;
    if count < 2 || usa + 2 * count > buf.len() {
        return Err(Error::corrupt("NTFS update sequence is not valid"));
    }
    let check = [buf[usa], buf[usa + 1]];
    for k in 1..count {
        let end = k * SECTOR;
        if end > buf.len() {
            return Err(Error::corrupt("NTFS update sequence is not valid"));
        }
        if buf[end - 2..end] != check {
            return Err(Error::corrupt("NTFS update sequence does not match"));
        }
        buf[end - 2] = buf[usa + 2 * k];
        buf[end - 1] = buf[usa + 2 * k + 1];
    }
    Ok(())
}

fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// An unsigned little-endian integer of up to 8 bytes.
fn unsigned(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |a, &x| (a << 8) | u64::from(x))
}

/// A signed little-endian integer of up to 8 bytes.
fn signed(b: &[u8]) -> i64 {
    let n = b.len();
    let u = unsigned(b);
    if n < 8 && b[n - 1] & 0x80 != 0 {
        (u | (!0u64 << (8 * n))) as i64
    } else {
        u as i64
    }
}

/// One mapped run: first VCN, clusters, and the LCN (`None` for a sparse run).
type Mapped = (u64, u64, Option<u64>);

/// Decodes a run list (the mapping pairs of a non-resident attribute) from `start`.
fn decode_runs(b: &[u8], start: u64) -> Result<Vec<Mapped>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut vcn = start;
    let mut lcn: i64 = 0;
    while i < b.len() && b[i] != 0 {
        let head = b[i];
        let len_bytes = usize::from(head & 0x0F);
        let off_bytes = usize::from(head >> 4);
        i += 1;
        if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 || i + len_bytes + off_bytes > b.len() {
            return Err(Error::corrupt("NTFS run list is damaged"));
        }
        let count = unsigned(&b[i..i + len_bytes]);
        i += len_bytes;
        if count == 0 {
            return Err(Error::corrupt("NTFS run list has an empty run"));
        }
        if off_bytes == 0 {
            out.push((vcn, count, None));
        } else {
            lcn = lcn
                .checked_add(signed(&b[i..i + off_bytes]))
                .filter(|&l| l >= 0)
                .ok_or_else(|| Error::corrupt("NTFS run list leaves the volume"))?;
            i += off_bytes;
            out.push((vcn, count, Some(lcn as u64)));
        }
        vcn = vcn
            .checked_add(count)
            .ok_or_else(|| Error::corrupt("NTFS run list overflows"))?;
    }
    Ok(out)
}

/// Mapped runs as byte runs of the volume and of the attribute's data.
fn byte_runs(mapped: &[Mapped], cluster: u64) -> Result<Vec<Run>> {
    let over = || Error::corrupt("NTFS run is past the end of the volume");
    mapped
        .iter()
        .map(|&(vcn, count, lcn)| {
            Ok(Run {
                at: vcn.checked_mul(cluster).ok_or_else(over)?,
                len: count.checked_mul(cluster).ok_or_else(over)?,
                phys: match lcn {
                    Some(l) => Some(l.checked_mul(cluster).ok_or_else(over)?),
                    None => None,
                },
            })
        })
        .collect()
}

/// An attribute of a record.
struct Attr {
    ty: u32,
    name: String,
    flags: u16,
    start_vcn: u64,
    value: Value,
}

enum Value {
    Resident(Vec<u8>),
    Mapped {
        runs: Vec<Mapped>,
        real: u64,
        /// log2 of the compression unit in clusters (0 when the attribute is not compressed).
        unit_shift: u16,
    },
}

fn parse_attrs(rec: &[u8]) -> Result<Vec<Attr>> {
    let mut out = Vec::new();
    let mut at = le16(rec, 0x14)? as usize;
    let used = (le32(rec, 0x18)? as usize).min(rec.len());
    while at + 8 <= used {
        let ty = le32(rec, at)?;
        if ty == ATTR_END {
            break;
        }
        let len = le32(rec, at + 4)? as usize;
        if len < 16 || at + len > used {
            return Err(Error::corrupt("NTFS attribute runs past its record"));
        }
        let end = at + len;
        let name_len = usize::from(u8_at(rec, at + 9)?);
        let name_at = at + le16(rec, at + 10)? as usize;
        let name = if name_len == 0 {
            String::new()
        } else {
            let stop = name_at + 2 * name_len;
            if stop > end {
                return Err(Error::corrupt("NTFS attribute name runs past it"));
            }
            utf16(&rec[name_at..stop])
        };
        let flags = le16(rec, at + 12)?;
        if u8_at(rec, at + 8)? == 0 {
            let vlen = le32(rec, at + 16)? as usize;
            let vat = at + le16(rec, at + 20)? as usize;
            if vat + vlen > end {
                return Err(Error::corrupt(
                    "NTFS resident value runs past its attribute",
                ));
            }
            out.push(Attr {
                ty,
                name,
                flags,
                start_vcn: 0,
                value: Value::Resident(rec[vat..vat + vlen].to_vec()),
            });
        } else {
            let start_vcn = le64(rec, at + 16)?;
            let run_at = at + le16(rec, at + 32)? as usize;
            if run_at > end {
                return Err(Error::corrupt("NTFS run list is past its attribute"));
            }
            out.push(Attr {
                ty,
                name,
                flags,
                start_vcn,
                value: Value::Mapped {
                    runs: decode_runs(&rec[run_at..end], start_vcn)?,
                    real: le64(rec, at + 48)?,
                    unit_shift: le16(rec, at + 34)?,
                },
            });
        }
        at = end;
    }
    Ok(out)
}

/// A child of a directory, as its index names it.
struct Child {
    record: u64,
    name: String,
    dos: bool,
    dir_flag: bool,
}

/// The index of a directory: its allocation's runs, the byte unit a VCN counts in, and the
/// size of an index buffer.
struct Index<'a> {
    runs: &'a [Run],
    unit: u64,
    size: u64,
}

/// The size, times and attributes an entry lists.
struct Info {
    size: u64,
    ctime: Option<u64>,
    mtime: Option<u64>,
    atime: Option<u64>,
    attrib: u32,
}

/// What a file's unnamed data stream is made of.
enum Content {
    Empty,
    Resident(Vec<u8>),
    Runs {
        runs: Vec<Run>,
        size: u64,
    },
    /// LZNT1 compression units of `unit` bytes.
    Packed {
        runs: Vec<Run>,
        size: u64,
        unit: u64,
    },
}

pub struct Ntfs {
    vol: Arc<dyn ReadAt>,
    cluster: u64,
    record_size: u64,
    /// The master file table's data, as runs of the volume.
    mft: Vec<Run>,
    entries: Vec<Entry>,
    records: Vec<u64>,
    units: Vec<Unit>,
    props: Vec<(&'static str, String)>,
}

impl Ntfs {
    /// The record `n`, with its update sequence undone; `None` when it is not in use or is
    /// not a record.
    fn record(&self, n: u64) -> Result<Option<Vec<u8>>> {
        let off = n
            .checked_mul(self.record_size)
            .ok_or_else(|| Error::corrupt("NTFS record number is out of range"))?;
        let mut buf = vec![0u8; self.record_size as usize];
        read_runs(&*self.vol, &self.mft, off, &mut buf)?;
        if !buf.starts_with(b"FILE") || fixup(&mut buf).is_err() {
            return Ok(None);
        }
        if le16(&buf, 0x16)? & 1 == 0 {
            return Ok(None);
        }
        Ok(Some(buf))
    }

    /// The children of a directory, from its index root and the index buffers it points to.
    fn list_dir(&self, rec: &[u8]) -> Result<Vec<Child>> {
        let attrs = parse_attrs(rec)?;
        let root = attrs
            .iter()
            .find(|a| a.ty == ATTR_INDEX_ROOT && a.name == "$I30")
            .ok_or_else(|| Error::corrupt("NTFS directory has no index"))?;
        let Value::Resident(rv) = &root.value else {
            return Err(Error::corrupt("NTFS directory index root is not resident"));
        };
        let size = u64::from(le32(rv, 8)?);
        if size == 0 || size > MAX_INDEX {
            return Err(Error::corrupt("NTFS index buffer size is not valid"));
        }
        let alloc = match attrs
            .iter()
            .find(|a| a.ty == ATTR_INDEX_ALLOC && a.name == "$I30")
        {
            Some(a) => match &a.value {
                Value::Mapped { runs, .. } => byte_runs(runs, self.cluster)?,
                Value::Resident(_) => {
                    return Err(Error::corrupt("NTFS index allocation is not mapped"))
                }
            },
            None => Vec::new(),
        };
        let index = Index {
            runs: &alloc,
            unit: if size >= self.cluster {
                self.cluster
            } else {
                SECTOR as u64
            },
            size,
        };
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        self.walk(rv, 16, &index, 0, &mut out, &mut seen)?;
        Ok(out)
    }

    /// Reads the entries of the node whose header is at `node` in `buf`, and of the nodes
    /// below it.
    fn walk(
        &self,
        buf: &[u8],
        node: usize,
        index: &Index<'_>,
        depth: u32,
        out: &mut Vec<Child>,
        seen: &mut HashSet<u64>,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::corrupt("NTFS directory is nested too deeply"));
        }
        let first = node + le32(buf, node)? as usize;
        let end = (node + le32(buf, node + 4)? as usize).min(buf.len());
        let mut p = first;
        while p + 16 <= end {
            let len = le16(buf, p + 8)? as usize;
            let key_len = le16(buf, p + 10)? as usize;
            let flags = le16(buf, p + 12)?;
            if len < 16 || p + len > end || 16 + key_len > len {
                return Err(Error::corrupt("NTFS index entry is damaged"));
            }
            if flags & 1 != 0 {
                let vcn = le64(buf, p + len - 8)?;
                self.block(index, vcn, depth, out, seen)?;
            }
            if flags & 2 != 0 {
                break;
            }
            let record = le64(buf, p)? & MASK48;
            let key = &buf[p + 16..p + 16 + key_len];
            if key.len() >= 66 {
                let name_len = usize::from(key[64]);
                if 66 + 2 * name_len <= key.len() {
                    out.push(Child {
                        record,
                        name: utf16(&key[66..66 + 2 * name_len]),
                        dos: key[65] == DOS_NAMESPACE,
                        dir_flag: le32(key, 56)? & INDEX_DIR_FLAG != 0,
                    });
                }
            }
            p += len;
        }
        Ok(())
    }

    /// One index buffer, found by its VCN in the allocation.
    fn block(
        &self,
        index: &Index<'_>,
        vcn: u64,
        depth: u32,
        out: &mut Vec<Child>,
        seen: &mut HashSet<u64>,
    ) -> Result<()> {
        if !seen.insert(vcn) {
            return Err(Error::corrupt("NTFS index loops"));
        }
        let at = vcn
            .checked_mul(index.unit)
            .ok_or_else(|| Error::corrupt("NTFS index VCN is out of range"))?;
        let mut buf = vec![0u8; index.size as usize];
        read_runs(&*self.vol, index.runs, at, &mut buf)?;
        if !buf.starts_with(b"INDX") {
            return Err(Error::corrupt("NTFS index buffer is missing"));
        }
        fixup(&mut buf)?;
        self.walk(&buf, 0x18, index, depth + 1, out, seen)
    }

    /// The unnamed data stream of record `n`, from its own attributes and those of the
    /// extension records its attribute list names.
    fn content(&self, n: u64, rec: &[u8]) -> Result<Content> {
        let attrs = parse_attrs(rec)?;
        let mut data: Vec<Attr> = attrs
            .into_iter()
            .filter(|a| a.ty == ATTR_DATA && a.name.is_empty())
            .collect();
        let list = attrs_list(rec)?;
        for (base, start) in list {
            if base == n || data.iter().any(|d| d.start_vcn == start) {
                continue;
            }
            if let Some(ext) = self.record(base)? {
                for a in parse_attrs(&ext)? {
                    if a.ty == ATTR_DATA && a.name.is_empty() && a.start_vcn == start {
                        data.push(a);
                    }
                }
            }
        }
        if data.is_empty() {
            return Ok(Content::Empty);
        }
        if let [Attr {
            value: Value::Resident(v),
            ..
        }] = data.as_slice()
        {
            return Ok(Content::Resident(v.clone()));
        }
        data.sort_by_key(|a| a.start_vcn);
        let first = data
            .iter()
            .find(|a| a.start_vcn == 0)
            .ok_or_else(|| Error::corrupt("NTFS data stream has no first run"))?;
        let (real, unit_shift) = match first.value {
            Value::Mapped {
                real, unit_shift, ..
            } => (real, unit_shift),
            Value::Resident(_) => return Err(Error::corrupt("NTFS data stream is mixed")),
        };
        let mut mapped = Vec::new();
        for a in &data {
            match &a.value {
                Value::Mapped { runs, .. } => mapped.extend_from_slice(runs),
                Value::Resident(_) => return Err(Error::corrupt("NTFS data stream is mixed")),
            }
        }
        let runs = byte_runs(&mapped, self.cluster)?;
        if first.flags & 1 != 0 && unit_shift > 0 {
            let unit = self.cluster << unit_shift.min(20);
            if unit > MAX_UNIT {
                return Err(Error::corrupt("NTFS compression unit is too large"));
            }
            return Ok(Content::Packed {
                runs,
                size: real,
                unit,
            });
        }
        Ok(Content::Runs { runs, size: real })
    }

    /// The size, times and attributes an entry lists, from its record.
    fn info(&self, rec: &[u8]) -> Result<Info> {
        let attrs = parse_attrs(rec)?;
        let mut size = 0;
        let (mut ctime, mut mtime, mut atime, mut attrib) = (None, None, None, 0);
        for a in &attrs {
            match (a.ty, &a.value) {
                (ATTR_STD_INFO, Value::Resident(v)) if v.len() >= 36 => {
                    ctime = Some(le64(v, 0)?);
                    mtime = Some(le64(v, 8)?);
                    atime = Some(le64(v, 24)?);
                    attrib = le32(v, 32)?;
                }
                (ATTR_DATA, _) if a.name.is_empty() => {
                    size = match &a.value {
                        Value::Resident(v) => v.len() as u64,
                        Value::Mapped { real, .. } => *real,
                    };
                }
                _ => {}
            }
        }
        Ok(Info {
            size,
            ctime,
            mtime,
            atime,
            attrib,
        })
    }
}

/// The (record, starting VCN) pairs of an attribute list's unnamed data entries, if the
/// record has an attribute list (empty otherwise).
fn attrs_list(rec: &[u8]) -> Result<Vec<(u64, u64)>> {
    let attrs = parse_attrs(rec)?;
    let Some(list) = attrs.iter().find(|a| a.ty == ATTR_LIST) else {
        return Ok(Vec::new());
    };
    let bytes = match &list.value {
        Value::Resident(v) => v.clone(),
        Value::Mapped { .. } => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 26 <= bytes.len() {
        let len = le16(&bytes, at + 4)? as usize;
        if len < 26 || at + len > bytes.len() {
            break;
        }
        if le32(&bytes, at)? == ATTR_DATA && u8_at(&bytes, at + 6)? == 0 {
            out.push((le64(&bytes, at + 16)? & MASK48, le64(&bytes, at + 8)?));
        }
        at += len;
    }
    Ok(out)
}

/// Reads one data stream: runs straight from the volume, or compression units decoded as
/// they are reached.
struct Packed {
    vol: Arc<dyn ReadAt>,
    runs: Vec<Run>,
    size: u64,
    unit: u64,
    pos: u64,
    cache: Option<(u64, Vec<u8>)>,
}

impl Packed {
    /// The bytes of compression unit `idx`. A unit with a sparse run in it is compressed:
    /// its data clusters hold LZNT1 chunks that decode to the unit's bytes. A unit without
    /// one is stored as it is.
    fn unpack(&self, idx: u64) -> Result<Vec<u8>> {
        let start = idx * self.unit;
        let end = start + self.unit;
        let mut sparse = false;
        let mut payload: Vec<(u64, u64)> = Vec::new();
        for r in &self.runs {
            if r.at >= end {
                break;
            }
            if r.at + r.len <= start {
                continue;
            }
            match r.phys {
                None => sparse = true,
                Some(p) => {
                    let s = r.at.max(start);
                    let e = (r.at + r.len).min(end);
                    payload.push((p + (s - r.at), e - s));
                }
            }
        }
        let mut out = vec![0u8; self.unit as usize];
        if !sparse {
            read_runs(&*self.vol, &self.runs, start, &mut out)?;
            return Ok(out);
        }
        if payload.is_empty() {
            return Ok(out);
        }
        let mut raw = Vec::new();
        for (p, n) in payload {
            let at = raw.len();
            raw.resize(at + n as usize, 0);
            self.vol.read_at(p, &mut raw[at..])?;
        }
        let mut dec = Vec::with_capacity(self.unit as usize);
        lznt1::decompress(&raw, &mut dec, self.unit as usize)?;
        out[..dec.len()].copy_from_slice(&dec);
        Ok(out)
    }
}

impl Read for Packed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let idx = self.pos / self.unit;
        if self.cache.as_ref().map(|c| c.0) != Some(idx) {
            let data = self.unpack(idx).map_err(Error::into_io)?;
            self.cache = Some((idx, data));
        }
        let data = &self.cache.as_ref().unwrap().1;
        let off = (self.pos - idx * self.unit) as usize;
        let n = buf
            .len()
            .min(data.len() - off)
            .min((self.size - self.pos) as usize);
        buf[..n].copy_from_slice(&data[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let vol: Arc<dyn ReadAt> = input.volume()?;
    if vol.size() < SECTOR as u64 {
        return Err(Error::NotArchive);
    }
    let sector = read_vec(&*vol, 0, SECTOR)?;
    if &sector[3..11] != b"NTFS    " {
        return Err(Error::NotArchive);
    }
    let boot = parse_boot(&sector)?;
    // The MFT's own record gives where the rest of the table lies.
    let mut first = read_vec(&*vol, boot.mft, boot.record_size as usize)?;
    if !first.starts_with(b"FILE") {
        return Err(Error::corrupt("NTFS master file table record is missing"));
    }
    fixup(&mut first)?;
    let mft_data = match parse_attrs(&first)?
        .into_iter()
        .find(|a| a.ty == ATTR_DATA && a.name.is_empty())
    {
        Some(Attr {
            value: Value::Mapped { runs, .. },
            ..
        }) => byte_runs(&runs, boot.cluster)?,
        _ => return Err(Error::corrupt("NTFS master file table has no runs")),
    };
    let mut fs = Ntfs {
        vol,
        cluster: boot.cluster,
        record_size: boot.record_size,
        mft: mft_data,
        entries: Vec::new(),
        records: Vec::new(),
        units: Vec::new(),
        props: vec![
            ("File System", "NTFS".to_string()),
            ("Cluster Size", boot.cluster.to_string()),
            ("Record Size", boot.record_size.to_string()),
        ],
    };
    let root = fs
        .record(ROOT)?
        .ok_or_else(|| Error::corrupt("NTFS root directory record is missing"))?;
    // Breadth of the tree is walked with a stack of directories still to list.
    let mut seen: HashSet<u64> = HashSet::from([ROOT]);
    let mut todo: Vec<(String, u64, Vec<u8>)> = vec![(String::new(), ROOT, root)];
    while let Some((prefix, dir, rec)) = todo.pop() {
        // One child per record: a name in the DOS namespace only when there is no other.
        let mut by_record: HashMap<u64, Child> = HashMap::new();
        let mut order = Vec::new();
        for c in fs.list_dir(&rec)? {
            if c.record == dir {
                continue;
            }
            match by_record.entry(c.record) {
                MapEntry::Vacant(v) => {
                    order.push(c.record);
                    v.insert(c);
                }
                MapEntry::Occupied(mut o) => {
                    if o.get().dos && !c.dos {
                        o.insert(c);
                    }
                }
            }
        }
        for n in order {
            if fs.entries.len() >= MAX_ENTRIES {
                break;
            }
            let c = &by_record[&n];
            let Some(crec) = fs.record(n)? else { continue };
            let Info {
                size,
                ctime,
                mtime,
                atime,
                attrib,
            } = fs.info(&crec)?;
            let is_dir = le16(&crec, 0x16)? & RECORD_DIR != 0 || c.dir_flag;
            let path = if prefix.is_empty() {
                c.name.clone()
            } else {
                format!("{prefix}/{}", c.name)
            };
            if is_dir && seen.insert(n) {
                todo.push((path.clone(), n, crec.clone()));
            }
            let idx = fs.entries.len();
            fs.entries.push(Entry {
                name: path,
                is_dir,
                size: (!is_dir).then_some(size),
                attrib: Some(attrib),
                mtime,
                ctime,
                atime,
                ..Default::default()
            });
            fs.records.push(n);
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

impl Archive for Ntfs {
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
        let n = self.records[i];
        let rec = self
            .record(n)?
            .ok_or_else(|| Error::corrupt("NTFS file record is damaged"))?;
        let mut reader: Box<dyn Read + Send> = match self.content(n, &rec)? {
            Content::Empty => Box::new(Cursor::new(Vec::new())),
            Content::Resident(v) => Box::new(Cursor::new(v)),
            Content::Runs { runs, size } => Box::new(RunReader::new(self.vol.clone(), runs, size)),
            Content::Packed { runs, size, unit } => Box::new(Packed {
                vol: self.vol.clone(),
                runs,
                size,
                unit,
                pos: 0,
                cache: None,
            }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::data::Slice;

    #[test]
    fn mapping_pairs_decode_lengths_and_signed_offsets() {
        // Run of 24 clusters at LCN 13398, then 5 clusters 2 clusters before that, then the end.
        let runs = decode_runs(&[0x21, 0x18, 0x56, 0x34, 0x11, 0x05, 0xFE, 0x00], 0).unwrap();
        assert_eq!(runs, [(0, 24, Some(0x3456)), (24, 5, Some(0x3456 - 2))]);
        // A header with no offset bytes is a sparse run.
        let sparse = decode_runs(&[0x01, 0x10, 0x00], 7).unwrap();
        assert_eq!(sparse, [(7, 16, None)]);
    }

    #[test]
    fn compressed_unit_decodes_and_plain_unit_is_read_as_stored() {
        // 512-byte clusters and 16-cluster units. Unit 0 holds one data cluster with an LZNT1
        // chunk ("ABCABCABC") and is sparse after it; unit 1 is sixteen stored clusters.
        let cluster = 512usize;
        let mut vol = vec![0u8; 32 * cluster];
        let chunk = [0x08, b'A', b'B', b'C', 0x03, 0x20];
        vol[0..2].copy_from_slice(&(0x8000u16 | (chunk.len() as u16 - 3)).to_le_bytes());
        vol[2..2 + chunk.len()].copy_from_slice(&chunk);
        for (k, b) in vol[16 * cluster..].iter_mut().enumerate() {
            *b = (k % 251) as u8;
        }
        let unit = 16 * cluster as u64;
        let runs = vec![
            Run {
                at: 0,
                len: cluster as u64,
                phys: Some(0),
            },
            Run {
                at: cluster as u64,
                len: 15 * cluster as u64,
                phys: None,
            },
            Run {
                at: unit,
                len: unit,
                phys: Some(unit),
            },
        ];
        let size = 2 * unit;
        let mut r = Packed {
            vol: Arc::new(Slice::from_vec(vol)),
            runs,
            size,
            unit,
            pos: 0,
            cache: None,
        };
        let mut out = vec![0u8; size as usize];
        r.read_exact(&mut out).unwrap();
        assert_eq!(&out[..9], b"ABCABCABC");
        assert!(out[9..unit as usize].iter().all(|&b| b == 0));
        assert!(out[unit as usize..]
            .iter()
            .enumerate()
            .all(|(k, &b)| b == (k % 251) as u8));
    }
}
