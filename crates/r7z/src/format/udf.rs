//! UDF images (OSTA UDF 1.02 to 2.60, including the metadata partition of UDF 2.50 and the
//! virtual partitions of write-once media).
//!
//! The reader finds an anchor (sector 256, N-256 or N-1), reads the main volume descriptor
//! sequence (the reserve one when the main is damaged), maps logical blocks through the
//! partition maps, and walks the directory tree from the file set descriptor. Logical
//! blocks are 2048 bytes. Unrecorded and sparse extents read as zeros. Symbolic links carry
//! their target text as their data, as tar does. Sparing tables that remap blocks and other
//! logical block sizes are rejected as unsupported.

use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;

use super::data::read_exact;
use super::{
    Archive, Ctx, Entry, EntryFn, Format, Input, Link, OpenOptions, ReadAt, Runs, Signature, Unit,
};
use crate::error::{Error, Result};
use crate::util::time::{days_from_civil, unix_to_filetime};

pub const FORMAT: Format = Format {
    name: "Udf",
    aliases: &[],
    extensions: &["udf"],
    signatures: &[Signature::at(32769, b"BEA01")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    open_udf(input.volume()?, opts)
}

const BLOCK: u64 = 2048;
const BLOCK_LEN: usize = 2048;
/// Offsets from here up read as zeros. Unrecorded and sparse extents are runs there, so the
/// reader needs no separate zero-fill path.
const ZERO_AREA: u64 = 1 << 62;
/// Largest file accepted, which keeps run arithmetic clear of `ZERO_AREA`.
const MAX_FILE: u64 = 1 << 60;
const MAX_DIR: u64 = 1 << 26;
const MAX_LINK: u64 = 1 << 22;
const MAX_VAT: u64 = 1 << 26;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_DEPTH: usize = 1024;
const MAX_ADS: usize = 1 << 20;
const MAX_AED: usize = 1 << 12;
const MAX_VDS: u64 = 256;
/// Unused or unrecorded block number in sparing and virtual allocation tables.
const NONE: u32 = u32::MAX;

const TAG_AVDP: u16 = 2;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_TD: u16 = 8;
const TAG_FSD: u16 = 256;
const TAG_FID: u16 = 257;
const TAG_AED: u16 = 258;
const TAG_FE: u16 = 261;
const TAG_EFE: u16 = 266;

const FT_DIR: u8 = 4;
const FT_SYMLINK: u8 = 12;
const FID_HIDDEN: u8 = 0x01;
const FID_DELETED: u8 = 0x04;
const FID_PARENT: u8 = 0x08;

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Whether `src` carries a UDF volume recognition sequence (BEA01, NSR02 or NSR03, TEA01) and
/// an anchor. Used by the ISO handler to prefer UDF on hybrid images.
pub fn is_udf(src: &dyn ReadAt) -> bool {
    recognized(src) && find_anchor(src).is_some()
}

/// Opens the UDF file system on `src`. Fails with `NotArchive` when no anchor is valid.
pub fn open_udf(src: Arc<dyn ReadAt>, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let src: Arc<dyn ReadAt> = Arc::new(Image(src));
    let (main, reserve) = find_anchor(&*src).ok_or(Error::NotArchive)?;
    let vds = read_vds(&*src, main).or_else(|e| {
        if reserve.len > 0 {
            read_vds(&*src, reserve).map_err(|_| e)
        } else {
            Err(e)
        }
    })?;
    let vol = Volume::open(src.clone(), &vds)?;
    let root = vol.file_set()?;
    let (entries, sources) = walk(&vol, root)?;
    let units = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.is_dir)
        .map(|(i, _)| Unit {
            entries: vec![i],
            encrypted: false,
        })
        .collect();
    Ok(Box::new(Udf {
        src,
        label: vol.label,
        entries,
        sources,
        units,
    }))
}

/// The image with the zero area past `ZERO_AREA`.
struct Image(Arc<dyn ReadAt>);

impl ReadAt for Image {
    fn size(&self) -> u64 {
        self.0.size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset >= ZERO_AREA {
            buf.fill(0);
            Ok(())
        } else {
            self.0.read_at(offset, buf)
        }
    }
}

/// The source of one entry's bytes.
enum Source {
    /// Image ranges, read in order.
    Runs(Vec<(u64, u64)>),
    /// Bytes held in memory (a symbolic link's target).
    Inline(Vec<u8>),
}

struct Udf {
    src: Arc<dyn ReadAt>,
    label: String,
    entries: Vec<Entry>,
    /// Parallel to `entries`; `None` for directories.
    sources: Vec<Option<Source>>,
    units: Vec<Unit>,
}

impl Archive for Udf {
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
        match self.sources[i].as_ref() {
            Some(Source::Runs(runs)) => {
                f(i, &mut Runs::new(self.src.clone(), runs.clone()))?;
            }
            Some(Source::Inline(bytes)) => {
                f(i, &mut Cursor::new(bytes))?;
            }
            None => {}
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        if self.label.is_empty() {
            Vec::new()
        } else {
            vec![("Volume Name", self.label.clone())]
        }
    }
}

// Descriptor tags and blocks.

/// Descriptor tag fields and CRC (ECMA-167 4/7.2). `loc` is the block the descriptor was read
/// from, when the tag must name it; FIDs live inside directory data and are not checked.
fn check_tag(b: &[u8], id: u16, loc: Option<u64>) -> Result<()> {
    let bad = |what: &str| Error::corrupt(format!("UDF descriptor {id} has a bad {what}"));
    if b.len() < 16 || u16_at(b, 0) != id {
        return Err(bad("tag"));
    }
    let sum = b[..4]
        .iter()
        .chain(&b[5..16])
        .fold(0u8, |s, &x| s.wrapping_add(x));
    if sum != b[4] {
        return Err(bad("checksum"));
    }
    if let Some(loc) = loc {
        if u64::from(u32_at(b, 12)) != loc {
            return Err(bad("location"));
        }
    }
    let body = b
        .get(16..16 + usize::from(u16_at(b, 10)))
        .ok_or_else(|| bad("CRC length"))?;
    if crc16(body) != u16_at(b, 8) {
        return Err(bad("CRC"));
    }
    Ok(())
}

const CRC_TABLE: [u16; 256] = {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u16) << 8;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000 != 0 {
                (c << 1) ^ 0x1021
            } else {
                c << 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-CCITT (polynomial 0x1021, initial value 0, no reflection) as used by descriptor tags.
fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |crc, &b| {
        (crc << 8) ^ CRC_TABLE[usize::from((crc >> 8) as u8 ^ b)]
    })
}

/// Little-endian bytes at `at`. Offsets used here are constants inside a 2048-byte block, so
/// the zero fallback never applies to a block that was read in full.
fn le<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    if let Some(s) = b.get(at..at + N) {
        out.copy_from_slice(s);
    }
    out
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(le(b, at))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(le(b, at))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(le(b, at))
}

/// One logical block of `src`, read at physical sector `sector`.
fn read_block(src: &dyn ReadAt, sector: u64) -> Result<Vec<u8>> {
    let at = sector
        .checked_mul(BLOCK)
        .ok_or_else(|| Error::corrupt("block number out of range"))?;
    let mut b = vec![0u8; BLOCK_LEN];
    src.read_at(at, &mut b)?;
    Ok(b)
}

/// Whether the volume recognition sequence starts at sector 16 with BEA01, then NSR02 or
/// NSR03, then TEA01. Other standard identifiers (ISO 9660's CD001) may come in between.
fn recognized(src: &dyn ReadAt) -> bool {
    let sectors = src.size() / BLOCK;
    let mut stage = 0u8;
    for s in 16..sectors.min(48) {
        let mut id = [0u8; 6];
        if src.read_at(s * BLOCK, &mut id).is_err() {
            break;
        }
        match (&id[1..], stage) {
            (b"BEA01", 0) => stage = 1,
            (b"NSR02" | b"NSR03", 1) => stage = 2,
            (b"TEA01", 2) => return true,
            _ => {}
        }
    }
    false
}

/// An extent descriptor: byte length and first block.
#[derive(Clone, Copy)]
struct Extent {
    len: u64,
    loc: u64,
}

fn extent(b: &[u8], at: usize) -> Extent {
    Extent {
        len: u64::from(u32_at(b, at) & 0x3FFF_FFFF),
        loc: u64::from(u32_at(b, at + 4)),
    }
}

/// The main and reserve volume descriptor sequences of the first valid anchor.
fn find_anchor(src: &dyn ReadAt) -> Option<(Extent, Extent)> {
    let n = src.size() / BLOCK;
    [Some(256), n.checked_sub(256), n.checked_sub(1)]
        .into_iter()
        .flatten()
        .find_map(|s| {
            let b = read_block(src, s).ok()?;
            check_tag(&b, TAG_AVDP, Some(s)).ok()?;
            Some((extent(&b, 16), extent(&b, 24)))
        })
}

/// A physical partition from a partition descriptor.
struct Pd {
    number: u16,
    start: u64,
    len: u64,
}

struct Vds {
    pds: Vec<Pd>,
    lvd: Vec<u8>,
}

fn read_vds(src: &dyn ReadAt, ext: Extent) -> Result<Vds> {
    let mut vds = Vds {
        pds: Vec::new(),
        lvd: Vec::new(),
    };
    let mut found_lvd = false;
    for i in 0..ext.len.div_ceil(BLOCK).min(MAX_VDS) {
        let sector = ext
            .loc
            .checked_add(i)
            .ok_or_else(|| Error::corrupt("volume descriptor sequence out of range"))?;
        let b = read_block(src, sector)?;
        match u16_at(&b, 0) {
            TAG_PD => {
                check_tag(&b, TAG_PD, Some(sector))?;
                vds.pds.push(Pd {
                    number: u16_at(&b, 22),
                    start: u64::from(u32_at(&b, 188)),
                    len: u64::from(u32_at(&b, 192)),
                });
            }
            TAG_LVD if !found_lvd => {
                check_tag(&b, TAG_LVD, Some(sector))?;
                vds.lvd = b;
                found_lvd = true;
            }
            TAG_TD => {
                check_tag(&b, TAG_TD, Some(sector))?;
                break;
            }
            _ => {}
        }
    }
    if !found_lvd {
        return Err(Error::corrupt("no logical volume descriptor"));
    }
    if vds.pds.is_empty() {
        return Err(Error::corrupt("no partition descriptor"));
    }
    Ok(vds)
}

fn pd_part(pds: &[Pd], number: u16) -> Result<Part> {
    pds.iter()
        .find(|p| p.number == number)
        .map(|p| Part {
            base: p.start,
            len: p.len,
            map: Map::Linear,
        })
        .ok_or_else(|| Error::corrupt(format!("no partition descriptor for partition {number}")))
}

// Partitions.

/// One logical partition: its blocks are mapped onto the physical partition at `base`.
struct Part {
    base: u64,
    /// Logical length in blocks.
    len: u64,
    map: Map,
}

enum Map {
    /// Logical block `b` is physical block `b`.
    Linear,
    /// Virtual partition: logical block `b` is physical block `table[b]`.
    Vat(Vec<u32>),
    /// Metadata partition: logical block `b` is block `b` of the metadata file, whose extents
    /// are `segs`.
    Meta(Vec<Seg>),
}

/// Blocks `start..start + len` of a metadata file, at physical block `phys`.
struct Seg {
    start: u64,
    len: u64,
    phys: u64,
}

impl Part {
    /// The physical sector of logical block `lbn`.
    fn sector(&self, lbn: u64) -> Result<u64> {
        let phys = match &self.map {
            Map::Linear => lbn,
            Map::Vat(table) => match usize::try_from(lbn).ok().and_then(|i| table.get(i)) {
                Some(&p) if p != NONE => u64::from(p),
                _ => {
                    return Err(Error::corrupt(format!(
                        "logical block {lbn} is not recorded"
                    )))
                }
            },
            Map::Meta(segs) => {
                let i = segs.partition_point(|s| s.start <= lbn);
                match i.checked_sub(1).and_then(|i| segs.get(i)) {
                    Some(s) if lbn - s.start < s.len => s.phys + (lbn - s.start),
                    _ => return Err(Error::corrupt(format!("logical block {lbn} is not mapped"))),
                }
            }
        };
        self.base
            .checked_add(phys)
            .ok_or_else(|| Error::corrupt("block number out of range"))
    }
}

/// Partition map entries, resolved after the whole map table is read.
enum Pending {
    Ready(Result<Part>),
    /// Virtual partition over the first physical partition; its VAT is read from there.
    Virtual,
    Metadata {
        number: u16,
        file: u64,
        mirror: u64,
    },
    Sparable {
        number: u16,
        tables: Vec<u64>,
    },
}

fn map_entry(m: &[u8], first_phys: &mut Option<u16>, pds: &[Pd]) -> Result<Pending> {
    let ident = m.get(5..28).unwrap_or(&[]);
    Ok(match m.first() {
        Some(1) if m.len() >= 6 => {
            let number = u16_at(m, 4);
            if first_phys.is_none() {
                *first_phys = Some(number);
            }
            Pending::Ready(pd_part(pds, number))
        }
        Some(2) if ident.starts_with(b"*UDF Virtual Partition") => Pending::Virtual,
        Some(2) if ident.starts_with(b"*UDF Sparable Partition") => {
            if m.len() < 64 {
                return Err(Error::corrupt("sparable partition map is truncated"));
            }
            let tables = (0..usize::from(m[40]).min(4))
                .map(|i| u64::from(u32_at(m, 48 + 4 * i)))
                .collect();
            Pending::Sparable {
                number: u16_at(m, 38),
                tables,
            }
        }
        Some(2) if ident.starts_with(b"*UDF Metadata Partition") => {
            if m.len() < 48 {
                return Err(Error::corrupt("metadata partition map is truncated"));
            }
            Pending::Metadata {
                number: u16_at(m, 38),
                file: u64::from(u32_at(m, 40)),
                mirror: u64::from(u32_at(m, 44)),
            }
        }
        Some(2) => Pending::Ready(Err(Error::unsupported(format!(
            "partition type {}",
            String::from_utf8_lossy(ident).trim_end_matches(['\0', ' '])
        )))),
        Some(t) => Pending::Ready(Err(Error::unsupported(format!("partition map type {t}")))),
        None => return Err(Error::corrupt("empty partition map")),
    })
}

/// Every partition the logical volume names, indexed by partition reference number.
struct Volume {
    src: Arc<dyn ReadAt>,
    parts: Vec<Result<Part>>,
    /// Partition reference and block of the file set descriptor.
    fsd: (u16, u64),
    label: String,
}

impl Volume {
    fn open(src: Arc<dyn ReadAt>, vds: &Vds) -> Result<Volume> {
        let lvd = &vds.lvd;
        if u64::from(u32_at(lvd, 212)) != BLOCK {
            return Err(Error::unsupported(format!(
                "logical block size {}",
                u32_at(lvd, 212)
            )));
        }
        // The partition maps follow the 8-byte integrity sequence extent at 432.
        let end = 440usize
            .checked_add(u32_at(lvd, 264) as usize)
            .filter(|&e| e <= BLOCK_LEN)
            .ok_or_else(|| Error::corrupt("partition maps run past the descriptor"))?;
        let mut pending = Vec::new();
        let mut first_phys = None;
        let mut at = 440usize;
        for _ in 0..u32_at(lvd, 268) {
            let len = lvd.get(at + 1).map_or(0, |&l| usize::from(l));
            let m = at
                .checked_add(len)
                .filter(|&e| len >= 2 && e <= end)
                .and_then(|e| lvd.get(at..e))
                .ok_or_else(|| Error::corrupt("partition map is truncated"))?;
            pending.push(map_entry(m, &mut first_phys, &vds.pds)?);
            at += len;
        }
        let mut parts = Vec::with_capacity(pending.len());
        let mut lazy = Vec::new();
        for (i, p) in pending.into_iter().enumerate() {
            match p {
                Pending::Ready(r) => parts.push(r),
                p => {
                    parts.push(Err(Error::corrupt("partition map is not loaded")));
                    lazy.push((i, p));
                }
            }
        }
        let mut vol = Volume {
            src,
            parts,
            fsd: (u16_at(lvd, 256), u64::from(u32_at(lvd, 252))),
            label: lvd.get(84..212).map_or(String::new(), fixed_dstring),
        };
        for (i, p) in lazy {
            let part = vol.load(p, first_phys, &vds.pds);
            vol.parts[i] = part;
        }
        Ok(vol)
    }

    /// Resolves a virtual, metadata or sparable map. Its physical partition is pushed as a
    /// temporary reference while the descriptors are read, then removed again.
    fn load(&mut self, p: Pending, first_phys: Option<u16>, pds: &[Pd]) -> Result<Part> {
        match p {
            Pending::Ready(r) => r,
            Pending::Virtual => {
                let number = first_phys
                    .ok_or_else(|| Error::corrupt("virtual partition without a physical one"))?;
                self.under(pds, number, |v, u| v.vat(u))
            }
            Pending::Metadata {
                number,
                file,
                mirror,
            } => self.under(pds, number, |v, u| v.metadata(u, file, mirror)),
            Pending::Sparable { number, tables } => {
                self.under(pds, number, |v, u| v.sparable(u, &tables))
            }
        }
    }

    fn under(
        &mut self,
        pds: &[Pd],
        number: u16,
        load: impl FnOnce(&Volume, u16) -> Result<Part>,
    ) -> Result<Part> {
        let keep = self.parts.len();
        self.parts.push(pd_part(pds, number));
        let vol: &Volume = self;
        let out = u16::try_from(keep)
            .map_err(|_| Error::corrupt("too many partition maps"))
            .and_then(|u| load(vol, u));
        self.parts.truncate(keep);
        out
    }

    /// Virtual partition: the allocation table is the last file entry of the physical
    /// partition (within the last 16 blocks), with 36 trailing identifier bytes.
    fn vat(&self, u: u16) -> Result<Part> {
        let under = self.part(u)?;
        let (base, end) = (under.base, under.len);
        let fe = (1..=16u64)
            .filter_map(|back| end.checked_sub(back))
            .find_map(|lbn| self.read_fe(u, lbn).ok())
            .ok_or_else(|| Error::corrupt("virtual partition has no allocation table"))?;
        let data = self.read_all(&fe, MAX_VAT, "virtual allocation table")?;
        let n = data
            .len()
            .checked_sub(36)
            .ok_or_else(|| Error::corrupt("virtual allocation table is too short"))?
            / 4;
        let table = data
            .as_chunks::<4>()
            .0
            .iter()
            .take(n)
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        Ok(Part {
            base,
            len: n as u64,
            map: Map::Vat(table),
        })
    }

    /// Metadata partition: the metadata file (or its mirror, when the file is damaged) maps
    /// logical blocks onto the physical partition.
    fn metadata(&self, u: u16, file: u64, mirror: u64) -> Result<Part> {
        match self.metadata_file(u, file) {
            Ok(p) => Ok(p),
            Err(e) => self.metadata_file(u, mirror).map_err(|_| e),
        }
    }

    fn metadata_file(&self, u: u16, lbn: u64) -> Result<Part> {
        let fe = self.read_fe(u, lbn)?;
        let Body::Ads(ads) = &fe.body else {
            return Err(Error::corrupt(
                "metadata file has no allocation descriptors",
            ));
        };
        let mut segs = Vec::new();
        let mut total = 0u64;
        for ad in ads {
            if ad.part != u {
                return Err(Error::corrupt(
                    "metadata file extent is outside its partition",
                ));
            }
            let blocks = ad.len.div_ceil(BLOCK);
            if ad.kind == 0 && blocks > 0 {
                segs.push(Seg {
                    start: total,
                    len: blocks,
                    phys: ad.lbn,
                });
            }
            total = total
                .checked_add(blocks)
                .ok_or_else(|| Error::corrupt("metadata file is too large"))?;
        }
        Ok(Part {
            base: self.part(u)?.base,
            len: total,
            map: Map::Meta(segs),
        })
    }

    /// Sparable partition: identity mapping. A sparing table that remaps a block is rejected.
    fn sparable(&self, u: u16, tables: &[u64]) -> Result<Part> {
        for &loc in tables.iter().filter(|&&l| l != u64::from(NONE)) {
            let t = self.block(u, loc)?;
            let used = usize::from(u16_at(&t, 48)).min((BLOCK_LEN - 56) / 8);
            for k in 0..used {
                let at = 56 + 8 * k;
                if u32_at(&t, at) != NONE && u32_at(&t, at + 4) != NONE {
                    return Err(Error::unsupported(
                        "sparable partition with remapped blocks",
                    ));
                }
            }
        }
        let under = self.part(u)?;
        Ok(Part {
            base: under.base,
            len: under.len,
            map: Map::Linear,
        })
    }

    fn part(&self, r: u16) -> Result<&Part> {
        match self.parts.get(usize::from(r)) {
            Some(Ok(p)) => Ok(p),
            Some(Err(e)) => Err(rebuild(e)),
            None => Err(Error::corrupt(format!(
                "partition reference {r} is out of range"
            ))),
        }
    }

    fn block(&self, r: u16, lbn: u64) -> Result<Vec<u8>> {
        read_block(&*self.src, self.part(r)?.sector(lbn)?)
    }

    /// The file set descriptor's root directory.
    fn file_set(&self) -> Result<Fe> {
        let (r, lbn) = self.fsd;
        let b = self.block(r, lbn)?;
        check_tag(&b, TAG_FSD, Some(lbn))?;
        self.read_fe(u16_at(&b, 408), u64::from(u32_at(&b, 404)))
    }

    fn read_fe(&self, r: u16, lbn: u64) -> Result<Fe> {
        let sector = self.part(r)?.sector(lbn)?;
        let b = read_block(&*self.src, sector)?;
        let id = u16_at(&b, 0);
        let ext = match id {
            TAG_FE => false,
            TAG_EFE => true,
            _ => {
                return Err(Error::corrupt(format!(
                    "logical block {lbn} is not a file entry"
                )))
            }
        };
        check_tag(&b, id, Some(lbn))?;
        // Offsets of the length fields, the header size, and the access, modification and
        // attribute times (basic and extended file entries, ECMA-167 4/14.9 and 14.17).
        let (hdr, ea_at, ad_at, times) = if ext {
            (216usize, 208usize, 212usize, [80usize, 92, 116])
        } else {
            (176, 168, 172, [72, 84, 96])
        };
        let l_ea = u32_at(&b, ea_at) as usize;
        let l_ad = u32_at(&b, ad_at) as usize;
        let area_at = hdr
            .checked_add(l_ea)
            .ok_or_else(|| Error::corrupt("file entry is too large"))?;
        let area = area_at
            .checked_add(l_ad)
            .and_then(|end| b.get(area_at..end))
            .ok_or_else(|| {
                Error::corrupt("file entry allocation descriptors run past the block")
            })?;
        let info_len = u64_at(&b, 56);
        if info_len > MAX_FILE {
            return Err(Error::corrupt("file is too large"));
        }
        let body = match u16_at(&b, 34) & 7 {
            3 => {
                if info_len > l_ad as u64 {
                    return Err(Error::corrupt(
                        "embedded file data is longer than its descriptor",
                    ));
                }
                Body::Embedded { off: area_at }
            }
            t @ 0..=2 => Body::Ads(self.ads(r, t, area.to_vec())?),
            _ => return Err(Error::corrupt("unknown allocation descriptor type")),
        };
        Ok(Fe {
            at: sector.saturating_mul(BLOCK),
            file_type: b[27],
            info_len,
            perms: u32_at(&b, 44),
            atime: timestamp(&b, times[0]),
            mtime: timestamp(&b, times[1]),
            ctime: timestamp(&b, times[2]),
            body,
        })
    }

    /// The allocation descriptors in `data` (short, long or extended, by `ad_type`), following
    /// allocation extent chains. Short descriptors name partition `r`.
    fn ads(&self, r: u16, ad_type: u16, mut data: Vec<u8>) -> Result<Vec<Ad>> {
        let size = match ad_type {
            0 => 8,
            1 => 16,
            _ => 20,
        };
        let mut out = Vec::new();
        let mut aeds = 0usize;
        loop {
            let mut next = None;
            for d in data.chunks_exact(size) {
                let word = u32_at(d, 0);
                let kind = (word >> 30) as u8;
                let len = u64::from(word & 0x3FFF_FFFF);
                let (part, lbn) = match ad_type {
                    0 => (r, u64::from(u32_at(d, 4))),
                    1 => (u16_at(d, 8), u64::from(u32_at(d, 4))),
                    _ => (u16_at(d, 16), u64::from(u32_at(d, 12))),
                };
                if kind == 3 {
                    next = Some((part, lbn));
                    break;
                }
                if out.len() >= MAX_ADS {
                    return Err(Error::corrupt("too many allocation descriptors"));
                }
                out.push(Ad {
                    kind,
                    len,
                    part,
                    lbn,
                });
            }
            let Some((part, lbn)) = next else {
                return Ok(out);
            };
            aeds += 1;
            if aeds > MAX_AED {
                return Err(Error::corrupt("allocation extent chain is too long"));
            }
            let b = self.block(part, lbn)?;
            check_tag(&b, TAG_AED, Some(lbn))?;
            let l = u32_at(&b, 20) as usize;
            let end = l
                .checked_add(24)
                .ok_or_else(|| Error::corrupt("allocation extent is too large"))?;
            data = b
                .get(24..end)
                .ok_or_else(|| Error::corrupt("allocation extent runs past its block"))?
                .to_vec();
        }
    }

    /// The image ranges holding a file's bytes, cut to its size.
    fn runs(&self, fe: &Fe) -> Result<Vec<(u64, u64)>> {
        let mut out = Vec::new();
        match &fe.body {
            Body::Embedded { off } => {
                push_run(&mut out, fe.at.saturating_add(*off as u64), fe.info_len)
            }
            Body::Ads(ads) => {
                let mut left = fe.info_len;
                let mut budget = self.src.size() / BLOCK + 1;
                for ad in ads {
                    if left == 0 {
                        break;
                    }
                    let take = ad.len.min(left);
                    if ad.kind == 0 {
                        self.map(ad.part, ad.lbn, take, &mut out, &mut budget)?;
                    } else {
                        push_run(&mut out, ZERO_AREA, take);
                    }
                    left -= take;
                }
                if left > 0 {
                    return Err(Error::corrupt("file data is shorter than its size"));
                }
            }
        }
        Ok(out)
    }

    /// Appends the image ranges for `bytes` from logical block `lbn` of partition `r`. A
    /// linear partition is one range; other maps are looked up block by block.
    fn map(
        &self,
        r: u16,
        lbn: u64,
        bytes: u64,
        out: &mut Vec<(u64, u64)>,
        budget: &mut u64,
    ) -> Result<()> {
        let part = self.part(r)?;
        if let Map::Linear = part.map {
            push_run(out, part.sector(lbn)?.saturating_mul(BLOCK), bytes);
            return Ok(());
        }
        let blocks = bytes.div_ceil(BLOCK);
        *budget = budget
            .checked_sub(blocks)
            .ok_or_else(|| Error::corrupt("file maps more blocks than the image holds"))?;
        for k in 0..blocks {
            let lb = lbn
                .checked_add(k)
                .ok_or_else(|| Error::corrupt("block number out of range"))?;
            let sector = part.sector(lb)?;
            push_run(
                out,
                sector.saturating_mul(BLOCK),
                (bytes - k * BLOCK).min(BLOCK),
            );
        }
        Ok(())
    }

    /// A whole small stream (a directory, a link, a table), capped at `cap` bytes.
    fn read_all(&self, fe: &Fe, cap: u64, what: &str) -> Result<Vec<u8>> {
        if fe.info_len > cap {
            return Err(Error::corrupt(format!("{what} is too large")));
        }
        let runs = self.runs(fe)?;
        let mut buf = vec![0u8; fe.info_len as usize];
        read_exact(&mut Runs::new(self.src.clone(), runs), &mut buf)?;
        Ok(buf)
    }

    /// A symbolic link's target, from its path components (ECMA-167 4/14.16.1).
    fn read_link(&self, fe: &Fe) -> Result<String> {
        let data = self.read_all(fe, MAX_LINK, "symbolic link")?;
        let mut out = String::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let rest = &data[pos..];
            let n = usize::from(*rest.get(1).unwrap_or(&0));
            let id = rest
                .get(4..4 + n)
                .ok_or_else(|| Error::corrupt("symbolic link path component is truncated"))?;
            pos += 4 + n;
            match rest[0] {
                1 if out.is_empty() => out.push('/'),
                2 => {
                    sep(&mut out);
                    out.push_str("..");
                }
                3 => {
                    sep(&mut out);
                    out.push('.');
                }
                5 => {
                    sep(&mut out);
                    out.push_str(&decode_name(id));
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

fn sep(out: &mut String) {
    if !out.is_empty() && !out.ends_with('/') {
        out.push('/');
    }
}

/// Maps an error kept from a failed partition load to a fresh error of the same kind.
fn rebuild(e: &Error) -> Error {
    match e {
        Error::Corrupt(m) => Error::corrupt(m.clone()),
        Error::Unsupported(m) => Error::unsupported(m.clone()),
        other => Error::corrupt(other.to_string()),
    }
}

/// Appends a range, merging it with the previous one when they are contiguous.
fn push_run(out: &mut Vec<(u64, u64)>, off: u64, len: u64) {
    if len == 0 {
        return;
    }
    match out.last_mut() {
        Some(last) if off < ZERO_AREA && last.0.checked_add(last.1) == Some(off) => last.1 += len,
        _ => out.push((off, len)),
    }
}

/// An allocation descriptor: kind (0 recorded, 1 allocated but unrecorded, 2 unallocated),
/// byte length, partition reference and block.
#[derive(Clone, Copy)]
struct Ad {
    kind: u8,
    len: u64,
    part: u16,
    lbn: u64,
}

enum Body {
    Ads(Vec<Ad>),
    /// The data is the file entry's own descriptor area, starting at byte `off` of its block.
    Embedded {
        off: usize,
    },
}

/// A parsed file entry (tag 261 or 266).
struct Fe {
    /// Byte offset of the entry's block; identifies the entry.
    at: u64,
    file_type: u8,
    info_len: u64,
    perms: u32,
    atime: Option<u64>,
    mtime: Option<u64>,
    ctime: Option<u64>,
    body: Body,
}

/// Walks the directory tree from `root`, returning the entries and their sources in listing
/// order.
fn walk(vol: &Volume, root: Fe) -> Result<(Vec<Entry>, Vec<Option<Source>>)> {
    let mut entries = Vec::new();
    let mut sources = Vec::new();
    let mut seen = HashSet::from([root.at]);
    let mut stack = vec![(root, String::new(), 0usize)];
    while let Some((dir, path, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(Error::corrupt("directories are nested too deeply"));
        }
        let data = vol.read_all(&dir, MAX_DIR, "directory")?;
        let mut subdirs = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let rest = &data[pos..];
            if u16_at(rest, 0) == 0 {
                break;
            }
            let fid = parse_fid(rest)?;
            pos += fid.stride;
            if fid.flags & (FID_DELETED | FID_PARENT) != 0 {
                continue;
            }
            if entries.len() >= MAX_ENTRIES {
                return Err(Error::corrupt("too many entries"));
            }
            let name = join(&path, &clean(&fid.name));
            let hidden = fid.flags & FID_HIDDEN != 0;
            let child = vol.read_fe(fid.icb.0, fid.icb.1)?;
            match child.file_type {
                FT_DIR => {
                    entries.push(new_entry(name.clone(), &child, true, S_IFDIR, hidden));
                    sources.push(None);
                    if seen.insert(child.at) {
                        subdirs.push((child, name, depth + 1));
                    }
                }
                FT_SYMLINK => {
                    let target = vol.read_link(&child)?;
                    let mut e = new_entry(name, &child, false, S_IFLNK, hidden);
                    e.size = Some(target.len() as u64);
                    e.link = Some(Link::Symbolic(target.clone()));
                    entries.push(e);
                    sources.push(Some(Source::Inline(target.into_bytes())));
                }
                // Device, FIFO, socket and terminal entries carry no content.
                6..=10 => {}
                _ => {
                    let runs = vol.runs(&child)?;
                    entries.push(new_entry(name, &child, false, S_IFREG, hidden));
                    sources.push(Some(Source::Runs(runs)));
                }
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    Ok((entries, sources))
}

/// A file identifier descriptor (tag 257) inside a directory.
struct Fid {
    flags: u8,
    name: String,
    /// Partition reference and block of the entry's file entry.
    icb: (u16, u64),
    /// Bytes this descriptor occupies, padding included.
    stride: usize,
}

fn parse_fid(rest: &[u8]) -> Result<Fid> {
    if rest.len() < 38 {
        return Err(Error::corrupt("truncated file identifier"));
    }
    check_tag(rest, TAG_FID, None)?;
    let name_at = 38 + usize::from(u16_at(rest, 36));
    let end = name_at + usize::from(rest[19]);
    let name = rest
        .get(name_at..end)
        .ok_or_else(|| Error::corrupt("file identifier runs past its directory"))?;
    let stride = end.next_multiple_of(4);
    if stride > rest.len() {
        return Err(Error::corrupt(
            "file identifier padding runs past its directory",
        ));
    }
    Ok(Fid {
        flags: rest[18],
        name: decode_name(name),
        icb: (u16_at(rest, 28), u64::from(u32_at(rest, 24))),
        stride,
    })
}

/// File attributes for an entry: the Windows bits plus the Unix mode in the high 16 bits.
/// The UDF permission word has other (bits 0-4), group (5-9) and owner (10-14) groups of
/// execute, write, read; bit set means allowed. Zero permissions (writers that record none)
/// fall back to 0755 for directories and 0644 for files.
fn attributes(fe: &Fe, is_dir: bool, kind: u32, hidden: bool) -> u32 {
    let p = fe.perms;
    let mode = if p == 0 {
        if is_dir {
            0o755
        } else {
            0o644
        }
    } else {
        (p & 0o7) | ((p >> 2) & 0o70) | ((p >> 4) & 0o700)
    };
    0x8000 | ((kind | mode) << 16) | if is_dir { 0x10 } else { 0 } | if hidden { 0x02 } else { 0 }
}

fn new_entry(name: String, fe: &Fe, is_dir: bool, kind: u32, hidden: bool) -> Entry {
    Entry {
        name,
        is_dir,
        size: (!is_dir).then_some(fe.info_len),
        mtime: fe.mtime,
        ctime: fe.ctime,
        atime: fe.atime,
        attrib: Some(attributes(fe, is_dir, kind, hidden)),
        ..Default::default()
    }
}

/// A 12-byte timestamp (ECMA-167 1/7.3) to FILETIME. A local-time zone is applied; invalid
/// fields give no time.
fn timestamp(b: &[u8], at: usize) -> Option<u64> {
    let raw = u16_at(b, at);
    let year = i64::from(u16_at(b, at + 2));
    let [mo, d, h, mi, s, cs, hus, us] = le::<8>(b, at + 4);
    if !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || s > 59
        || cs > 99
        || hus > 99
        || us > 99
    {
        return None;
    }
    let tz = if raw >> 12 == 1 {
        i64::from(((raw << 4) as i16) >> 4)
    } else {
        0
    };
    let tz = if (-1440..=1440).contains(&tz) { tz } else { 0 };
    let secs = days_from_civil(year, u32::from(mo), u32::from(d)) * 86_400
        + i64::from(h) * 3600
        + i64::from(mi) * 60
        + i64::from(s)
        - tz * 60;
    let sub = u64::from(cs) * 100_000 + u64::from(hus) * 1_000 + u64::from(us) * 10;
    Some(unix_to_filetime(secs).saturating_add(sub))
}

/// A dstring (OSTA CS0): a compression ID byte (8 for 8-bit, 16 for UTF-16BE) and the
/// characters. Other IDs are read as 8-bit.
fn decode_name(b: &[u8]) -> String {
    let s: String = match b.split_first() {
        Some((&16, rest)) => char::decode_utf16(
            rest.chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])),
        )
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect(),
        Some((_, rest)) => rest.iter().map(|&c| char::from(c)).collect(),
        None => String::new(),
    };
    s.trim_end_matches('\0').to_string()
}

/// A fixed-length dstring, whose last byte gives the used length.
fn fixed_dstring(b: &[u8]) -> String {
    let used = b
        .last()
        .map_or(0, |&n| usize::from(n))
        .min(b.len().saturating_sub(1));
    decode_name(&b[..used])
}

/// A file name that is one path component: separators and NULs become `_`, and names that
/// would be empty or relative (`.`, `..`) are prefixed.
fn clean(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | '\0') {
                '_'
            } else {
                c
            }
        })
        .collect();
    if s.is_empty() || s == "." || s == ".." {
        format!("_{s}")
    } else {
        s
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}
