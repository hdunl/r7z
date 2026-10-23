//! UDF reader tests against images written by a small test-only UDF writer.
//!
//! Two layouts are written: UDF 2.01 with one physical partition, and UDF 2.50 with a
//! metadata partition whose logical blocks sit in scattered physical blocks, reached through
//! the metadata file. Both carry the same tree: directories, multi-extent and sparse files,
//! an embedded file, a chained allocation extent, symbolic links, Latin-1 and UTF-16 names, a
//! deleted entry, a device entry, a directory cycle and a hard link.

use std::collections::BTreeMap;
use std::sync::Arc;

use r7z::format::udf::{is_udf, open_udf};
use r7z::format::{self, Archive, Ctx, Flow, Link, OpenOptions, OpenRequest, Slice};
use r7z::Error;

const BLOCK: usize = 2048;
/// Sectors in the image. The anchors sit at 256, at N-256 and at N-1.
const SECTORS: usize = 768;
/// Physical sector of the physical partition's first block.
const PART_START: usize = 288;
/// Volume descriptor sequences (six blocks each) and the integrity descriptor.
const MAIN_VDS: usize = 32;
const RESERVE_VDS: usize = 38;
const VDS_BLOCKS: usize = 6;
const INTEGRITY: usize = 48;
const PART_BLOCKS: u32 = 160;
/// 2020-05-17 13:34:56 at UTC+01:00, as a recording time (UTC 12:34:56).
const TIMESTAMP: [u8; 12] = [0x3C, 0x10, 0xE4, 0x07, 5, 17, 13, 34, 56, 0, 0, 0];
/// `TIMESTAMP` as FILETIME: 2020-05-17 12:34:56 UTC.
const TIME: u64 = 132_341_924_960_000_000;
const UNICODE: &str = "Ünïcødé ✓ 日本語 long name.txt";
const LAYOUTS: [Layout; 3] = [Layout::Udf201, Layout::Udf250, Layout::Udf201Vat];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Layout {
    /// One physical partition, logical blocks where they are written.
    Udf201,
    /// A metadata partition over the physical one (UDF 2.50).
    Udf250,
    /// A virtual partition (write-once media): logical blocks are found through the
    /// allocation table kept in the last block of the physical partition.
    Udf201Vat,
}

/// A written image and the spans the damage tests aim at.
struct Image {
    bytes: Vec<u8>,
    /// Read and checked by the reader itself: damage here must fail the open or a read.
    strict: Vec<(usize, usize)>,
    /// Has a redundant copy: damage here must leave the listing and the bytes unchanged.
    fallback: Vec<(usize, usize)>,
    /// First sector past the last block of partition data.
    end_sector: usize,
}

/// An allocation descriptor the writer emits: kind (0 recorded, 1 unrecorded, 2 unallocated).
#[derive(Clone, Copy)]
struct Ext {
    kind: u8,
    len: u32,
    lbn: u32,
}

#[derive(Clone)]
enum Ads {
    None,
    Short(Vec<Ext>),
    Long(Vec<Ext>),
    /// Descriptors held in an allocation extent block, reached by a continuation.
    Chained(Vec<Ext>),
    Embedded(Vec<u8>),
}

enum Name {
    /// 8-bit characters (compression ID 8).
    Latin(&'static str),
    /// UTF-16BE characters (compression ID 16).
    Wide(&'static str),
}

enum Kind {
    Dir(Vec<Child>),
    File(u32, Ads),
    /// A symbolic link to a path; its components are embedded or stored in a block.
    Link(&'static str, bool),
    /// A block device: skipped by the reader.
    Device,
    /// A deleted identifier pointing at a block that holds no entry.
    Deleted,
    /// A directory entry naming the root again: a cycle.
    Loop,
    /// A second name for the entry of an earlier sibling (a hard link).
    Alias(&'static str),
}

struct Child {
    name: Name,
    flags: u8,
    kind: Kind,
}

fn latin(s: &'static str) -> Name {
    Name::Latin(s)
}

fn wide(s: &'static str) -> Name {
    Name::Wide(s)
}

fn dir(name: &'static str, kids: Vec<Child>) -> Child {
    Child {
        name: latin(name),
        flags: 0,
        kind: Kind::Dir(kids),
    }
}

fn file(name: Name, perms: u32, ads: Ads) -> Child {
    Child {
        name,
        flags: 0,
        kind: Kind::File(perms, ads),
    }
}

fn plain(name: &'static str, kind: Kind) -> Child {
    Child {
        name: latin(name),
        flags: 0,
        kind,
    }
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// A character set specification (charspec) at `at`: OSTA Compressed Unicode (CS0).
fn charspec(b: &mut [u8], at: usize) {
    b[at + 1..at + 1 + 23].copy_from_slice(b"OSTA Compressed Unicode");
}

/// An entity identifier (regid) naming the OSTA UDF domain at `at`, with its revision.
fn domain_id(b: &mut [u8], at: usize, revision: u16) {
    b[at + 1..at + 1 + 19].copy_from_slice(b"*OSTA UDF Compliant");
    put_u16(b, at + 24, revision);
}

/// CRC-CCITT, bit by bit (independent of the reader's table).
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Writes a descriptor tag over `b`, with the CRC covering `crc_len` bytes after the tag.
fn seal(b: &mut [u8], id: u16, loc: u32, crc_len: usize) {
    put_u16(b, 0, id);
    // Descriptor version 3 is what UDF 2.x writers use (version 2 is UDF 1.x).
    put_u16(b, 2, 3);
    put_u16(b, 6, 1);
    put_u16(b, 10, crc_len as u16);
    put_u32(b, 12, loc);
    let crc = crc16(&b[16..16 + crc_len]);
    put_u16(b, 8, crc);
    b[4] = b[..4]
        .iter()
        .chain(&b[5..16])
        .fold(0u8, |s, &x| s.wrapping_add(x));
}

/// A dstring of 8-bit characters, with its compression ID.
fn latin_dstring(s: &str) -> Vec<u8> {
    std::iter::once(8)
        .chain(s.chars().map(|c| c as u8))
        .collect()
}

/// A dstring with its compression ID.
fn dstring(n: &Name) -> Vec<u8> {
    match n {
        Name::Latin(s) => latin_dstring(s),
        Name::Wide(s) => std::iter::once(16)
            .chain(s.encode_utf16().flat_map(u16::to_be_bytes))
            .collect(),
    }
}

/// A file identifier descriptor. Returns the bytes and the protected length (without
/// padding).
fn fid_bytes(flags: u8, name: &[u8], icb: u32, part: u16, loc: u32) -> (Vec<u8>, usize) {
    let protected = 38 + name.len();
    let mut b = vec![0u8; protected.next_multiple_of(4)];
    put_u16(&mut b, 16, 1);
    b[18] = flags;
    b[19] = name.len() as u8;
    put_u32(&mut b, 20, BLOCK as u32);
    put_u32(&mut b, 24, icb);
    put_u16(&mut b, 28, part);
    b[38..protected].copy_from_slice(name);
    seal(&mut b, 257, loc, protected - 16);
    (b, protected)
}

/// Allocation descriptors as bytes: short (8) or long (16) with partition `part`.
fn encode(exts: &[Ext], long: bool, part: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for e in exts {
        out.extend_from_slice(&((u32::from(e.kind) << 30) | e.len).to_le_bytes());
        out.extend_from_slice(&e.lbn.to_le_bytes());
        if long {
            out.extend_from_slice(&part.to_le_bytes());
            out.extend_from_slice(&[0; 6]);
        }
    }
    out
}

/// The UDF permission word for a Unix mode: other bits 0-2, group 5-7, owner 10-12.
fn udf_permissions(mode: u32) -> u32 {
    (mode & 0o7) | ((mode & 0o70) << 2) | ((mode & 0o700) << 4)
}

fn ads_len(ads: &Ads) -> u64 {
    match ads {
        Ads::None => 0,
        Ads::Short(v) | Ads::Long(v) | Ads::Chained(v) => v.iter().map(|e| u64::from(e.len)).sum(),
        Ads::Embedded(d) => d.len() as u64,
    }
}

/// Symbolic link components (ECMA-167 4/14.16.1) for `target`.
fn components(target: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if target.starts_with('/') {
        out.extend([1, 0, 0, 0]);
    }
    for seg in target.split('/').filter(|s| !s.is_empty()) {
        match seg {
            ".." => out.extend([2, 0, 0, 0]),
            "." => out.extend([3, 0, 0, 0]),
            name => {
                let id = latin_dstring(name);
                out.extend([5, id.len() as u8, 0, 0]);
                out.extend(id);
            }
        }
    }
    out
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

struct Writer {
    layout: Layout,
    img: Vec<u8>,
    next: u32,
    strict: Vec<(usize, usize)>,
    fallback: Vec<(usize, usize)>,
    end_sector: usize,
}

impl Writer {
    /// The partition map entry that logical blocks are referenced through.
    fn part(&self) -> u16 {
        match self.layout {
            Layout::Udf201 => 0,
            Layout::Udf250 | Layout::Udf201Vat => 1,
        }
    }

    /// Physical block of logical block `lbn`. The metadata and virtual layouts keep runs of
    /// six logical blocks and leave three physical blocks free after each run; in the metadata
    /// layout blocks 0 and 1 hold the metadata file and its mirror.
    fn phys(&self, lbn: u32) -> u32 {
        match self.layout {
            Layout::Udf201 => lbn,
            Layout::Udf250 | Layout::Udf201Vat => lbn + 2 + 3 * (lbn / 6),
        }
    }

    fn alloc(&mut self, n: u32) -> u32 {
        let l = self.next;
        self.next += n;
        l
    }

    fn write_sector(&mut self, sector: usize, block: &[u8]) -> usize {
        let at = sector * BLOCK;
        let mut b = block.to_vec();
        b.resize(BLOCK, 0);
        self.img[at..at + BLOCK].copy_from_slice(&b);
        at
    }

    fn write_phys(&mut self, phys: u32, block: &[u8]) -> usize {
        self.write_sector(PART_START + phys as usize, block)
    }

    fn put(&mut self, lbn: u32, block: &[u8]) -> usize {
        let p = self.phys(lbn);
        self.end_sector = self.end_sector.max(PART_START + p as usize + 1);
        self.write_phys(p, block)
    }

    /// Stores `data` in extents of the given sizes, each in its own blocks with one unused
    /// block after it, so that extents are not adjacent.
    fn split(&mut self, data: &[u8], sizes: &[usize]) -> Vec<Ext> {
        let mut out = Vec::new();
        let mut at = 0;
        for &n in sizes {
            let blocks = n.div_ceil(BLOCK) as u32;
            let start = self.alloc(blocks);
            for (i, c) in data[at..at + n].chunks(BLOCK).enumerate() {
                self.put(start + i as u32, c);
            }
            self.alloc(1);
            out.push(Ext {
                kind: 0,
                len: n as u32,
                lbn: start,
            });
            at += n;
        }
        out
    }

    /// A file entry block at `loc`, the bytes of its protected range and that range's length.
    fn fe_bytes(
        &mut self,
        loc: u32,
        extended: bool,
        file_type: u8,
        perms: u32,
        info_len: u64,
        ads: &Ads,
    ) -> (Vec<u8>, usize) {
        let (ad_type, area): (u16, Vec<u8>) = match ads {
            Ads::None => (0, Vec::new()),
            Ads::Short(v) => (0, encode(v, false, 0)),
            Ads::Long(v) => (1, encode(v, true, self.part())),
            Ads::Chained(v) => {
                let aed = self.alloc(1);
                let body = encode(v, false, 0);
                let mut b = vec![0u8; BLOCK];
                put_u32(&mut b, 20, body.len() as u32);
                b[24..24 + body.len()].copy_from_slice(&body);
                seal(&mut b, 258, aed, 8 + body.len());
                let at = self.put(aed, &b);
                self.strict.push((at, 24 + body.len()));
                let cont = Ext {
                    kind: 3,
                    len: (24 + body.len()) as u32,
                    lbn: aed,
                };
                (0, encode(&[cont], false, 0))
            }
            Ads::Embedded(d) => (3, d.clone()),
        };
        let hdr = if extended { 216 } else { 176 };
        let mut b = vec![0u8; BLOCK];
        put_u16(&mut b, 20, 4);
        b[27] = file_type;
        put_u16(&mut b, 34, ad_type);
        put_u32(&mut b, 36, u32::MAX);
        put_u32(&mut b, 40, u32::MAX);
        put_u32(&mut b, 44, udf_permissions(perms));
        // A directory counts its own entry and its parent's.
        put_u16(&mut b, 48, if file_type == 4 { 2 } else { 1 });
        put_u16(&mut b, 24, 1);
        put_u64(&mut b, 56, info_len);
        let blocks = info_len.div_ceil(BLOCK as u64);
        put_u64(&mut b, if extended { 72 } else { 64 }, blocks);
        // An extended entry also records its object size and a creation time.
        if extended {
            put_u64(&mut b, 64, info_len);
        }
        // Access, modification and attribute times (the extended entry adds a creation time).
        let times: &[usize] = if extended {
            &[80, 92, 104, 116]
        } else {
            &[72, 84, 96]
        };
        for &t in times {
            b[t..t + 12].copy_from_slice(&TIMESTAMP);
        }
        put_u32(&mut b, if extended { 212 } else { 172 }, area.len() as u32);
        b[hdr..hdr + area.len()].copy_from_slice(&area);
        let len = hdr + area.len();
        seal(&mut b, if extended { 266 } else { 261 }, loc, len - 16);
        (b, len)
    }

    fn write_fe(
        &mut self,
        lbn: u32,
        extended: bool,
        file_type: u8,
        perms: u32,
        info_len: u64,
        ads: &Ads,
    ) {
        let (b, len) = self.fe_bytes(lbn, extended, file_type, perms, info_len, ads);
        let at = self.put(lbn, &b);
        self.strict.push((at, len));
    }

    /// A directory: its file identifiers (parent first), its data blocks and its entry.
    fn emit(&mut self, own: u32, parent: u32, root: u32, children: &[Child]) {
        let part = self.part();
        // (characteristics, name, file entry block) for each identifier, parent first.
        let mut fids: Vec<(u8, Vec<u8>, u32)> = vec![(0x0A, Vec::new(), parent)];
        let mut made: Vec<(String, u32)> = Vec::new();
        for c in children {
            let name = dstring(&c.name);
            let text = match &c.name {
                Name::Latin(s) | Name::Wide(s) => s.to_string(),
            };
            let (icb, flags) = match &c.kind {
                Kind::Dir(sub) => {
                    let lbn = self.alloc(1);
                    self.emit(lbn, own, root, sub);
                    (lbn, 0x02)
                }
                Kind::File(perms, ads) => {
                    let lbn = self.alloc(1);
                    self.write_fe(lbn, true, 5, *perms, ads_len(ads), ads);
                    (lbn, 0)
                }
                Kind::Link(target, embedded) => {
                    let comps = components(target);
                    let ads = if *embedded {
                        Ads::Embedded(comps.clone())
                    } else {
                        Ads::Short(self.split(&comps, &[comps.len()]))
                    };
                    let lbn = self.alloc(1);
                    self.write_fe(lbn, true, 12, 0o777, comps.len() as u64, &ads);
                    (lbn, 0)
                }
                Kind::Device => {
                    let lbn = self.alloc(1);
                    self.write_fe(lbn, true, 6, 0o600, 0, &Ads::None);
                    (lbn, 0)
                }
                Kind::Deleted => (self.alloc(1), 0x04),
                Kind::Loop => (root, 0x02),
                Kind::Alias(target) => {
                    let lbn = made
                        .iter()
                        .find(|(n, _)| n.as_str() == *target)
                        .map(|(_, l)| *l)
                        .expect("alias of an earlier sibling");
                    (lbn, 0)
                }
            };
            fids.push((flags | c.flags, name, icb));
            made.push((text, icb));
        }
        // Identifiers are packed into the directory's blocks, each tagged with its block.
        let total: usize = fids
            .iter()
            .map(|(_, n, _)| (38 + n.len()).next_multiple_of(4))
            .sum();
        let start = self.alloc(total.div_ceil(BLOCK) as u32);
        let mut data = Vec::with_capacity(total);
        let mut spans = Vec::new();
        for (flags, name, icb) in &fids {
            let loc = start + (data.len() / BLOCK) as u32;
            let (fid, protected) = fid_bytes(*flags, name, *icb, part, loc);
            spans.push((data.len(), protected));
            data.extend_from_slice(&fid);
        }
        for (i, chunk) in data.chunks(BLOCK).enumerate() {
            self.put(start + i as u32, chunk);
        }
        for (off, len) in spans {
            let (mut o, mut n) = (off, len);
            while n > 0 {
                let within = o % BLOCK;
                let take = n.min(BLOCK - within);
                let phys = self.phys(start + (o / BLOCK) as u32) as usize;
                self.strict
                    .push(((PART_START + phys) * BLOCK + within, take));
                o += take;
                n -= take;
            }
        }
        let ads = Ads::Short(vec![Ext {
            kind: 0,
            len: data.len() as u32,
            lbn: start,
        }]);
        self.write_fe(own, true, 4, 0o755, data.len() as u64, &ads);
    }

    /// The metadata file of a UDF 2.50 image, and its mirror at physical block 1.
    fn metadata_file(&mut self) {
        let total = self.next;
        let mut exts = Vec::new();
        for k in 0..total.div_ceil(6) {
            let start = 6 * k;
            exts.push(Ext {
                kind: 0,
                len: (total - start).min(6) * BLOCK as u32,
                lbn: self.phys(start),
            });
        }
        let info = u64::from(total) * BLOCK as u64;
        for phys in [0, 1] {
            let (b, len) = self.fe_bytes(phys, true, 0, 0o644, info, &Ads::Short(exts.clone()));
            let at = self.write_phys(phys, &b);
            self.fallback.push((at, len));
        }
    }

    /// The virtual allocation table of a UDF 2.01 virtual partition: one entry per logical
    /// block (its physical block), then a 36-byte trailer. The table lives in physical blocks
    /// 150 onward; its file entry is the last physical block.
    fn vat(&mut self) {
        let mut table: Vec<u8> = (0..self.next)
            .flat_map(|l| self.phys(l).to_le_bytes())
            .collect();
        table.extend([0u8; 36]);
        for (i, c) in table.chunks(BLOCK).enumerate() {
            self.write_phys(150 + i as u32, c);
        }
        let ads = Ads::Short(vec![Ext {
            kind: 0,
            len: table.len() as u32,
            lbn: 150,
        }]);
        let (b, len) = self.fe_bytes(PART_BLOCKS - 1, true, 0, 0o644, table.len() as u64, &ads);
        let at = self.write_phys(PART_BLOCKS - 1, &b);
        self.strict.push((at, len));
        self.end_sector = self.end_sector.max(PART_START + PART_BLOCKS as usize);
    }

    /// The UDF revision the image claims (in its domain identifiers).
    fn revision(&self) -> u16 {
        match self.layout {
            Layout::Udf250 => 0x0250,
            Layout::Udf201 | Layout::Udf201Vat => 0x0201,
        }
    }

    fn vrs(&mut self) {
        // UDF 2.x volumes name NSR03 (NSR02 is UDF 1.x).
        let nsr = *b"NSR03";
        for (i, id) in [*b"BEA01", nsr, *b"TEA01"].into_iter().enumerate() {
            let mut b = vec![0u8; BLOCK];
            b[1..6].copy_from_slice(&id);
            b[6] = 1;
            self.write_sector(16 + i, &b);
        }
    }

    /// The anchor at `sector`: main sequence at 32 and reserve sequence at 38, six blocks each.
    fn anchor(&mut self, sector: usize) {
        let mut b = vec![0u8; BLOCK];
        put_u32(&mut b, 16, (VDS_BLOCKS * BLOCK) as u32);
        put_u32(&mut b, 20, MAIN_VDS as u32);
        put_u32(&mut b, 24, (VDS_BLOCKS * BLOCK) as u32);
        put_u32(&mut b, 28, RESERVE_VDS as u32);
        seal(&mut b, 2, sector as u32, 496);
        let at = self.write_sector(sector, &b);
        self.fallback.push((at, BLOCK));
    }

    /// A main or reserve volume descriptor sequence at `base`: primary volume, implementation
    /// use, partition, logical volume, unallocated space and terminating descriptors, in the
    /// order Windows writes them.
    fn vds(&mut self, base: usize) {
        let part = self.part();
        let mut pvd = vec![0u8; BLOCK];
        let vol_id = dstring(&latin("UDF TEST"));
        pvd[24..24 + vol_id.len()].copy_from_slice(&vol_id);
        pvd[24 + 31] = vol_id.len() as u8;
        put_u16(&mut pvd, 56, 1);
        put_u16(&mut pvd, 58, 1);
        put_u16(&mut pvd, 60, 2);
        put_u16(&mut pvd, 62, 3);
        put_u32(&mut pvd, 64, 1);
        put_u32(&mut pvd, 68, 1);
        seal(&mut pvd, 1, base as u32, 496);
        let at = self.write_sector(base, &pvd);
        self.fallback.push((at, BLOCK));

        let mut iuvd = vec![0u8; BLOCK];
        put_u32(&mut iuvd, 16, 2);
        iuvd[21..28].copy_from_slice(b"*LVInfo");
        seal(&mut iuvd, 4, base as u32 + 1, 496);
        let at = self.write_sector(base + 1, &iuvd);
        self.fallback.push((at, BLOCK));

        let mut pd = vec![0u8; BLOCK];
        put_u16(&mut pd, 20, 1);
        put_u16(&mut pd, 22, 0);
        pd[25..31].copy_from_slice(b"+NSR03");
        put_u32(&mut pd, 184, 1);
        put_u32(&mut pd, 188, PART_START as u32);
        put_u32(&mut pd, 192, PART_BLOCKS);
        seal(&mut pd, 5, base as u32 + 3, 496);
        let at = self.write_sector(base + 3, &pd);
        self.fallback.push((at, BLOCK));

        // Map 0 is the physical partition; map 1 is the metadata or virtual partition.
        let mut maps = vec![1, 6, 1, 0, 0, 0];
        let mut count = 1;
        let second = match self.layout {
            Layout::Udf201 => None,
            Layout::Udf250 => {
                let mut m = vec![0u8; 64];
                m[0] = 2;
                m[1] = 64;
                m[5..28].copy_from_slice(b"*UDF Metadata Partition");
                put_u16(&mut m, 36, 1);
                put_u16(&mut m, 38, 0);
                put_u32(&mut m, 40, 0);
                put_u32(&mut m, 44, 1);
                put_u32(&mut m, 48, u32::MAX);
                put_u32(&mut m, 52, 1);
                Some(m)
            }
            Layout::Udf201Vat => {
                let mut m = vec![0u8; 64];
                m[0] = 2;
                m[1] = 64;
                m[5..27].copy_from_slice(b"*UDF Virtual Partition");
                Some(m)
            }
        };
        if let Some(m) = second {
            count = 2;
            maps.extend(m);
        }
        let mut lvd = vec![0u8; BLOCK];
        put_u32(&mut lvd, 16, 2);
        let label = dstring(&latin("UDF TEST"));
        lvd[84..84 + label.len()].copy_from_slice(&label);
        lvd[84 + 127] = label.len() as u8;
        charspec(&mut lvd, 20);
        put_u32(&mut lvd, 212, BLOCK as u32);
        domain_id(&mut lvd, 216, self.revision());
        put_u32(&mut lvd, 248, BLOCK as u32);
        put_u32(&mut lvd, 252, 0);
        put_u16(&mut lvd, 256, part);
        put_u32(&mut lvd, 264, maps.len() as u32);
        put_u32(&mut lvd, 268, count);
        // The integrity sequence extent (length, location) precedes the partition maps.
        put_u32(&mut lvd, 432, 2 * BLOCK as u32);
        put_u32(&mut lvd, 436, INTEGRITY as u32);
        lvd[440..440 + maps.len()].copy_from_slice(&maps);
        seal(&mut lvd, 6, base as u32 + 2, 440 + maps.len() - 16);
        let at = self.write_sector(base + 2, &lvd);
        self.fallback.push((at, 440 + maps.len()));

        let mut usd = vec![0u8; BLOCK];
        put_u32(&mut usd, 16, 5);
        seal(&mut usd, 7, base as u32 + 4, 8);
        let at = self.write_sector(base + 4, &usd);
        self.fallback.push((at, 24));

        let mut td = vec![0u8; BLOCK];
        seal(&mut td, 8, base as u32 + 5, 496);
        let at = self.write_sector(base + 5, &td);
        self.fallback.push((at, BLOCK));
    }

    /// The integrity sequence at `INTEGRITY`: a logical volume integrity descriptor (closed,
    /// one partition) and the terminating descriptor that ends the sequence.
    fn integrity(&mut self) {
        let mut b = vec![0u8; BLOCK];
        b[16..28].copy_from_slice(&TIMESTAMP);
        put_u32(&mut b, 28, 1);
        put_u32(&mut b, 72, 1);
        put_u32(&mut b, 76, 0);
        put_u32(&mut b, 80, u32::MAX);
        put_u32(&mut b, 84, PART_BLOCKS);
        seal(&mut b, 9, INTEGRITY as u32, 88 - 16);
        self.write_sector(INTEGRITY, &b);
        let mut td = vec![0u8; BLOCK];
        seal(&mut td, 8, INTEGRITY as u32 + 1, 496);
        self.write_sector(INTEGRITY + 1, &td);
    }
}

/// The tree every image carries, with its data written.
fn tree(w: &mut Writer) -> Vec<Child> {
    // Data for the sparse file: one recorded extent, an unrecorded one, one recorded.
    let mut sparse = w.split(&pattern(3, 2048), &[2048]);
    sparse.push(Ext {
        kind: 1,
        len: 4096,
        lbn: 0,
    });
    sparse.extend(w.split(&pattern(4, 2048), &[2048]));
    let chained = w.split(&pattern(9, 6144), &[2048, 2048, 2048]);
    let readme = w.split(b"hello udf\n", &[10]);
    let deep_ads = w.split(&pattern(7, 10363), &[4096, 4096, 2171]);
    let latin_ads = w.split(b"latin\n", &[6]);
    let unicode_ads = w.split(b"unicode\n", &[8]);
    let slash_ads = w.split(b"slash\n", &[6]);
    let hidden_ads = w.split(b"h\n", &[2]);
    vec![
        dir(
            "docs",
            vec![
                file(latin("readme.txt"), 0o644, Ads::Short(readme)),
                plain("readme-link.txt", Kind::Alias("readme.txt")),
                dir(
                    "sub",
                    vec![file(latin("deep.bin"), 0o644, Ads::Long(deep_ads))],
                ),
            ],
        ),
        dir("empty", Vec::new()),
        file(latin("empty.txt"), 0o644, Ads::None),
        file(
            latin("embedded.txt"),
            0o644,
            Ads::Embedded(b"tiny embedded".to_vec()),
        ),
        file(latin("chained.bin"), 0o644, Ads::Chained(chained)),
        file(latin("sparse.bin"), 0o644, Ads::Short(sparse)),
        plain("link", Kind::Link("docs/readme.txt", true)),
        plain("abs_link", Kind::Link("/docs", true)),
        plain("dotdot_link", Kind::Link("../empty.txt", false)),
        file(latin("café.txt"), 0o644, Ads::Short(latin_ads)),
        file(wide(UNICODE), 0o644, Ads::Short(unicode_ads)),
        file(latin("a/b.txt"), 0o644, Ads::Short(slash_ads)),
        Child {
            name: latin("hidden.txt"),
            flags: 0x01,
            kind: Kind::File(0o644, Ads::Short(hidden_ads)),
        },
        plain("gone.txt", Kind::Deleted),
        plain("blockdev", Kind::Device),
        plain("loop", Kind::Loop),
    ]
}

fn build(layout: Layout) -> Image {
    build_with(layout, tree)
}

fn build_with(layout: Layout, make: fn(&mut Writer) -> Vec<Child>) -> Image {
    let mut w = Writer {
        layout,
        img: vec![0; SECTORS * BLOCK],
        next: 0,
        strict: Vec::new(),
        fallback: Vec::new(),
        end_sector: 0,
    };
    let fsd = w.alloc(1);
    let root = w.alloc(1);
    let children = make(&mut w);
    w.emit(root, root, root, &children);
    let mut f = vec![0u8; BLOCK];
    f[16..28].copy_from_slice(&TIMESTAMP);
    put_u16(&mut f, 28, 3);
    put_u16(&mut f, 30, 3);
    put_u32(&mut f, 32, 1);
    put_u32(&mut f, 36, 1);
    charspec(&mut f, 48);
    charspec(&mut f, 240);
    let id = dstring(&latin("UDF FILESET"));
    f[304..304 + id.len()].copy_from_slice(&id);
    f[304 + 31] = id.len() as u8;
    domain_id(&mut f, 416, w.revision());
    put_u32(&mut f, 400, BLOCK as u32);
    put_u32(&mut f, 404, root);
    put_u16(&mut f, 408, w.part());
    seal(&mut f, 256, fsd, 496);
    let at = w.put(fsd, &f);
    w.strict.push((at, 512));
    match layout {
        Layout::Udf201 => {}
        Layout::Udf250 => w.metadata_file(),
        Layout::Udf201Vat => w.vat(),
    }
    w.vrs();
    w.vds(MAIN_VDS);
    w.vds(RESERVE_VDS);
    w.integrity();
    for s in [256, SECTORS - 256, SECTORS - 1] {
        w.anchor(s);
    }
    Image {
        bytes: w.img,
        strict: w.strict,
        fallback: w.fallback,
        end_sector: w.end_sector,
    }
}

type Row = (String, bool, Option<u64>, Option<String>);

/// Listing rows (name, is directory, size, symbolic link target), sorted by name.
fn rows(a: &dyn Archive) -> Vec<Row> {
    let mut v: Vec<Row> = a
        .entries()
        .iter()
        .map(|e| {
            let link = match &e.link {
                Some(Link::Symbolic(t)) => Some(t.clone()),
                _ => None,
            };
            (e.name.clone(), e.is_dir, e.size, link)
        })
        .collect();
    v.sort();
    v
}

/// The bytes of every non-directory entry, keyed by name.
fn contents(a: &dyn Archive) -> r7z::Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for u in 0..a.units().len() {
        a.extract_unit(u, &Ctx::default(), &mut |i, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            out.insert(a.entries()[i].name.clone(), v);
            Ok(Flow::Continue)
        })?;
    }
    Ok(out)
}

/// Listing rows and the bytes of every file, keyed by name.
type Listed = (Vec<Row>, BTreeMap<String, Vec<u8>>);

/// Opens, lists and reads every entry of `bytes`; any failure is returned.
fn read_all(bytes: &[u8]) -> r7z::Result<Listed> {
    let opened = format::open_bytes(bytes.to_vec(), "image.udf", &OpenRequest::default())?;
    let a = opened.archive();
    Ok((rows(a), contents(a)?))
}

fn expected_rows() -> Vec<Row> {
    let f = |n: &str, size: u64| (n.to_string(), false, Some(size), None);
    let d = |n: &str| (n.to_string(), true, None, None);
    let l = |n: &str, target: &str| {
        (
            n.to_string(),
            false,
            Some(target.len() as u64),
            Some(target.to_string()),
        )
    };
    let mut v = vec![
        d("docs"),
        f("docs/readme.txt", 10),
        f("docs/readme-link.txt", 10),
        d("docs/sub"),
        f("docs/sub/deep.bin", 10363),
        d("empty"),
        f("empty.txt", 0),
        f("embedded.txt", 13),
        f("chained.bin", 6144),
        f("sparse.bin", 8192),
        l("link", "docs/readme.txt"),
        l("abs_link", "/docs"),
        l("dotdot_link", "../empty.txt"),
        f("café.txt", 6),
        f(UNICODE, 8),
        f("a_b.txt", 6),
        f("hidden.txt", 2),
        d("loop"),
    ];
    v.sort();
    v
}

fn expected_contents() -> BTreeMap<String, Vec<u8>> {
    let mut sparse = pattern(3, 2048);
    sparse.extend(vec![0u8; 4096]);
    sparse.extend(pattern(4, 2048));
    [
        ("docs/readme.txt", b"hello udf\n".to_vec()),
        ("docs/readme-link.txt", b"hello udf\n".to_vec()),
        ("docs/sub/deep.bin", pattern(7, 10363)),
        ("empty.txt", Vec::new()),
        ("embedded.txt", b"tiny embedded".to_vec()),
        ("chained.bin", pattern(9, 6144)),
        ("sparse.bin", sparse),
        ("link", b"docs/readme.txt".to_vec()),
        ("abs_link", b"/docs".to_vec()),
        ("dotdot_link", b"../empty.txt".to_vec()),
        ("café.txt", b"latin\n".to_vec()),
        (UNICODE, b"unicode\n".to_vec()),
        ("a_b.txt", b"slash\n".to_vec()),
        ("hidden.txt", b"h\n".to_vec()),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_string(), v))
    .collect()
}

fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v[at] ^= 1;
    v
}

#[test]
fn crc_matches_the_standard_check_value() {
    assert_eq!(crc16(b"123456789"), 0x31C3);
}

#[test]
fn lists_both_layouts() {
    for layout in LAYOUTS {
        let img = build(layout);
        let (got, _) = read_all(&img.bytes).unwrap_or_else(|e| panic!("{layout:?}: {e}"));
        assert_eq!(got, expected_rows(), "{layout:?}");
    }
}

#[test]
fn extracts_every_entry() {
    for layout in LAYOUTS {
        let img = build(layout);
        let (_, got) = read_all(&img.bytes).unwrap_or_else(|e| panic!("{layout:?}: {e}"));
        assert_eq!(got, expected_contents(), "{layout:?}");
    }
}

#[test]
fn reports_format_and_attributes() {
    let img = build(Layout::Udf201);
    let opened = format::open_bytes(img.bytes, "image.udf", &OpenRequest::default()).unwrap();
    let a = opened.archive();
    assert_eq!(a.format().name, "Udf");
    let find = |n: &str| a.entries().iter().find(|e| e.name == n).unwrap();
    let readme = find("docs/readme.txt");
    assert_eq!(readme.mtime, Some(TIME));
    let attrib = readme.attrib.unwrap();
    assert_ne!(attrib & 0x8000, 0);
    assert_eq!((attrib >> 16) & 0o7777, 0o644);
    assert_eq!((attrib >> 16) & 0o170000, 0o100000);
    let docs = find("docs");
    assert_ne!(docs.attrib.unwrap() & 0x10, 0);
    assert_eq!((docs.attrib.unwrap() >> 16) & 0o170000, 0o040000);
    assert_eq!((docs.attrib.unwrap() >> 16) & 0o7777, 0o755);
    assert_ne!(find("hidden.txt").attrib.unwrap() & 0x02, 0);
}

#[test]
fn rejects_images_without_a_udf_anchor() {
    let zeros = vec![0u8; 300 * BLOCK];
    assert!(!is_udf(&Slice::from_vec(zeros.clone())));
    assert!(matches!(
        open_udf(
            Arc::new(Slice::from_vec(zeros.clone())),
            &OpenOptions::default()
        ),
        Err(Error::NotArchive)
    ));
    assert!(format::open_bytes(zeros, "blank.udf", &OpenRequest::default()).is_err());

    // An ISO 9660 volume descriptor (CD001) with no UDF recognition sequence or anchor.
    let mut iso = vec![0u8; 300 * BLOCK];
    iso[16 * BLOCK..16 * BLOCK + 7].copy_from_slice(&[1, b'C', b'D', b'0', b'0', b'1', 1]);
    assert!(!is_udf(&Slice::from_vec(iso.clone())));
    assert!(matches!(
        open_udf(Arc::new(Slice::from_vec(iso)), &OpenOptions::default()),
        Err(Error::NotArchive)
    ));
}

#[test]
fn recognizes_udf_images() {
    for layout in LAYOUTS {
        let img = build(layout);
        assert!(is_udf(&Slice::from_vec(img.bytes.clone())), "{layout:?}");

        // Without the NSR descriptor the recognition sequence is incomplete.
        let mut no_nsr = img.bytes.clone();
        no_nsr[17 * BLOCK + 1] = b'X';
        assert!(!is_udf(&Slice::from_vec(no_nsr)), "{layout:?}");
    }
}

#[test]
fn damage_to_checked_descriptors_is_reported() {
    for layout in LAYOUTS {
        let img = build(layout);
        for &(start, len) in &img.strict {
            for at in start..start + len {
                let bad = flipped(&img.bytes, at);
                assert!(
                    read_all(&bad).is_err(),
                    "{layout:?}: bit flip at byte {at} was not reported"
                );
            }
        }
    }
}

#[test]
fn damaged_redundant_copies_fall_back_without_changing_the_listing() {
    for layout in LAYOUTS {
        let img = build(layout);
        let want = read_all(&img.bytes).unwrap();
        for &(start, len) in &img.fallback {
            for at in (start..start + len.min(600)).step_by(3) {
                let got = read_all(&flipped(&img.bytes, at));
                assert!(
                    got.as_ref().is_ok_and(|g| *g == want),
                    "{layout:?}: bit flip at byte {at} changed the result: {:?}",
                    got.err().map(|e| e.to_string())
                );
            }
        }
    }
}

#[test]
fn truncated_images_are_reported() {
    for layout in LAYOUTS {
        let img = build(layout);
        for sectors in 0..img.end_sector {
            let short = &img.bytes[..sectors * BLOCK];
            assert!(
                read_all(short).is_err(),
                "{layout:?}: truncation to {sectors} sectors was not reported"
            );
        }
    }
}

#[test]
fn random_damage_never_panics() {
    for layout in LAYOUTS {
        let img = build(layout);
        for at in (0..img.bytes.len()).step_by(997) {
            let mut bad = img.bytes.clone();
            bad[at] ^= 0x80;
            let _ = read_all(&bad);
        }
    }
}

/// Writes both images to `UDF_DUMP_DIR` for the 7-Zip cross-check.
#[test]
#[ignore = "writes images for the 7-Zip cross-check when UDF_DUMP_DIR is set"]
fn dump_images_for_seven_zip() {
    let Ok(dir) = std::env::var("UDF_DUMP_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    for (layout, name) in [
        (Layout::Udf201, "udf201.udf"),
        (Layout::Udf250, "udf250.udf"),
        (Layout::Udf201Vat, "udf201vat.udf"),
    ] {
        std::fs::write(dir.join(name), build(layout).bytes).unwrap();
    }
}
