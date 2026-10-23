//! ISO 9660 images (`.iso`): the directory tree with Rock Ridge names, permissions,
//! symlinks and timestamps; Joliet names when the image has them, as 7-Zip shows them;
//! El Torito boot images under `[BOOT]`; and files split over several extents. An image
//! that also carries a UDF file system opens as UDF, as 7-Zip does.
//!
//! Joliet and ISO records describe the same file data but not the same directories, so a
//! Joliet image is read in two passes: the primary tree supplies the Rock Ridge fields of
//! each file, keyed by its first extent, length and date (the Joliet record for that file
//! carries the same three), and then the Joliet tree supplies the names and the listing.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{
    udf, Archive, Ctx, Entry, EntryFn, Format, Input, Link, OpenOptions, ReadAt, Runs, Signature,
    Unit,
};
use crate::error::{Error, Result};
use crate::sevenz::attr;
use crate::util::time;

pub const FORMAT: Format = Format {
    name: "Iso",
    aliases: &[],
    extensions: &["iso"],
    signatures: &[Signature::at(32769, b"CD001")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

/// The volume descriptors start at the 17th 2048-byte sector and end at a terminator.
const VD_OFFSET: u64 = 32 * 1024;
const SECTOR: u64 = 2048;
const MAX_VDS: u64 = 64;
/// Logical block sizes accepted: ECMA-119 specifies 2048, and a few tools write smaller.
const MIN_BLOCK: u64 = 512;
const MAX_BLOCK: u64 = 4096;
/// Records listed in all; guards against a crafted tree.
const MAX_ENTRIES: usize = 1 << 21;
/// Deepest directory nesting followed.
const MAX_DEPTH: usize = 128;
/// Continuation areas (Rock Ridge `CE`) followed for one record, and the largest read.
const MAX_CE_HOPS: u32 = 8;
const MAX_CE_BYTES: usize = 1 << 16;
/// Longest Rock Ridge name and symlink target kept.
const MAX_NAME: usize = 4096;
const MAX_TARGET: usize = 4096;
/// Entries in the El Torito catalog (32 bytes each, after the validation entry).
const CATALOG_ENTRIES: usize = 63;

fn bad(msg: &str) -> Error {
    Error::corrupt(format!("ISO 9660: {msg}"))
}

fn u16le(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// `len` bytes at `off`, which must lie inside the image.
fn read_range(src: &dyn ReadAt, off: u64, len: usize) -> Result<Vec<u8>> {
    let end = off.checked_add(len as u64);
    if end.is_none_or(|e| e > src.size()) {
        return Err(bad("structure is past the end of the image"));
    }
    let mut buf = vec![0u8; len];
    src.read_at(off, &mut buf)?;
    Ok(buf)
}

/// The volume descriptors this reader uses.
struct Descriptors {
    primary: Vec<u8>,
    joliet: Option<Vec<u8>>,
    boot_catalog: Option<u32>,
}

fn descriptors(src: &dyn ReadAt) -> Result<Descriptors> {
    let mut primary = None;
    let mut joliet = None;
    let mut boot_catalog = None;
    for i in 0..MAX_VDS {
        let off = VD_OFFSET + i * SECTOR;
        if off + SECTOR > src.size() {
            break;
        }
        let vd = read_range(src, off, SECTOR as usize)?;
        if &vd[1..6] != b"CD001" {
            break;
        }
        match vd[0] {
            0 if &vd[7..30] == b"EL TORITO SPECIFICATION" => boot_catalog = u32le(&vd, 71),
            1 if primary.is_none() => primary = Some(vd),
            2 if joliet.is_none() && matches!(&vd[88..91], b"%/@" | b"%/C" | b"%/E") => {
                joliet = Some(vd);
            }
            255 => break,
            _ => {}
        }
    }
    let primary = primary.ok_or(Error::NotArchive)?;
    Ok(Descriptors {
        primary,
        joliet,
        boot_catalog,
    })
}

/// A directory's extent: where its records start, and how many bytes they fill. A length
/// of 0 means the length is in the directory's own "." record (a relocated directory).
#[derive(Clone, Copy)]
struct Dir {
    lba: u32,
    len: u32,
}

/// One directory record.
#[derive(Clone)]
struct Record {
    lba: u32,
    len: u32,
    dir: bool,
    /// Flag 0x80: another record continues this file.
    more: bool,
    date: [u8; 7],
    ident: Vec<u8>,
    /// The System Use area (Rock Ridge fields); empty in Joliet trees.
    sys: Vec<u8>,
}

fn record(r: &[u8]) -> Result<Record> {
    let ilen = usize::from(*r.get(32).ok_or_else(|| bad("directory record is short"))?);
    let ident = r
        .get(33..33 + ilen)
        .ok_or_else(|| bad("directory record name runs past its length"))?;
    // The identifier is padded to an even length, so the record stays even.
    let sys_at = 33 + ilen + usize::from(ilen % 2 == 0);
    let mut date = [0u8; 7];
    date.copy_from_slice(
        r.get(18..25)
            .ok_or_else(|| bad("directory record is short"))?,
    );
    let flags = *r.get(25).ok_or_else(|| bad("directory record is short"))?;
    Ok(Record {
        lba: u32le(r, 2).ok_or_else(|| bad("directory record is short"))?,
        len: u32le(r, 10).ok_or_else(|| bad("directory record is short"))?,
        dir: flags & 0x02 != 0,
        more: flags & 0x80 != 0,
        date,
        ident: ident.to_vec(),
        sys: r.get(sys_at..).unwrap_or_default().to_vec(),
    })
}

/// The records of a directory, its "." and ".." entries left out. Read one logical block
/// at a time: a record never crosses a block, so memory does not depend on the directory.
fn read_dir(src: &dyn ReadAt, bs: u64, dir: Dir) -> Result<Vec<Record>> {
    let base = u64::from(dir.lba) * bs;
    let total = u64::from(dir.len);
    let mut out = Vec::new();
    let mut at = 0u64;
    while at < total {
        let n = bs.min(total - at) as usize;
        let block = read_range(src, base + at, n)?;
        let mut p = 0usize;
        while let Some(&rl) = block.get(p).filter(|&&rl| rl != 0) {
            let end = p + usize::from(rl);
            let bytes = block
                .get(p..end)
                .ok_or_else(|| bad("directory record crosses a block"))?;
            let rec = record(bytes)?;
            if rec.ident != [0] && rec.ident != [1] {
                out.push(rec);
                if out.len() > MAX_ENTRIES {
                    return Err(bad("too many directory records"));
                }
            }
            p = end;
        }
        at += n as u64;
    }
    Ok(out)
}

/// The records of one file or directory: several records when the file has several
/// extents.
struct Node {
    dir: bool,
    ident: Vec<u8>,
    date: [u8; 7],
    /// (extent location, length) for each record, in order.
    extents: Vec<(u32, u32)>,
    /// The System Use area of the first record.
    sys: Vec<u8>,
}

fn nodes(recs: Vec<Record>) -> Vec<Node> {
    let mut out = Vec::new();
    let mut cur: Option<Node> = None;
    for r in recs {
        let more = r.more;
        let node = cur.get_or_insert_with(|| Node {
            dir: r.dir,
            ident: r.ident.clone(),
            date: r.date,
            extents: Vec::new(),
            sys: r.sys.clone(),
        });
        node.extents.push((r.lba, r.len));
        if !more {
            out.extend(cur.take());
        }
    }
    out.extend(cur);
    out
}

/// Rock Ridge fields of one record.
#[derive(Clone, Default)]
struct RockRidge {
    name: Option<String>,
    mode: Option<u32>,
    mtime: Option<u64>,
    link: Option<String>,
    /// `CL`: a directory moved below the depth limit lives at this extent.
    child: Option<u32>,
    /// `RE`: the placeholder of a relocated directory, listed where it moved to.
    relocated: bool,
}

/// State for reading one record's System Use area.
#[derive(Default)]
struct Susp {
    rr: RockRidge,
    /// Whether any Rock Ridge field was found.
    found: bool,
    /// A name or symlink that continues in the next `NM` or `SL` field.
    name: Vec<u8>,
    links: Vec<(u8, Vec<u8>)>,
}

/// Reads the System Use area `area`, following continuation areas (`CE`).
fn susp(src: &dyn ReadAt, bs: u64, area: &[u8], st: &mut Susp, hops: u32) -> Result<()> {
    let mut p = 0usize;
    while p + 4 <= area.len() {
        let len = usize::from(area[p + 2]);
        if len < 4 || p + len > area.len() {
            break;
        }
        let sig = [area[p], area[p + 1]];
        let data = &area[p + 4..p + len];
        p += len;
        match &sig {
            b"PX" => {
                st.found = true;
                st.rr.mode = u32le(data, 0);
            }
            b"NM" => {
                st.found = true;
                let flags = data.first().copied().unwrap_or(0);
                if st.name.len() < MAX_NAME {
                    st.name.extend_from_slice(data.get(1..).unwrap_or_default());
                }
                if flags & 0x01 == 0 {
                    let name = String::from_utf8_lossy(&std::mem::take(&mut st.name)).into_owned();
                    // "." and ".." are not names.
                    if flags & 0x06 == 0 {
                        st.rr.name = Some(name);
                    }
                }
            }
            b"SL" => {
                st.found = true;
                let flags = data.first().copied().unwrap_or(0);
                let mut rest = data.get(1..).unwrap_or_default();
                while let [flag, n, tail @ ..] = rest {
                    let n = usize::from(*n);
                    let Some(text) = tail.get(..n) else { break };
                    st.links.push((*flag, text.to_vec()));
                    rest = &tail[n..];
                }
                if flags & 0x01 == 0 {
                    st.rr.link = Some(link_target(&std::mem::take(&mut st.links)));
                }
            }
            b"TF" => {
                st.found = true;
                if let Some(t) = tf_modify(data) {
                    st.rr.mtime = Some(t);
                }
            }
            b"CL" => {
                st.found = true;
                st.rr.child = u32le(data, 0);
            }
            b"RE" => {
                st.found = true;
                st.rr.relocated = true;
            }
            b"CE" if hops < MAX_CE_HOPS => {
                if let (Some(block), Some(off), Some(n)) =
                    (u32le(data, 0), u32le(data, 8), u32le(data, 16))
                {
                    let at = u64::from(block)
                        .checked_mul(bs)
                        .and_then(|b| b.checked_add(u64::from(off)));
                    if let Some(at) = at {
                        // An unreadable continuation area only loses its fields.
                        if let Ok(bytes) = read_range(src, at, (n as usize).min(MAX_CE_BYTES)) {
                            susp(src, bs, &bytes, st, hops + 1)?;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A symlink target from its `SL` components: root, current, parent, or text. A component
/// with the continue flag joins the next one without a separator.
fn link_target(parts: &[(u8, Vec<u8>)]) -> String {
    let mut out = String::new();
    let mut continued = false;
    for (flags, text) in parts {
        let piece = if flags & 0x08 != 0 {
            "/".to_string()
        } else if flags & 0x02 != 0 {
            ".".to_string()
        } else if flags & 0x04 != 0 {
            "..".to_string()
        } else {
            String::from_utf8_lossy(text).into_owned()
        };
        if !continued && !out.is_empty() && !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(&piece);
        continued = flags & 0x01 != 0;
        if out.len() > MAX_TARGET {
            out.truncate(MAX_TARGET);
            break;
        }
    }
    out
}

/// The modification time of a Rock Ridge `TF` field, when it has one.
fn tf_modify(data: &[u8]) -> Option<u64> {
    let flags = *data.first()?;
    let long = flags & 0x80 != 0;
    let size = if long { 17 } else { 7 };
    let mut at = 1usize;
    // Creation, modification, access, attributes, backup, expiration, effective.
    for bit in 0u8..7 {
        if flags & (1u8 << bit) == 0 {
            continue;
        }
        let field = data.get(at..at + size)?;
        if bit == 1 {
            return if long {
                long_time(field)
            } else {
                let d: [u8; 7] = field.try_into().ok()?;
                iso_time(d)
            };
        }
        at += size;
    }
    None
}

/// Civil time (year, month, day, hour, minute, second, quarter hours from GMT) as FILETIME.
fn civil_time(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, off_qh: i64) -> Option<u64> {
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = time::days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + s - off_qh * 900;
    Some(time::unix_to_filetime(secs))
}

/// A directory record date: years since 1900, then month to second and the GMT offset.
fn iso_time(d: [u8; 7]) -> Option<u64> {
    let [y, mo, day, h, mi, s, off] = d;
    civil_time(
        1900 + i64::from(y),
        i64::from(mo),
        i64::from(day),
        i64::from(h),
        i64::from(mi),
        i64::from(s),
        i64::from(off as i8),
    )
}

/// The 17-byte date form of Rock Ridge `TF`: sixteen ASCII digits, then the GMT offset.
fn long_time(d: &[u8]) -> Option<u64> {
    let num = |a: usize, b: usize| -> Option<i64> {
        std::str::from_utf8(d.get(a..b)?).ok()?.parse().ok()
    };
    let off = i64::from(*d.get(16)? as i8);
    civil_time(
        num(0, 4)?,
        num(4, 6)?,
        num(6, 8)?,
        num(8, 10)?,
        num(10, 12)?,
        num(12, 14)?,
        off,
    )
}

/// The media name El Torito gives a boot image.
fn media_name(m: u8) -> &'static str {
    match m {
        0 => "NoEmul",
        1 => "1.2M",
        2 => "1.44M",
        3 => "2.88M",
        4 => "HardDisk",
        _ => "Unknown",
    }
}

/// Drops the `;1` version number that ISO 9660 and Joliet put on file names.
fn strip_version(name: &str) -> &str {
    match name.rsplit_once(';') {
        Some((base, ver)) if !ver.is_empty() && ver.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => name,
    }
}

/// An ISO 9660 name. Files drop their version, and a trailing `.` (an empty extension).
fn iso_name(ident: &[u8], dir: bool) -> String {
    let name = String::from_utf8_lossy(ident).into_owned();
    if dir {
        return name;
    }
    let name = strip_version(&name);
    name.strip_suffix('.').unwrap_or(name).to_string()
}

/// A Joliet name: UCS-2 big-endian.
fn joliet_name(ident: &[u8], dir: bool) -> String {
    let units: Vec<u16> = ident
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect();
    let name = String::from_utf16_lossy(&units);
    if dir {
        name
    } else {
        strip_version(&name).to_string()
    }
}

/// A name safe to use as one path component.
fn component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "_".into()
    } else {
        cleaned
    }
}

/// What an entry's bytes come from.
enum Source {
    /// Directories have no data.
    None,
    /// Byte runs `(offset, length)` of the image, in order.
    Extents(Vec<(u64, u64)>),
    /// Text held in the directory record: a symlink's target.
    Inline(Vec<u8>),
}

/// An entry found in a directory, with the Rock Ridge fields of its record.
struct Found {
    node: Node,
    rr: RockRidge,
}

/// Rock Ridge fields by (first extent, length, date), for files of a Joliet image.
type Key = (u32, u32, [u8; 7]);

fn key_of(node: &Node) -> Option<Key> {
    node.extents
        .first()
        .map(|&(lba, len)| (lba, len, node.date))
}

fn dir_of(node: &Node) -> Option<Dir> {
    if !node.dir {
        return None;
    }
    node.extents.first().map(|&(lba, len)| Dir { lba, len })
}

/// The root directory record of a volume descriptor.
fn root_dir(vd: &[u8]) -> Result<Dir> {
    let rec = record(
        vd.get(156..190)
            .ok_or_else(|| bad("volume descriptor is short"))?,
    )?;
    if !rec.dir {
        return Err(bad("root record is not a directory"));
    }
    Ok(Dir {
        lba: rec.lba,
        len: rec.len,
    })
}

/// The tree being read: the image, what has been emitted, and the directories visited.
struct Tree {
    src: Arc<dyn ReadAt>,
    bs: u64,
    entries: Vec<Entry>,
    data: Vec<Source>,
    seen: HashSet<u32>,
    rock_ridge: bool,
}

impl Tree {
    /// The records of `dir`. Rock Ridge fields are read from the primary tree only.
    fn found(&mut self, dir: Dir, joliet: bool) -> Result<Vec<Found>> {
        let len = if dir.len == 0 {
            self.dir_len(dir.lba)?
        } else {
            dir.len
        };
        let mut out = Vec::new();
        for node in nodes(read_dir(&*self.src, self.bs, Dir { lba: dir.lba, len })?) {
            let mut rr = RockRidge::default();
            if !joliet {
                let mut st = Susp::default();
                susp(&*self.src, self.bs, &node.sys, &mut st, 0)?;
                self.rock_ridge |= st.found;
                rr = st.rr;
            }
            if rr.relocated {
                continue;
            }
            let mut node = node;
            if let Some(child) = rr.child {
                // A placeholder: the directory itself lives at `child`.
                node.dir = true;
                node.extents = vec![(child, 0)];
            }
            out.push(Found { node, rr });
        }
        Ok(out)
    }

    /// The length of the directory at `lba`, from its own "." record.
    fn dir_len(&self, lba: u32) -> Result<u32> {
        let head = read_range(&*self.src, u64::from(lba) * self.bs, self.bs as usize)?;
        let rl = usize::from(head[0]);
        let rec = record(
            head.get(..rl)
                .ok_or_else(|| bad("directory record is past its block"))?,
        )?;
        Ok(rec.len)
    }

    /// Pass one of a Joliet image: the Rock Ridge fields of every file below `dir`.
    fn gather(
        &mut self,
        dir: Dir,
        depth: usize,
        out: &mut HashMap<Key, RockRidge>,
        seen: &mut HashSet<u32>,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(bad("directories nest too deeply"));
        }
        for f in self.found(dir, false)? {
            if let Some(d) = dir_of(&f.node) {
                if seen.insert(d.lba) {
                    self.gather(d, depth + 1, out, seen)?;
                }
            } else if let Some(key) = key_of(&f.node) {
                out.entry(key).or_insert(f.rr);
            }
        }
        Ok(())
    }

    /// Lists `dir` and everything below it, naming entries from the primary tree (Rock
    /// Ridge or ISO names) or, when `joliet` is given, from the Joliet tree with Rock Ridge
    /// fields taken from the gathered map.
    fn emit_dir(
        &mut self,
        dir: Dir,
        prefix: &str,
        depth: usize,
        joliet: Option<&HashMap<Key, RockRidge>>,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(bad("directories nest too deeply"));
        }
        for f in self.found(dir, joliet.is_some())? {
            let Found { node, mut rr } = f;
            let name = match joliet {
                Some(map) => {
                    rr = if node.dir {
                        RockRidge::default()
                    } else {
                        key_of(&node)
                            .and_then(|k| map.get(&k).cloned())
                            .unwrap_or_default()
                    };
                    joliet_name(&node.ident, node.dir)
                }
                None => rr
                    .name
                    .clone()
                    .unwrap_or_else(|| iso_name(&node.ident, node.dir)),
            };
            let path = if prefix.is_empty() {
                component(&name)
            } else {
                format!("{prefix}/{}", component(&name))
            };
            if let Some(child) = dir_of(&node) {
                if !self.seen.insert(child.lba) {
                    continue;
                }
                self.emit(path.clone(), &node, &rr)?;
                self.emit_dir(child, &path, depth + 1, joliet)?;
            } else {
                self.emit(path, &node, &rr)?;
            }
        }
        Ok(())
    }

    fn emit(&mut self, path: String, node: &Node, rr: &RockRidge) -> Result<()> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(bad("too many files"));
        }
        let mode = rr.mode.map(|m| attr::UNIX_EXTENSION | ((m & 0xFFFF) << 16));
        let mut entry = Entry {
            name: path,
            is_dir: node.dir,
            mtime: rr.mtime.or_else(|| iso_time(node.date)),
            ..Default::default()
        };
        let source = if node.dir {
            entry.attrib = Some(attr::DIRECTORY | mode.unwrap_or(0));
            Source::None
        } else if let Some(target) = &rr.link {
            entry.size = Some(target.len() as u64);
            entry.attrib = mode;
            entry.link = Some(Link::Symbolic(target.clone()));
            Source::Inline(target.as_bytes().to_vec())
        } else {
            let mut runs = Vec::with_capacity(node.extents.len());
            let mut size = 0u64;
            for &(lba, len) in &node.extents {
                let off = u64::from(lba)
                    .checked_mul(self.bs)
                    .ok_or_else(|| bad("file extent is past the end of the image"))?;
                runs.push((off, u64::from(len)));
                size = size.saturating_add(u64::from(len));
            }
            entry.size = Some(size);
            entry.attrib = mode;
            Source::Extents(runs)
        };
        self.entries.push(entry);
        self.data.push(source);
        Ok(())
    }

    fn add_file(&mut self, name: String, runs: Vec<(u64, u64)>, size: u64) -> Result<()> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(bad("too many files"));
        }
        self.entries.push(Entry {
            name,
            size: Some(size),
            ..Default::default()
        });
        self.data.push(Source::Extents(runs));
        Ok(())
    }

    /// Lists the El Torito boot images of the catalog at `catalog` as `[BOOT]/Boot-<media>.img`
    /// files, as 7-Zip does. Returns whether any were found. An unreadable or unrecognized
    /// catalog is not an error for the rest of the image.
    fn boot(&mut self, catalog: u32) -> Result<bool> {
        let at = u64::from(catalog) * SECTOR;
        let Ok(cat) = read_range(&*self.src, at, SECTOR as usize) else {
            return Ok(false);
        };
        if cat[0] != 1 || cat[30..32] != [0x55, 0xAA] {
            return Ok(false);
        }
        let mut boots: Vec<(u8, u64, u64)> = Vec::new();
        for e in cat.as_chunks::<32>().0.iter().skip(1).take(CATALOG_ENTRIES) {
            if e.iter().all(|&b| b == 0) {
                break;
            }
            // Boot indicator 0x88 (bootable) or 0x00 (not). Headers (0x90, 0x91) and
            // extensions (0x44) are skipped.
            if e[0] == 0x88 || e[0] == 0x00 {
                let sectors = u64::from(u16le(e, 6).unwrap_or(0));
                let lba = u64::from(u32le(e, 8).unwrap_or(0));
                if sectors > 0 && lba > 0 {
                    boots.push((e[1], lba, sectors));
                }
            }
        }
        if boots.is_empty() {
            return Ok(false);
        }
        let mut counts = HashMap::<u8, u32>::new();
        for (media, lba, sectors) in boots {
            let n = counts.entry(media).or_insert(0);
            *n += 1;
            let base = format!("Boot-{}", media_name(media));
            let name = if *n == 1 {
                format!("[BOOT]/{base}.img")
            } else {
                format!("[BOOT]/{base}-{n}.img")
            };
            let size = sectors * 512;
            self.add_file(name, vec![(lba * SECTOR, size)], size)?;
        }
        Ok(true)
    }
}

/// An opened ISO 9660 image.
struct Iso {
    src: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
    data: Vec<Source>,
    units: Vec<Unit>,
    properties: Vec<(&'static str, String)>,
}

impl Archive for Iso {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> crate::Result<()> {
        let i = self.units[unit].entries[0];
        match &self.data[i] {
            Source::Extents(runs) => {
                let mut r = Runs::new(self.src.clone(), runs.clone());
                f(i, &mut r)?;
            }
            Source::Inline(bytes) => {
                let mut r: &[u8] = bytes;
                f(i, &mut r)?;
            }
            Source::None => {}
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.properties.clone()
    }
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let src = input.volume()?;
    // A hybrid image also carries a UDF file system; 7-Zip opens those as UDF.
    if udf::is_udf(&*src) {
        if let Ok(archive) = udf::open_udf(src.clone(), opts) {
            return Ok(archive);
        }
    }
    Ok(Box::new(open_iso(src)?))
}

fn open_iso(src: Arc<dyn ReadAt>) -> Result<Iso> {
    let desc = descriptors(&*src)?;
    let bs = u64::from(u16le(&desc.primary, 128).ok_or_else(|| bad("volume descriptor is short"))?);
    if !(MIN_BLOCK..=MAX_BLOCK).contains(&bs) || !bs.is_power_of_two() {
        return Err(bad("unsupported logical block size"));
    }
    let volume_name = String::from_utf8_lossy(&desc.primary[40..72])
        .trim_end_matches([' ', '\0'])
        .to_string();
    let primary = root_dir(&desc.primary)?;
    let joliet = desc.joliet.as_deref().map(root_dir).transpose()?;

    let mut tree = Tree {
        src: src.clone(),
        bs,
        entries: Vec::new(),
        data: Vec::new(),
        seen: HashSet::new(),
        rock_ridge: false,
    };
    match joliet {
        Some(j) => {
            let mut map = HashMap::new();
            let mut seen = HashSet::from([primary.lba]);
            tree.gather(primary, 0, &mut map, &mut seen)?;
            tree.seen.insert(j.lba);
            tree.emit_dir(j, "", 0, Some(&map))?;
        }
        None => {
            tree.seen.insert(primary.lba);
            tree.emit_dir(primary, "", 0, None)?;
        }
    }
    let el_torito = match desc.boot_catalog {
        Some(catalog) => tree.boot(catalog)?,
        None => false,
    };

    let mut properties = vec![("Volume Name", volume_name)];
    if desc.joliet.is_some() {
        properties.push(("Joliet", "Yes".into()));
    }
    if tree.rock_ridge {
        properties.push(("Rock Ridge", "Yes".into()));
    }
    if el_torito {
        properties.push(("El Torito", "Yes".into()));
    }
    let units = (0..tree.entries.len())
        .filter(|&i| !tree.entries[i].is_dir)
        .map(|i| Unit {
            entries: vec![i],
            encrypted: false,
        })
        .collect();
    Ok(Iso {
        src,
        entries: tree.entries,
        data: tree.data,
        units,
        properties,
    })
}
