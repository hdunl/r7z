//! Microsoft compiled HTML help (CHM), read-only.
//!
//! A CHM is an ITSF container: a header, a directory of fixed-size chunks, and a content
//! area ("section 0") that holds the stored files and the `::DataSpace` files describing
//! every other section. PMGL chunks list files as a name, a section number, an offset and a
//! length; PMGI chunks only index them, so the reader scans all chunks and keeps the PMGL
//! entries. Names are UTF-8 paths that start with `/`; a trailing `/` marks a directory;
//! names starting with `::` are the format's own metadata and are not listed.
//!
//! Section 0 is stored: a file's bytes sit at the content offset plus the file offset. The
//! other sections are named by `::DataSpace/NameList`. The usual one, `MSCompressed`, is a
//! single LZX stream (the CAB bitstream) cut into 32 KiB frames, with the window size and
//! the reset interval in its LZXC control data and the compressed offset of every frame in
//! its reset table. The decoder starts over at each reset interval, so intervals decode
//! independently; a file is read by decoding from the start of the interval it begins in.
//!
//! Listing follows 7-Zip: directories first, then files by section, offset and size;
//! stored files are `Copy`, compressed ones `LZX:<window bits>`, and the `Block` column
//! numbers the reset interval a file starts in. Each unit is the files that start in one reset
//! interval, which decode in one pass, so intervals decode in parallel and none is decoded twice
//! by one unit.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};
use std::ops::Range;

use super::data::Slice;
use super::{
    Archive, Columns, Ctx, Entry, EntryFn, Flow, Format, Input, OpenOptions, Signature, Unit,
};
use crate::codec::lzx::Lzx;
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "Chm",
    aliases: &["chi", "chw"],
    extensions: &["chm"],
    signatures: &[Signature::at(0, b"ITSF")],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

const ITSF_V2_LEN: usize = 0x58;
const ITSF_V3_LEN: usize = 0x60;
const ITSP_LEN: usize = 0x54;
const PMGL_HEADER: usize = 0x14;
/// Uncompressed bytes per LZX frame, which is also the reset table's block size.
const FRAME: u64 = 0x8000;
const LZX_GUID: &str = "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}";
/// A directory never has more chunks than this (4 GiB of 4 KiB chunks).
const MAX_CHUNKS: u64 = 1 << 20;
/// Entries a directory may list; each takes at least four bytes of the file, and the largest
/// help files hold a few hundred thousand.
const MAX_ITEMS: usize = 1 << 20;
/// Damage notes kept; a hostile directory could otherwise make one per chunk.
const MAX_NOTES: usize = 32;
/// Chains kept open while grouping files into units. A chain that has to close early only
/// costs a unit boundary, and the bound keeps grouping linear when files overlap.
const MAX_ACTIVE_CHAINS: usize = 64;
/// Transforms remembered per section: more than one is unsupported anyway.
const MAX_TRANSFORMS: usize = 4;

fn corrupt(what: &str) -> Error {
    Error::corrupt(format!("CHM {what}"))
}

fn truncated() -> Error {
    corrupt("data is truncated")
}

/// Bounds-checked little-endian reads.
struct Cur<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn at(d: &'a [u8], pos: usize) -> Self {
        Cur { d, pos }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(truncated)?;
        let s = self.d.get(self.pos..end).ok_or_else(truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A big-endian base-128 number: seven bits per byte, the high bit set on all but the
    /// last.
    fn encint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for _ in 0..10 {
            let b = self.take(1)?[0];
            if v >> 57 != 0 {
                return Err(corrupt("number is too large"));
            }
            v = (v << 7) | u64::from(b & 0x7F);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(corrupt("number is too long"))
    }
}

struct Header {
    /// File offset that section 0 offsets are relative to.
    data_start: u64,
    dir_start: u64,
    /// The archive size recorded in the header's section 0.
    file_size: Option<u64>,
}

fn parse_header(d: &[u8]) -> Result<Header> {
    if !FORMAT.signatures[0].matches(d) {
        return Err(Error::NotArchive);
    }
    let version = Cur::at(d, 4).u32()?;
    let len = match version {
        2 => ITSF_V2_LEN,
        3 => ITSF_V3_LEN,
        v => return Err(Error::unsupported(format!("CHM version {v}"))),
    };
    let mut c = Cur::at(d.get(..len).ok_or_else(truncated)?, 0x38);
    let (s0, s0_len) = (c.u64()?, c.u64()?);
    let (dir_start, dir_len) = (c.u64()?, c.u64()?);
    let data_start = if version >= 3 {
        c.u64()?
    } else {
        dir_start
            .checked_add(dir_len)
            .ok_or_else(|| corrupt("directory is out of range"))?
    };
    // Section 0 holds `0x1FE, 0, file size, 0, 0`.
    let file_size = usize::try_from(s0)
        .ok()
        .filter(|_| s0_len >= 16)
        .and_then(|at| Cur::at(d, at.checked_add(8)?).u64().ok());
    Ok(Header {
        data_start,
        dir_start,
        file_size,
    })
}

/// One directory entry as stored.
struct Raw {
    name: String,
    section: u64,
    offset: u64,
    len: u64,
}

/// Records damage found while opening, up to a bound.
fn note(damage: &mut Vec<String>, msg: String) {
    if damage.len() < MAX_NOTES {
        damage.push(msg);
    }
}

/// Reads the entries of every PMGL chunk. A damaged directory is an error unless `recover`
/// is set, which keeps what was read and notes the rest in `damage`.
fn read_directory(d: &[u8], at: u64, recover: bool, damage: &mut Vec<String>) -> Result<Vec<Raw>> {
    let at = usize::try_from(at)
        .ok()
        .filter(|&a| a <= d.len())
        .ok_or_else(|| corrupt("directory is past the end of the file"))?;
    if !d.get(at..).is_some_and(|r| r.starts_with(b"ITSP")) {
        return Err(corrupt("directory has no ITSP header"));
    }
    let header_len = Cur::at(d, at + 8).u32()? as usize;
    let chunk_len = Cur::at(d, at + 0x10).u32()? as usize;
    let declared = u64::from(Cur::at(d, at + 0x2C).u32()?);
    if header_len < ITSP_LEN || chunk_len < PMGL_HEADER + 2 {
        return Err(corrupt("directory header is invalid"));
    }
    if declared > MAX_CHUNKS {
        return Err(corrupt("directory has too many chunks"));
    }
    let base = at
        .checked_add(header_len)
        .filter(|&b| b <= d.len())
        .ok_or_else(truncated)?;
    let available = ((d.len() - base) / chunk_len) as u64;
    let mut count = declared;
    if declared > available {
        if !recover {
            return Err(corrupt("directory is truncated"));
        }
        note(damage, "The directory is truncated".into());
        count = available;
    }
    let mut items = Vec::new();
    for i in 0..count as usize {
        let chunk = i
            .checked_mul(chunk_len)
            .and_then(|o| base.checked_add(o))
            .and_then(|s| d.get(s..s.checked_add(chunk_len)?))
            .ok_or_else(truncated)?;
        if !chunk.starts_with(b"PMGL") {
            continue;
        }
        if let Err(e) = parse_listing(chunk, &mut items) {
            if !recover {
                return Err(e);
            }
            note(damage, format!("Listing chunk {i}: {e}"));
            if damage.len() >= MAX_NOTES {
                break;
            }
        }
    }
    Ok(items)
}

/// Appends the entries of one PMGL chunk: they fill the chunk from its header up to the
/// free space, where the quick-reference table starts.
fn parse_listing(chunk: &[u8], out: &mut Vec<Raw>) -> Result<()> {
    let free = Cur::at(chunk, 4).u32()? as usize;
    let end = chunk
        .len()
        .checked_sub(free)
        .filter(|&e| e >= PMGL_HEADER)
        .ok_or_else(|| corrupt("listing chunk has no room for entries"))?;
    let mut c = Cur::at(chunk.get(..end).ok_or_else(truncated)?, PMGL_HEADER);
    while c.pos < end {
        if out.len() >= MAX_ITEMS {
            return Err(corrupt("directory has too many entries"));
        }
        let n = usize::try_from(c.encint()?).map_err(|_| truncated())?;
        let name = c.take(n)?;
        let section = c.encint()?;
        let offset = c.encint()?;
        let len = c.encint()?;
        out.push(Raw {
            name: String::from_utf8_lossy(name).into_owned(),
            section,
            offset,
            len,
        });
    }
    Ok(())
}

/// Where a directory entry's bytes are.
#[derive(Clone, Copy)]
struct Loc {
    section: u64,
    offset: u64,
    len: u64,
}

struct Transform {
    guid: String,
    reset_table: Option<Loc>,
}

/// The `::DataSpace/Storage/<name>/` files of one section.
#[derive(Default)]
struct Storage {
    content: Option<Loc>,
    control: Option<Loc>,
    transforms: Vec<Transform>,
}

/// The `::DataSpace` entries, indexed once so each section is found without searching.
#[derive(Default)]
struct DataSpace {
    name_list: Option<Loc>,
    /// Keyed by lowercase section name.
    storage: HashMap<String, Storage>,
}

/// `s` without `prefix`, comparing ASCII case-insensitively.
fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| s.get(prefix.len()..))
        .flatten()
}

impl DataSpace {
    fn index(raws: &[Raw]) -> DataSpace {
        let mut ds = DataSpace::default();
        for r in raws {
            let Some(rest) = strip_ci(&r.name, "::DataSpace/") else {
                continue;
            };
            let loc = Loc {
                section: r.section,
                offset: r.offset,
                len: r.len,
            };
            if rest.eq_ignore_ascii_case("NameList") {
                ds.name_list = Some(loc);
                continue;
            }
            let Some((name, tail)) = strip_ci(rest, "Storage/").and_then(|s| s.split_once('/'))
            else {
                continue;
            };
            let files = ds.storage.entry(name.to_ascii_lowercase()).or_default();
            if tail.eq_ignore_ascii_case("Content") {
                files.content = Some(loc);
            } else if tail.eq_ignore_ascii_case("ControlData") {
                files.control = Some(loc);
            } else if let Some((guid, file)) =
                strip_ci(tail, "Transform/").and_then(|t| t.split_once('/'))
            {
                // `Transform/List` has no slash and is not needed: the GUIDs are named by
                // the directory entries below it.
                let known = files
                    .transforms
                    .iter()
                    .position(|t| t.guid.eq_ignore_ascii_case(guid));
                let at = match known {
                    Some(i) => i,
                    None if files.transforms.len() < MAX_TRANSFORMS => {
                        files.transforms.push(Transform {
                            guid: guid.to_string(),
                            reset_table: None,
                        });
                        files.transforms.len() - 1
                    }
                    None => continue,
                };
                if file.eq_ignore_ascii_case("InstanceData/ResetTable") {
                    files.transforms[at].reset_table = Some(loc);
                }
            }
        }
        ds
    }
}

/// The section names of `::DataSpace/NameList`: section 0 first, then 1, 2, ...
fn parse_name_list(b: &[u8]) -> Result<Vec<String>> {
    let mut c = Cur::at(b, 0);
    c.u16()?; // length in 16-bit words
    let n = c.u16()?;
    let mut names = Vec::new();
    for _ in 0..n {
        let chars = c.u16()? as usize;
        let raw = c.take(chars * 2)?;
        c.take(2)?; // NUL
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|w| u16::from_le_bytes(*w))
            .collect();
        names.push(String::from_utf16_lossy(&units));
    }
    Ok(names)
}

/// An LZX-compressed section, ready to decode.
struct LzxSection {
    window_bits: u32,
    /// Frames between decoder resets.
    interval: u64,
    /// The compressed stream in the file.
    content: Range<usize>,
    /// Uncompressed length.
    len: u64,
    /// Compressed offset of each frame, then the end of the data.
    frames: Vec<u64>,
}

impl LzxSection {
    fn interval_bytes(&self) -> u64 {
        self.interval * FRAME
    }
}

/// A section that cannot be read; its files are listed but not extracted.
enum Failure {
    Unsupported(String),
    Corrupt(String),
}

impl Failure {
    fn error(&self) -> Error {
        match self {
            Failure::Unsupported(m) => Error::Unsupported(m.clone()),
            Failure::Corrupt(m) => Error::Corrupt(m.clone()),
        }
    }
}

enum Packing {
    Stored,
    Lzx(LzxSection),
    Failed(Failure),
}

/// `(window bits, frames per reset interval)` from LZXC control data.
fn control_data(b: &[u8]) -> Result<(u32, u64)> {
    let mut c = Cur::at(b, 4);
    if c.take(4)? != b"LZXC" {
        return Err(Error::unsupported("CHM section without LZXC control data"));
    }
    let unit = match c.u32()? {
        1 => 1,
        2 => FRAME,
        v => return Err(Error::unsupported(format!("LZXC control data version {v}"))),
    };
    // Both are bytes in version 1 and 32 KiB units in version 2.
    let interval = u64::from(c.u32()?) * unit;
    let window = u64::from(c.u32()?) * unit;
    if interval == 0 || !interval.is_multiple_of(FRAME) {
        return Err(corrupt("reset interval is not a whole number of frames"));
    }
    if !window.is_power_of_two() || !(1 << 15..=1 << 21).contains(&window) {
        return Err(Error::unsupported(format!("LZX window of {window} bytes")));
    }
    Ok((window.trailing_zeros(), interval / FRAME))
}

/// `(uncompressed length, frames)` from a reset table, where `frames` lists the compressed
/// offset of each frame and ends with the compressed length.
fn reset_table(b: &[u8], content_len: usize) -> Result<(u64, Vec<u64>)> {
    let mut c = Cur::at(b, 4);
    let count = u64::from(c.u32()?);
    let entry = c.u32()? as usize;
    let table = c.u32()? as usize;
    let (len, packed, block) = (c.u64()?, c.u64()?, c.u64()?);
    if block != FRAME {
        return Err(Error::unsupported(format!(
            "CHM reset table with {block}-byte blocks"
        )));
    }
    if entry != 4 && entry != 8 {
        return Err(corrupt("reset table entries are neither 4 nor 8 bytes"));
    }
    let needed = len.div_ceil(FRAME);
    if needed > count {
        return Err(corrupt("reset table is shorter than the section"));
    }
    let raw = usize::try_from(needed)
        .ok()
        .and_then(|n| n.checked_mul(entry))
        .and_then(|n| table.checked_add(n))
        .and_then(|end| b.get(table..end))
        .ok_or_else(|| corrupt("reset table is truncated"))?;
    let mut frames: Vec<u64> = raw
        .chunks_exact(entry)
        .map(|e| {
            let mut w = [0u8; 8];
            w[..entry].copy_from_slice(e);
            u64::from_le_bytes(w)
        })
        .collect();
    frames.push(packed);
    if frames.windows(2).any(|w| w[0] > w[1]) || packed > content_len as u64 {
        return Err(corrupt("reset table offsets are out of order"));
    }
    Ok((len, frames))
}

/// Resolves sections on first use, so only the ones some file lives in are read.
struct Loader<'a> {
    d: &'a [u8],
    data_start: u64,
    names: Vec<String>,
    ds: DataSpace,
    recover: bool,
    damage: Vec<String>,
    by_section: HashMap<u64, usize>,
    list: Vec<Packing>,
}

impl Loader<'_> {
    /// The bytes of a section 0 file.
    fn stored(&self, loc: Loc) -> Option<Range<usize>> {
        if loc.section != 0 {
            return None;
        }
        let start = self.data_start.checked_add(loc.offset)?;
        let end = start.checked_add(loc.len)?;
        let r = usize::try_from(start).ok()?..usize::try_from(end).ok()?;
        self.d.get(r.clone()).map(|_| r)
    }

    fn file(&self, loc: Option<Loc>, what: &str) -> Result<Range<usize>> {
        loc.and_then(|l| self.stored(l))
            .ok_or_else(|| corrupt(&format!("{what} is missing or past the end of the file")))
    }

    /// The index in `list` of `section`'s packing.
    fn index(&mut self, section: u64) -> Result<usize> {
        if let Some(&i) = self.by_section.get(&section) {
            return Ok(i);
        }
        let packing = match self.load(section) {
            Ok(p) => p,
            Err(Error::Unsupported(m)) => Packing::Failed(Failure::Unsupported(m)),
            Err(e) if self.recover => {
                note(&mut self.damage, e.to_string());
                let m = match e {
                    Error::Corrupt(m) => m,
                    other => other.to_string(),
                };
                Packing::Failed(Failure::Corrupt(m))
            }
            Err(e) => return Err(e),
        };
        self.list.push(packing);
        self.by_section.insert(section, self.list.len() - 1);
        Ok(self.list.len() - 1)
    }

    fn load(&self, section: u64) -> Result<Packing> {
        if section == 0 {
            return Ok(Packing::Stored);
        }
        let name = usize::try_from(section)
            .ok()
            .and_then(|s| self.names.get(s))
            .ok_or_else(|| Error::unsupported(format!("CHM section {section} has no name")))?;
        let files = self
            .ds
            .storage
            .get(&name.to_ascii_lowercase())
            .ok_or_else(|| corrupt(&format!("section {name} has no storage")))?;
        let [transform] = files.transforms.as_slice() else {
            return Err(Error::unsupported(format!(
                "CHM section {name} with {} transforms",
                files.transforms.len()
            )));
        };
        if !transform.guid.eq_ignore_ascii_case(LZX_GUID) {
            return Err(Error::unsupported(format!(
                "CHM transform {}",
                transform.guid
            )));
        }
        let control = self.file(files.control, "control data")?;
        let (window_bits, interval) = control_data(self.d.get(control).unwrap_or_default())?;
        let content = self.file(files.content, "compressed content")?;
        let table = self.file(transform.reset_table, "reset table")?;
        let (len, frames) = reset_table(self.d.get(table).unwrap_or_default(), content.len())?;
        Ok(Packing::Lzx(LzxSection {
            window_bits,
            interval,
            content,
            len,
            frames,
        }))
    }
}

/// A user-visible directory entry.
struct Item {
    raw: usize,
    name: String,
    is_dir: bool,
}

/// The entries 7-Zip lists: names that start with `/` and name something besides the root.
fn user_items(raws: &[Raw]) -> Vec<Item> {
    raws.iter()
        .enumerate()
        .filter_map(|(raw, r)| {
            let rest = r.name.strip_prefix('/')?;
            let name = rest.trim_end_matches('/');
            (!name.is_empty()).then(|| Item {
                raw,
                name: name.to_string(),
                is_dir: rest.ends_with('/'),
            })
        })
        .collect()
}

/// Files that start in the same reset interval, decoded in one pass.
struct Chain {
    entries: Vec<usize>,
    /// Where the next file may start without overlapping the last one.
    end: u64,
}

/// Splits the files of one compressed section (in offset order) into chains: the files that
/// start in one reset interval make a chain, which decodes that interval and any later
/// ones its last file runs into. Chains of different intervals are independent, so they
/// can decode in parallel, and no byte is decoded twice by one chain; a file that
/// straddles an interval boundary only has its tail decoded again by the next chain. Files
/// that overlap an earlier one in the same interval need a chain of their own.
fn chains(files: &[usize], offsets: &[u64], entries: &[Entry], interval_bytes: u64) -> Vec<Chain> {
    let mut active: Vec<Chain> = Vec::new();
    let mut done: Vec<Chain> = Vec::new();
    let mut interval = u64::MAX;
    for &e in files {
        let (off, size) = (offsets[e], entries[e].size_or_zero());
        if off / interval_bytes != interval {
            interval = off / interval_bytes;
            done.append(&mut active);
        }
        let end = off.saturating_add(size);
        match active.iter_mut().find(|c| c.end <= off) {
            Some(c) => {
                c.entries.push(e);
                c.end = end;
            }
            None => {
                if active.len() >= MAX_ACTIVE_CHAINS {
                    done.push(active.remove(0));
                }
                active.push(Chain {
                    entries: vec![e],
                    end,
                });
            }
        }
    }
    done.extend(active);
    done.sort_by_key(|c| c.entries[0]);
    done
}

pub struct Chm {
    data: Slice,
    data_start: u64,
    physical: u64,
    entries: Vec<Entry>,
    /// Each entry's offset inside its section.
    offsets: Vec<u64>,
    units: Vec<Unit>,
    /// The index in `sections` of each unit's section.
    sources: Vec<usize>,
    sections: Vec<Packing>,
    damage: Vec<String>,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    Ok(Box::new(Chm::parse(input.into_mem()?, opts.recover)?))
}

impl Chm {
    fn parse(data: Slice, recover: bool) -> Result<Chm> {
        let d: &[u8] = &data;
        let head = parse_header(d)?;
        let mut damage = Vec::new();
        let raws = read_directory(d, head.dir_start, recover, &mut damage)?;
        let ds = DataSpace::index(&raws);
        let mut loader = Loader {
            d,
            data_start: head.data_start,
            names: Vec::new(),
            ds,
            recover,
            damage,
            by_section: HashMap::new(),
            list: Vec::new(),
        };
        if let Some(loc) = loader.ds.name_list {
            let parsed = loader
                .file(Some(loc), "section name list")
                .and_then(|r| parse_name_list(d.get(r).unwrap_or_default()));
            match parsed {
                Ok(names) => loader.names = names,
                Err(e) if recover => note(&mut loader.damage, e.to_string()),
                Err(e) => return Err(e),
            }
        }

        // 7-Zip's order: directories first, then by section, offset and size.
        let mut items = user_items(&raws);
        items.sort_by_key(|it| {
            let r = &raws[it.raw];
            (!it.is_dir, r.section, r.offset, r.len, it.raw)
        });
        let mut entries = Vec::with_capacity(items.len());
        let mut offsets = Vec::with_capacity(items.len());
        let mut packing_of: Vec<Option<usize>> = Vec::with_capacity(items.len());
        for it in &items {
            let r = &raws[it.raw];
            if it.is_dir {
                entries.push(Entry {
                    name: it.name.clone(),
                    is_dir: true,
                    size: Some(0),
                    ..Default::default()
                });
                offsets.push(0);
                packing_of.push(None);
                continue;
            }
            let p = loader.index(r.section)?;
            let (method, block) = match &loader.list[p] {
                Packing::Stored => (Some("Copy".to_string()), None),
                Packing::Lzx(s) => (
                    Some(format!("LZX:{}", s.window_bits)),
                    Some(usize::try_from(r.offset / s.interval_bytes()).unwrap_or(usize::MAX)),
                ),
                Packing::Failed(_) => (None, None),
            };
            entries.push(Entry {
                name: it.name.clone(),
                size: Some(r.len),
                method,
                block,
                ..Default::default()
            });
            offsets.push(r.offset);
            packing_of.push(Some(p));
        }
        let Loader { list, damage, .. } = loader;

        let (units, sources) = plan_units(&entries, &offsets, &packing_of, &list);
        let physical = head
            .file_size
            .filter(|&s| s > 0 && s <= d.len() as u64)
            .unwrap_or(d.len() as u64);
        Ok(Chm {
            data_start: head.data_start,
            physical,
            entries,
            offsets,
            units,
            sources,
            sections: list,
            damage,
            data,
        })
    }

    fn extract_stored(&self, unit: usize, f: &mut EntryFn<'_>) -> Result<()> {
        for &i in &self.units[unit].entries {
            let size = self.entries[i].size_or_zero();
            let bytes = self
                .data_start
                .checked_add(self.offsets[i])
                .and_then(|s| Some(s..s.checked_add(size)?))
                .and_then(|r| Some(usize::try_from(r.start).ok()?..usize::try_from(r.end).ok()?))
                .and_then(|r| self.data.get(r))
                .ok_or_else(|| corrupt("file data is past the end of the archive"))?;
            let mut r = bytes;
            if f(i, &mut r)? == Flow::Stop {
                break;
            }
        }
        Ok(())
    }

    fn extract_lzx(&self, unit: usize, sec: &LzxSection, f: &mut EntryFn<'_>) -> Result<()> {
        let mut r = FrameReader::new(sec, &self.data)?;
        for &i in &self.units[unit].entries {
            let (off, size) = (self.offsets[i], self.entries[i].size_or_zero());
            r.skip_to(off)?;
            let mut take = (&mut r).take(size);
            if f(i, &mut take)? == Flow::Stop {
                return Ok(());
            }
            r.skip_to(off.saturating_add(size))?;
        }
        Ok(())
    }
}

/// Groups the files into units: stored files one each, files of a compressed section into
/// chains, files of an unreadable section into one unit that reports its error. Empty files
/// need no unit.
fn plan_units(
    entries: &[Entry],
    offsets: &[u64],
    packing_of: &[Option<usize>],
    sections: &[Packing],
) -> (Vec<Unit>, Vec<usize>) {
    let mut by_packing: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, p) in packing_of.iter().enumerate() {
        if let Some(p) = *p {
            if entries[i].size_or_zero() > 0 {
                by_packing.entry(p).or_default().push(i);
            }
        }
    }
    let unit = |entries: Vec<usize>| Unit {
        entries,
        encrypted: false,
    };
    let (mut units, mut sources) = (Vec::new(), Vec::new());
    for (p, files) in by_packing {
        match &sections[p] {
            Packing::Stored => {
                for i in files {
                    units.push(unit(vec![i]));
                    sources.push(p);
                }
            }
            Packing::Lzx(s) => {
                for c in chains(&files, offsets, entries, s.interval_bytes()) {
                    units.push(unit(c.entries));
                    sources.push(p);
                }
            }
            Packing::Failed(_) => {
                units.push(unit(files));
                sources.push(p);
            }
        }
    }
    (units, sources)
}

/// Decodes a compressed section front to back, one frame at a time. A new decoder starts
/// at every reset interval.
struct FrameReader<'a> {
    sec: &'a LzxSection,
    content: &'a [u8],
    lzx: Option<Box<Lzx>>,
    /// The next frame to decode.
    next: u64,
    /// The last decoded frame and the read position in it.
    out: Vec<u8>,
    pos: usize,
    /// Uncompressed offset of `out[0]`.
    base: u64,
}

impl<'a> FrameReader<'a> {
    fn new(sec: &'a LzxSection, data: &'a [u8]) -> Result<Self> {
        let content = data
            .get(sec.content.clone())
            .ok_or_else(|| corrupt("compressed data is past the end of the archive"))?;
        Ok(FrameReader {
            sec,
            content,
            lzx: None,
            next: 0,
            out: Vec::new(),
            pos: 0,
            base: 0,
        })
    }

    fn position(&self) -> u64 {
        self.base + self.pos as u64
    }

    /// The compressed bytes of frame `k`.
    fn packed(&self, k: u64) -> Result<&'a [u8]> {
        let at = usize::try_from(k)
            .ok()
            .filter(|&k| k + 1 < self.sec.frames.len());
        at.and_then(|k| {
            let s = usize::try_from(self.sec.frames[k]).ok()?;
            let e = usize::try_from(self.sec.frames[k + 1]).ok()?;
            self.content.get(s..e)
        })
        .ok_or_else(|| corrupt("compressed data ends early"))
    }

    /// Decodes frame `i` of `size` bytes with the interval's decoder, starting one at the
    /// interval's first frame.
    fn decode_frame(&mut self, i: u64, size: usize) -> Result<()> {
        let packed = self.packed(i)?;
        if i.is_multiple_of(self.sec.interval) {
            self.lzx = None;
        }
        let lzx = match &mut self.lzx {
            Some(l) => l,
            none => none.insert(Box::new(Lzx::new(self.sec.window_bits)?)),
        };
        lzx.decode_frame(packed, size, &mut self.out)
    }

    /// Starts a decoder over again and runs it through the frames of frame `i`'s interval
    /// that come before it.
    fn replay_interval(&mut self, i: u64) -> Result<()> {
        let first = i / self.sec.interval * self.sec.interval;
        for k in first..i {
            self.decode_frame(k, FRAME as usize)?;
        }
        Ok(())
    }

    fn decode_next(&mut self) -> Result<()> {
        let i = self.next;
        self.packed(i)?;
        let size = (self.sec.len - i * FRAME).min(FRAME) as usize;
        if size < FRAME as usize {
            // Microsoft's compressor codes the last frame as a whole 32 KiB, zero padded,
            // and its last match may run into the padding, which the decoder rejects when
            // it is asked for the true size. Other encoders stop at the true size, so try
            // that when the whole frame fails; the failed attempt spoiled the decoder, so
            // rebuild it.
            if self.decode_frame(i, FRAME as usize).is_err() {
                self.lzx = None;
                self.replay_interval(i)?;
                self.decode_frame(i, size)?;
            }
            self.out.truncate(size);
        } else {
            self.decode_frame(i, size)?;
        }
        if self.out.is_empty() {
            return Err(corrupt("compressed data ends early"));
        }
        self.base = i * FRAME;
        self.pos = 0;
        self.next = i + 1;
        Ok(())
    }

    /// Moves forward to uncompressed offset `target`, decoding only the frames of its reset
    /// interval that come before it.
    fn skip_to(&mut self, target: u64) -> Result<()> {
        if target < self.position() {
            return Err(corrupt("files overlap"));
        }
        let interval_start = target / FRAME / self.sec.interval * self.sec.interval;
        if interval_start > self.next {
            self.next = interval_start;
            self.out.clear();
            self.pos = 0;
            self.base = interval_start * FRAME;
        }
        while self.position() < target {
            if self.pos >= self.out.len() {
                self.decode_next()?;
                continue;
            }
            let n = ((self.out.len() - self.pos) as u64).min(target - self.position());
            self.pos += n as usize;
        }
        Ok(())
    }
}

impl Read for FrameReader<'_> {
    /// Fails, rather than returning 0, when the section ends: callers only read bytes that
    /// a file claims.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.out.len() {
            self.decode_next().map_err(Error::into_io)?;
        }
        let n = (self.out.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Archive for Chm {
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
        match &self.sections[self.sources[unit]] {
            Packing::Stored => self.extract_stored(unit, f),
            Packing::Lzx(s) => self.extract_lzx(unit, s, f),
            Packing::Failed(x) => Err(x.error()),
        }
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        vec![("Physical Size", self.physical.to_string())]
    }

    fn columns(&self) -> Columns {
        Columns {
            crc: false,
            method: true,
            encrypted: false,
            block: true,
        }
    }

    fn damage(&self) -> Vec<String> {
        self.damage.clone()
    }
}
