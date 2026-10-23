//! Compound File Binary (OLE storage), read-only: Windows Installer `.msi`/`.msp`/`.msm`
//! packages and the storages of older Office files.
//!
//! A file is a header sector followed by equal-sized sectors. The FAT (whose sectors the
//! header and the DIFAT chain list) links sectors into chains; the directory is one such
//! chain of 128-byte entries forming a tree of storages (folders) and streams (files). A
//! stream shorter than the header's cutoff (4096) lives in the mini stream instead: the
//! root entry's own chain, cut into 64-byte mini sectors that the mini FAT links.
//!
//! The listing follows 7-Zip: the root storage's entries sit at the top level, storages are
//! folders, and each entry is followed by its left subtree, its right subtree and then (for
//! a storage) its own children. Names are UTF-16. Windows Installer packs a name that
//! consists only of code units in `U+3800..=U+4840` into one unit per two characters (see
//! `decode_name`); other names are literal, with control characters shown as `[N]`.
//!
//! An MSI package that keeps exactly one `.cab` stream (and no `.exe` one) opens the
//! cabinet as a nested archive, the way 7-Zip lists such a package: [`Archive::main_entry`]
//! names the stream and the generic open path hands it to the CAB reader. Opening the file
//! as exactly this type (`-tcompound`) lists the packaging streams instead.
//!
//! Every count, size and sector number in the file is untrusted. Chains are followed with
//! a step budget of the file's sector count, tables are read straight from the mapped
//! file, the entry count and name bytes are capped, and a damaged structure shortens the
//! listing (and is reported as a property) instead of failing the open where it can.

use std::io::{self, Read};
use std::ops::Range;
use std::sync::Arc;

use super::data::{BoxRead, Input, Opener, Slice};
use super::{Archive, Ctx, Entry, EntryFn, Flow, Format, OpenOptions, Signature, Unit};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "Compound",
    aliases: &["msi", "msp", "msm"],
    extensions: &["msi", "msp", "msm"],
    signatures: &[Signature::at(0, &SIGNATURE)],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const HEADER_LEN: usize = 512;
const ENTRY_LEN: usize = 128;
/// Sector numbers from here up are markers, not sectors.
const MAX_REG_SECT: u32 = 0xFFFF_FFFA;
const FREE_SECT: u32 = 0xFFFF_FFFF;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const NO_STREAM: u32 = 0xFFFF_FFFF;
/// Directory entries examined; real packages have a few thousand.
const MAX_ENTRIES: usize = 1 << 20;
/// Storage nesting followed; Office files and patches use one or two levels.
const MAX_DEPTH: usize = 32;
/// Bytes of entry names kept, so a deep tree cannot multiply its directory in memory.
const MAX_NAME_BYTES: usize = 64 << 20;
/// Most bytes one `read` call takes from a run of consecutive sectors.
const MAX_RUN: u64 = 1 << 20;

const KIND_STORAGE: u8 = 1;
const KIND_STREAM: u8 = 2;
const KIND_ROOT: u8 = 5;

// ---------------------------------------------------------------------------------------
// Names

/// Windows Installer's 64-character alphabet for compressed stream names.
const MSI_CHARS: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
const MSI_FIRST: u16 = 0x3800;
/// The table prefix, shown as `!`.
const MSI_TABLE: u16 = 0x4840;
/// First unit that stands for one character instead of two.
const MSI_SINGLE: u16 = 0x4800;

fn msi_char(i: usize) -> char {
    MSI_CHARS.get(i).map_or('_', |&b| char::from(b))
}

/// A stream name as 7-Zip shows it, and whether it was Windows Installer packed.
///
/// A name made only of units in `U+3800..=U+4840` is packed: a unit below `U+4800` holds
/// two alphabet indexes (the low six bits of `unit - 0x3800` first), a unit up to `U+483F`
/// one, and `U+4840` stands for `!`. One unit outside that range makes the whole name
/// literal. Literal names keep their text, with each control character (below `U+20`)
/// written as its decimal value in brackets (`\u{5}SummaryInformation` is
/// `[5]SummaryInformation`).
fn decode_name(units: &[u16]) -> (String, bool) {
    let packed = !units.is_empty() && units.iter().all(|u| (MSI_FIRST..=MSI_TABLE).contains(u));
    let mut s = String::with_capacity(units.len() * 2);
    if packed {
        for &u in units {
            if u == MSI_TABLE {
                s.push('!');
            } else if u >= MSI_SINGLE {
                s.push(msi_char(usize::from(u - MSI_SINGLE)));
            } else {
                let v = usize::from(u - MSI_FIRST);
                s.push(msi_char(v & 63));
                s.push(msi_char(v >> 6));
            }
        }
        return (s, true);
    }
    for c in char::decode_utf16(units.iter().copied()) {
        match c {
            Ok(c) if u32::from(c) < 0x20 => s.push_str(&format!("[{}]", u32::from(c))),
            Ok(c) => s.push(c),
            Err(_) => s.push(char::REPLACEMENT_CHARACTER),
        }
    }
    (s, false)
}

// ---------------------------------------------------------------------------------------
// Bounds-checked little-endian reads

fn le<const N: usize>(d: &[u8], at: usize) -> Option<[u8; N]> {
    d.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn le16(d: &[u8], at: usize) -> u16 {
    le::<2>(d, at).map_or(0, u16::from_le_bytes)
}

fn le32(d: &[u8], at: usize) -> u32 {
    le::<4>(d, at).map_or(0, u32::from_le_bytes)
}

fn le64(d: &[u8], at: usize) -> u64 {
    le::<8>(d, at).map_or(0, u64::from_le_bytes)
}

// ---------------------------------------------------------------------------------------
// Header

struct Header {
    major: u16,
    shift: u32,
    mini_shift: u32,
    cutoff: u32,
    n_fat: u32,
    dir_start: u32,
    mini_fat_start: u32,
    n_mini_fat: u32,
    difat_start: u32,
    n_difat: u32,
    /// The first 109 FAT sector numbers.
    difat: Vec<u32>,
}

impl Header {
    fn parse(d: &[u8]) -> Result<Header> {
        if !d.starts_with(&SIGNATURE) {
            return Err(Error::NotArchive);
        }
        if d.len() < HEADER_LEN {
            return Err(Error::corrupt("Compound File header is truncated"));
        }
        if le16(d, 28) != 0xFFFE {
            return Err(Error::corrupt(
                "Compound File byte order is not little-endian",
            ));
        }
        let major = le16(d, 26);
        let shift = u32::from(le16(d, 30));
        if !matches!(major, 3 | 4) || !matches!(shift, 9 | 12) {
            return Err(Error::unsupported(format!(
                "Compound File version {major} with sector shift {shift}"
            )));
        }
        let mini_shift = u32::from(le16(d, 32));
        if !(2..=shift).contains(&mini_shift) {
            return Err(Error::corrupt("Compound File mini sector size is invalid"));
        }
        Ok(Header {
            major,
            shift,
            mini_shift,
            n_fat: le32(d, 44),
            dir_start: le32(d, 48),
            cutoff: le32(d, 56),
            mini_fat_start: le32(d, 60),
            n_mini_fat: le32(d, 64),
            difat_start: le32(d, 68),
            n_difat: le32(d, 72),
            difat: (0..109).map(|i| le32(d, 76 + 4 * i)).collect(),
        })
    }
}

// ---------------------------------------------------------------------------------------
// Sector access

/// How a sector chain ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChainEnd {
    /// Reached the end-of-chain marker.
    Terminated,
    /// Collected as many sectors as were wanted.
    Enough,
    /// A free or out-of-range link, or a file too short for the FAT.
    Broken,
}

/// The file's sector tables and the mapped bytes they point into.
struct Core {
    data: Slice,
    shift: u32,
    mini_shift: u32,
    /// Streams smaller than this are in the mini stream.
    cutoff: u64,
    /// Sectors that hold the FAT, in order.
    fat: Vec<u32>,
    /// Sectors that hold the mini FAT, in order.
    mini_fat: Vec<u32>,
    /// Sectors that hold the mini stream, in order.
    mini_stream: Vec<u32>,
    /// Bytes of the mini stream that its chain covers.
    mini_len: u64,
    /// Sector slots after the header that the file can hold (a cut-off last one counts):
    /// no valid chain is longer.
    total: u64,
}

impl Core {
    fn sector_size(&self) -> u64 {
        1 << self.shift
    }

    /// Where sector `s` is in the file, cut short where the file ends.
    fn sector_range(&self, s: u32) -> Option<Range<usize>> {
        let start = (u64::from(s) + 1) << self.shift;
        let len = self.data.len() as u64;
        if start >= len {
            return None;
        }
        let end = (start + self.sector_size()).min(len);
        Some(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
    }

    fn sector(&self, s: u32) -> Option<&[u8]> {
        self.data.get(self.sector_range(s)?)
    }

    /// Entry `i` of a table stored in `sectors` (the FAT or the mini FAT).
    fn table_entry(&self, sectors: &[u32], i: u32) -> Option<u32> {
        let per = (self.sector_size() / 4) as usize;
        let sector = *sectors.get(i as usize / per)?;
        le::<4>(self.sector(sector)?, (i as usize % per) * 4).map(u32::from_le_bytes)
    }

    fn fat_entry(&self, s: u32) -> Option<u32> {
        self.table_entry(&self.fat, s)
    }

    fn mini_fat_entry(&self, m: u32) -> Option<u32> {
        self.table_entry(&self.mini_fat, m)
    }

    /// Up to `want` sectors of the chain starting at `start`.
    fn chain(&self, start: u32, want: u64) -> (Vec<u32>, ChainEnd) {
        let want = want.min(self.total);
        let mut out = Vec::new();
        let mut s = start;
        while (out.len() as u64) < want {
            if s >= MAX_REG_SECT {
                let end = if s == END_OF_CHAIN {
                    ChainEnd::Terminated
                } else {
                    ChainEnd::Broken
                };
                return (out, end);
            }
            out.push(s);
            s = self.fat_entry(s).unwrap_or(FREE_SECT);
        }
        (out, ChainEnd::Enough)
    }
}

/// Sectors the FAT accounts for: one past the last sector it marks as used.
fn extent(core: &Core) -> u64 {
    let per = core.sector_size() / 4;
    for (k, &s) in core.fat.iter().enumerate().rev() {
        let Some(sector) = core.sector(s) else {
            continue;
        };
        for j in (0..per).rev() {
            if le::<4>(sector, (j * 4) as usize).is_some_and(|b| u32::from_le_bytes(b) != FREE_SECT)
            {
                return k as u64 * per + j + 1;
            }
        }
    }
    0
}

/// The FAT sector numbers: the header's list, then the DIFAT chain.
fn fat_sectors(core: &Core, h: &Header) -> Vec<u32> {
    // A file cannot hold more FAT sectors than it has sectors.
    let cap = u64::from(h.n_fat).min(core.total) as usize;
    let mut out: Vec<u32> = h
        .difat
        .iter()
        .copied()
        .filter(|&s| s < MAX_REG_SECT)
        .take(cap)
        .collect();
    let per = (core.sector_size() / 4) as usize;
    let mut next = h.difat_start;
    let mut steps = u64::from(h.n_difat).min(core.total);
    while steps > 0 && out.len() < cap && next < MAX_REG_SECT {
        let Some(sector) = core.sector(next) else {
            break;
        };
        for i in 0..per - 1 {
            let s = le32(sector, i * 4);
            if s < MAX_REG_SECT && out.len() < cap {
                out.push(s);
            }
        }
        next = le32(sector, (per - 1) * 4);
        steps -= 1;
    }
    out
}

// ---------------------------------------------------------------------------------------
// Directory

/// One 128-byte directory entry.
#[derive(Clone, Copy)]
struct Dirent<'a>(&'a [u8]);

impl Dirent<'_> {
    fn kind(&self) -> u8 {
        self.0.get(66).copied().unwrap_or(0)
    }

    fn left(&self) -> u32 {
        le32(self.0, 68)
    }

    fn right(&self) -> u32 {
        le32(self.0, 72)
    }

    fn child(&self) -> u32 {
        le32(self.0, 76)
    }

    fn ctime(&self) -> u64 {
        le64(self.0, 100)
    }

    fn mtime(&self) -> u64 {
        le64(self.0, 108)
    }

    fn start(&self) -> u32 {
        le32(self.0, 116)
    }

    fn size(&self) -> u64 {
        le64(self.0, 120)
    }

    /// The name's UTF-16 units up to the first NUL (at most 32), whatever the length field
    /// says.
    fn name(&self) -> Vec<u16> {
        self.0
            .get(..64)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect()
    }
}

struct Dir {
    bytes: Vec<u8>,
}

impl Dir {
    fn count(&self) -> usize {
        self.bytes.len() / ENTRY_LEN
    }

    fn entry(&self, i: u32) -> Option<Dirent<'_>> {
        let at = (i as usize).checked_mul(ENTRY_LEN)?;
        self.bytes.get(at..at + ENTRY_LEN).map(Dirent)
    }
}

/// Where an entry's bytes start and how many there are.
#[derive(Clone, Copy)]
struct Source {
    start: u32,
    size: u64,
}

/// What walking the directory tree found.
#[derive(Default)]
struct Listing {
    entries: Vec<Entry>,
    sources: Vec<Source>,
    /// Packed `.cab` and `.exe` streams: a package with exactly one cab and no exe has a
    /// main entry.
    cabs: usize,
    exes: usize,
    cab: usize,
    /// Reasons the tree is shorter than the directory.
    notes: Vec<&'static str>,
}

impl Listing {
    fn note(&mut self, why: &'static str) {
        if !self.notes.contains(&why) {
            self.notes.push(why);
        }
    }
}

/// The extension 7-Zip reports for the file, from the first directory entry (by number,
/// listed or not) that names a patch or an Office document; failing that, `msi` when any
/// name is packed, else `compound`.
fn extension(dir: &Dir) -> &'static str {
    let mut packed_any = false;
    for e in (1..dir.count()).filter_map(|i| dir.entry(i as u32)) {
        let (name, packed) = decode_name(&e.name());
        if packed {
            packed_any = true;
            if name == "!MsiPatchMetadata" {
                return "msp";
            }
        } else {
            match name.as_str() {
                "WordDocument" => return "doc",
                "Workbook" => return "xls",
                "PowerPoint Document" => return "ppt",
                _ => {}
            }
        }
    }
    if packed_any {
        "msi"
    } else {
        "compound"
    }
}

/// What 7-Zip calls an entry with no name: the archive's name without its extension.
fn unnamed(archive: &str) -> String {
    let base = archive.rsplit(['/', '\\']).next().unwrap_or(archive);
    let stem = base.rsplit_once('.').map_or(base, |(stem, _)| stem);
    if stem.is_empty() {
        "[no name]".into()
    } else {
        stem.into()
    }
}

/// Lists the tree below the root: each entry, then its left subtree, its right subtree and
/// (for a storage) its children, iteratively and visiting every directory entry once.
fn walk(dir: &Dir, h: &Header, unnamed: &str) -> Listing {
    let mut out = Listing::default();
    let Some(root) = dir.entry(0) else {
        return out;
    };
    let mut seen = vec![false; dir.count()];
    if let Some(s) = seen.first_mut() {
        *s = true;
    }
    let mut depths: Vec<usize> = Vec::new();
    let mut name_bytes = 0usize;
    // (directory entry, listed parent)
    let mut stack: Vec<(u32, Option<usize>)> = vec![(root.child(), None)];
    while let Some((did, parent)) = stack.pop() {
        if did == NO_STREAM {
            continue;
        }
        let (Some(e), Some(done)) = (dir.entry(did), seen.get_mut(did as usize)) else {
            out.note("directory entry number is out of range");
            continue;
        };
        if std::mem::replace(done, true) {
            out.note("directory tree has a loop");
            continue;
        }
        let is_dir = match e.kind() {
            KIND_STORAGE | KIND_ROOT => true,
            KIND_STREAM => false,
            _ => continue,
        };
        let depth = parent.and_then(|p| depths.get(p)).map_or(0, |d| d + 1);
        if depth >= MAX_DEPTH {
            out.note("storages are nested too deeply");
            continue;
        }
        if out.entries.len() >= MAX_ENTRIES || name_bytes >= MAX_NAME_BYTES {
            out.note("directory has too many entries");
            break;
        }
        let index = out.entries.len();
        let (mut leaf, packed) = decode_name(&e.name());
        if leaf.is_empty() {
            leaf = unnamed.into();
        }
        if packed && !is_dir {
            let lower = leaf.to_ascii_lowercase();
            if lower.ends_with(".cab") {
                out.cabs += 1;
                out.cab = index;
            } else if lower.ends_with(".exe") {
                out.exes += 1;
            }
        }
        let name = match parent.and_then(|p| out.entries.get(p)) {
            Some(p) => format!("{}/{leaf}", p.name),
            None => leaf,
        };
        name_bytes += name.len();

        let size = if h.major == 3 {
            e.size() & 0xFFFF_FFFF
        } else {
            e.size()
        };
        let filetime = |t: u64| (t != 0).then_some(t);
        let mut entry = Entry {
            name,
            is_dir,
            ctime: filetime(e.ctime()),
            mtime: filetime(e.mtime()),
            ..Default::default()
        };
        if !is_dir {
            // 7-Zip's Packed Size: the sectors the stream occupies.
            let unit = if size < u64::from(h.cutoff) {
                1u64 << h.mini_shift
            } else {
                1u64 << h.shift
            };
            entry.size = Some(size);
            entry.packed_size = Some(size.div_ceil(unit).saturating_mul(unit));
        }
        out.entries.push(entry);
        out.sources.push(Source {
            start: e.start(),
            size: if is_dir { 0 } else { size },
        });
        depths.push(depth);
        if is_dir {
            stack.push((e.child(), Some(index)));
        }
        stack.push((e.right(), parent));
        stack.push((e.left(), parent));
    }
    out
}

// ---------------------------------------------------------------------------------------
// Opening

pub struct Cfb {
    core: Arc<Core>,
    entries: Vec<Entry>,
    sources: Vec<Source>,
    units: Vec<Unit>,
    main: Option<usize>,
    props: Vec<(&'static str, String)>,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    Ok(Box::new(Cfb::parse(input.into_mem()?, &opts.name)?))
}

impl Cfb {
    fn parse(data: Slice, archive_name: &str) -> Result<Cfb> {
        let h = Header::parse(&data)?;
        let len = data.len() as u64;
        let sector = 1u64 << h.shift;
        let mut core = Core {
            data,
            shift: h.shift,
            mini_shift: h.mini_shift,
            cutoff: u64::from(h.cutoff),
            fat: Vec::new(),
            mini_fat: Vec::new(),
            mini_stream: Vec::new(),
            mini_len: 0,
            total: len.saturating_sub(sector).div_ceil(sector),
        };
        core.fat = fat_sectors(&core, &h);
        if core.fat.is_empty() {
            return Err(Error::corrupt("Compound File has no FAT"));
        }

        // The directory chain, read into one buffer (at most the file's own size).
        let (sectors, end) = core.chain(h.dir_start, core.total);
        let mut bytes = Vec::new();
        for &s in &sectors {
            match core.sector(s) {
                Some(b) if bytes.len() < MAX_ENTRIES * ENTRY_LEN => bytes.extend_from_slice(b),
                _ => break,
            }
        }
        bytes.truncate(bytes.len() / ENTRY_LEN * ENTRY_LEN);
        let dir = Dir { bytes };
        let root = match dir.entry(0) {
            Some(r) if r.kind() == KIND_ROOT => r,
            _ => return Err(Error::corrupt("Compound File has no root storage")),
        };

        let size_of = |e: &Dirent| {
            if h.major == 3 {
                e.size() & 0xFFFF_FFFF
            } else {
                e.size()
            }
        };
        let (stream, _) = core.chain(root.start(), size_of(&root).div_ceil(sector));
        core.mini_len = size_of(&root).min(stream.len() as u64 * sector);
        core.mini_stream = stream;
        core.mini_fat = core.chain(h.mini_fat_start, u64::from(h.n_mini_fat)).0;

        let mut listing = walk(&dir, &h, &unnamed(archive_name));
        if end == ChainEnd::Broken
            || (end == ChainEnd::Enough && sectors.len() as u64 >= core.total)
        {
            listing.note("directory chain is damaged");
        }

        // The header sector and the sectors the FAT accounts for are the archive proper;
        // what the file has beyond that is a tail, and less is a truncation.
        let physical = extent(&core).saturating_add(1).saturating_mul(sector);

        let units = listing
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_dir && e.size_or_zero() > 0)
            .map(|(i, _)| Unit {
                entries: vec![i],
                encrypted: false,
            })
            .collect();
        let main = (listing.cabs == 1 && listing.exes == 0).then_some(listing.cab);

        let mut props: Vec<(&'static str, String)> = Vec::new();
        if len < physical {
            props.push(("ERROR", "Unexpected end of archive".into()));
        } else if len > physical {
            props.push(("Warning", "There are data after the end of archive".into()));
        }
        for why in &listing.notes {
            props.push(("Warning", (*why).into()));
        }
        props.push(("Physical Size", physical.to_string()));
        if len > physical {
            props.push(("Tail Size", (len - physical).to_string()));
        }
        props.push(("Extension", extension(&dir).into()));
        props.push(("Cluster Size", sector.to_string()));
        props.push(("Sector Size", (1u64 << h.mini_shift).to_string()));

        Ok(Cfb {
            core: Arc::new(core),
            entries: listing.entries,
            sources: listing.sources,
            units,
            main,
            props,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Stream data

/// Reads one stream by following its sector chain (the FAT, or the mini FAT inside the
/// mini stream), delivering exactly the declared size or failing where the data stops.
struct StreamReader {
    core: Arc<Core>,
    mini: bool,
    /// Next sector (or mini sector) of the chain.
    next: u32,
    remaining: u64,
    /// Sectors this stream may still use: a chain cannot outgrow the file.
    budget: u64,
    /// Brent's cycle detection over the sectors visited: the sector at the last
    /// power-of-two step, how many steps since, and the current power.
    tortoise: u32,
    steps: u64,
    power: u64,
    /// Unread bytes of the current run of sectors.
    cur: Range<usize>,
}

impl StreamReader {
    fn new(core: Arc<Core>, src: Source) -> StreamReader {
        let mini = src.size < core.cutoff;
        let budget = if mini {
            core.mini_len.div_ceil(1 << core.mini_shift)
        } else {
            core.total
        };
        StreamReader {
            core,
            mini,
            next: src.start,
            remaining: src.size,
            budget,
            tortoise: FREE_SECT,
            steps: 0,
            power: 1,
            cur: 0..0,
        }
    }

    /// Counts sector `s` as used; a chain that comes back to a sector it has been through
    /// is a loop.
    fn visit(&mut self, s: u32) -> Result<()> {
        if self.budget == 0 || s == self.tortoise {
            return Err(Error::corrupt("stream's sector chain loops"));
        }
        self.budget -= 1;
        self.steps += 1;
        if self.steps == self.power {
            self.tortoise = s;
            self.power *= 2;
            self.steps = 0;
        }
        Ok(())
    }

    /// Takes the next run of sectors; the chain, not the declared size, decides whether
    /// there is one.
    fn load(&mut self) -> Result<()> {
        let core = Arc::clone(&self.core);
        let s = self.next;
        if s == END_OF_CHAIN {
            return Err(Error::corrupt("stream ends before its declared size"));
        }
        if s >= MAX_REG_SECT {
            return Err(Error::corrupt("stream's sector chain is damaged"));
        }
        self.visit(s)?;
        let past_end = || Error::corrupt("stream data is past the end of the file");
        if self.mini {
            let off = u64::from(s) << core.mini_shift;
            if off >= core.mini_len {
                return Err(Error::corrupt("stream is outside the mini stream"));
            }
            let sector = *core
                .mini_stream
                .get((off >> core.shift) as usize)
                .ok_or_else(past_end)?;
            let r = core.sector_range(sector).ok_or_else(past_end)?;
            let start = r.start + (off & (core.sector_size() - 1)) as usize;
            let want = (1u64 << core.mini_shift).min(core.mini_len - off) as usize;
            let end = start.saturating_add(want).min(r.end);
            if start >= end {
                return Err(past_end());
            }
            self.cur = start..end;
            self.next = core.mini_fat_entry(s).unwrap_or(FREE_SECT);
            return Ok(());
        }
        let first = core.sector_range(s).ok_or_else(past_end)?;
        let (mut end, mut last) = (first.end, s);
        // Consecutive sectors are one run, so a big stream is a few large copies.
        while ((end - first.start) as u64) < self.remaining.min(MAX_RUN) {
            let Some(n) = core
                .fat_entry(last)
                .filter(|&n| n == last.wrapping_add(1) && n < MAX_REG_SECT)
            else {
                break;
            };
            match core.sector_range(n) {
                Some(r) if r.start == end => {
                    self.visit(n)?;
                    end = r.end;
                    last = n;
                }
                _ => break,
            }
        }
        self.cur = first.start..end;
        self.next = core.fat_entry(last).unwrap_or(FREE_SECT);
        Ok(())
    }
}

impl Read for StreamReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        if self.cur.is_empty() {
            self.load().map_err(Error::into_io)?;
        }
        let n = (buf.len() as u64)
            .min(self.remaining)
            .min(self.cur.len() as u64) as usize;
        let src = self
            .core
            .data
            .get(self.cur.start..self.cur.start + n)
            .ok_or_else(|| Error::corrupt("stream data is past the end of the file").into_io())?;
        buf[..n].copy_from_slice(src);
        self.cur.start += n;
        self.remaining -= n as u64;
        Ok(n)
    }
}

impl Archive for Cfb {
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
        let unit = self
            .units
            .get(unit)
            .ok_or_else(|| Error::corrupt("no such unit"))?;
        for &i in &unit.entries {
            let Some(&src) = self.sources.get(i) else {
                continue;
            };
            let mut r = StreamReader::new(Arc::clone(&self.core), src);
            if f(i, &mut r)? == Flow::Stop {
                break;
            }
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.props.clone()
    }

    fn stream(&self, i: usize) -> Option<Opener> {
        if self.entries.get(i)?.is_dir {
            return None;
        }
        let src = *self.sources.get(i)?;
        let core = Arc::clone(&self.core);
        Some(Arc::new(move || {
            Ok(Box::new(StreamReader::new(Arc::clone(&core), src)) as BoxRead)
        }))
    }

    fn main_entry(&self) -> Option<usize> {
        self.main
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn packed_names() {
        // Two characters per unit: low six bits first.
        assert_eq!(decode_name(&[0x3800 + 10 + (11 << 6)]), ("AB".into(), true));
        // One character, then the table prefix.
        assert_eq!(decode_name(&[0x4840, 0x4800 + 62]), ("!.".into(), true));
        assert_eq!(decode_name(&[0x47FF]), ("__".into(), true));
        assert_eq!(decode_name(&[0x4840]), ("!".into(), true));
        assert_eq!(decode_name(&[0x4800]), ("0".into(), true));
    }

    #[test]
    fn any_unit_outside_the_range_makes_a_name_literal() {
        let (s, packed) = decode_name(&[0x4841, 0x3800]);
        assert!(!packed);
        assert_eq!(s, "\u{4841}\u{3800}");
        assert!(!decode_name(&units("Book")).1);
        assert!(!decode_name(&[]).1);
    }

    #[test]
    fn literal_names_escape_control_characters() {
        assert_eq!(
            decode_name(&units("\u{5}SummaryInformation")).0,
            "[5]SummaryInformation"
        );
        assert_eq!(decode_name(&units("a\u{1f}b")).0, "a[31]b");
        assert_eq!(decode_name(&[0xD800, 0x41]).0, "\u{FFFD}A");
    }
}
