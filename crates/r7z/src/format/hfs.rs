//! HFS+ and HFSX volumes (a disk partition or a raw volume image). The catalog B-tree gives the
//! tree; each file's data fork, or its decmpfs-compressed bytes, is read on demand through
//! random-access volume reads, so memory stays at the B-tree nodes and blocks in use.

mod be;
mod btree;
mod catalog;
mod decmpfs;
mod volume;

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use super::{
    Archive, Columns, Ctx, Entry, EntryFn, Format, Input, Link, OpenOptions, Runs, Signature, Unit,
};
use crate::error::{Error, Result};
use crate::sevenz::attr::{DIRECTORY, UNIX_EXTENSION};
use crate::util::time::unix_to_filetime;
use catalog::{Record, ROOT};
use decmpfs::{Attr, Codec, Compressed};
use volume::{ForkData, Volume, DATA_FORK};

pub const FORMAT: Format = Format {
    name: "HFS",
    aliases: &["hfsplus", "hfsx"],
    extensions: &["hfs"],
    signatures: &[Signature::at(1024, b"H+"), Signature::at(1024, b"HX")],
    detect: Some(detect),
    write: false,
    stream: false,
    sequential: true,
    open,
};

/// Deepest folder nesting listed; deeper folders are skipped as damage.
const MAX_DEPTH: usize = 1024;
/// Longest symbolic-link target read.
const MAX_LINK: u64 = 4096;
/// The two private folders at the root: hard-link data, and directory hard links.
const PRIVATE_DATA: &str = "\0\0\0\0HFS+ Private Data";
const PRIVATE_DIRS: &str = "\0\0\0\0HFS+ Private Directory Data\r";
/// Seconds from 1904-01-01 (HFS+ dates) to 1970-01-01 (Unix time).
const HFS_TO_UNIX: i64 = 2_082_844_800;

/// Content of a hard-link proxy (type `hlnk`, creator `hfs+`) and of a symbolic link.
const HARD_LINK_TYPE: &[u8; 4] = b"hlnk";
const HARD_LINK_CREATOR: &[u8; 4] = b"hfs+";
const SYMLINK_TYPE: &[u8; 4] = b"slnk";
const SYMLINK_CREATOR: &[u8; 4] = b"rhap";

/// Checks the signature against the version and the allocation block size, so text that
/// happens to start with `H+` is not taken for a volume.
fn detect(head: &[u8]) -> bool {
    let Some(h) = head.get(1024..1024 + 48) else {
        return false;
    };
    let version = u16::from_be_bytes([h[2], h[3]]);
    let block = u32::from_be_bytes([h[40], h[41], h[42], h[43]]);
    matches!((&h[..2], version), (b"H+", 4) | (b"HX", 5))
        && block % 512 == 0
        && (512..=1 << 20).contains(&block)
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let volume = Volume::open(input.volume()?)?;
    Ok(Box::new(Hfs::new(volume)?))
}

/// Where an entry's bytes come from, resolved when its unit is extracted.
enum Content {
    /// Directories have no unit.
    None,
    /// The data fork of file `file_id`.
    Fork { file_id: u32, data: ForkData },
    /// Transparently compressed data.
    Compressed(Compressed),
    /// Listed, but the bytes cannot be read; extraction reports why.
    Unsupported(String),
    /// Listed, but the data is damaged or missing; extraction reports why.
    Broken(String),
}

/// An opened HFS+ or HFSX volume.
pub struct Hfs {
    volume: Arc<Volume>,
    entries: Vec<Entry>,
    units: Vec<Unit>,
    contents: Vec<Content>,
    properties: Vec<(&'static str, String)>,
    damage: Vec<String>,
}

impl Hfs {
    fn new(volume: Volume) -> Result<Hfs> {
        let records = catalog::read(&volume)?;
        let attrs = decmpfs::scan(&volume)?;
        let index = Index::new(&records);
        let mut listing = Listing::default();
        walk(&volume, &records, &attrs, &index, &mut listing)?;
        let format = if volume.version() == 5 {
            "HFSX"
        } else {
            "HFS+"
        };
        Ok(Hfs {
            properties: vec![
                ("Format", format.to_string()),
                ("Block Size", volume.block_size().to_string()),
            ],
            volume: Arc::new(volume),
            entries: listing.entries,
            units: listing.units,
            contents: listing.contents,
            damage: listing.damage,
        })
    }
}

impl Archive for Hfs {
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
        let mut data: Box<dyn Read + Send> = match &self.contents[i] {
            Content::None => return Ok(()),
            Content::Fork { file_id, data } => {
                let fork = self.volume.fork(*file_id, DATA_FORK, data)?;
                Box::new(Runs::new(self.volume.src(), fork.ranges()))
            }
            Content::Compressed(c) => decmpfs::open(&self.volume, c)?,
            Content::Unsupported(why) => return Err(Error::unsupported(why.clone())),
            Content::Broken(why) => return Err(Error::corrupt(why.clone())),
        };
        f(i, data.as_mut())?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.properties.clone()
    }

    fn columns(&self) -> Columns {
        Columns {
            method: true,
            ..Columns::default()
        }
    }

    fn damage(&self) -> Vec<String> {
        self.damage.clone()
    }
}

/// The catalog records grouped by parent, with the records the listing hides.
struct Index {
    children: HashMap<u32, Vec<usize>>,
    /// Records in the private folders, and the folders themselves.
    hidden: Vec<bool>,
    /// The hidden `iNode<n>` data file of each hard-link number `n`.
    links: HashMap<u32, usize>,
}

impl Index {
    fn new(records: &[Record]) -> Index {
        let mut children: HashMap<u32, Vec<usize>> = HashMap::new();
        for (i, r) in records.iter().enumerate() {
            children.entry(r.parent).or_default().push(i);
        }
        let mut hidden = vec![false; records.len()];
        let mut stack = Vec::new();
        for (i, r) in records.iter().enumerate() {
            if r.parent == ROOT && r.is_dir && (r.name == PRIVATE_DATA || r.name == PRIVATE_DIRS) {
                hidden[i] = true;
                stack.push(r.cnid);
            }
        }
        while let Some(cnid) = stack.pop() {
            let Some(kids) = children.get(&cnid) else {
                continue;
            };
            for &i in kids {
                if !hidden[i] {
                    hidden[i] = true;
                    if records[i].is_dir {
                        stack.push(records[i].cnid);
                    }
                }
            }
        }
        let mut links: HashMap<u32, usize> = HashMap::new();
        for (i, r) in records.iter().enumerate() {
            if hidden[i] && !r.is_dir {
                if let Some(n) = r
                    .name
                    .strip_prefix("iNode")
                    .and_then(|n| n.parse::<u32>().ok())
                {
                    links.entry(n).or_insert(i);
                }
            }
        }
        Index {
            children,
            hidden,
            links,
        }
    }
}

#[derive(Default)]
struct Listing {
    entries: Vec<Entry>,
    units: Vec<Unit>,
    contents: Vec<Content>,
    damage: Vec<String>,
}

impl Listing {
    fn push(&mut self, entry: Entry, content: Content) {
        if !matches!(content, Content::None) {
            self.units.push(Unit {
                entries: vec![self.entries.len()],
                encrypted: false,
            });
        }
        self.entries.push(entry);
        self.contents.push(content);
    }
}

/// Lists the visible tree from the root, depth first, with paths built from the parent
/// links that the walk follows down from the root.
fn walk(
    volume: &Volume,
    records: &[Record],
    attrs: &HashMap<u32, Attr>,
    index: &Index,
    out: &mut Listing,
) -> Result<()> {
    let mut seen = vec![false; records.len()];
    let mut expanded = HashSet::from([ROOT]);
    let mut stack = vec![(ROOT, String::new(), 0usize)];
    while let Some((folder, prefix, depth)) = stack.pop() {
        let Some(kids) = index.children.get(&folder) else {
            continue;
        };
        for &i in kids {
            if index.hidden[i] || std::mem::replace(&mut seen[i], true) {
                continue;
            }
            let r = &records[i];
            let path = join(&prefix, &component(&r.name, r.cnid));
            if r.is_dir {
                if depth >= MAX_DEPTH || !expanded.insert(r.cnid) {
                    out.damage.push(format!(
                        "{path}: folder skipped (nested too deeply, or listed twice)"
                    ));
                    continue;
                }
                out.push(
                    entry_of(path.clone(), r, true, None, None, None),
                    Content::None,
                );
                stack.push((r.cnid, path, depth + 1));
            } else {
                let (entry, content, note) = file_entry(volume, records, attrs, index, path, r);
                out.damage.extend(note);
                out.push(entry, content);
            }
        }
    }
    let lost = (0..records.len())
        .filter(|&i| !index.hidden[i] && !seen[i])
        .count();
    if lost > 0 {
        out.damage.push(format!(
            "{lost} catalog records are not reachable from the root and were skipped"
        ));
    }
    Ok(())
}

/// The entry, data source and optional damage note of a file record. A hard link lists
/// with the data of its `iNode<n>` file.
fn file_entry(
    volume: &Volume,
    records: &[Record],
    attrs: &HashMap<u32, Attr>,
    index: &Index,
    path: String,
    r: &Record,
) -> (Entry, Content, Option<String>) {
    let is_hard_link = r.file_type == *HARD_LINK_TYPE && r.creator == *HARD_LINK_CREATOR;
    let source = if is_hard_link {
        match index.links.get(&r.special) {
            Some(&t) => &records[t],
            None => {
                let why = format!(
                    "hard link {path} has no data (iNode{} is missing)",
                    r.special
                );
                return (
                    entry_of(path, r, false, Some(0), None, None),
                    Content::Broken(why),
                    None,
                );
            }
        }
    } else {
        r
    };
    let (content, size, method) = content_of(attrs, source);

    let mut note = None;
    let link = if !is_hard_link && r.file_type == *SYMLINK_TYPE && r.creator == *SYMLINK_CREATOR {
        match read_link(volume, r) {
            Ok(target) => Some(Link::Symbolic(target)),
            Err(e) => {
                note = Some(format!("{path}: symbolic link target unreadable: {e}"));
                None
            }
        }
    } else {
        None
    };
    let entry = entry_of(path, r, false, size, method, link);
    (entry, content, note)
}

/// The data source, listed size and method name of a file's data.
fn content_of(attrs: &HashMap<u32, Attr>, src: &Record) -> (Content, Option<u64>, Option<String>) {
    let plain = || {
        (
            Content::Fork {
                file_id: src.cnid,
                data: src.data,
            },
            Some(src.data.logical_size),
            None,
        )
    };
    match attrs.get(&src.cnid) {
        None => plain(),
        Some(Attr::Unreadable(why)) => (Content::Broken(why.clone()), None, None),
        Some(&Attr::Header {
            method,
            size,
            inline,
        }) => {
            let Some(codec) = decmpfs::codec(method) else {
                return (
                    Content::Unsupported(format!(
                        "decmpfs compression type {method} is not supported"
                    )),
                    Some(size),
                    Some(format!("decmpfs/type{method}")),
                );
            };
            let Some(inline) = inline else {
                return (
                    Content::Broken("decmpfs payload is not inline".into()),
                    Some(size),
                    None,
                );
            };
            (
                Content::Compressed(Compressed {
                    codec,
                    size,
                    inline,
                }),
                Some(size),
                Some(codec_name(codec).into()),
            )
        }
    }
}

fn codec_name(codec: Codec) -> &'static str {
    match codec {
        Codec::Zlib => "decmpfs/zlib",
        Codec::Lzvn => "decmpfs/lzvn",
    }
}

/// The target text of a symbolic link (its data fork).
fn read_link(volume: &Volume, r: &Record) -> Result<String> {
    if r.data.logical_size > MAX_LINK {
        return Err(Error::corrupt("symbolic link target is too long"));
    }
    let mut target = vec![0u8; r.data.logical_size as usize];
    let src = volume.src();
    volume
        .fork(r.cnid, DATA_FORK, &r.data)?
        .read_at(&*src, 0, &mut target)?;
    Ok(String::from_utf8_lossy(&target).into_owned())
}

fn entry_of(
    name: String,
    r: &Record,
    is_dir: bool,
    size: Option<u64>,
    method: Option<String>,
    link: Option<Link>,
) -> Entry {
    // The BSD mode goes in the high 16 bits, flagged as a Unix extension, when it is set.
    let mut attrib = if is_dir { DIRECTORY } else { 0 };
    if r.mode != 0 {
        attrib |= UNIX_EXTENSION | (u32::from(r.mode) << 16);
    }
    Entry {
        name,
        is_dir,
        size,
        method,
        link,
        attrib: Some(attrib),
        mtime: hfs_time(r.modified),
        ctime: hfs_time(r.created),
        atime: hfs_time(r.accessed),
        ..Default::default()
    }
}

/// An HFS+ date (seconds since 1904, zero when unset) as a FILETIME.
fn hfs_time(secs: u32) -> Option<u64> {
    (secs != 0).then(|| unix_to_filetime(i64::from(secs) - HFS_TO_UNIX))
}

/// A name as one path component. Separators and NUL become look-alike characters, and empty
/// or dot names are replaced by their CNID.
fn component(name: &str, cnid: u32) -> String {
    let s: String = name
        .chars()
        .map(|c| match c {
            '/' => '\u{2215}',
            '\\' => '\u{f05c}',
            '\0' => '\u{2400}',
            c => c,
        })
        .collect();
    if s.is_empty() || s == "." || s == ".." {
        format!("#{cnid}")
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
