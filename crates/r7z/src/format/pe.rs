//! PE executables and libraries (`.exe`, `.dll`): the resource tree as folders.
//!
//! Only asked for explicitly (`-t PE`, or "Open as archive"): a plain executable is never
//! detected as an archive. Installers and self-extractors are recognized by the payload
//! they carry instead (`nsis`, `sfx`), and they use [`Image`] to find where the image ends.
//!
//! The tree has three levels: resource type, name and language. Each type is a folder, each
//! name a folder inside it, and each language a file named by its LCID. Icon groups become
//! `.ico` files assembled from the icon images they name, and the images are then hidden as
//! separate entries. Version information becomes `key=value` lines when it parses, manifests
//! keep their XML, and everything else is raw bytes.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, Cursor, Read};
use std::ops::Range;

use super::data::{Input, Slice};
use super::{Archive, Ctx, Entry, EntryFn, Format, OpenOptions, Unit};
use crate::error::{Error, Result};

/// Forced with `-t` (or "Open as archive"); a plain executable is never detected as one.
pub const FORMAT: Format = Format {
    name: "PE",
    aliases: &["exe", "dll"],
    extensions: &[],
    signatures: &[],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

/// Bit set on a resource directory entry's name or offset: a string name (in the name
/// field) or a subdirectory (in the offset field).
const HIGH: u32 = 0x8000_0000;
/// Resource levels below the root: type, name, language.
const MAX_DEPTH: usize = 3;
const MAX_LEAVES: usize = 1 << 16;

/// The parts of a PE image r7z reads: its sections, the resource directory, and where the
/// image ends in the file.
pub struct Image {
    sections: Vec<Section>,
    /// RVA and size of the resource directory (data directory 2).
    resources: Option<(u32, u32)>,
    /// File offset just past the image's section data, where appended data starts.
    pub overlay: usize,
}

#[derive(Clone, Copy)]
struct Section {
    va: u32,
    raw_size: u32,
    raw_ptr: u32,
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

impl Image {
    /// Reads the headers of a PE file. Fails when the file is not a PE image.
    pub fn parse(d: &[u8]) -> Result<Image> {
        if !d.starts_with(b"MZ") {
            return Err(Error::NotArchive);
        }
        let pe = u32_at(d, 0x3c).ok_or(Error::NotArchive)? as usize;
        if d.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err(Error::NotArchive);
        }
        let truncated = || Error::corrupt("PE headers are truncated");
        let coff = pe + 4;
        let sections = u16_at(d, coff + 2).ok_or_else(truncated)? as usize;
        let opt_len = u16_at(d, coff + 16).ok_or_else(truncated)? as usize;
        let opt = coff + 20;
        // NumberOfRvaAndSizes and the data directories sit at 92 and 96 in a PE32 optional
        // header, and at 108 and 112 in PE32+.
        let (count_at, dirs_at) = match u16_at(d, opt) {
            Some(0x10b) => (92, 96),
            Some(0x20b) => (108, 112),
            _ => return Err(Error::NotArchive),
        };
        let dir_count = u32_at(d, opt + count_at).ok_or_else(truncated)?;
        let resources = match (dir_count > 2)
            .then(|| (u32_at(d, opt + dirs_at + 16), u32_at(d, opt + dirs_at + 20)))
        {
            Some((Some(rva), Some(size))) if rva != 0 && size != 0 => Some((rva, size)),
            _ => None,
        };
        let headers_size = u32_at(d, opt + 60).ok_or_else(truncated)? as usize;
        let table = opt + opt_len;
        let mut out = Vec::new();
        let mut overlay = headers_size;
        for i in 0..sections {
            let at = table + 40 * i;
            let (Some(va), Some(raw_size), Some(raw_ptr)) =
                (u32_at(d, at + 12), u32_at(d, at + 16), u32_at(d, at + 20))
            else {
                break;
            };
            overlay = overlay.max((raw_ptr as usize).saturating_add(raw_size as usize));
            out.push(Section {
                va,
                raw_size,
                raw_ptr,
            });
        }
        Ok(Image {
            sections: out,
            resources,
            overlay: overlay.min(d.len()),
        })
    }

    /// The file bytes behind `size` bytes of the image at `rva`, when they all lie in one
    /// section's raw data.
    fn file_range(&self, rva: u32, size: u32) -> Option<Range<usize>> {
        self.sections.iter().find_map(|s| {
            let off = rva.checked_sub(s.va)?;
            (off as u64 + size as u64 <= s.raw_size as u64).then(|| {
                let start = s.raw_ptr as usize + off as usize;
                start..start + size as usize
            })
        })
    }
}

/// A resource path component: a numeric ID, or a string name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Id(u32),
    Name(String),
}

/// A data entry of the resource tree: its path from the root and where its bytes are.
struct Leaf {
    path: Vec<Key>,
    rva: u32,
    size: u32,
}

fn resource_string(d: &[u8], at: usize) -> Option<String> {
    let n = u16_at(d, at)? as usize;
    let (pairs, _) = d.get(at + 2..at + 2 + 2 * n)?.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
    Some(String::from_utf16_lossy(&units))
}

/// Walks the directory at file offset `dir`; `base` is the file offset of the resource
/// section, which entry offsets are relative to. Bad entries are skipped.
fn walk(d: &[u8], base: usize, dir: usize, path: &mut Vec<Key>, out: &mut Vec<Leaf>) {
    let (Some(named), Some(ids)) = (u16_at(d, dir + 12), u16_at(d, dir + 14)) else {
        return;
    };
    for k in 0..named as usize + ids as usize {
        if out.len() >= MAX_LEAVES {
            return;
        }
        let at = dir + 16 + 8 * k;
        let (Some(name), Some(target)) = (u32_at(d, at), u32_at(d, at + 4)) else {
            return;
        };
        let key = if name & HIGH != 0 {
            match resource_string(d, base + (name & !HIGH) as usize) {
                Some(s) => Key::Name(s),
                None => continue,
            }
        } else {
            Key::Id(name)
        };
        path.push(key);
        let off = base + (target & !HIGH) as usize;
        if target & HIGH != 0 {
            if path.len() < MAX_DEPTH {
                walk(d, base, off, path, out);
            }
        } else if let (Some(rva), Some(size)) = (u32_at(d, off), u32_at(d, off + 4)) {
            out.push(Leaf {
                path: path.clone(),
                rva,
                size,
            });
        }
        path.pop();
    }
}

/// The name 7-Zip-style tools show for a standard resource type.
fn type_name(id: u32) -> String {
    let name = match id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => return id.to_string(),
    };
    name.to_string()
}

/// A folder or file name from a resource key, with path separators and characters
/// Windows does not allow in names replaced.
fn component(key: &Key) -> String {
    let raw = match key {
        Key::Id(id) => return id.to_string(),
        Key::Name(s) => s.as_str(),
    };
    let clean: String = raw
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    if clean.is_empty() || clean == "." || clean == ".." {
        "_".into()
    } else {
        clean
    }
}

/// A payload of a resource file: bytes this reader wrote, or a range of the image.
enum Part {
    Bytes(Vec<u8>),
    Data(Slice),
}

impl Part {
    fn len(&self) -> usize {
        match self {
            Part::Bytes(b) => b.len(),
            Part::Data(s) => s.len(),
        }
    }
}

/// Icon images by resource ID, with their language.
type Icons = HashMap<u32, Vec<(Option<u32>, Slice)>>;

/// Assembles an `.ico` from a RT_GROUP_ICON resource and the RT_ICON images it names, in the
/// group's language when one exists. Returns the parts and the IDs used; None when no image
/// of the group is present.
fn icon_file(group: &[u8], lang: Option<u32>, icons: &Icons) -> Option<(Vec<Part>, Vec<u32>)> {
    let count = u16_at(group, 4)? as usize;
    // Each group entry: width, height, colors, reserved, planes, bit count, size, ID.
    let mut fields = Vec::new();
    let mut images = Vec::new();
    let mut ids = Vec::new();
    for k in 0..count {
        let Some(g) = group.get(6 + 14 * k..6 + 14 * k + 14) else {
            break;
        };
        let id = u16::from_le_bytes([g[12], g[13]]) as u32;
        let Some(options) = icons.get(&id) else {
            continue;
        };
        let image = options
            .iter()
            .find(|(l, _)| *l == lang)
            .or_else(|| options.first());
        let Some((_, image)) = image else {
            continue;
        };
        fields.push([g[0], g[1], g[2], 0, g[4], g[5], g[6], g[7]]);
        images.push(image.clone());
        ids.push(id);
    }
    if images.is_empty() {
        return None;
    }
    let n = images.len();
    let mut head = vec![0, 0, 1, 0];
    head.extend_from_slice(&(n as u16).to_le_bytes());
    let mut offset = 6 + 16 * n;
    let mut parts = Vec::with_capacity(n + 1);
    for (f, image) in fields.iter().zip(&images) {
        head.extend_from_slice(&f[..4]);
        head.extend_from_slice(&f[4..]);
        head.extend_from_slice(&u32::try_from(image.len()).ok()?.to_le_bytes());
        head.extend_from_slice(&u32::try_from(offset).ok()?.to_le_bytes());
        offset += image.len();
    }
    parts.push(Part::Bytes(head));
    parts.extend(images.into_iter().map(Part::Data));
    Some((parts, ids))
}

fn utf16_units(d: &[u8], at: usize, end: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut p = at;
    loop {
        if p + 2 > end {
            return None;
        }
        let u = u16::from_le_bytes([d[p], d[p + 1]]);
        p += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    Some((String::from_utf16_lossy(&units), p))
}

fn align4(p: usize) -> usize {
    (p + 3) & !3
}

fn version_number(ms: u32, ls: u32) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
}

/// One VS_VERSIONINFO block and its children. Returns the block's length.
fn version_block(
    d: &[u8],
    at: usize,
    end: usize,
    depth: u32,
    lines: &mut Vec<String>,
) -> Option<usize> {
    if depth > 4 {
        return None;
    }
    let len = u16_at(d, at)? as usize;
    let vlen = u16_at(d, at + 2)? as usize;
    let text = u16_at(d, at + 4)? == 1;
    if len < 6 || at.checked_add(len)? > end {
        return None;
    }
    let block_end = at + len;
    let (key, after_key) = utf16_units(d, at + 6, block_end)?;
    let value_at = align4(after_key);
    let value_len = if text { vlen.checked_mul(2)? } else { vlen };
    let value_end = value_at.checked_add(value_len)?;
    if value_end > block_end {
        return None;
    }
    if key == "VS_VERSION_INFO" && vlen >= 52 && u32_at(d, value_at) == Some(0xFEEF_04BD) {
        let ms = u32_at(d, value_at + 8)?;
        let ls = u32_at(d, value_at + 12)?;
        lines.push(format!("FileVersion={}", version_number(ms, ls)));
        let pms = u32_at(d, value_at + 16)?;
        let pls = u32_at(d, value_at + 20)?;
        lines.push(format!("ProductVersion={}", version_number(pms, pls)));
    }
    if text && depth == 3 {
        let (value, _) = utf16_units(d, value_at, value_end).unwrap_or_default();
        lines.push(format!("{key}={}", value.trim_end_matches('\0')));
    }
    let mut q = align4(value_end);
    while q + 6 <= block_end {
        let child = version_block(d, q, block_end, depth + 1, lines)?;
        if child == 0 {
            break;
        }
        q = align4(q + child);
    }
    Some(len)
}

/// The text shown for a RT_VERSION resource, one `key=value` per line. None when the bytes
/// are not a version block.
fn version_text(d: &[u8]) -> Option<String> {
    let mut lines = Vec::new();
    version_block(d, 0, d.len(), 0, &mut lines)?;
    (!lines.is_empty()).then(|| lines.join("\n") + "\n")
}

/// The extension and parts of a resource that is not an icon group: version information
/// becomes text, manifests keep their XML, and everything else is raw bytes.
fn leaf_file(kind: &Key, data: &Slice) -> (&'static str, Vec<Part>) {
    let raw = || vec![Part::Data(data.clone())];
    match kind {
        Key::Id(16) => match version_text(data) {
            Some(text) => (".txt", vec![Part::Bytes(text.into_bytes())]),
            None => (".bin", raw()),
        },
        Key::Id(24) => (".manifest", raw()),
        _ => (".bin", raw()),
    }
}

struct PeArchive {
    entries: Vec<Entry>,
    parts: Vec<Vec<Part>>,
    units: Vec<Unit>,
    size: usize,
}

impl Archive for PeArchive {
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
        let mut r = Chain {
            parts: self.parts[i].iter(),
            cur: None,
        };
        f(i, &mut r)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        vec![("Physical Size", self.size.to_string())]
    }
}

/// Reads a file's parts one after another.
struct Chain<'a> {
    parts: std::slice::Iter<'a, Part>,
    cur: Option<Box<dyn Read + Send>>,
}

impl Read for Chain<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(r) = self.cur.as_mut() {
                let n = r.read(buf)?;
                if n > 0 || buf.is_empty() {
                    return Ok(n);
                }
            }
            match self.parts.next() {
                Some(Part::Bytes(b)) => self.cur = Some(Box::new(Cursor::new(b.clone()))),
                Some(Part::Data(s)) => self.cur = Some(Box::new(s.reader())),
                None => return Ok(0),
            }
        }
    }
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let file = input.into_mem()?;
    let image = Image::parse(&file)?;
    let mut leaves = Vec::new();
    if let Some((rva, _)) = image.resources {
        // Entry offsets are relative to the start of the resource section.
        if let Some(base) = image.file_range(rva, 16).map(|r| r.start) {
            walk(&file, base, base, &mut Vec::new(), &mut leaves);
        }
    }
    let mut found: Vec<(Vec<Key>, Slice)> = leaves
        .into_iter()
        .filter_map(|l| {
            let r = image.file_range(l.rva, l.size)?;
            Some((l.path, file.sub(r.start as u64..r.end as u64).ok()?))
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));

    let mut icons: Icons = HashMap::new();
    for (path, data) in &found {
        if let [Key::Id(3), Key::Id(id), rest @ ..] = path.as_slice() {
            icons
                .entry(*id)
                .or_default()
                .push((lang_of(rest), data.clone()));
        }
    }

    // An icon group becomes an `.ico`, and the icon images it names are then hidden.
    let mut used: HashSet<u32> = HashSet::new();
    let mut made: Vec<Option<Vec<Part>>> = Vec::with_capacity(found.len());
    for (path, data) in &found {
        let assembled = match path.as_slice() {
            [Key::Id(14), rest @ ..] => icon_file(data, lang_of(rest), &icons),
            _ => None,
        };
        made.push(assembled.map(|(parts, ids)| {
            used.extend(ids);
            parts
        }));
    }
    let mut files: Vec<(Vec<String>, Vec<Part>)> = Vec::new();
    for ((path, data), icon) in found.iter().zip(made) {
        if let [Key::Id(3), Key::Id(id), ..] = path.as_slice() {
            if used.contains(id) {
                continue;
            }
        }
        let (ext, parts) = match icon {
            Some(parts) => (".ico", parts),
            None => leaf_file(&path[0], data),
        };
        let mut comps: Vec<String> = path
            .iter()
            .enumerate()
            .map(|(i, k)| match (i, k) {
                (0, Key::Id(id)) => type_name(*id),
                _ => component(k),
            })
            .collect();
        if let Some(last) = comps.last_mut() {
            last.push_str(ext);
        }
        files.push((comps, parts));
    }

    let mut dirs = BTreeSet::new();
    let mut names = HashSet::new();
    let mut listed: Vec<(String, Vec<Part>)> = Vec::new();
    for (comps, parts) in files {
        for i in 1..comps.len() {
            dirs.insert(comps[..i].join("/"));
        }
        let name = comps.join("/");
        if names.insert(name.clone()) {
            listed.push((name, parts));
        }
    }
    listed.sort_by(|a, b| a.0.cmp(&b.0));

    let mut entries = Vec::new();
    let mut parts_out = Vec::new();
    let mut units = Vec::new();
    for dir in dirs {
        if names.contains(&dir) {
            continue;
        }
        entries.push(Entry {
            name: dir,
            is_dir: true,
            ..Default::default()
        });
        parts_out.push(Vec::new());
    }
    for (name, parts) in listed {
        let size: usize = parts.iter().map(Part::len).sum();
        units.push(Unit {
            entries: vec![entries.len()],
            encrypted: false,
        });
        entries.push(Entry {
            name,
            size: Some(size as u64),
            ..Default::default()
        });
        parts_out.push(parts);
    }
    Ok(Box::new(PeArchive {
        entries,
        parts: parts_out,
        units,
        size: file.len(),
    }))
}

/// The language ID of a resource path, when its next component is numeric.
fn lang_of(rest: &[Key]) -> Option<u32> {
    match rest.first() {
        Some(Key::Id(l)) => Some(*l),
        _ => None,
    }
}
