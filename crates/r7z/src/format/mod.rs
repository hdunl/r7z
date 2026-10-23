//! The format-neutral archive layer.
//!
//! Every archive type is a [`Format`] in the registry ([`FORMATS`]) whose `open` returns an
//! [`Archive`]: a list of [`Entry`] values plus decodable [`Unit`]s. A unit is a run of
//! entries that decode from one stream in order (a 7z folder, a CAB folder, a whole tar);
//! formats with per-entry random access (zip) make one unit per entry, so the extractor
//! can decode units in parallel.
//!
//! [`open`] detects the format by signature, then by extension, and opens archives nested
//! inside single-stream compressors (`.tar.gz` lists as the tar inside).

pub mod ar;
pub mod arj;
pub mod cab;
pub mod cpio;
pub mod data;
pub mod lzh;
pub mod misc;
pub mod rar;
pub mod rpm;
pub mod salvage;
pub mod sevenz;
pub mod stream;
pub mod tar;
pub mod wim;
pub mod write;
pub mod xar;
pub mod zip;
pub mod zipsplit;

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub use data::{BoxRead, Input, Opener, Slice};

use crate::error::{Error, Result};
pub use crate::util::codepage::{CodePage, NameCoding};

/// A link stored in place of file data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    /// The entry's data is the link target text.
    Symbolic(String),
    /// The entry has no data of its own; it names an earlier entry with the same content.
    Hard(String),
}

/// One item in an archive.
#[derive(Clone, Debug, Default)]
pub struct Entry {
    /// Path inside the archive, `/`-separated.
    pub name: String,
    pub is_dir: bool,
    /// Unpacked size, when the format records it.
    pub size: Option<u64>,
    /// Packed size attributed to this entry (7z puts a folder's size on its first entry).
    pub packed_size: Option<u64>,
    /// Times as Windows FILETIME (100 ns ticks since 1601).
    pub mtime: Option<u64>,
    pub ctime: Option<u64>,
    pub atime: Option<u64>,
    /// Windows attribute bits; `0x8000` set means the high 16 bits hold a Unix mode.
    pub attrib: Option<u32>,
    /// CRC32 of the unpacked data, checked by the extractor unless the format verifies.
    pub crc: Option<u32>,
    /// Compression method as 7-Zip prints it (`Deflate`, `LZMA2:24`).
    pub method: Option<String>,
    pub encrypted: bool,
    /// 7z anti-item (a deletion marker); never extracted.
    pub is_anti: bool,
    /// Solid block / folder index, for formats that have them.
    pub block: Option<usize>,
    pub link: Option<Link>,
    pub comment: Option<String>,
    /// The name as stored, when it was decoded with a legacy code page
    /// ([`Archive::name_coding`]); `name` is its decoding.
    pub raw_name: Option<Vec<u8>>,
}

impl Entry {
    pub fn size_or_zero(&self) -> u64 {
        self.size.unwrap_or(0)
    }

    /// 7-Zip's five-letter attribute column: `D R H S A`.
    pub fn attr_string(&self) -> String {
        use crate::sevenz::attr;
        let a = self.attrib.unwrap_or(0);
        let d = self.is_dir || a & attr::DIRECTORY != 0;
        format!(
            "{}{}{}{}{}",
            if d { 'D' } else { '.' },
            if a & attr::READONLY != 0 { 'R' } else { '.' },
            if a & attr::HIDDEN != 0 { 'H' } else { '.' },
            if a & attr::SYSTEM != 0 { 'S' } else { '.' },
            if a & attr::ARCHIVE != 0 { 'A' } else { '.' },
        )
    }
}

/// A run of entries decoded from one stream, in stream order.
#[derive(Clone, Debug, Default)]
pub struct Unit {
    pub entries: Vec<usize>,
    /// Data errors inside this unit most likely mean a wrong password.
    pub encrypted: bool,
}

/// Decoding context for one unit.
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    pub password: Option<String>,
    /// Threads this unit's decoder may use.
    pub threads: usize,
}

/// What the extractor wants after an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// No later entry of this unit is needed.
    Stop,
}

/// Receives each entry of a unit with a reader over exactly that entry's bytes. The
/// callback may leave data unread; the format skips it.
pub type EntryFn<'a> = dyn FnMut(usize, &mut dyn Read) -> Result<Flow> + 'a;

/// Which per-entry fields a format has, for `l -slt`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Columns {
    pub crc: bool,
    pub method: bool,
    pub encrypted: bool,
    pub block: bool,
}

/// An opened archive of any format.
pub trait Archive: Send + Sync {
    fn format(&self) -> &'static Format;
    fn entries(&self) -> &[Entry];
    fn units(&self) -> &[Unit];

    /// Decodes unit `unit`, calling `f` for its entries in order until it returns `Stop`.
    fn extract_unit(&self, unit: usize, ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()>;

    /// Archive-level lines for the listing header, after `Path` and `Type`.
    fn properties(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    fn columns(&self) -> Columns {
        Columns::default()
    }

    /// The format checks data integrity itself (gzip trailer, xz check, zip AES MAC), so the
    /// extractor does not need to compute CRC32.
    fn verifies_data(&self) -> bool {
        false
    }

    fn has_encrypted_data(&self) -> bool {
        self.entries().iter().any(|e| e.encrypted)
    }

    /// A re-openable stream over entry `i`, for single-stream formats. Used to open archives
    /// nested inside (`.tar.gz`).
    fn stream(&self, _i: usize) -> Option<Opener> {
        None
    }

    /// An entry holding the archive's real content (a `.deb`'s `data.tar.*`), opened
    /// automatically like the content of a stream format. Needs `stream(i)`.
    fn main_entry(&self) -> Option<usize> {
        None
    }

    /// The code page legacy names and comments were decoded with, when there were any
    /// (zip names without the UTF-8 flag, LZH, ARJ, old tar headers).
    fn name_coding(&self) -> Option<NameCoding> {
        None
    }

    /// What a recovery open (`OpenOptions::recover`) had to rebuild, skip or give up on.
    fn damage(&self) -> Vec<String> {
        Vec::new()
    }

    /// Recovery: unpacked offsets inside unit `unit` where decoding can start over without
    /// the data before them (LZMA2 dictionary resets). Empty when there are none.
    fn restart_points(&self, _unit: usize) -> Vec<u64> {
        Vec::new()
    }

    /// Recovery: decodes unit `unit` from `at`, one of its `restart_points`, calling `f` for
    /// each entry that starts at or after `at`, in order.
    fn extract_unit_at(
        &self,
        _unit: usize,
        _at: u64,
        _ctx: &Ctx,
        _f: &mut EntryFn<'_>,
    ) -> Result<()> {
        Err(Error::unsupported("restarting a unit after damage"))
    }
}

/// A byte signature at a fixed offset.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub offset: usize,
    pub bytes: &'static [u8],
}

impl Signature {
    pub const fn at(offset: usize, bytes: &'static [u8]) -> Self {
        Signature { offset, bytes }
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() >= self.offset + self.bytes.len()
            && &data[self.offset..self.offset + self.bytes.len()] == self.bytes
    }
}

/// Options for opening an archive.
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    pub password: Option<String>,
    /// The archive's file name, used to name the single entry of stream formats.
    pub name: String,
    /// The archive's path on disk for the outermost level (to find sibling volumes); `None`
    /// for nested archives.
    pub path: Option<std::path::PathBuf>,
    /// The archive is a split zip joined from its parts; its disk numbers are not an error.
    pub split: bool,
    /// Damaged-archive recovery: rebuild what can be rebuilt (a zip central directory, a
    /// lost 7z header, a tar past a bad header) instead of failing, and report it through
    /// `Archive::damage`.
    pub recover: bool,
    /// Decode legacy names with this code page instead of detecting one (`-mcp`).
    pub code_page: Option<CodePage>,
}

pub type OpenFn = fn(Input, &OpenOptions) -> Result<Box<dyn Archive>>;

/// A registered archive format.
pub struct Format {
    /// Type name, as `-t` takes it and `l` prints it.
    pub name: &'static str,
    /// Other names `-t` accepts.
    pub aliases: &'static [&'static str],
    pub extensions: &'static [&'static str],
    pub signatures: &'static [Signature],
    /// Extra content check for formats with weak or no signatures.
    pub detect: Option<fn(&[u8]) -> bool>,
    /// r7z can create this format.
    pub write: bool,
    /// The format wraps one compressed stream; archives inside it are opened too.
    pub stream: bool,
    /// The handler can be opened over a sequential stream (`Input::Stream`).
    pub sequential: bool,
    pub open: OpenFn,
}

impl std::fmt::Debug for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

impl Format {
    pub fn matches_name(&self, n: &str) -> bool {
        self.name.eq_ignore_ascii_case(n) || self.aliases.iter().any(|a| a.eq_ignore_ascii_case(n))
    }

    pub fn has_extension(&self, ext: &str) -> bool {
        self.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
    }

    fn signature_matches(&self, head: &[u8]) -> bool {
        self.signatures.iter().any(|s| s.matches(head)) && self.detect.is_none_or(|d| d(head))
    }
}

/// The format table and an extensions-only copy of it, from one list.
macro_rules! formats {
    ($($f:path),* $(,)?) => {
        /// Every format r7z knows, in detection priority order.
        pub static FORMATS: &[&Format] = &[$(&$f),*];

        /// The file extensions of [`FORMATS`], in the same order, evaluated at compile
        /// time. Code that only needs to recognize archive names (the Explorer menu)
        /// reads this, so linking it doesn't pull in every parser.
        pub const EXTENSIONS: &[&[&str]] = &[$($f.extensions),*];
    };
}

formats![
    sevenz::FORMAT,
    zip::FORMAT,
    tar::FORMAT,
    xar::FORMAT,
    rpm::FORMAT,
    ar::FORMAT,
    cpio::FORMAT,
    cab::FORMAT,
    wim::FORMAT,
    arj::FORMAT,
    lzh::FORMAT,
    rar::FORMAT,
    stream::GZIP,
    stream::BZIP2,
    stream::XZ,
    stream::ZSTD,
    stream::LZ4,
    stream::Z,
    stream::LZMA86,
    stream::LZMA,
    misc::SPLIT,
    misc::BASE64,
    misc::IHEX,
];

pub fn find_format(name: &str) -> Option<&'static Format> {
    FORMATS.iter().copied().find(|f| f.matches_name(name))
}

/// One level of an opened archive chain (`x.tar.gz` has a gzip level and a tar level).
pub struct Level {
    pub archive: Arc<dyn Archive>,
    /// Display name of this level.
    pub name: String,
    pub physical_size: Option<u64>,
}

/// Damage notes shared with readers that find the damage later, while decoding.
pub type Notes = Arc<Mutex<Vec<String>>>;

/// An opened archive: the outermost level first, the archive to work on last.
pub struct Opened {
    pub levels: Vec<Level>,
    /// Recovery opens: where a compressed stream between levels stopped decoding.
    pub notes: Notes,
}

impl Opened {
    /// Everything a recovery open noted, outermost level first.
    pub fn damage(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for l in &self.levels {
            out.extend(l.archive.damage());
        }
        for n in self.notes.lock().unwrap().iter() {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }

    pub fn archive(&self) -> &dyn Archive {
        &*self.levels.last().unwrap().archive
    }

    pub fn arc(&self) -> Arc<dyn Archive> {
        self.levels.last().unwrap().archive.clone()
    }
}

/// How to open: a forced type (`-t`) and whether nested archives are opened.
#[derive(Clone, Debug, Default)]
pub struct OpenRequest {
    pub password: Option<String>,
    pub format: Option<&'static Format>,
    /// Code page for names the archive does not mark as Unicode (`-mcp`); detected if None.
    pub code_page: Option<CodePage>,
    /// The archive is the joined parts of a split zip (see `zipsplit`).
    pub split: bool,
}

/// The extension of `name` and, for `x.tar.gz`, the compound `tar.gz`.
pub fn extensions_of(name: &str) -> (String, Option<String>) {
    let lower = name.to_ascii_lowercase();
    let mut parts = lower.rsplit('.');
    let last = parts.next().unwrap_or("").to_string();
    if !lower.contains('.') {
        return (String::new(), None);
    }
    let compound = parts
        .next()
        .filter(|p| !p.is_empty())
        .map(|p| format!("{p}.{last}"));
    (last, compound)
}

/// Bytes examined for signatures.
const HEAD: usize = 1 << 16;

/// Picks the format for `head`, preferring one that owns the file's extension.
pub fn detect_format(head: &[u8], file_name: &str) -> Option<&'static Format> {
    let (ext, _) = extensions_of(file_name);
    // The first of several volumes starts with a signature of the inner format, so `.001`
    // goes through the split handler, which joins the volumes first.
    if ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit()) && ext.parse::<u32>() == Ok(1) {
        return Some(&misc::SPLIT);
    }
    let by_sig: Vec<&'static Format> = FORMATS
        .iter()
        .copied()
        .filter(|f| !f.signatures.is_empty() && f.signature_matches(head))
        .collect();
    if let Some(f) = by_sig.iter().find(|f| f.has_extension(&ext)) {
        return Some(f);
    }
    if let Some(f) = by_sig.first() {
        return Some(f);
    }
    // Then by extension, confirmed by the format's content check (formats without a
    // signature, and old tar files without the ustar magic).
    FORMATS
        .iter()
        .copied()
        .find(|f| f.has_extension(&ext) && f.detect.is_some_and(|d| d(head)))
}

/// Opens `path`, detecting its format and descending into nested archives.
pub fn open(path: &Path, req: &OpenRequest) -> Result<Opened> {
    if let Some(parts) = zipsplit::volumes(path) {
        // The name of a split zip is its last part's, with `.zip`.
        let name = path.with_extension("zip");
        let file_name = name
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let req = OpenRequest {
            split: true,
            ..req.clone()
        };
        return open_input(
            Input::Mem(zipsplit::join(&parts)?),
            &file_name,
            &req,
            None,
            false,
        );
    }
    let data = Slice::map_file(path)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    open_input(Input::Mem(data), &file_name, req, Some(path), false)
}

/// Opens archive bytes held in memory (tests and nested use).
pub fn open_bytes(data: Vec<u8>, file_name: &str, req: &OpenRequest) -> Result<Opened> {
    let input = Input::Mem(Slice::from_vec(data));
    open_input(input, file_name, req, None, false)
}

/// Opens a damaged archive for recovery: handlers rebuild what they can, compressed
/// streams end at their first error, and a file whose signature is gone is tried as the
/// format its extension names.
pub fn open_recover(path: &Path, req: &OpenRequest) -> Result<Opened> {
    let data = Slice::map_file(path)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    open_input(Input::Mem(data), &file_name, req, Some(path), true)
}

/// `open_recover` over bytes in memory.
pub fn open_bytes_recover(data: Vec<u8>, file_name: &str, req: &OpenRequest) -> Result<Opened> {
    let input = Input::Mem(Slice::from_vec(data));
    open_input(input, file_name, req, None, true)
}

fn head_of(input: &Input) -> Result<Vec<u8>> {
    Ok(match input {
        Input::Mem(s) => s[..s.len().min(HEAD)].to_vec(),
        Input::Stream { open, .. } => {
            let mut r = open()?;
            let mut buf = vec![0u8; HEAD];
            let mut n = 0;
            while n < buf.len() {
                let k = data::read_some(&mut *r, &mut buf[n..])?;
                if k == 0 {
                    break;
                }
                n += k;
            }
            buf.truncate(n);
            buf
        }
    })
}

fn open_level(
    fmt: &'static Format,
    input: Input,
    name: &str,
    req: &OpenRequest,
    path: Option<&Path>,
    recover: bool,
) -> Result<Level> {
    let physical_size = match &input {
        Input::Mem(s) => Some(s.len() as u64),
        Input::Stream { size_hint, .. } => *size_hint,
    };
    let input = if fmt.sequential {
        input
    } else {
        Input::Mem(input.into_mem()?)
    };
    let opts = OpenOptions {
        password: req.password.clone(),
        code_page: req.code_page,
        name: name.to_string(),
        path: path.map(Path::to_path_buf),
        recover,
        split: req.split,
    };
    let archive: Arc<dyn Archive> = Arc::from((fmt.open)(input, &opts)?);
    Ok(Level {
        archive,
        name: name.to_string(),
        physical_size,
    })
}

fn open_input(
    input: Input,
    file_name: &str,
    req: &OpenRequest,
    path: Option<&Path>,
    recover: bool,
) -> Result<Opened> {
    let head = head_of(&input)?;
    let mut levels = Vec::new();
    let notes: Notes = Arc::default();
    let inner_stream = |lvl: &Level| {
        let (input, name) = inner_stream(lvl)?;
        Some(if recover {
            (salvage::until_error(input, lvl, &notes), name)
        } else {
            (input, name)
        })
    };
    let fmt = match req.format {
        // A forced archive type over a compressed stream: open the compressor first.
        Some(f) if !f.stream && !f.signatures.is_empty() && !f.signature_matches(&head) => {
            match detect_format(&head, file_name).filter(|o| o.stream) {
                Some(outer) => {
                    let lvl = open_level(outer, input, file_name, req, path, recover)?;
                    let (inner, inner_name) = inner_stream(&lvl).ok_or(Error::NotArchive)?;
                    levels.push(lvl);
                    levels.push(open_level(f, inner, &inner_name, req, None, recover)?);
                    return Ok(Opened { levels, notes });
                }
                None => f,
            }
        }
        Some(f) => f,
        None => detect_format(&head, file_name)
            .or_else(|| recover.then(|| by_extension(file_name)).flatten())
            .ok_or(Error::NotArchive)?,
    };
    levels.push(open_level(fmt, input, file_name, req, path, recover)?);
    // A forced type is opened as exactly that (`-tgzip` gives the .tar, `-tar` a deb's
    // members).
    if req.format.is_some() {
        return Ok(Opened { levels, notes });
    }
    // Descend while the current level is one stream (or has a main entry) holding another
    // archive.
    while levels.len() < 8 {
        let lvl = levels.last().unwrap();
        let Some((inner, inner_name)) = inner_stream(lvl) else {
            break;
        };
        let inner_head = match head_of(&inner) {
            Ok(h) => h,
            Err(_) => break,
        };
        let Some(f) = detect_format(&inner_head, &inner_name) else {
            break;
        };
        match open_level(f, inner, &inner_name, req, None, recover) {
            Ok(l) => levels.push(l),
            Err(_) => break,
        }
    }
    Ok(Opened { levels, notes })
}

/// The format an extension names, without a content check (recovery of a file whose
/// signature was damaged).
fn by_extension(file_name: &str) -> Option<&'static Format> {
    let (ext, _) = extensions_of(file_name);
    FORMATS.iter().copied().find(|f| f.has_extension(&ext))
}

/// The stream a level wraps: the only entry of a stream format, or a main entry.
fn inner_stream(lvl: &Level) -> Option<(Input, String)> {
    let a = &lvl.archive;
    let i = if a.format().stream {
        if a.entries().len() != 1 || a.entries()[0].is_dir {
            return None;
        }
        0
    } else {
        a.main_entry()?
    };
    let open = a.stream(i)?;
    let e = &a.entries()[i];
    Some((
        Input::Stream {
            open,
            size_hint: e.size,
        },
        e.name.clone(),
    ))
}

/// Name for the single entry of a stream format: the archive name minus its extension,
/// with `tgz`-style extensions mapped to `.tar`.
pub fn stream_entry_name(archive_name: &str, exts: &[&str], tar_exts: &[&str]) -> String {
    let base = archive_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(archive_name);
    if let Some((stem, ext)) = base.rsplit_once('.') {
        let ext_l = ext.to_ascii_lowercase();
        if tar_exts.contains(&ext_l.as_str()) {
            return format!("{stem}.tar");
        }
        if exts.contains(&ext_l.as_str()) && !stem.is_empty() {
            return stem.to_string();
        }
    }
    if base.is_empty() {
        "data".into()
    } else {
        format!("{base}~")
    }
}
