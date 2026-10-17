//! The preview pane's loader: images, text, hex, and summaries of archives (including
//! archives inside archives). Loading runs as a cancellable task; changing the selection
//! drops the old task.

use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui::{self, ColorImage, TextureHandle, TextureOptions};
use r7z::error::{Error, Result};
use r7z::format::{self, Archive, OpenRequest, Opened};
use r7z::ops::inspect::{inspect, Finding};

use crate::icons::{classify, extension, FileClass};
use crate::jobs::Task;
use crate::model::{Tree, ROOT};

/// Above this size nothing is decoded until the user asks.
pub const AUTO_LIMIT: u64 = 48 << 20;
const IMAGE_READ_LIMIT: usize = 96 << 20;
const TEXT_READ_LIMIT: usize = 384 << 10;
const MAX_TEXTURE: u32 = 2048;

#[derive(Clone)]
pub enum Source {
    Disk(PathBuf),
    Entry {
        archive: Arc<dyn Archive>,
        index: usize,
        password: Option<String>,
    },
}

pub struct ArchiveSummary {
    pub chain: String,
    pub files: u64,
    pub dirs: usize,
    pub unpacked: u64,
    pub packed: u64,
    pub top: Vec<(String, bool)>,
    pub more: usize,
    pub findings: Vec<Finding>,
    pub encrypted: bool,
}

pub enum Body {
    Image {
        rgba: Vec<u8>,
        w: u32,
        h: u32,
        orig: (u32, u32),
    },
    Text {
        text: String,
        lines: usize,
        truncated: bool,
    },
    Hex {
        text: String,
        truncated: bool,
    },
    Archive(ArchiveSummary),
    Locked,
    Empty,
}

pub struct Digest {
    pub sha256: String,
    pub crc32: String,
    /// Only computed when a pasted hash asks for them.
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

impl Digest {
    pub fn get(&self, algo: Algo) -> Option<&str> {
        match algo {
            Algo::Sha256 => Some(&self.sha256),
            Algo::Crc32 => Some(&self.crc32),
            Algo::Sha1 => self.sha1.as_deref(),
            Algo::Md5 => self.md5.as_deref(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha256,
    Sha1,
    Md5,
    Crc32,
}

impl Algo {
    pub fn name(self) -> &'static str {
        match self {
            Algo::Sha256 => "SHA-256",
            Algo::Sha1 => "SHA-1",
            Algo::Md5 => "MD5",
            Algo::Crc32 => "CRC32",
        }
    }

    fn from_len(n: usize) -> Option<Algo> {
        match n {
            64 => Some(Algo::Sha256),
            40 => Some(Algo::Sha1),
            32 => Some(Algo::Md5),
            8 => Some(Algo::Crc32),
            _ => None,
        }
    }

    /// A checksum tool's label (`SHA256`, `sha-1`, `MD5`). `Err` names one that is
    /// recognized but not computed here; `Ok(None)` is a label that isn't a hash name.
    fn from_label(label: &str) -> std::result::Result<Option<Algo>, String> {
        let l: String = label
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase();
        Ok(Some(match l.as_str() {
            "SHA256" | "SHA2256" => Algo::Sha256,
            "SHA1" => Algo::Sha1,
            "MD5" => Algo::Md5,
            "CRC32" | "CRC" => Algo::Crc32,
            "SHA224" | "SHA384" | "SHA512" | "SHA512224" | "SHA512256" | "SHA3256" | "SHA3512"
            | "BLAKE2B" | "BLAKE2S" | "BLAKE3" | "XXH64" | "XXH3" | "CRC64" => {
                return Err(format!("{label} isn't supported here. {SUPPORTED}"))
            }
            _ => return Ok(None),
        }))
    }
}

const SUPPORTED: &str = "Paste a SHA-256, SHA-1, MD5 or CRC32 hash.";

/// A pasted checksum, read by `parse_expected`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub algo: Algo,
    /// Lowercase hex.
    pub hex: String,
    /// The file the pasted line names, if it names one.
    pub name: Option<String>,
}

impl Expected {
    pub fn matches(&self, actual: &str) -> bool {
        self.hex.eq_ignore_ascii_case(actual)
    }

    /// Whether the pasted line names `file_name` (or names nothing).
    pub fn is_for(&self, file_name: &str) -> bool {
        self.name.as_deref().is_none_or(|n| {
            let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
            base.eq_ignore_ascii_case(file_name)
        })
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hash_from(
    hex: &str,
    label: Option<Algo>,
    name: Option<String>,
) -> std::result::Result<Expected, String> {
    let Some(algo) = Algo::from_len(hex.len()) else {
        return Err(match hex.len() {
            96 => format!("That looks like SHA-384, which isn't supported here. {SUPPORTED}"),
            128 => format!("That looks like SHA-512, which isn't supported here. {SUPPORTED}"),
            n => format!("That has {n} hex digits; SHA-256 has 64, SHA-1 40, MD5 32 and CRC32 8."),
        });
    };
    if let Some(l) = label.filter(|&l| l != algo) {
        return Err(format!(
            "It says {} but has {} hex digits, the length of {}.",
            l.name(),
            hex.len(),
            algo.name()
        ));
    }
    Ok(Expected {
        algo,
        hex: hex.to_ascii_lowercase(),
        name: name.filter(|n| !n.is_empty()),
    })
}

/// One line: `SHA256 (name) = hex` (BSD and `shasum --tag`), `hex  name` or `hex *name`
/// (sha256sum), a bare hash (spaces between groups are fine), or failing those, the
/// longest hash-length hex run on the line, as in `SHA-256: hex`.
fn parse_line(line: &str) -> Option<std::result::Result<Expected, String>> {
    let line = line.trim().trim_start_matches('\u{feff}');
    if line.is_empty() {
        return None;
    }
    if let Some((head, hex)) = line.rsplit_once('=') {
        let (head, hex) = (head.trim_end(), hex.trim());
        if let (Some(open), true, true) = (head.find('('), head.ends_with(')'), is_hex(hex)) {
            let label = match Algo::from_label(head[..open].trim()) {
                Ok(l) => l,
                Err(e) => return Some(Err(e)),
            };
            let name = head[open + 1..head.len() - 1].to_string();
            return Some(hash_from(hex, label, Some(name)));
        }
    }
    let (first, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let mut label = None;
    let mut hex = first;
    if let Some((l, h)) = first.split_once(':') {
        match Algo::from_label(l) {
            Ok(Some(a)) => {
                label = Some(a);
                hex = h;
            }
            Ok(None) => {}
            Err(e) => return Some(Err(e)),
        }
    }
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    if is_hex(hex) && Algo::from_len(hex.len()).is_some() {
        let name = rest.trim().trim_start_matches('*').to_string();
        return Some(hash_from(hex, label, Some(name)));
    }
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if is_hex(&compact) {
        return Some(hash_from(&compact, None, None));
    }
    let best = line
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| is_hex(t) && Algo::from_len(t.len()).is_some())
        .max_by_key(|t| t.len());
    Some(match best {
        Some(t) => hash_from(t, None, None),
        None => Err(SUPPORTED.to_string()),
    })
}

/// Reads pasted checksum text for the file `file_name`. With several lines (a pasted
/// SHA256SUMS list), the line naming the file is used, else the first that reads.
/// `None` when there is nothing to read.
pub fn parse_expected(
    text: &str,
    file_name: &str,
) -> Option<std::result::Result<Expected, String>> {
    let mut first_ok = None;
    let mut first_err = None;
    let mut lines = 0;
    for r in text.lines().filter_map(parse_line) {
        lines += 1;
        match r {
            Ok(e) if e.name.is_some() && e.is_for(file_name) => return Some(Ok(e)),
            Ok(e) => {
                first_ok.get_or_insert(e);
            }
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    match (first_ok, first_err) {
        (Some(e), _) if lines > 1 && e.name.is_some() => {
            Some(Err(format!("None of the pasted lines is for {file_name}.")))
        }
        (Some(e), _) => Some(Ok(e)),
        (None, Some(e)) => Some(Err(e)),
        (None, None) => None,
    }
}

#[derive(Default)]
pub struct Preview {
    pub key: Option<String>,
    task: Option<Task<Body>>,
    pub body: Option<std::result::Result<Body, String>>,
    pub texture: Option<TextureHandle>,
    pub waiting_for_user: bool,
    hash_task: Option<Task<Digest>>,
    /// What the running hash task computes besides SHA-256 and CRC32.
    hashing_extra: Vec<Algo>,
    pub digest: Option<std::result::Result<Digest, String>>,
    source: Option<(Source, String)>,
    /// The hash pasted to check against; kept when the selection changes.
    pub expected: String,
    /// When that text was last edited, until the check it asks for has started.
    pub expected_edit: Option<std::time::Instant>,
}

impl Preview {
    pub fn loading(&self) -> bool {
        self.task.is_some()
    }

    pub fn hashing(&self) -> bool {
        self.hash_task.is_some()
    }

    pub fn clear(&mut self) {
        let expected = std::mem::take(&mut self.expected);
        *self = Preview {
            expected,
            ..Preview::default()
        };
    }

    /// Shows `source`; a no-op when `key` is already shown.
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        key: String,
        source: Source,
        name: &str,
        size: Option<u64>,
    ) {
        if self.key.as_deref() == Some(key.as_str()) {
            return;
        }
        self.clear();
        self.key = Some(key);
        self.source = Some((source, name.to_string()));
        if size.unwrap_or(0) > AUTO_LIMIT {
            self.waiting_for_user = true;
        } else {
            self.start(ctx);
        }
    }

    pub fn start(&mut self, ctx: &egui::Context) {
        let Some((source, name)) = self.source.clone() else {
            return;
        };
        self.waiting_for_user = false;
        self.task = Some(Task::spawn(ctx, move |cancel| load(&source, &name, cancel)));
    }

    pub fn start_hash(&mut self, ctx: &egui::Context) {
        self.hash_with(ctx, Vec::new());
    }

    /// Makes sure `algo` gets computed: does nothing when it is done or on its way,
    /// otherwise hashes again with it added to what was asked for before.
    pub fn ensure_hash(&mut self, ctx: &egui::Context, algo: Algo) {
        let have = matches!(&self.digest, Some(Ok(d)) if d.get(algo).is_some());
        let coming = self.hash_task.is_some()
            && (matches!(algo, Algo::Sha256 | Algo::Crc32) || self.hashing_extra.contains(&algo));
        if have || coming {
            return;
        }
        let mut extra = self.hashing_extra.clone();
        if let Some(Ok(d)) = &self.digest {
            extra.extend(d.sha1.as_ref().map(|_| Algo::Sha1));
            extra.extend(d.md5.as_ref().map(|_| Algo::Md5));
        }
        extra.push(algo);
        extra.retain(|a| matches!(a, Algo::Sha1 | Algo::Md5));
        extra.dedup();
        self.hash_with(ctx, extra);
    }

    fn hash_with(&mut self, ctx: &egui::Context, extra: Vec<Algo>) {
        let Some((source, _)) = self.source.clone() else {
            return;
        };
        self.hashing_extra = extra.clone();
        self.hash_task = Some(Task::spawn(ctx, move |cancel| {
            digest(&source, &extra, cancel)
        }));
    }

    pub fn poll(&mut self, ctx: &egui::Context) {
        if let Some(r) = self.task.as_mut().and_then(|t| t.take()) {
            self.task = None;
            match r {
                Ok(Body::Image { rgba, w, h, orig }) => {
                    let img = ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
                    self.texture = Some(ctx.load_texture("preview", img, TextureOptions::LINEAR));
                    self.body = Some(Ok(Body::Image {
                        rgba: Vec::new(),
                        w,
                        h,
                        orig,
                    }));
                }
                Ok(b) => self.body = Some(Ok(b)),
                Err(Error::PasswordRequired) | Err(Error::WrongPassword) => {
                    self.body = Some(Ok(Body::Locked))
                }
                Err(e) => self.body = Some(Err(e.to_string())),
            }
        }
        if let Some(r) = self.hash_task.as_mut().and_then(|t| t.take()) {
            self.hash_task = None;
            self.hashing_extra.clear();
            self.digest = Some(r.map_err(|e| e.to_string()));
        }
    }
}

fn read_prefix(source: &Source, limit: usize, cancel: &AtomicBool) -> Result<(Vec<u8>, bool)> {
    match source {
        Source::Disk(p) => {
            let f = std::fs::File::open(p)?;
            let len = f.metadata()?.len();
            let mut data = Vec::with_capacity((len as usize).min(limit));
            f.take(limit as u64).read_to_end(&mut data)?;
            Ok((data, len > limit as u64))
        }
        Source::Entry {
            archive,
            index,
            password,
        } => {
            let p = r7z::ops::peek::read_entry(
                &**archive,
                *index,
                password.as_deref(),
                limit,
                &|| cancel.load(Ordering::Relaxed),
            )?;
            Ok((p.data, p.truncated))
        }
    }
}

const IMAGE_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "tif", "tiff",
];

fn load(source: &Source, name: &str, cancel: &AtomicBool) -> Result<Body> {
    let ext = extension(name);
    if IMAGE_EXTS.contains(&ext.as_str()) {
        let (data, truncated) = read_prefix(source, IMAGE_READ_LIMIT, cancel)?;
        if !truncated {
            if let Ok(img) = decode_image(&data) {
                return Ok(img);
            }
        }
        return Ok(hex_body(&data, truncated));
    }
    if classify(name) == FileClass::Archive
        || (matches!(source, Source::Disk(_)) && looks_like_archive(source))
    {
        if let Some(summary) = summarize_archive(source, name, cancel)? {
            return Ok(Body::Archive(summary));
        }
    }
    let (data, truncated) = read_prefix(source, TEXT_READ_LIMIT, cancel)?;
    if data.is_empty() {
        return Ok(Body::Empty);
    }
    Ok(match as_text(&data) {
        Some(text) => {
            let lines = text.lines().count();
            Body::Text {
                text,
                lines,
                truncated,
            }
        }
        None => hex_body(&data, truncated),
    })
}

fn looks_like_archive(source: &Source) -> bool {
    let Source::Disk(p) = source else {
        return false;
    };
    let mut head = vec![0u8; 1 << 12];
    let n = std::fs::File::open(p)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    head.truncate(n);
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format::detect_format(&head, &name).is_some()
}

fn decode_image(data: &[u8]) -> std::result::Result<Body, String> {
    let mut reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| e.to_string())?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(24_000);
    limits.max_image_height = Some(24_000);
    limits.max_alloc = Some(768 << 20);
    reader.limits(limits);
    let img = reader.decode().map_err(|e| e.to_string())?;
    let orig = (img.width(), img.height());
    let img = if img.width() > MAX_TEXTURE || img.height() > MAX_TEXTURE {
        img.thumbnail(MAX_TEXTURE, MAX_TEXTURE)
    } else {
        img
    };
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    Ok(Body::Image {
        rgba: rgba.into_raw(),
        w,
        h,
        orig,
    })
}

fn as_text(data: &[u8]) -> Option<String> {
    if data.starts_with(&[0xFF, 0xFE]) || data.starts_with(&[0xFE, 0xFF]) {
        let le = data[0] == 0xFF;
        let units: Vec<u16> = data[2..]
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        return Some(String::from_utf16_lossy(&units));
    }
    let sample = &data[..data.len().min(16 << 10)];
    if sample.contains(&0) {
        return None;
    }
    let control = sample
        .iter()
        .filter(|&&b| b < 0x09 || (0x0E..0x20).contains(&b))
        .count();
    if control * 50 > sample.len() {
        return None;
    }
    let body = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
    let text = String::from_utf8_lossy(body);
    let bad = text.chars().filter(|&c| c == '\u{FFFD}').count();
    if bad * 100 > text.len().max(1) {
        return None;
    }
    Some(text.replace("\r\n", "\n").replace('\t', "    "))
}

fn hex_body(data: &[u8], truncated: bool) -> Body {
    let shown = &data[..data.len().min(4096)];
    let mut text = String::with_capacity(shown.len() * 4);
    for (row, chunk) in shown.chunks(16).enumerate() {
        text.push_str(&format!("{:08X}  ", row * 16));
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => text.push_str(&format!("{b:02X} ")),
                None => text.push_str("   "),
            }
            if i == 7 {
                text.push(' ');
            }
        }
        text.push(' ');
        for &b in chunk {
            text.push(if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '·'
            });
        }
        text.push('\n');
    }
    Body::Hex {
        text,
        truncated: truncated || data.len() > shown.len(),
    }
}

fn summarize(opened: &Opened, physical: u64) -> ArchiveSummary {
    let a = opened.archive();
    let tree = Tree::build(a.entries(), "");
    let root = &tree.nodes[ROOT];
    let mut top: Vec<(String, bool)> = root
        .children
        .iter()
        .map(|&c| (tree.nodes[c].name.clone(), tree.nodes[c].is_dir))
        .collect();
    top.sort_by(|x, y| {
        y.1.cmp(&x.1)
            .then_with(|| crate::model::natural_cmp(&x.0, &y.0))
    });
    let more = top.len().saturating_sub(12);
    top.truncate(12);
    ArchiveSummary {
        chain: opened
            .levels
            .iter()
            .map(|l| l.archive.format().name)
            .collect::<Vec<_>>()
            .join(" › "),
        files: root.files,
        dirs: tree.dir_count(),
        unpacked: root.size,
        packed: physical,
        top,
        more,
        findings: inspect(a.entries(), Some(physical)),
        encrypted: a.has_encrypted_data(),
    }
}

/// Opens an archive file (or entry) far enough to describe it. Large stream-compressed
/// files are skipped, since listing them means decompressing everything.
fn summarize_archive(
    source: &Source,
    name: &str,
    cancel: &AtomicBool,
) -> Result<Option<ArchiveSummary>> {
    let ext = extension(name);
    let stream = matches!(
        ext.as_str(),
        "gz" | "tgz" | "bz2" | "tbz2" | "xz" | "txz" | "zst" | "lz4" | "lzma" | "z"
    );
    match source {
        Source::Disk(p) => {
            let size = std::fs::metadata(p)?.len();
            if stream && size > (256 << 20) {
                return Ok(None);
            }
            match format::open(p, &OpenRequest::default()) {
                Ok(o) => Ok(Some(summarize(&o, size))),
                Err(Error::PasswordRequired) => Err(Error::PasswordRequired),
                Err(_) => Ok(None),
            }
        }
        Source::Entry {
            archive,
            index,
            password,
        } => {
            let size = archive.entries()[*index].size_or_zero();
            if size > AUTO_LIMIT {
                return Ok(None);
            }
            let p = r7z::ops::peek::read_entry(
                &**archive,
                *index,
                password.as_deref(),
                usize::MAX,
                &|| cancel.load(Ordering::Relaxed),
            )?;
            match format::open_bytes(p.data, name, &OpenRequest::default()) {
                Ok(o) => Ok(Some(summarize(&o, size))),
                Err(_) => Ok(None),
            }
        }
    }
}

fn digest(source: &Source, extra: &[Algo], cancel: &AtomicBool) -> Result<Digest> {
    use sha2::Digest as _;
    let mut sha = sha2::Sha256::new();
    let mut crc = crc32fast::Hasher::new();
    let mut sha1 = extra.contains(&Algo::Sha1).then(sha1::Sha1::new);
    let mut md5 = extra.contains(&Algo::Md5).then(md5::Md5::new);
    let mut feed = |b: &[u8]| {
        sha.update(b);
        crc.update(b);
        if let Some(h) = sha1.as_mut() {
            h.update(b);
        }
        if let Some(h) = md5.as_mut() {
            h.update(b);
        }
    };
    match source {
        Source::Disk(p) => {
            let mut f = std::fs::File::open(p)?;
            let mut buf = vec![0u8; 1 << 20];
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                feed(&buf[..n]);
            }
        }
        Source::Entry {
            archive,
            index,
            password,
        } => {
            r7z::ops::peek::stream_entry(
                &**archive,
                *index,
                password.as_deref(),
                &|| cancel.load(Ordering::Relaxed),
                &mut |b| {
                    feed(b);
                    Ok(())
                },
            )?;
        }
    }
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                s.push_str(&format!("{b:02x}"));
                s
            })
    };
    Ok(Digest {
        sha256: hex(&sha.finalize()),
        crc32: format!("{:08X}", crc.finalize()),
        sha1: sha1.map(|h| hex(&h.finalize())),
        md5: md5.map(|h| hex(&h.finalize())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> std::result::Result<Expected, String> {
        parse_expected(text, "app-1.2.zip").unwrap()
    }

    const SHA256: &str = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";

    #[test]
    fn pasted_hashes_by_length() {
        assert_eq!(parse(SHA256).unwrap().algo, Algo::Sha256);
        assert_eq!(parse(SHA256).unwrap().hex, SHA256.to_ascii_lowercase());
        let sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        assert_eq!(parse(sha1).unwrap().algo, Algo::Sha1);
        let md5 = "098F6BCD4621D373CADE4E832627B4F6";
        assert_eq!(parse(md5).unwrap().algo, Algo::Md5);
        assert_eq!(parse("d87f7e0c").unwrap().algo, Algo::Crc32);
        assert_eq!(parse("0xD87F7E0C").unwrap().hex, "d87f7e0c");
        assert_eq!(parse("  d87f 7e0c \n").unwrap().hex, "d87f7e0c");
        assert!(parse_expected("   \n ", "x").is_none());
        assert!(parse("not a hash").is_err());
        assert!(parse("abc123").unwrap_err().contains("6 hex digits"));
        assert!(parse(&"ab".repeat(64)).unwrap_err().contains("SHA-512"));
    }

    #[test]
    fn pasted_checksum_lines() {
        let bsd = format!("SHA256 (app-1.2.zip) = {SHA256}");
        let e = parse(&bsd).unwrap();
        assert_eq!(
            (e.algo, e.name.as_deref()),
            (Algo::Sha256, Some("app-1.2.zip"))
        );
        let gnu = format!("{}  app-1.2.zip", SHA256.to_ascii_lowercase());
        assert_eq!(parse(&gnu).unwrap().name.as_deref(), Some("app-1.2.zip"));
        let binary = format!("{SHA256} *dist/app-1.2.zip");
        let e = parse(&binary).unwrap();
        assert_eq!(e.name.as_deref(), Some("dist/app-1.2.zip"));
        assert!(e.is_for("APP-1.2.ZIP"));
        assert!(!e.is_for("other.zip"));
        let web = format!("SHA-256: {SHA256}");
        assert_eq!(parse(&web).unwrap().algo, Algo::Sha256);
        let tagged = "md5:098f6bcd4621d373cade4e832627b4f6";
        assert_eq!(parse(tagged).unwrap().algo, Algo::Md5);
        // The label has to agree with the length.
        let wrong = format!("MD5 (app-1.2.zip) = {SHA256}");
        assert!(parse(&wrong).unwrap_err().contains("says MD5"));
        let sha512 = format!("SHA512 (app-1.2.zip) = {}", "ab".repeat(64));
        assert!(parse(&sha512)
            .unwrap_err()
            .contains("SHA512 isn't supported"));
        // A name with an equals sign in it.
        let odd = format!(
            "SHA1 (a=b.zip) = {}",
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        );
        assert_eq!(parse(&odd).unwrap().name.as_deref(), Some("a=b.zip"));
    }

    #[test]
    fn pasted_lists_pick_the_selected_file() {
        let other = "1".repeat(64);
        let list = format!("{other}  app-1.1.zip\n{SHA256}  app-1.2.zip\n");
        let e = parse(&list).unwrap();
        assert_eq!(e.hex, SHA256.to_ascii_lowercase());
        let none = format!("{other}  app-1.1.zip\n{other}  app-1.0.zip\n");
        assert!(parse(&none).unwrap_err().contains("app-1.2.zip"));
        // A single line naming another file is still read; the pane says whose it is.
        let single = format!("{other}  app-1.1.zip");
        assert!(!parse(&single).unwrap().is_for("app-1.2.zip"));
    }

    #[test]
    fn matching_ignores_case() {
        let e = parse("d87f7e0c").unwrap();
        assert!(e.matches("D87F7E0C"));
        assert!(!e.matches("D87F7E0D"));
    }

    #[test]
    fn digest_computes_what_is_asked() {
        let dir = std::env::temp_dir().join(format!("r7z-digest-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("test.txt");
        std::fs::write(&f, b"test").unwrap();
        let src = Source::Disk(f);
        let stop = AtomicBool::new(false);
        let d = digest(&src, &[], &stop).unwrap();
        assert_eq!(d.sha256, SHA256.to_ascii_lowercase());
        assert_eq!(d.crc32, "D87F7E0C");
        assert!(d.sha1.is_none() && d.md5.is_none());
        let d = digest(&src, &[Algo::Sha1, Algo::Md5], &stop).unwrap();
        assert_eq!(
            d.get(Algo::Sha1),
            Some("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
        );
        assert_eq!(d.get(Algo::Md5), Some("098f6bcd4621d373cade4e832627b4f6"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn text_detection() {
        assert!(as_text(b"hello\nworld\n").is_some());
        assert!(as_text(&[0x00, 0x01, 0x02, 0x03]).is_none());
        assert!(as_text(&[0xFF, 0xFE, b'h', 0, b'i', 0])
            .unwrap()
            .starts_with("hi"));
    }

    #[test]
    fn hex_layout() {
        match hex_body(b"ABCDEFGHIJKLMNOPQ", false) {
            Body::Hex { text, .. } => {
                assert!(text.starts_with("00000000  41 42"));
                assert_eq!(text.lines().count(), 2);
            }
            _ => panic!("expected hex"),
        }
    }
}
