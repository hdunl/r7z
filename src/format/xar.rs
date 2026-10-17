//! xar archives (`.xar`, macOS `.pkg` and `.xip`): a binary header, a zlib-compressed XML
//! table of contents and a heap of independently encoded file data. One unit per file. The
//! decoded table of contents is exposed as `[TOC].xml`, as 7-Zip does.

use std::collections::HashMap;
use std::io::{self, Read};

use sha1::digest::DynDigest;

use super::Unit;
use super::{
    Archive, Columns, Ctx, Entry, EntryFn, Format, Input, Link, OpenOptions, Signature, Slice,
};
use crate::error::{Error, Result};

pub static FORMAT: Format = Format {
    name: "Xar",
    aliases: &[],
    extensions: &["xar", "pkg", "xip"],
    signatures: &[Signature::at(0, b"xar!\0")],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

const HEADER_MIN: usize = 28;
/// Largest table of contents accepted (decoded).
const MAX_TOC: u64 = 1 << 28;
/// Deepest element nesting accepted in the table of contents.
const MAX_DEPTH: usize = 256;
/// Memory limit for LZMA/XZ dictionaries, in KiB.
const LZMA_MEM_KB: u32 = 1 << 18;
const TOC_NAME: &str = "[TOC].xml";

mod xml {
    //! A small XML reader for xar tables of contents: elements, attributes, text, entity
    //! and character references, CDATA; declarations, comments and DOCTYPE are skipped.

    use crate::error::{Error, Result};

    #[derive(Debug, Default)]
    pub struct Node {
        pub name: String,
        pub attrs: Vec<(String, String)>,
        pub children: Vec<Node>,
        pub text: String,
    }

    impl Node {
        pub fn child(&self, name: &str) -> Option<&Node> {
            self.children.iter().find(|c| c.name == name)
        }

        pub fn attr(&self, name: &str) -> Option<&str> {
            self.attrs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        }

        /// Trimmed text of child `name`.
        pub fn text_of(&self, name: &str) -> Option<&str> {
            self.child(name).map(|c| c.text.trim())
        }
    }

    fn bad(msg: &str) -> Error {
        Error::corrupt(format!("xar table of contents: {msg}"))
    }

    fn decode_entities(s: &str, out: &mut String) {
        let mut rest = s;
        while let Some(amp) = rest.find('&') {
            out.push_str(&rest[..amp]);
            rest = &rest[amp..];
            let Some(semi) = rest.bytes().take(12).position(|c| c == b';') else {
                out.push('&');
                rest = &rest[1..];
                continue;
            };
            let ent = &rest[1..semi];
            let c = match ent {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => ent
                    .strip_prefix("#x")
                    .or_else(|| ent.strip_prefix("#X"))
                    .map(|h| u32::from_str_radix(h, 16))
                    .or_else(|| ent.strip_prefix('#').map(|d| d.parse::<u32>()))
                    .and_then(|r| r.ok())
                    .and_then(char::from_u32),
            };
            match c {
                Some(c) => {
                    out.push(c);
                    rest = &rest[semi + 1..];
                }
                None => {
                    out.push('&');
                    rest = &rest[1..];
                }
            }
        }
        out.push_str(rest);
    }

    fn is_name_char(c: char) -> bool {
        !c.is_whitespace() && !matches!(c, '/' | '>' | '=' | '<' | '"' | '\'')
    }

    /// Parses a document; the returned node is a nameless root holding the top element.
    pub fn parse(doc: &str) -> Result<Node> {
        let mut stack = vec![Node::default()];
        let mut rest = doc;
        while !rest.is_empty() {
            let Some(lt) = rest.find('<') else {
                decode_entities(rest, &mut stack.last_mut().unwrap().text);
                break;
            };
            decode_entities(&rest[..lt], &mut stack.last_mut().unwrap().text);
            rest = &rest[lt..];
            let skip_past = |r: &str, end: &str| r.find(end).map(|p| p + end.len());
            if let Some(body) = rest.strip_prefix("<![CDATA[") {
                let end = body.find("]]>").ok_or_else(|| bad("unterminated CDATA"))?;
                stack.last_mut().unwrap().text.push_str(&body[..end]);
                rest = &body[end + 3..];
            } else if rest.starts_with("<!--") {
                rest =
                    &rest[skip_past(rest, "-->").ok_or_else(|| bad("unterminated comment"))?..];
            } else if rest.starts_with("<?") {
                rest = &rest
                    [skip_past(rest, "?>").ok_or_else(|| bad("unterminated declaration"))?..];
            } else if rest.starts_with("<!") {
                // DOCTYPE, possibly with an internal subset in brackets.
                let mut depth = 0usize;
                let end = rest
                    .char_indices()
                    .find(|&(_, c)| {
                        match c {
                            '[' => depth += 1,
                            ']' => depth = depth.saturating_sub(1),
                            '>' if depth == 0 => return true,
                            _ => {}
                        }
                        false
                    })
                    .ok_or_else(|| bad("unterminated declaration"))?;
                rest = &rest[end.0 + 1..];
            } else if let Some(body) = rest.strip_prefix("</") {
                let end = body.find('>').ok_or_else(|| bad("unterminated end tag"))?;
                let name = body[..end].trim();
                if stack.len() < 2 || stack.last().unwrap().name != name {
                    return Err(bad("mismatched end tag"));
                }
                let node = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(node);
                rest = &body[end + 1..];
            } else {
                let body = &rest[1..];
                let name_len = body.find(|c| !is_name_char(c)).unwrap_or(body.len());
                if name_len == 0 {
                    return Err(bad("bad start tag"));
                }
                let mut node = Node {
                    name: body[..name_len].to_string(),
                    ..Default::default()
                };
                let mut b = &body[name_len..];
                let self_closing;
                loop {
                    b = b.trim_start();
                    if let Some(r) = b.strip_prefix("/>") {
                        self_closing = true;
                        b = r;
                        break;
                    }
                    if let Some(r) = b.strip_prefix('>') {
                        self_closing = false;
                        b = r;
                        break;
                    }
                    let key_len = b.find(|c| !is_name_char(c)).unwrap_or(b.len());
                    if key_len == 0 {
                        return Err(bad("bad attribute"));
                    }
                    let key = b[..key_len].to_string();
                    let r = b[key_len..]
                        .trim_start()
                        .strip_prefix('=')
                        .ok_or_else(|| bad("bad attribute"))?
                        .trim_start();
                    let quote = r.chars().next().filter(|&q| q == '"' || q == '\'');
                    let quote = quote.ok_or_else(|| bad("unquoted attribute"))?;
                    let end = r[1..]
                        .find(quote)
                        .ok_or_else(|| bad("unterminated attribute"))?;
                    let mut value = String::new();
                    decode_entities(&r[1..1 + end], &mut value);
                    node.attrs.push((key, value));
                    b = &r[end + 2..];
                }
                rest = b;
                if self_closing {
                    stack.last_mut().unwrap().children.push(node);
                } else {
                    if stack.len() > super::MAX_DEPTH {
                        return Err(bad("nesting is too deep"));
                    }
                    stack.push(node);
                }
            }
        }
        if stack.len() != 1 {
            return Err(bad("unclosed element"));
        }
        Ok(stack.pop().unwrap())
    }
}

use xml::Node;

/// How a file's heap data is encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Encoding {
    Stored,
    Zlib,
    Bzip2,
    Xz,
    Lzma,
    Unknown(String),
}

#[derive(Clone, Copy, Debug)]
enum HashKind {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashKind {
    fn of(style: &str) -> Option<HashKind> {
        match style.to_ascii_lowercase().as_str() {
            "md5" => Some(HashKind::Md5),
            "sha1" => Some(HashKind::Sha1),
            "sha256" => Some(HashKind::Sha256),
            "sha512" => Some(HashKind::Sha512),
            _ => None,
        }
    }

    fn hasher(self) -> Box<dyn DynDigest + Send> {
        match self {
            HashKind::Md5 => Box::new(md5::Md5::default()),
            HashKind::Sha1 => Box::new(sha1::Sha1::default()),
            HashKind::Sha256 => Box::new(sha2::Sha256::default()),
            HashKind::Sha512 => Box::new(sha2::Sha512::default()),
        }
    }
}

/// Where one entry's bytes come from.
enum Source {
    /// Heap data: archive-relative range, encoding, expected decoded digest.
    Heap {
        offset: u64,
        length: u64,
        encoding: Encoding,
        check: Option<(HashKind, Vec<u8>)>,
    },
    /// Bytes held in memory (symbolic link targets, the table of contents).
    Mem(Vec<u8>),
}

pub struct Xar {
    data: Slice,
    entries: Vec<Entry>,
    sources: Vec<Option<Source>>,
    units: Vec<Unit>,
    properties: Vec<(&'static str, String)>,
}

fn be(b: &[u8]) -> u64 {
    b.iter().fold(0, |v, &x| (v << 8) | u64::from(x))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses an ISO 8601 time (`2024-01-02T03:04:05[.fff][Z|+hh:mm]`) into a FILETIME.
fn parse_time(s: &str) -> Option<u64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut ticks = 0i64;
    if let Some(frac) = rest.strip_prefix(['.', ',']) {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        let digits = &frac[..n];
        let mut scaled = String::from(&digits[..digits.len().min(7)]);
        while scaled.len() < 7 {
            scaled.push('0');
        }
        ticks = scaled.parse().ok()?;
        rest = &frac[n..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let t = rest[1..].replace(':', "");
            if t.len() != 4 || !t.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            sign * (t[..2].parse::<i64>().ok()? * 3600 + t[2..].parse::<i64>().ok()? * 60)
        }
    };
    let unix = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset;
    let ft = (unix + 11_644_473_600)
        .checked_mul(10_000_000)?
        .checked_add(ticks)?;
    u64::try_from(ft).ok()
}

/// 7-Zip's name for an encoding style: `application/x-gzip` is zlib, others drop the
/// `application/` and `x-` prefixes.
fn method_name(style: &str) -> String {
    let s = style.strip_prefix("application/").unwrap_or(style);
    match s {
        "x-gzip" => "zlib".into(),
        _ => s.strip_prefix("x-").unwrap_or(s).into(),
    }
}

fn encoding_of(style: &str) -> Encoding {
    match style {
        "application/octet-stream" => Encoding::Stored,
        "application/x-gzip" => Encoding::Zlib,
        "application/x-bzip2" => Encoding::Bzip2,
        "application/x-xz" => Encoding::Xz,
        "application/x-lzma" => Encoding::Lzma,
        other => Encoding::Unknown(other.to_string()),
    }
}

/// Unix file type bits for a `<type>` value.
fn type_bits(t: &str) -> u32 {
    match t {
        "directory" => 0o040000,
        "symlink" => 0o120000,
        "fifo" => 0o010000,
        "character special" => 0o020000,
        "block special" => 0o060000,
        "socket" => 0o140000,
        _ => 0o100000,
    }
}

struct Builder<'a> {
    heap: u64,
    heap_end: u64,
    entries: Vec<Entry>,
    sources: Vec<Option<Source>>,
    /// `id` attribute to entry index, for hard links.
    ids: HashMap<&'a str, usize>,
    /// Entries that are hard links, with the target's id.
    hard: Vec<(usize, &'a str)>,
}

impl<'a> Builder<'a> {
    fn walk(&mut self, parent: &str, node: &'a Node) {
        for f in node.children.iter().filter(|c| c.name == "file") {
            let Some(name) = f.text_of("name").filter(|n| !n.is_empty()) else {
                continue;
            };
            let path = if parent.is_empty() {
                name.to_string()
            } else {
                format!("{parent}/{name}")
            };
            self.add(&path, f);
            self.walk(&path, f);
        }
    }

    fn add(&mut self, path: &str, f: &'a Node) {
        let index = self.entries.len();
        let type_node = f.child("type");
        let ty = type_node.map_or("file", |t| t.text.trim());
        let is_dir = ty == "directory";
        let mut e = Entry {
            name: path.to_string(),
            is_dir,
            mtime: f.text_of("mtime").and_then(parse_time),
            ctime: f.text_of("ctime").and_then(parse_time),
            atime: f.text_of("atime").and_then(parse_time),
            ..Default::default()
        };
        if let Some(mode) = f
            .text_of("mode")
            .and_then(|m| u32::from_str_radix(m, 8).ok())
        {
            let mode = (mode & 0o7777) | type_bits(ty);
            e.attrib = Some(0x8000 | (mode << 16) | if is_dir { 0x10 } else { 0 });
        }
        let mut source = None;
        if let Some(d) = f.child("data").filter(|_| !is_dir) {
            let num = |n: &str| d.text_of(n).and_then(|v| v.parse::<u64>().ok());
            let style = d
                .child("encoding")
                .and_then(|n| n.attr("style"))
                .unwrap_or("application/octet-stream");
            let offset = num("offset").unwrap_or(0);
            let length = num("length").unwrap_or(0);
            let checksum = |n: &str| -> (String, Option<(HashKind, Vec<u8>)>) {
                match d.child(n) {
                    Some(c) => {
                        let style = c.attr("style").unwrap_or("");
                        let check = HashKind::of(style).zip(hex_bytes(&c.text));
                        (style.to_string(), check)
                    }
                    None => ("NO-CHECKSUM".into(), None),
                }
            };
            let (archived, _) = checksum("archived-checksum");
            let (extracted, check) = checksum("extracted-checksum");
            e.size = num("size");
            e.packed_size = Some(length);
            e.method = Some(format!("{} {archived} {extracted}", method_name(style)));
            self.heap_end = self
                .heap_end
                .max(self.heap.saturating_add(offset).saturating_add(length));
            source = Some(Source::Heap {
                offset: self.heap.saturating_add(offset),
                length,
                encoding: encoding_of(style),
                check,
            });
        } else if ty == "symlink" {
            if let Some(target) = f.text_of("link") {
                e.link = Some(Link::Symbolic(target.to_string()));
                source = Some(Source::Mem(target.as_bytes().to_vec()));
            }
        }
        if ty == "hardlink" {
            if let Some(target) = type_node
                .and_then(|t| t.attr("link"))
                .filter(|l| *l != "original")
            {
                if source.is_none() {
                    self.hard.push((index, target));
                }
            }
        }
        if let Some(id) = f.attr("id") {
            self.ids.entry(id).or_insert(index);
        }
        self.entries.push(e);
        self.sources.push(source);
    }
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let data = input.into_mem()?;
    if data.len() < HEADER_MIN || !data.starts_with(b"xar!") {
        return Err(Error::NotArchive);
    }
    let header_size = be(&data[4..6]) as usize;
    let toc_packed = be(&data[8..16]);
    let toc_size = be(&data[16..24]);
    let check_alg = be(&data[24..28]);
    if header_size < HEADER_MIN || header_size > data.len() {
        return Err(Error::corrupt("bad xar header size"));
    }
    let heap = (header_size as u64)
        .checked_add(toc_packed)
        .filter(|&h| h <= data.len() as u64)
        .ok_or_else(|| Error::corrupt("xar table of contents is truncated"))?;
    let packed = data.sub(header_size as u64..heap)?;
    let mut toc = Vec::new();
    let limit = toc_size.min(MAX_TOC);
    let mut z = flate2::read::ZlibDecoder::new(packed.reader()).take(limit + 1);
    z.read_to_end(&mut toc).map_err(super::data::data_err)?;
    if toc.len() as u64 != toc_size {
        return Err(Error::corrupt("xar table of contents has the wrong size"));
    }
    let doc = String::from_utf8_lossy(&toc).into_owned();
    let root = xml::parse(&doc)?;
    let toc_node = root
        .child("xar")
        .and_then(|x| x.child("toc"))
        .ok_or_else(|| Error::corrupt("xar table of contents has no <toc>"))?;

    let mut b = Builder {
        heap,
        heap_end: heap,
        entries: Vec::new(),
        sources: Vec::new(),
        ids: HashMap::new(),
        hard: Vec::new(),
    };

    // The table of contents checksum is stored in the heap.
    let toc_check = toc_node.child("checksum");
    let check_name = match check_alg {
        0 => "NONE".to_string(),
        1 => "SHA1".to_string(),
        2 => "MD5".to_string(),
        _ => toc_check
            .and_then(|c| c.attr("style"))
            .unwrap_or("")
            .to_ascii_uppercase(),
    };
    if let Some(c) = toc_check.filter(|_| check_alg != 0) {
        let num = |n: &str| c.text_of(n).and_then(|v| v.parse::<u64>().ok());
        if let (Some(kind), Some(off), Some(size)) = (
            c.attr("style").and_then(HashKind::of),
            num("offset"),
            num("size"),
        ) {
            let start = heap.saturating_add(off);
            let stored = data.sub(start..start.saturating_add(size))?;
            let mut h = kind.hasher();
            h.update(&packed);
            if *h.finalize() != *stored {
                return Err(Error::Checksum("xar table of contents".into()));
            }
            b.heap_end = b.heap_end.max(start + size);
        }
    }

    b.walk("", toc_node);
    for (i, target) in std::mem::take(&mut b.hard) {
        if let Some(&t) = b.ids.get(target) {
            if t != i {
                b.entries[i].link = Some(Link::Hard(b.entries[t].name.clone()));
            }
        }
    }
    let Builder {
        heap_end,
        mut entries,
        mut sources,
        ..
    } = b;
    let toc_len = toc.len() as u64;
    entries.push(Entry {
        name: TOC_NAME.into(),
        size: Some(toc_len),
        packed_size: Some(toc_len),
        ..Default::default()
    });
    sources.push(Some(Source::Mem(toc)));

    let units = sources
        .iter()
        .enumerate()
        .filter(|(i, s)| match s {
            Some(Source::Heap { .. }) => entries[*i].size != Some(0),
            Some(Source::Mem(m)) => !m.is_empty(),
            None => false,
        })
        .map(|(i, _)| Unit {
            entries: vec![i],
            encrypted: false,
        })
        .collect();

    let mut properties = vec![("Physical Size", heap_end.to_string())];
    if (data.len() as u64) > heap_end {
        properties.push(("Tail Size", (data.len() as u64 - heap_end).to_string()));
    }
    properties.push(("Method", check_name));
    if let Some(t) = toc_node.text_of("creation-time") {
        properties.push(("Created", t.to_string()));
    }
    Ok(Box::new(Xar {
        data,
        entries,
        sources,
        units,
        properties,
    }))
}

/// Limits decoded output to the recorded size and, once the last byte (or the end of the
/// data, when no size is recorded) has been read, checks that the encoded stream ends there
/// and that the extracted digest matches.
struct Verify<R> {
    inner: R,
    left: Option<u64>,
    check: Option<(Box<dyn DynDigest + Send>, Vec<u8>)>,
    done: bool,
}

impl<R: Read> Verify<R> {
    fn finish(&mut self) -> io::Result<()> {
        if std::mem::replace(&mut self.done, true) {
            return Ok(());
        }
        if self.left.is_some() && self.inner.read(&mut [0u8; 1])? != 0 {
            return Err(Error::corrupt("xar file data is longer than its recorded size").into_io());
        }
        if let Some((h, want)) = self.check.take() {
            if *h.finalize() != *want {
                return Err(Error::Checksum("xar extracted checksum".into()).into_io());
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for Verify<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = match self.left {
            Some(0) => {
                self.finish()?;
                return Ok(0);
            }
            Some(l) => buf.len().min(usize::try_from(l).unwrap_or(usize::MAX)),
            None => buf.len(),
        };
        let n = self.inner.read(&mut buf[..want])?;
        if let Some((h, _)) = self.check.as_mut() {
            h.update(&buf[..n]);
        }
        if let Some(l) = self.left.as_mut() {
            *l -= n as u64;
        }
        if n == 0 && want > 0 && self.left.is_none() || self.left == Some(0) {
            self.finish()?;
        }
        Ok(n)
    }
}

impl Xar {
    fn decoder<'a>(&'a self, source: &'a Source) -> Result<Box<dyn Read + 'a>> {
        Ok(match source {
            Source::Mem(m) => Box::new(m.as_slice()),
            Source::Heap {
                offset,
                length,
                encoding,
                ..
            } => {
                let raw = self
                    .data
                    .sub(*offset..offset.saturating_add(*length))
                    .map_err(|_| Error::corrupt("xar file data is past the end of the archive"))?
                    .reader();
                match encoding {
                    Encoding::Stored => Box::new(raw),
                    Encoding::Zlib => Box::new(flate2::read::ZlibDecoder::new(raw)),
                    Encoding::Bzip2 => Box::new(bzip2::read::BzDecoder::new(raw)),
                    Encoding::Xz => {
                        Box::new(lzma_rust2::XzReader::new_mem_limit(raw, true, LZMA_MEM_KB))
                    }
                    Encoding::Lzma => Box::new(
                        lzma_rust2::LzmaReader::new_mem_limit(raw, LZMA_MEM_KB, None)
                            .map_err(super::data::data_err)?,
                    ),
                    Encoding::Unknown(style) => {
                        return Err(Error::unsupported(format!("xar encoding {style}")))
                    }
                }
            }
        })
    }
}

impl Archive for Xar {
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
        let Some(source) = &self.sources[i] else {
            return Ok(());
        };
        let check = match source {
            Source::Heap {
                check: Some((kind, want)),
                ..
            } => Some((kind.hasher(), want.clone())),
            _ => None,
        };
        let mut r = Verify {
            inner: self.decoder(source)?,
            left: self.entries[i].size,
            check,
            done: false,
        };
        f(i, &mut r)?;
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

    fn verifies_data(&self) -> bool {
        true
    }
}
