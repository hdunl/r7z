//! Apple disk images (UDIF, `.dmg`): the `koly` trailer, the XML property list whose
//! `blkx` entries hold block tables (`mish`), and the partitions those tables describe.
//!
//! Each non-empty partition is one entry that opens as a volume. A partition reads through
//! a random-access view: a chunk is decoded when a read reaches it, and a partition keeps
//! only its last couple of decoded chunks. Nothing decodes a whole image into memory.
//!
//! Supported: raw, zero-fill and ignore chunks, ADC, zlib, bzip2 and LZFSE chunks, and an
//! uncompressed or compressed image of one segment. Not supported: encrypted images (the
//! `encrcdsa` header), segmented images, and XZ chunks. Checksums are not verified; see
//! [`Archive::verifies_data`].

use std::io::Read;
use std::sync::{Arc, Mutex, PoisonError};

use super::{Archive, Ctx, Entry, EntryFn, Format, Input, OpenOptions, ReadAt, Runs, Unit};
use crate::codec::{adc, lzfse};
use crate::error::{Error, Result};
use plist::Value;

pub const FORMAT: Format = Format {
    name: "Dmg",
    aliases: &["udif"],
    extensions: &["dmg"],
    signatures: &[],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

const SECTOR: u64 = 512;
const TRAILER_LEN: u64 = 512;
const MISH_HEADER: usize = 204;
const MISH_RUN: usize = 40;
/// Largest decoded chunk accepted, in bytes.
const MAX_CHUNK: u64 = 64 << 20;
/// Largest compressed chunk accepted, in bytes.
const MAX_PACKED: u64 = 2 * MAX_CHUNK;
/// Largest property list accepted, in bytes.
const MAX_PLIST: u64 = 64 << 20;
/// Decoded chunks kept per partition.
const CACHE_SLOTS: usize = 2;
/// The header of an encrypted image, at offset 0.
const ENCRYPTED_HEAD: &[u8; 8] = b"encrcdsa";

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let image = input.volume()?;
    let mut head = [0u8; 8];
    if image.size() >= 8 {
        image.read_at(0, &mut head)?;
        if &head == ENCRYPTED_HEAD {
            return Err(if opts.password.is_none() {
                Error::PasswordRequired
            } else {
                Error::unsupported("encrypted disk images cannot be decrypted")
            });
        }
    }
    let koly = read_koly(&*image)?;
    let doc = read_plist(&*image, &koly)?;
    let blocks = doc
        .get("resource-fork")
        .and_then(|r| r.get("blkx"))
        .and_then(Value::items)
        .ok_or_else(|| Error::corrupt("UDIF property list has no block tables"))?;

    let mut entries = Vec::new();
    let mut parts = Vec::new();
    let mut main = None;
    for (index, block) in blocks.iter().enumerate() {
        let data = block
            .get("Data")
            .and_then(Value::data)
            .ok_or_else(|| Error::corrupt("UDIF block table entry has no data"))?;
        let (sectors, chunks) = block_table(data, koly.data_fork, image.size())?;
        if sectors == 0 {
            continue;
        }
        let name = block
            .get("Name")
            .or_else(|| block.get("CFName"))
            .and_then(Value::str)
            .unwrap_or("");
        let size = sectors
            .checked_mul(SECTOR)
            .ok_or_else(|| Error::corrupt("UDIF partition is too large"))?;
        if main.is_none() && name.contains("Apple_HFS") {
            main = Some(entries.len());
        }
        entries.push(Entry {
            name: format!("{index}.{}.img", sanitize(name)),
            is_dir: false,
            size: Some(size),
            ..Entry::default()
        });
        parts.push(Arc::new(Partition {
            image: image.clone(),
            chunks,
            size,
            cache: Mutex::new(Vec::new()),
        }));
    }
    let units = (0..entries.len())
        .map(|i| Unit {
            entries: vec![i],
            encrypted: false,
        })
        .collect();
    Ok(Box::new(Dmg {
        entries,
        units,
        parts,
        main,
    }))
}

/// Whether `src` is a UDIF image: its `koly` trailer is the last 512 bytes, with the header
/// size it always has. An encrypted image is recognized by its leading `encrcdsa` header.
pub fn is_udif(src: &dyn ReadAt) -> bool {
    let size = src.size();
    let mut head = [0u8; 8];
    if size >= 8 && src.read_at(0, &mut head).is_ok() && &head == ENCRYPTED_HEAD {
        return true;
    }
    if size < TRAILER_LEN {
        return false;
    }
    let mut k = [0u8; 12];
    src.read_at(size - TRAILER_LEN, &mut k).is_ok()
        && &k[..4] == b"koly"
        && be_u32(&k, 8) == Some(512)
}

/// The fields of the `koly` trailer that the reader uses.
struct Koly {
    data_fork: u64,
    xml_at: u64,
    xml_len: u64,
}

fn read_koly(image: &dyn ReadAt) -> Result<Koly> {
    let size = image.size();
    if size < TRAILER_LEN {
        return Err(Error::NotArchive);
    }
    let mut k = [0u8; TRAILER_LEN as usize];
    image.read_at(size - TRAILER_LEN, &mut k)?;
    if &k[..4] != b"koly" {
        return Err(Error::NotArchive);
    }
    if be_u32(&k, 8) != Some(512) {
        return Err(Error::corrupt("UDIF trailer has a bad header size"));
    }
    if be_u32(&k, 60).unwrap_or(0) > 1 {
        return Err(Error::unsupported("segmented disk images"));
    }
    let field = |at| be_u64(&k, at).ok_or_else(|| Error::corrupt("UDIF trailer is truncated"));
    Ok(Koly {
        data_fork: field(24)?,
        xml_at: field(216)?,
        xml_len: field(224)?,
    })
}

fn read_plist(image: &dyn ReadAt, koly: &Koly) -> Result<Value> {
    let inside = koly
        .xml_at
        .checked_add(koly.xml_len)
        .is_some_and(|end| end <= image.size());
    if !inside {
        return Err(Error::corrupt("UDIF property list is outside the image"));
    }
    if koly.xml_len > MAX_PLIST {
        return Err(Error::unsupported("UDIF property list larger than 64 MiB"));
    }
    let mut xml = vec![0u8; koly.xml_len as usize];
    image.read_at(koly.xml_at, &mut xml)?;
    plist::parse(&xml)
}

/// The chunk codecs a block table can name.
#[derive(Clone, Copy)]
enum Codec {
    Adc,
    Zlib,
    Bzip2,
    Lzfse,
}

/// The kind of a block-table run that holds sectors.
enum Run {
    Zero,
    Raw,
    Packed(Codec),
}

/// What a chunk holds: nothing (zeros), bytes stored at an image offset, or compressed bytes
/// at an image offset.
enum Body {
    Zero,
    Raw(u64),
    Packed { codec: Codec, at: u64, len: u64 },
}

/// A run of sectors of a partition.
struct Chunk {
    first: u64,
    sectors: u64,
    body: Body,
}

/// Parses a block table (`mish`) into the partition's sector count and its chunks. The
/// chunks must cover the partition's sectors in order, without gaps.
fn block_table(m: &[u8], data_fork: u64, image_size: u64) -> Result<(u64, Vec<Chunk>)> {
    if m.get(..4) != Some(b"mish") {
        return Err(Error::corrupt("UDIF block table has a bad magic"));
    }
    if be_u32(m, 4) != Some(1) {
        return Err(Error::unsupported("UDIF block table version"));
    }
    let bad = || Error::corrupt("UDIF block table is truncated");
    let sectors = be_u64(m, 16).ok_or_else(bad)?;
    let runs = be_u32(m, 200).ok_or_else(bad)? as usize;
    let fits = runs
        .checked_mul(MISH_RUN)
        .and_then(|n| n.checked_add(MISH_HEADER))
        .is_some_and(|n| n <= m.len());
    if !fits {
        return Err(Error::corrupt("UDIF block table has too many runs"));
    }

    let mut chunks = Vec::new();
    let mut next = 0u64;
    for i in 0..runs {
        let at = MISH_HEADER + i * MISH_RUN;
        let run = m.get(at..at + MISH_RUN).ok_or_else(bad)?;
        let code = be_u32(run, 0).ok_or_else(bad)?;
        let first = be_u64(run, 8).ok_or_else(bad)?;
        let count = be_u64(run, 16).ok_or_else(bad)?;
        let off = be_u64(run, 24).ok_or_else(bad)?;
        let len = be_u64(run, 32).ok_or_else(bad)?;
        let kind = match code {
            // Comment and terminator markers hold no sectors.
            0x7FFF_FFFE | 0xFFFF_FFFF => continue,
            0x0000_0000 | 0x0000_0002 => Run::Zero,
            0x0000_0001 => Run::Raw,
            0x8000_0004 => Run::Packed(Codec::Adc),
            0x8000_0005 => Run::Packed(Codec::Zlib),
            0x8000_0006 => Run::Packed(Codec::Bzip2),
            0x8000_0007 => Run::Packed(Codec::Lzfse),
            other => return Err(Error::unsupported(format!("UDIF chunk type {other:#010x}"))),
        };
        if count == 0 {
            continue;
        }
        if first != next {
            return Err(Error::corrupt(
                "UDIF block table runs do not cover the partition in order",
            ));
        }
        next = first
            .checked_add(count)
            .ok_or_else(|| Error::corrupt("UDIF block table sector count overflows"))?;
        let bytes = count
            .checked_mul(SECTOR)
            .ok_or_else(|| Error::corrupt("UDIF block table sector count overflows"))?;
        let at = data_fork
            .checked_add(off)
            .ok_or_else(|| Error::corrupt("UDIF chunk offset overflows"))?;
        let body = match kind {
            Run::Zero => Body::Zero,
            Run::Raw => {
                if len < bytes || at.checked_add(bytes).is_none_or(|e| e > image_size) {
                    return Err(Error::corrupt("UDIF raw chunk is outside the image"));
                }
                Body::Raw(at)
            }
            Run::Packed(codec) => {
                if bytes > MAX_CHUNK {
                    return Err(Error::unsupported(format!(
                        "UDIF chunk decoding to {bytes} bytes"
                    )));
                }
                if len == 0 || len > MAX_PACKED {
                    return Err(Error::unsupported("UDIF compressed chunk size"));
                }
                if at.checked_add(len).is_none_or(|e| e > image_size) {
                    return Err(Error::corrupt("UDIF compressed chunk is outside the image"));
                }
                Body::Packed { codec, at, len }
            }
        };
        chunks.push(Chunk {
            first,
            sectors: count,
            body,
        });
    }
    if next != sectors {
        return Err(Error::corrupt(format!(
            "UDIF block table covers {next} sectors, expected {sectors}"
        )));
    }
    Ok((sectors, chunks))
}

/// Decodes one compressed chunk to its exact size.
fn decode_chunk(chunk: &Chunk, image: &dyn ReadAt) -> Result<Vec<u8>> {
    let Body::Packed { codec, at, len } = chunk.body else {
        return Err(Error::corrupt("UDIF chunk has no compressed data"));
    };
    let mut packed = vec![0u8; len as usize];
    image.read_at(at, &mut packed)?;
    let mut out = vec![0u8; (chunk.sectors * SECTOR) as usize];
    match codec {
        Codec::Adc => adc::decode(&packed, &mut out)?,
        Codec::Lzfse => lzfse::decode(&packed, &mut out)?,
        Codec::Zlib => read_chunk(
            flate2::read::ZlibDecoder::new(&packed[..]),
            &mut out,
            "zlib",
        )?,
        Codec::Bzip2 => read_chunk(bzip2::read::BzDecoder::new(&packed[..]), &mut out, "bzip2")?,
    }
    Ok(out)
}

fn read_chunk(mut r: impl Read, out: &mut [u8], what: &str) -> Result<()> {
    r.read_exact(out)
        .map_err(|e| Error::corrupt(format!("{what} chunk in a disk image: {e}")))
}

/// A partition: its chunks over the image, read as one byte range.
struct Partition {
    image: Arc<dyn ReadAt>,
    chunks: Vec<Chunk>,
    size: u64,
    /// Recently decoded chunks, as (chunk index, bytes).
    cache: Mutex<Vec<(usize, Arc<Vec<u8>>)>>,
}

impl Partition {
    /// The index of the chunk holding byte `pos` (which is below the partition size).
    fn chunk_at(&self, pos: u64) -> Result<usize> {
        let sector = pos / SECTOR;
        let idx = self
            .chunks
            .partition_point(|c| c.first <= sector)
            .checked_sub(1)
            .ok_or_else(|| Error::corrupt("UDIF partition has no chunk at this offset"))?;
        match self.chunks.get(idx) {
            Some(c) if sector < c.first + c.sectors => Ok(idx),
            _ => Err(Error::corrupt("UDIF partition has no chunk at this offset")),
        }
    }

    fn decoded(&self, idx: usize) -> Result<Arc<Vec<u8>>> {
        let hit = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, d)| d.clone());
        if let Some(d) = hit {
            return Ok(d);
        }
        let chunk = self
            .chunks
            .get(idx)
            .ok_or_else(|| Error::corrupt("UDIF partition chunk index"))?;
        let data = Arc::new(decode_chunk(chunk, &*self.image)?);
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE_SLOTS {
            cache.remove(0);
        }
        cache.push((idx, data.clone()));
        Ok(data)
    }
}

impl ReadAt for Partition {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|&e| e <= self.size)
            .ok_or_else(|| Error::corrupt("read past the end of a disk image partition"))?;
        let mut pos = offset;
        while pos < end {
            let idx = self.chunk_at(pos)?;
            let chunk = self
                .chunks
                .get(idx)
                .ok_or_else(|| Error::corrupt("UDIF partition chunk index"))?;
            let within = pos - chunk.first * SECTOR;
            let take = (chunk.sectors * SECTOR - within).min(end - pos);
            let from = (pos - offset) as usize;
            let dst = &mut buf[from..from + take as usize];
            match &chunk.body {
                Body::Zero => dst.fill(0),
                Body::Raw(base) => self.image.read_at(base + within, dst)?,
                Body::Packed { .. } => {
                    let data = self.decoded(idx)?;
                    let part = data
                        .get(within as usize..(within + take) as usize)
                        .ok_or_else(|| Error::corrupt("UDIF decoded chunk is short"))?;
                    dst.copy_from_slice(part);
                }
            }
            pos += take;
        }
        Ok(())
    }
}

/// The partitions of a UDIF image, one entry each.
struct Dmg {
    entries: Vec<Entry>,
    units: Vec<Unit>,
    /// `parts[i]` is the partition of `entries[i]`.
    parts: Vec<Arc<Partition>>,
    /// The HFS+ partition, which the next level opens.
    main: Option<usize>,
}

impl Archive for Dmg {
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
        let i = self
            .units
            .get(unit)
            .and_then(|u| u.entries.first().copied())
            .ok_or_else(|| Error::corrupt("UDIF unit index is out of range"))?;
        let part: Arc<dyn ReadAt> = self
            .parts
            .get(i)
            .ok_or_else(|| Error::corrupt("UDIF unit index is out of range"))?
            .clone();
        f(i, &mut Runs::whole(part))?;
        Ok(())
    }

    fn volume(&self, i: usize) -> Option<Arc<dyn ReadAt>> {
        self.parts.get(i).map(|p| p.clone() as Arc<dyn ReadAt>)
    }

    fn main_entry(&self) -> Option<usize> {
        self.main
    }
}

/// An entry name for a partition: the name without path separators or control characters.
fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    if s.is_empty() {
        "unnamed".into()
    } else {
        s
    }
}

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Standard base64, with ASCII whitespace ignored and optional padding.
fn base64(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut n) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return Err(Error::corrupt("UDIF data is not base64")),
        };
        acc = (acc << 6) | u32::from(v);
        n += 1;
        if n == 4 {
            out.extend([(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => out.push((acc >> 4) as u8),
        3 => out.extend([(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => return Err(Error::corrupt("UDIF base64 data has a stray character")),
    }
    Ok(out)
}

/// The XML property list subset that UDIF images use: dictionaries, arrays, strings,
/// integers, data, and booleans, with declarations, comments and a DOCTYPE skipped.
mod plist {
    use super::base64;
    use crate::error::{Error, Result};

    const MAX_DEPTH: usize = 64;

    /// A parsed value. Scalars other than strings and data are kept as markers only.
    pub enum Value {
        Dict(Vec<(String, Value)>),
        Array(Vec<Value>),
        Str(String),
        Data(Vec<u8>),
        Scalar,
    }

    impl Value {
        /// The value under `key` in a dictionary.
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }

        pub fn items(&self) -> Option<&[Value]> {
            match self {
                Value::Array(items) => Some(items),
                _ => None,
            }
        }

        pub fn str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }

        pub fn data(&self) -> Option<&[u8]> {
            match self {
                Value::Data(d) => Some(d),
                _ => None,
            }
        }
    }

    pub fn parse(doc: &[u8]) -> Result<Value> {
        let mut p = Parser {
            s: doc,
            i: 0,
            depth: 0,
        };
        let v = p.value()?;
        p.misc()?;
        if p.i != doc.len() {
            return Err(bad("data after the property list"));
        }
        Ok(v)
    }

    fn bad(msg: &str) -> Error {
        Error::corrupt(format!("UDIF property list: {msg}"))
    }

    struct Parser<'a> {
        s: &'a [u8],
        i: usize,
        depth: usize,
    }

    impl Parser<'_> {
        fn rest(&self) -> &[u8] {
            self.s.get(self.i..).unwrap_or(&[])
        }

        fn eat(&mut self, lit: &[u8]) -> bool {
            if self.rest().starts_with(lit) {
                self.i += lit.len();
                true
            } else {
                false
            }
        }

        fn skip_spaces(&mut self) {
            while self.rest().first().is_some_and(u8::is_ascii_whitespace) {
                self.i += 1;
            }
        }

        fn skip_past(&mut self, end: &[u8]) -> Result<()> {
            let at = self
                .rest()
                .windows(end.len())
                .position(|w| w == end)
                .ok_or_else(|| bad("unterminated declaration or comment"))?;
            self.i += at + end.len();
            Ok(())
        }

        /// Skips whitespace, declarations, comments and the DOCTYPE between values.
        fn misc(&mut self) -> Result<()> {
            loop {
                self.skip_spaces();
                if self.eat(b"<?") {
                    self.skip_past(b"?>")?;
                } else if self.eat(b"<!--") {
                    self.skip_past(b"-->")?;
                } else if self.rest().starts_with(b"<!") {
                    self.doctype()?;
                } else {
                    return Ok(());
                }
            }
        }

        /// Skips a DOCTYPE, including a bracketed internal subset.
        fn doctype(&mut self) -> Result<()> {
            self.i += 2;
            let mut in_subset = false;
            while let Some(&c) = self.s.get(self.i) {
                self.i += 1;
                match c {
                    b'[' => in_subset = true,
                    b']' => in_subset = false,
                    b'>' if !in_subset => return Ok(()),
                    _ => {}
                }
            }
            Err(bad("unterminated DOCTYPE"))
        }

        /// Reads `<name ...>` or `<name .../>`, returning the name and whether it is empty.
        fn start(&mut self) -> Result<(String, bool)> {
            if !self.eat(b"<") {
                return Err(bad("expected an element"));
            }
            let begin = self.i;
            while self.s.get(self.i).is_some_and(|c| {
                c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':' | b'.')
            }) {
                self.i += 1;
            }
            let name = self
                .s
                .get(begin..self.i)
                .and_then(|n| std::str::from_utf8(n).ok())
                .filter(|n| !n.is_empty())
                .ok_or_else(|| bad("element without a name"))?
                .to_string();
            let mut quote = None;
            loop {
                let c = *self.s.get(self.i).ok_or_else(|| bad("unterminated tag"))?;
                self.i += 1;
                match (quote, c) {
                    (Some(q), _) if c == q => quote = None,
                    (Some(_), _) => {}
                    (None, b'"' | b'\'') => quote = Some(c),
                    (None, b'>') => {
                        let empty = self.i >= 2 && self.s.get(self.i - 2) == Some(&b'/');
                        return Ok((name, empty));
                    }
                    _ => {}
                }
            }
        }

        /// Reads `</name>`, allowing spaces before the `>`.
        fn close(&mut self, name: &str) -> Result<()> {
            if self.eat(b"</") && self.eat(name.as_bytes()) {
                self.skip_spaces();
                if self.eat(b">") {
                    return Ok(());
                }
            }
            Err(bad(&format!("expected </{name}>")))
        }

        /// Consumes `</name>` if it is next.
        fn close_if(&mut self, name: &str) -> bool {
            let save = self.i;
            if self.rest().starts_with(b"</") && self.close(name).is_ok() {
                return true;
            }
            self.i = save;
            false
        }

        fn value(&mut self) -> Result<Value> {
            self.misc()?;
            let (name, empty) = self.start()?;
            self.depth += 1;
            if self.depth > MAX_DEPTH {
                return Err(bad("nested too deeply"));
            }
            let v = self.element(&name, empty);
            self.depth -= 1;
            v
        }

        fn element(&mut self, name: &str, empty: bool) -> Result<Value> {
            match name {
                "plist" => {
                    let v = self.value()?;
                    self.misc()?;
                    self.close("plist")?;
                    Ok(v)
                }
                "dict" => {
                    let mut items = Vec::new();
                    if !empty {
                        loop {
                            self.misc()?;
                            if self.close_if("dict") {
                                break;
                            }
                            let (key, key_empty) = self.start()?;
                            if key != "key" {
                                return Err(bad("dictionary entry without a key"));
                            }
                            let key = self.text("key", key_empty)?;
                            let v = self.value()?;
                            items.push((key, v));
                        }
                    }
                    Ok(Value::Dict(items))
                }
                "array" => {
                    let mut items = Vec::new();
                    if !empty {
                        loop {
                            self.misc()?;
                            if self.close_if("array") {
                                break;
                            }
                            items.push(self.value()?);
                        }
                    }
                    Ok(Value::Array(items))
                }
                "string" => Ok(Value::Str(self.text(name, empty)?)),
                "data" => {
                    let text = self.text(name, empty)?;
                    Ok(Value::Data(base64(&text)?))
                }
                "integer" => {
                    let text = self.text(name, empty)?;
                    text.trim().parse::<i64>().map_err(|_| bad("bad integer"))?;
                    Ok(Value::Scalar)
                }
                "true" | "false" => {
                    if !empty {
                        self.close(name)?;
                    }
                    Ok(Value::Scalar)
                }
                other => Err(Error::unsupported(format!(
                    "property list element <{other}>"
                ))),
            }
        }

        /// The text of a simple element, with entities decoded.
        fn text(&mut self, name: &str, empty: bool) -> Result<String> {
            if empty {
                return Ok(String::new());
            }
            let end = self
                .rest()
                .iter()
                .position(|&c| c == b'<')
                .ok_or_else(|| bad("unterminated element"))?;
            let raw = self.rest()[..end].to_vec();
            self.i += end;
            self.close(name)?;
            decode_entities(&raw)
        }
    }

    fn decode_entities(raw: &[u8]) -> Result<String> {
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] != b'&' {
                out.push(raw[i]);
                i += 1;
                continue;
            }
            let semi = raw[i..]
                .iter()
                .take(12)
                .position(|&c| c == b';')
                .ok_or_else(|| bad("bad character reference"))?;
            let name = &raw[i + 1..i + semi];
            let ch = match name {
                b"lt" => '<',
                b"gt" => '>',
                b"amp" => '&',
                b"quot" => '"',
                b"apos" => '\'',
                _ => {
                    let code = match name.strip_prefix(b"#") {
                        Some(hex) if hex.first() == Some(&b'x') => std::str::from_utf8(&hex[1..])
                            .ok()
                            .and_then(|h| u32::from_str_radix(h, 16).ok()),
                        Some(dec) => std::str::from_utf8(dec).ok().and_then(|d| d.parse().ok()),
                        None => None,
                    };
                    code.and_then(char::from_u32)
                        .ok_or_else(|| bad("unknown entity"))?
                }
            };
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            i += semi + 1;
        }
        String::from_utf8(out).map_err(|_| bad("text is not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip_and_whitespace() {
        assert_eq!(base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64("aGVs\n\tbG8").unwrap(), b"hello");
        assert_eq!(base64("aGVsbG8h").unwrap(), b"hello!");
        assert!(base64("a").is_err());
        assert!(base64("a$bc").is_err());
    }

    #[test]
    fn plist_subset() {
        let doc = br#"<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "x.dtd" [ <!ENTITY e "x"> ]>
<!-- comment -->
<plist version="1.0"><dict>
  <key>a&amp;b</key><string>x &lt; y</string>
  <key>list</key><array><integer>7</integer><true/><false/><dict/></array>
  <key>d</key><data>
    aGVs bG8=
  </data>
</dict></plist>"#;
        let v = plist::parse(doc).unwrap();
        assert_eq!(v.get("a&b").and_then(Value::str), Some("x < y"));
        assert_eq!(v.get("d").and_then(Value::data), Some(&b"hello"[..]));
        assert_eq!(
            v.get("list").and_then(Value::items).map(<[Value]>::len),
            Some(4)
        );
    }

    #[test]
    fn plist_rejects_unsupported_and_malformed() {
        assert!(plist::parse(b"<plist><real>1.5</real></plist>").is_err());
        assert!(plist::parse(b"<plist><dict><string>x</string></dict></plist>").is_err());
        assert!(plist::parse(b"<plist><string>x</plist>").is_err());
        assert!(plist::parse(b"<plist><integer>x</integer></plist>").is_err());
        assert!(plist::parse(b"<plist><dict><key>a</key>").is_err());
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize("Apple_HFS"), "Apple_HFS");
        assert_eq!(sanitize("a/b\\c\0d"), "a_b_c_d");
        assert_eq!(sanitize(""), "unnamed");
    }
}
