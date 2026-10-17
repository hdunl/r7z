//! Windows Imaging (WIM, ESD, split SWM, provisioning PPKG), read-only.
//!
//! A WIM is a header, a lookup table of blobs (SHA-1 addressed resources), one metadata
//! resource per image (security data plus a directory tree of dentries) and an XML
//! description. Resources are stored raw, compressed in independent chunks (XPRESS, LZX
//! or LZMS) behind a chunk offset table, or packed together into solid resources (ESD)
//! that carry their own chunk size and method.
//!
//! Listing follows 7-Zip: entries are ordered directories first, then by blob, image
//! and dentry position; with several images every path gets an `N/` image prefix, the
//! image roots are listed as directories and the XML is listed as `[1].xml`; blobs no
//! dentry references are listed under `[DELETED]`. Alternate data streams are listed as
//! `file:stream`. Every blob's SHA-1 is verified while it is read.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::Arc;

use rayon::prelude::*;
use sha1::{Digest, Sha1};

use super::{
    Archive, Columns, Ctx, Entry, EntryFn, Flow, Format, Input, Link, OpenOptions, Signature,
    Slice, Unit,
};
use crate::codec::lzms::LzmsDecoder;
use crate::codec::lzx_wim::LzxDecoder;
use crate::codec::xpress::XpressDecoder;
use crate::error::{Error, Result};

pub static FORMAT: Format = Format {
    name: "wim",
    aliases: &[],
    extensions: &["wim", "swm", "esd", "ppkg"],
    signatures: &[Signature::at(0, SIGNATURE)],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

const SIGNATURE: &[u8] = b"MSWIM\0\0\0";
const HEADER_SIZE: usize = 0xD0;
const HASH: usize = 20;
const LOOKUP_ENTRY: usize = 50;
const DENTRY: usize = 0x66;
const ALT_ENTRY: usize = 0x26;

const RES_METADATA: u8 = 2;
const RES_COMPRESSED: u8 = 4;
const RES_SOLID: u8 = 0x10;
/// Uncompressed-size field of the lookup entry describing a whole solid resource.
const SOLID_BIG: u64 = 1 << 32;

const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_REPARSE: u32 = 0x400;

const METHOD_NAMES: [&str; 4] = ["Copy", "XPress", "LZX", "LZMS"];

/// Largest header-referenced resource (lookup table, XML, metadata) read into memory.
const MAX_META: u64 = 1 << 30;
/// Budget for all listed path text, against crafted deep trees.
const MAX_PATH_BYTES: usize = 1 << 30;
/// Memory for one batch of chunks decoded in parallel.
const BATCH_BYTES: usize = 128 << 20;

fn corrupt(m: &str) -> Error {
    Error::corrupt(format!("WIM: {m}"))
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// A resource header: where a resource lies and how it is stored.
#[derive(Clone, Copy, Debug, Default)]
struct ResHdr {
    packed: u64,
    flags: u8,
    offset: u64,
    size: u64,
}

impl ResHdr {
    fn parse(b: &[u8]) -> Self {
        ResHdr {
            packed: u64_at(b, 0) & ((1 << 56) - 1),
            flags: b[7],
            offset: u64_at(b, 8),
            size: u64_at(b, 16),
        }
    }

    fn end(&self) -> u64 {
        self.offset.saturating_add(self.packed)
    }

    fn solid(&self) -> bool {
        self.flags & RES_SOLID != 0
    }

    fn solid_big(&self) -> bool {
        self.solid() && self.size == SOLID_BIG
    }

    fn solid_small(&self) -> bool {
        self.solid() && self.size == 0
    }
}

#[derive(Clone, Debug)]
struct Header {
    version: u32,
    /// 0 = stored, 1 = XPRESS, 2 = LZX, 3 = LZMS.
    method: u32,
    chunk_bits: u32,
    guid: [u8; 16],
    part: u16,
    parts: u16,
    boot_index: u32,
    lookup: ResHdr,
    xml: ResHdr,
    phys_size: u64,
}

fn log2_exact(v: u64) -> Option<u32> {
    (v.is_power_of_two() && v >= 1 << 12).then(|| v.trailing_zeros())
}

fn parse_header(d: &[u8]) -> Result<Header> {
    if d.len() < HEADER_SIZE || &d[..8] != SIGNATURE {
        return Err(Error::NotArchive);
    }
    let hsize = u32_at(d, 8);
    let version = u32_at(d, 0x0C);
    let flags = u32_at(d, 0x10);
    let method = if flags & 2 != 0 {
        match flags & 0xFFFE_0000 {
            0x0002_0000 | 0x0020_0000 => 1,
            0x0004_0000 => 2,
            0x0008_0000 => 3,
            _ => {
                return Err(Error::unsupported(format!(
                    "WIM compression flags {flags:#x}"
                )))
            }
        }
    } else {
        0
    };
    let chunk = u32_at(d, 0x14);
    let chunk_bits = if chunk == 0 {
        15
    } else {
        log2_exact(chunk as u64).ok_or_else(|| corrupt("bad chunk size"))?
    };
    let solid_version = version == 0xE00;
    if !solid_version && (version < 0x10B00 || (version == 0x10B00 && hsize == 0x60)) {
        return Err(Error::unsupported(format!(
            "WIM version {}.{:02} (pre-Vista format)",
            version >> 16,
            (version >> 8) & 0xFF
        )));
    }
    let new = solid_version || version >= 0x10D00;
    if hsize < 0x74 || (new && hsize != 0xD0) {
        return Err(corrupt("bad header size"));
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&d[0x18..0x28]);
    let part = u16_at(d, 0x28);
    let parts = u16_at(d, 0x2A);
    if part == 0 || part > parts {
        return Err(corrupt("bad part number"));
    }
    let mut off = 0x2C;
    let mut boot_index = 0;
    let mut phys = hsize as u64;
    let mut extra = Vec::new();
    if new {
        off += 4;
        boot_index = u32_at(d, off + 0x48);
        extra.push(ResHdr::parse(&d[off + 0x4C..]));
    }
    let lookup = ResHdr::parse(&d[off..]);
    let xml = ResHdr::parse(&d[off + 0x18..]);
    extra.push(ResHdr::parse(&d[off + 0x30..]));
    for r in extra.iter().chain([&lookup, &xml]) {
        phys = phys.max(r.end());
    }
    Ok(Header {
        version,
        method,
        chunk_bits,
        guid,
        part,
        parts,
        boot_index,
        lookup,
        xml,
        phys_size: phys,
    })
}

/// One lookup table entry (a blob, a metadata resource or a whole solid resource).
#[derive(Clone, Debug)]
struct Stream {
    res: ResHdr,
    part: u16,
    hash: [u8; HASH],
    /// Continues the solid group of the previous entry.
    keep_solid: bool,
    solid: Option<usize>,
}

/// A solid resource: chunks of the concatenation of many blobs.
#[derive(Debug)]
struct Solid {
    stream: usize,
    /// Start of this resource in the uncompressed data of its solid group.
    group_offset: u64,
    size: u64,
    chunk_bits: u32,
    method: u32,
    /// Chunk start offsets from the resource start, plus the end.
    chunks: Vec<u64>,
    /// First blob (in lookup order) stored in this resource.
    first_small: Option<usize>,
}

/// A parsed dentry or alternate data stream.
#[derive(Clone, Debug)]
struct Item {
    image: usize,
    offset: usize,
    parent: Option<usize>,
    level: u32,
    name: String,
    is_dir: bool,
    dir_plain: bool,
    alt: bool,
    attrib: u32,
    /// Creation, last access, last write.
    times: [u64; 3],
    hash: [u8; HASH],
    reparse_tag: u32,
    subdir: u64,
    stream: Option<usize>,
}

struct Image {
    /// The root list is one unnamed directory, left out of paths.
    empty_root: bool,
}

/// Where an entry's bytes come from.
#[derive(Clone, Debug)]
enum Source {
    None,
    Blob(usize),
    /// The dentry names a blob that is not in the lookup table.
    Missing,
    Mem(Arc<[u8]>),
}

struct Volume {
    data: Slice,
    header: Header,
}

pub struct Wim {
    vols: Vec<Option<Volume>>,
    streams: Vec<Stream>,
    solids: Vec<Solid>,
    entries: Vec<Entry>,
    sources: Vec<Source>,
    units: Vec<Unit>,
    props: Vec<(&'static str, String)>,
}

/// A chunked stream: a compressed non-solid resource or a solid resource.
struct Chunked<'a> {
    key: usize,
    data: &'a [u8],
    chunks: Cow<'a, [u64]>,
    size: u64,
    bits: u32,
    method: u32,
}

impl Chunked<'_> {
    fn count(&self) -> usize {
        self.chunks.len() - 1
    }

    fn out_len(&self, i: usize) -> usize {
        let start = (i as u64) << self.bits;
        (self.size - start).min(1 << self.bits) as usize
    }

    fn input(&self, i: usize) -> Result<&[u8]> {
        let (a, b) = (self.chunks[i], self.chunks[i + 1]);
        if a > b || b > self.data.len() as u64 {
            return Err(corrupt("bad chunk table"));
        }
        Ok(&self.data[a as usize..b as usize])
    }
}

enum Src<'a> {
    Stored(&'a [u8]),
    Chunked(Chunked<'a>),
}

/// Decoders for every method, created on first use.
#[derive(Default)]
struct Codecs {
    xpress: Option<XpressDecoder>,
    lzx: Option<Box<LzxDecoder>>,
    lzms: Option<Box<LzmsDecoder>>,
}

/// Fails for a chunk method or chunk size no WIM decoder supports.
fn check_method(method: u32, bits: u32) -> Result<()> {
    let ok_bits = match method {
        1 => (12..=16).contains(&bits),
        2 => (15..=21).contains(&bits),
        3 => (15..=30).contains(&bits),
        _ => return Err(Error::unsupported(format!("WIM chunk method {method}"))),
    };
    if !ok_bits {
        return Err(Error::unsupported(format!(
            "{} with 2^{bits}-byte chunks",
            METHOD_NAMES[method as usize]
        )));
    }
    Ok(())
}

impl Codecs {
    fn decode(&mut self, method: u32, bits: u32, input: &[u8], out: &mut [u8]) -> Result<()> {
        check_method(method, bits)?;
        if input.len() == out.len() {
            out.copy_from_slice(input);
            return Ok(());
        }
        if input.len() as u64 >= 1u64 << bits {
            return Err(corrupt("chunk larger than its uncompressed size"));
        }
        match method {
            1 => self
                .xpress
                .get_or_insert_with(XpressDecoder::new)
                .decompress(input, out),
            2 => self
                .lzx
                .get_or_insert_with(|| Box::new(LzxDecoder::new()))
                .decompress(input, out, bits),
            _ => self
                .lzms
                .get_or_insert_with(|| Box::new(LzmsDecoder::new()))
                .decompress(input, out),
        }
    }
}

thread_local! {
    static CODECS: RefCell<Codecs> = RefCell::new(Codecs::default());
}

/// A decoded chunk.
struct Slot {
    key: usize,
    index: usize,
    data: Vec<u8>,
    err: Option<Error>,
}

/// Recently decoded chunks of one unit, decoded in parallel batches when the unit may
/// use several threads.
struct Cache {
    threads: usize,
    slots: Vec<Slot>,
    codecs: Codecs,
}

impl Cache {
    fn new(threads: usize) -> Self {
        Cache {
            threads: threads.max(1),
            slots: Vec::new(),
            codecs: Codecs::default(),
        }
    }

    fn chunk(&mut self, c: &Chunked, index: usize) -> Result<&[u8]> {
        if index >= c.count() {
            return Err(corrupt("read past the end of a resource"));
        }
        let found = self
            .slots
            .iter()
            .position(|s| s.key == c.key && s.index == index);
        let at = match found {
            Some(at) => at,
            None => self.fill(c, index)?,
        };
        let slot = &mut self.slots[at];
        if let Some(e) = slot.err.take() {
            slot.key = usize::MAX;
            return Err(e);
        }
        Ok(&slot.data)
    }

    /// Decodes chunk `index` (and, with threads, the chunks after it); returns its slot.
    fn fill(&mut self, c: &Chunked, index: usize) -> Result<usize> {
        check_method(c.method, c.bits)?;
        let mut n = 1;
        if self.threads > 1 {
            let by_mem = (BATCH_BYTES >> c.bits).max(1);
            n = self.threads.min(by_mem).min(c.count() - index);
        }
        let mut bufs: Vec<Vec<u8>> = self.slots.drain(..).map(|s| s.data).collect();
        bufs.resize_with(n.max(bufs.len()), Vec::new);
        bufs.truncate(n);
        for (k, b) in bufs.iter_mut().enumerate() {
            b.clear();
            b.resize(c.out_len(index + k), 0);
        }
        let decode = |codecs: &mut Codecs, i: usize, out: &mut Vec<u8>| -> Result<()> {
            codecs.decode(c.method, c.bits, c.input(i)?, out)
        };
        let results: Vec<(Vec<u8>, Option<Error>)> = if n == 1 {
            let mut b = bufs.pop().unwrap();
            let r = decode(&mut self.codecs, index, &mut b);
            vec![(b, r.err())]
        } else {
            bufs.into_par_iter()
                .enumerate()
                .map(|(k, mut b)| {
                    let r = CODECS.with(|cd| decode(&mut cd.borrow_mut(), index + k, &mut b));
                    (b, r.err())
                })
                .collect()
        };
        self.slots = results
            .into_iter()
            .enumerate()
            .map(|(k, (data, err))| Slot {
                key: c.key,
                index: index + k,
                data,
                err,
            })
            .collect();
        Ok(0)
    }
}

/// Reads `len` bytes of a stream from `start`, verifying the SHA-1 at the end.
struct BlobReader<'a, 'c> {
    src: &'c Src<'a>,
    cache: &'c mut Cache,
    pos: u64,
    end: u64,
    sha: Option<(Sha1, [u8; HASH])>,
    name: &'c str,
}

impl Read for BlobReader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.end || buf.is_empty() {
            if self.pos >= self.end {
                if let Some((sha, want)) = self.sha.take() {
                    if sha.finalize()[..] != want {
                        return Err(Error::Checksum(format!("{} (SHA-1)", self.name)).into_io());
                    }
                }
            }
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.end - self.pos) as usize;
        let n = match self.src {
            Src::Stored(d) => {
                let p = self.pos as usize;
                buf[..want].copy_from_slice(&d[p..p + want]);
                want
            }
            Src::Chunked(c) => {
                let index = (self.pos >> c.bits) as usize;
                let off = (self.pos & ((1 << c.bits) - 1)) as usize;
                let chunk = self.cache.chunk(c, index).map_err(Error::into_io)?;
                if off >= chunk.len() {
                    return Err(corrupt("short chunk").into_io());
                }
                let n = want.min(chunk.len() - off);
                buf[..n].copy_from_slice(&chunk[off..off + n]);
                n
            }
        };
        if let Some((sha, _)) = self.sha.as_mut() {
            sha.update(&buf[..n]);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

fn utf16_name(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// A path component as 7-Zip shows it: `/` becomes `_`, `\` its WSL private-use stand-in.
fn component(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' => '_',
            '\\' => '\u{F05C}',
            c => c,
        })
        .collect()
}

/// Parses the directory tree of one image's metadata resource.
struct DirParser<'m> {
    meta: &'m [u8],
    image: usize,
    dir_start: usize,
    /// One flag per 8-byte unit of metadata: every unit belongs to at most one record,
    /// which bounds the work on crafted (cyclic) trees.
    used: Vec<bool>,
}

impl DirParser<'_> {
    fn claim(&mut self, pos: usize, len: usize) -> Result<()> {
        let (a, b) = (pos / 8, (pos + len.max(8)).div_ceil(8));
        let span = self
            .used
            .get_mut(a..b)
            .ok_or_else(|| corrupt("directory entry out of range"))?;
        if span.iter().any(|&u| u) {
            return Err(corrupt("overlapping directory entries"));
        }
        span.fill(true);
        Ok(())
    }

    /// Parses one directory list; returns whether it is a lone unnamed root.
    fn list(
        &mut self,
        items: &mut Vec<Item>,
        mut pos: usize,
        parent: Option<usize>,
        level: u32,
    ) -> Result<bool> {
        let m = self.meta;
        let len = m.len();
        let mut empty_root = false;
        let mut n = 0usize;
        loop {
            if pos % 8 != 0 || pos < self.dir_start || pos > len || len - pos < 8 {
                return Err(corrupt("bad directory entry offset"));
            }
            let rlen = u64_at(m, pos);
            if rlen > (len - pos) as u64 || rlen % 8 != 0 {
                return Err(corrupt("bad directory entry length"));
            }
            let rlen = rlen as usize;
            self.claim(pos, rlen)?;
            if rlen == 0 {
                return Ok(empty_root);
            }
            if rlen < DENTRY {
                return Err(corrupt("short directory entry"));
            }
            let p = &m[pos..pos + rlen];
            let attrib = u32_at(p, 8);
            let subdir = u64_at(p, 0x10);
            if subdir > len as u64 {
                return Err(corrupt("bad subdirectory offset"));
            }
            let num_alt = u16_at(p, 0x60);
            let short_len = u16_at(p, 0x62) as usize;
            let name_len = u16_at(p, 0x64) as usize;
            if short_len % 2 != 0 || name_len % 2 != 0 {
                return Err(corrupt("bad name length"));
            }
            let names = if name_len == 0 { 0 } else { name_len + 2 }
                + if short_len == 0 { 0 } else { short_len + 2 };
            if DENTRY + names > rlen {
                return Err(corrupt("directory entry names overflow"));
            }
            let name = utf16_name(&p[DENTRY..DENTRY + name_len]);
            let is_dir = attrib & ATTR_DIRECTORY != 0;
            let mut hash = [0u8; HASH];
            hash.copy_from_slice(&p[0x40..0x54]);
            let idx = items.len();
            items.push(Item {
                image: self.image,
                offset: pos,
                parent,
                level,
                name,
                is_dir,
                dir_plain: is_dir && attrib & ATTR_REPARSE == 0,
                alt: false,
                attrib,
                times: [u64_at(p, 0x28), u64_at(p, 0x30), u64_at(p, 0x38)],
                hash,
                reparse_tag: u32_at(p, 0x58),
                subdir,
                stream: None,
            });
            pos += rlen;
            for _ in 0..num_alt {
                if len - pos < 8 {
                    return Err(corrupt("truncated stream entry"));
                }
                let alen = u64_at(m, pos);
                if alen > (len - pos) as u64 || alen % 8 != 0 || alen < ALT_ENTRY as u64 {
                    return Err(corrupt("bad stream entry length"));
                }
                let alen = alen as usize;
                self.claim(pos, alen)?;
                let a = &m[pos..pos + alen];
                let nlen = u16_at(a, 0x24) as usize;
                if nlen % 2 != 0 || (ALT_ENTRY + nlen + 2).next_multiple_of(8) > alen {
                    return Err(corrupt("bad stream name length"));
                }
                let aname = utf16_name(&a[ALT_ENTRY..ALT_ENTRY + nlen]);
                let mut ahash = [0u8; HASH];
                ahash.copy_from_slice(&a[0x10..0x24]);
                let main = &mut items[idx];
                if aname.is_empty() && !main.dir_plain && main.hash == [0; HASH] {
                    // The unnamed stream of a file with named streams.
                    main.hash = ahash;
                } else {
                    items.push(Item {
                        image: self.image,
                        offset: pos,
                        parent: Some(idx),
                        level,
                        name: aname,
                        is_dir: false,
                        dir_plain: false,
                        alt: true,
                        attrib: 0,
                        times: [0; 3],
                        hash: ahash,
                        reparse_tag: 0,
                        subdir: 0,
                        stream: None,
                    });
                }
                pos += alen;
            }
            if parent.is_none() && n == 0 && is_dir && len - pos >= 8 && u64_at(m, pos) == 0 {
                // A lone root directory. Writers may leave its child offset zero (empty
                // image) or point past a list placed right after the root list.
                if items[idx].name.is_empty() {
                    empty_root = true;
                }
                if len - pos >= 16 {
                    let next = (pos + 8) as u64;
                    if subdir == 0 || (next < subdir && u64_at(m, pos + 8) != 0) {
                        items[idx].subdir = next;
                    }
                }
            }
            n += 1;
        }
    }
}

/// Parses an image's metadata: security data, then the directory tree.
fn parse_image(meta: &[u8], image: usize, items: &mut Vec<Item>) -> Result<Image> {
    let len = meta.len();
    if len < 8 {
        return Err(corrupt("metadata too short"));
    }
    let total = u32_at(meta, 0) as usize;
    let mut pos = 8usize;
    if total != 0 {
        let count = u32_at(meta, 4) as usize;
        if total < 8 || total > len || count > (total - 8) / 8 {
            return Err(corrupt("bad security data"));
        }
        let mut sum = 8 + count * 8;
        for i in 0..count {
            let l = u64_at(meta, 8 + i * 8);
            if l > (total - sum) as u64 {
                return Err(corrupt("bad security descriptor size"));
            }
            sum += l as usize;
        }
        pos = sum.next_multiple_of(8);
        if pos != total.next_multiple_of(8) {
            return Err(corrupt("bad security data size"));
        }
    }
    if pos > len {
        return Err(corrupt("bad security data size"));
    }
    let start = items.len();
    let mut p = DirParser {
        meta,
        image,
        dir_start: pos,
        used: vec![false; len.div_ceil(8)],
    };
    let empty_root = p.list(items, pos, None, 0)?;
    let mut i = start;
    while i < items.len() {
        let it = &items[i];
        if it.is_dir && it.subdir != 0 {
            let (off, level) = (it.subdir as usize, it.level + 1);
            p.list(items, off, Some(i), level)?;
        }
        i += 1;
    }
    Ok(Image { empty_root })
}

/// Text value of the first `<tag>` inside `xml`.
fn xml_tag<'x>(xml: &'x str, tag: &str) -> Option<&'x str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let a = xml.find(&open)? + open.len();
    let b = xml[a..].find(&close)? + a;
    Some(&xml[a..b])
}

fn xml_time(image: &str, tag: &str) -> Option<u64> {
    let t = xml_tag(image, tag)?;
    let num = |s: &str| {
        let s = s.trim();
        match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(h) => u32::from_str_radix(h, 16).ok(),
            None => s.parse::<u32>().ok(),
        }
    };
    let hi = num(xml_tag(t, "HIGHPART")?)?;
    let lo = num(xml_tag(t, "LOWPART")?)?;
    Some(((hi as u64) << 32) | lo as u64)
}

/// The `<IMAGE ...>...</IMAGE>` blocks of the XML description.
fn xml_images(xml: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(a) = rest.find("<IMAGE") {
        let after = &rest[a..];
        let Some(b) = after.find("</IMAGE>") else {
            break;
        };
        out.push(&after[..b]);
        rest = &after[b + 8..];
    }
    out
}

fn xml_text(data: &[u8]) -> String {
    if data.len() < 2 || u16_at(data, 0) != 0xFEFF {
        return String::new();
    }
    utf16_name(&data[2..data.len() & !1])
}

/// Reparse data stored for a symbolic link or junction: its target.
fn reparse_target(tag: u32, d: &[u8]) -> Option<String> {
    let path_at = match tag {
        0xA000_000C => 12,
        0xA000_0003 => 8,
        _ => return None,
    };
    if d.len() < path_at {
        return None;
    }
    let name = |off: usize, len: usize| -> Option<String> {
        let a = path_at + off;
        d.get(a..a + len).map(utf16_name)
    };
    let sub = name(u16_at(d, 0) as usize, u16_at(d, 2) as usize)?;
    let print = name(u16_at(d, 4) as usize, u16_at(d, 6) as usize)?;
    let t = if print.is_empty() {
        sub.strip_prefix("\\??\\").unwrap_or(&sub).to_string()
    } else {
        print
    };
    (!t.is_empty()).then_some(t)
}

/// `name.swm` → `name<k>.swm`, as 7-Zip names the parts of a split set.
fn part_name(first: &str, k: u16) -> String {
    match first.rfind('.') {
        Some(dot) => format!("{}{k}{}", &first[..dot], &first[dot..]),
        None => format!("{first}{k}"),
    }
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let data = input.into_mem()?;
    let header = parse_header(&data)?;
    if header.part != 1 {
        return Err(Error::unsupported(format!(
            "this is part {} of a split WIM; open part 1",
            header.part
        )));
    }
    let parts = header.parts;
    let mut vols: Vec<Option<Volume>> = (0..=parts).map(|_| None).collect();
    vols[1] = Some(Volume { data, header });
    if parts > 1 {
        let path = opts.path.as_ref().ok_or_else(|| {
            Error::unsupported("the parts of a split WIM must be opened from files")
        })?;
        let file = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let first = vols[1].as_ref().unwrap().header.clone();
        for k in 2..=parts {
            let p = path.with_file_name(part_name(&file, k));
            if !p.is_file() {
                return Err(Error::unsupported(format!(
                    "split WIM part {k} of {parts} is missing ({})",
                    p.display()
                )));
            }
            let d = Slice::map_file(&p)?;
            let h = parse_header(&d)?;
            if h.guid != first.guid || h.parts != parts || h.version != first.version {
                return Err(Error::unsupported(format!(
                    "{} is not part of the same split WIM",
                    p.display()
                )));
            }
            if h.part != k {
                return Err(Error::unsupported(format!(
                    "{} holds part {} instead of part {k}",
                    p.display(),
                    h.part
                )));
            }
            vols[k as usize] = Some(Volume { data: d, header: h });
        }
    }
    Wim::load(vols).map(|w| Box::new(w) as Box<dyn Archive>)
}

impl Wim {
    fn vol(&self, part: u16) -> Result<&Volume> {
        self.vols
            .get(part as usize)
            .and_then(Option::as_ref)
            .ok_or_else(|| corrupt("blob in a missing part"))
    }

    /// The bytes of a non-solid resource as stored in its volume.
    fn packed_bytes<'a>(&'a self, v: &'a Volume, r: &ResHdr) -> Result<&'a [u8]> {
        let end = r
            .offset
            .checked_add(r.packed)
            .ok_or_else(|| corrupt("resource out of range"))?;
        if end > v.data.len() as u64 {
            return Err(corrupt("resource is past the end of the file"));
        }
        Ok(&v.data[r.offset as usize..end as usize])
    }

    /// Source and range of a non-solid resource stored in volume `v`.
    fn plain_src<'a>(&'a self, v: &'a Volume, r: &ResHdr, key: usize) -> Result<Src<'a>> {
        let data = self.packed_bytes(v, r)?;
        if r.flags & RES_COMPRESSED == 0 {
            if r.packed != r.size {
                return Err(corrupt("stored resource size mismatch"));
            }
            return Ok(Src::Stored(data));
        }
        if r.size == 0 {
            return Ok(Src::Stored(&[]));
        }
        let h = &v.header;
        let bits = h.chunk_bits;
        let n = ((r.size - 1) >> bits) + 1;
        let entry = if r.size < 1 << 32 { 4 } else { 8 };
        let table = (n - 1)
            .checked_mul(entry)
            .filter(|&t| t <= r.packed)
            .ok_or_else(|| corrupt("chunk table larger than the resource"))?
            as usize;
        let mut chunks = Vec::with_capacity(n as usize + 1);
        chunks.push(table as u64);
        for i in 0..(n - 1) as usize {
            let o = if entry == 4 {
                u32_at(data, i * 4) as u64
            } else {
                u64_at(data, i * 8)
            };
            chunks.push(table as u64 + o);
        }
        chunks.push(r.packed);
        if chunks.windows(2).any(|w| w[0] > w[1]) {
            return Err(corrupt("bad chunk table"));
        }
        Ok(Src::Chunked(Chunked {
            key,
            data,
            chunks: Cow::Owned(chunks),
            size: r.size,
            bits,
            method: h.method,
        }))
    }

    /// Source of stream `s` and the byte range of its data in that source.
    fn stream_src(&self, s: usize) -> Result<(Src<'_>, u64, u64)> {
        let st = &self.streams[s];
        let v = self.vol(st.part)?;
        if !st.res.solid() {
            let src = self.plain_src(v, &st.res, s)?;
            return Ok((src, 0, st.res.size));
        }
        let si = st
            .solid
            .ok_or_else(|| corrupt("blob outside every solid resource"))?;
        let so = &self.solids[si];
        let big = &self.streams[so.stream];
        let data = self.packed_bytes(self.vol(big.part)?, &big.res)?;
        let (start, len) = if st.res.solid_big() {
            (0, so.size)
        } else {
            (st.res.offset - so.group_offset, st.res.packed)
        };
        let src = Src::Chunked(Chunked {
            key: usize::MAX - si,
            data,
            chunks: Cow::Borrowed(&so.chunks),
            size: so.size,
            bits: so.chunk_bits,
            method: so.method,
        });
        Ok((src, start, len))
    }

    /// Reads a whole range into memory (verifying `hash` when given).
    fn read_all(
        src: &Src,
        start: u64,
        len: u64,
        hash: Option<[u8; HASH]>,
        name: &str,
    ) -> Result<Vec<u8>> {
        let mut cache = Cache::new(1);
        let mut r = BlobReader {
            src,
            cache: &mut cache,
            pos: start,
            end: start + len,
            sha: hash.map(|h| (Sha1::new(), h)),
            name,
        };
        let mut out = Vec::new();
        r.read_to_end(&mut out).map_err(super::data::data_err)?;
        Ok(out)
    }

    fn read_header_res(&self, part: u16, r: &ResHdr, what: &str) -> Result<Vec<u8>> {
        if r.solid() {
            return Err(corrupt(&format!("solid {what}")));
        }
        if r.size > MAX_META {
            return Err(Error::unsupported(format!(
                "WIM {what} of {} bytes",
                r.size
            )));
        }
        let v = self.vol(part)?;
        let src = self.plain_src(v, r, usize::MAX / 2)?;
        Self::read_all(&src, 0, r.size, None, what)
    }

    fn load(vols: Vec<Option<Volume>>) -> Result<Wim> {
        let mut w = Wim {
            vols,
            streams: Vec::new(),
            solids: Vec::new(),
            entries: Vec::new(),
            sources: Vec::new(),
            units: Vec::new(),
            props: Vec::new(),
        };
        let mut metas: Vec<Stream> = Vec::new();
        let mut xmls: Vec<(u16, Vec<u8>)> = Vec::new();
        for part in 1..w.vols.len() as u16 {
            let h = w.vol(part)?.header.clone();
            let table = w.read_header_res(part, &h.lookup, "lookup table")?;
            if table.len() % LOOKUP_ENTRY != 0 {
                return Err(corrupt("bad lookup table size"));
            }
            let mut keep = false;
            for e in table.chunks_exact(LOOKUP_ENTRY) {
                let res = ResHdr::parse(e);
                let spart = u16_at(e, 24);
                let refs = u32_at(e, 26);
                let mut hash = [0u8; HASH];
                hash.copy_from_slice(&e[30..50]);
                if spart != part {
                    continue;
                }
                let keep_solid = res.solid() && keep;
                keep = res.solid();
                let st = Stream {
                    res,
                    part: spart,
                    hash,
                    keep_solid,
                    solid: None,
                };
                if res.flags & RES_METADATA == 0 {
                    w.streams.push(st);
                } else if res.solid() || refs > 1 {
                    return Err(corrupt("bad metadata resource entry"));
                } else if refs == 1 && part == 1 {
                    metas.push(st);
                }
            }
            let xml = w.read_header_res(part, &h.xml, "XML data")?;
            if !xmls.iter().any(|(_, x)| *x == xml) {
                xmls.push((part, xml));
            }
        }
        let xml_main = xmls.first().map(|(_, x)| xml_text(x)).unwrap_or_default();
        if let Some(esd) = xml_tag(&xml_main, "ESD") {
            if esd.contains("<ENCRYPTED") {
                return Err(Error::unsupported("encrypted ESD"));
            }
        }

        let mut items: Vec<Item> = Vec::new();
        let mut images: Vec<Image> = Vec::new();
        for (i, m) in metas.iter().enumerate() {
            let meta = w.read_header_res(1, &m.res, "metadata")?;
            if Sha1::digest(&meta)[..] != m.hash {
                return Err(corrupt("metadata SHA-1 mismatch"));
            }
            images.push(parse_image(&meta, i, &mut items)?);
        }
        w.setup_solids()?;

        // Blob lookup by hash; solid resource entries are not blobs.
        let mut by_hash: HashMap<[u8; HASH], usize> = HashMap::new();
        for (i, s) in w.streams.iter().enumerate() {
            if !s.res.solid_big() {
                by_hash.entry(s.hash).or_insert(i);
            }
        }
        let mut refs = vec![0u32; w.streams.len()];
        for it in &mut items {
            if it.hash != [0; HASH] {
                it.stream = by_hash.get(&it.hash).copied();
                if let Some(s) = it.stream {
                    refs[s] += 1;
                }
            }
        }
        let deleted: Vec<usize> = (0..w.streams.len())
            .filter(|&s| {
                refs[s] == 0
                    && match (w.streams[s].res.solid_big(), w.streams[s].solid) {
                        (true, Some(si)) => w.solids[si].first_small.is_none(),
                        _ => true,
                    }
            })
            .collect();
        w.build_entries(&items, &images, &deleted, &xmls)?;
        let phys = metas
            .iter()
            .map(|m| m.res.end())
            .fold(w.vols[1].as_ref().unwrap().header.phys_size, u64::max);
        w.build_props(phys, &images, &xmls, &xml_main);
        Ok(w)
    }

    /// Reads solid resource headers and assigns every blob to its solid resource.
    fn setup_solids(&mut self) -> Result<()> {
        let n = self.streams.len();
        let mut i = 0;
        while i < n {
            if !self.streams[i].res.solid() {
                i += 1;
                continue;
            }
            let group_start = self.solids.len();
            let mut run = 0u64;
            let mut k = i;
            while k < n {
                let st = &self.streams[k];
                if !st.res.solid() || (k != i && !st.keep_solid) {
                    break;
                }
                if st.res.flags != RES_SOLID {
                    return Err(corrupt("bad solid resource flags"));
                }
                if st.res.solid_big() {
                    let solid = self.read_solid(k, run)?;
                    run = run
                        .checked_add(solid.size)
                        .ok_or_else(|| corrupt("solid resources too large"))?;
                    self.streams[k].solid = Some(self.solids.len());
                    self.solids.push(solid);
                }
                k += 1;
            }
            for j in i..k {
                let r = self.streams[j].res;
                if !r.solid_small() {
                    continue;
                }
                let group = &self.solids[group_start..];
                let at = group.partition_point(|s| s.group_offset <= r.offset);
                let si = at
                    .checked_sub(1)
                    .filter(|&g| r.offset - group[g].group_offset < group[g].size)
                    .ok_or_else(|| corrupt("blob outside every solid resource"))?;
                let so = &mut self.solids[group_start + si];
                if r.packed > so.size - (r.offset - so.group_offset) {
                    return Err(corrupt("blob crosses the end of its solid resource"));
                }
                so.first_small.get_or_insert(j);
                self.streams[j].solid = Some(group_start + si);
            }
            i = k;
        }
        if self.solids.is_empty() {
            // Non-solid archives list blobs in file order.
            let sorted = self.streams.windows(2).all(|w| {
                (w[0].part, w[0].res.offset, w[0].res.packed)
                    <= (w[1].part, w[1].res.offset, w[1].res.packed)
            });
            if !sorted {
                self.streams
                    .sort_by_key(|s| (s.part, s.res.offset, s.res.packed));
            }
        }
        Ok(())
    }

    fn read_solid(&self, k: usize, group_offset: u64) -> Result<Solid> {
        let st = &self.streams[k];
        let data = self.packed_bytes(self.vol(st.part)?, &st.res)?;
        if data.len() < 16 {
            return Err(corrupt("short solid resource"));
        }
        let size = u64_at(data, 0);
        let chunk = u32_at(data, 8);
        let method = u32_at(data, 12);
        let bits = log2_exact(chunk as u64).ok_or_else(|| corrupt("bad solid chunk size"))?;
        if size >= 1 << 63 {
            return Err(corrupt("bad solid resource size"));
        }
        let n = size.div_ceil(1 << bits);
        let mut off = n
            .checked_mul(4)
            .and_then(|t| t.checked_add(16))
            .filter(|&e| e <= data.len() as u64)
            .ok_or_else(|| corrupt("solid chunk table larger than the resource"))?;
        let mut chunks = Vec::with_capacity(n as usize + 1);
        for i in 0..n as usize {
            chunks.push(off);
            off += u32_at(data, 16 + 4 * i) as u64;
        }
        chunks.push(off);
        if off != data.len() as u64 {
            return Err(corrupt("solid chunk sizes do not match the resource"));
        }
        Ok(Solid {
            stream: k,
            group_offset,
            size,
            chunk_bits: bits,
            method,
            chunks,
            first_small: None,
        })
    }

    /// Uncompressed size of stream `s`.
    fn stream_size(&self, s: usize) -> u64 {
        let r = &self.streams[s].res;
        if !r.solid() {
            r.size
        } else if r.solid_small() {
            r.packed
        } else {
            self.streams[s].solid.map_or(0, |si| self.solids[si].size)
        }
    }

    /// Packed size 7-Zip attributes to an entry of stream `s`.
    fn stream_packed(&self, s: usize) -> Option<u64> {
        let r = &self.streams[s].res;
        if !r.solid_small() {
            return Some(r.packed);
        }
        let si = self.streams[s].solid?;
        let so = &self.solids[si];
        (so.first_small == Some(s)).then(|| self.streams[so.stream].res.packed)
    }

    fn stream_method(&self, s: usize) -> String {
        let st = &self.streams[s];
        let (m, bits) = if st.res.solid() {
            match st.solid {
                Some(si) => (self.solids[si].method, Some(self.solids[si].chunk_bits)),
                None => return String::new(),
            }
        } else if st.res.flags & RES_COMPRESSED == 0 {
            (0, None)
        } else {
            match self.vols.get(st.part as usize).and_then(Option::as_ref) {
                Some(v) => (v.header.method, Some(v.header.chunk_bits)),
                None => return String::new(),
            }
        };
        let name = METHOD_NAMES
            .get(m as usize)
            .map(|s| s.to_string())
            .unwrap_or_else(|| m.to_string());
        match bits {
            Some(b) => format!("{name}:{b}"),
            None => name,
        }
    }

    fn build_entries(
        &mut self,
        items: &[Item],
        images: &[Image],
        deleted: &[usize],
        xmls: &[(u16, Vec<u8>)],
    ) -> Result<()> {
        let show_images = images.len() != 1;
        let excluded = |i: usize| -> bool {
            let it = &items[i];
            it.parent.is_none() && images[it.image].empty_root
        };

        // Paths, parents first (children always follow their parent).
        const LONG: &str = "[LONG_PATH]/[LONG_PATH_ITEM]";
        let mut rel: Vec<String> = Vec::with_capacity(items.len());
        let mut long = vec![false; items.len()];
        let mut budget = 0usize;
        for (i, it) in items.iter().enumerate() {
            let name = component(&it.name);
            let parent_long = it.parent.is_some_and(|p| long[p]);
            let path = if parent_long || it.level > 1 << 12 {
                long[i] = true;
                String::new()
            } else if excluded(i) {
                String::new()
            } else {
                match it.parent {
                    None => name,
                    Some(p) if rel[p].is_empty() && excluded(p) => {
                        if it.alt {
                            format!(":{name}")
                        } else {
                            name
                        }
                    }
                    Some(p) => {
                        let sep = if it.alt { ':' } else { '/' };
                        format!("{}{sep}{name}", rel[p])
                    }
                }
            };
            if path.len() >= 1 << 15 {
                long[i] = true;
                rel.push(String::new());
                continue;
            }
            budget += path.len();
            if budget > MAX_PATH_BYTES {
                return Err(Error::unsupported("WIM directory tree too large"));
            }
            rel.push(path);
        }
        let full = |i: usize| -> String {
            if long[i] {
                return LONG.to_string();
            }
            let r = &rel[i];
            if !show_images {
                return r.clone();
            }
            let root = (items[i].image + 1).to_string();
            if r.is_empty() {
                root
            } else if r.starts_with(':') {
                format!("{root}{r}")
            } else {
                format!("{root}/{r}")
            }
        };

        // 7-Zip's order: directories (plain ones first), files, alternate streams; then
        // by blob, image and position in the metadata.
        #[derive(Clone, Copy)]
        enum Key {
            Item(usize),
            Deleted(usize),
        }
        let mut keys: Vec<Key> = (0..items.len())
            .filter(|&i| show_images || !excluded(i))
            .map(Key::Item)
            .chain(deleted.iter().map(|&s| Key::Deleted(s)))
            .collect();
        let sort_key = |k: &Key| match *k {
            Key::Item(i) => {
                let it = &items[i];
                (
                    !it.is_dir,
                    !it.dir_plain,
                    it.alt,
                    it.stream.map_or(-1, |s| s as i64),
                    it.image as i64,
                    it.offset,
                )
            }
            Key::Deleted(s) => (true, true, false, s as i64, -1, 0),
        };
        keys.sort_by_key(sort_key);

        let mut by_stream: HashMap<usize, usize> = HashMap::new();
        let mut by_solid: HashMap<usize, usize> = HashMap::new();
        let nz = |t: u64| (t != 0).then_some(t);
        for k in keys {
            let (e, src) = match k {
                Key::Item(i) => {
                    let it = &items[i];
                    let main = if it.alt {
                        &items[it.parent.unwrap()]
                    } else {
                        it
                    };
                    let mut e = Entry {
                        name: full(i),
                        is_dir: it.is_dir,
                        ctime: nz(main.times[0]),
                        atime: nz(main.times[1]),
                        mtime: nz(main.times[2]),
                        attrib: (!it.alt).then_some(it.attrib),
                        ..Entry::default()
                    };
                    let src = match it.stream {
                        Some(s) => {
                            e.size = Some(self.stream_size(s));
                            e.packed_size = self.stream_packed(s);
                            e.method = Some(self.stream_method(s));
                            Source::Blob(s)
                        }
                        None if it.is_dir => Source::None,
                        None => {
                            e.size = Some(0);
                            e.packed_size = Some(0);
                            if it.hash == [0; HASH] {
                                Source::None
                            } else {
                                Source::Missing
                            }
                        }
                    };
                    let src = self.reparse(it, &mut e, src);
                    if it.is_dir {
                        (e, Source::None)
                    } else {
                        (e, src)
                    }
                }
                Key::Deleted(s) => {
                    let e = Entry {
                        name: format!("[DELETED]/{s}"),
                        size: Some(self.stream_size(s)),
                        packed_size: self.stream_packed(s),
                        method: Some(self.stream_method(s)),
                        ..Entry::default()
                    };
                    (e, Source::Blob(s))
                }
            };
            self.push_entry(e, src, &mut by_stream, &mut by_solid);
        }
        if show_images {
            for (part, x) in xmls {
                let e = Entry {
                    name: format!("[{part}].xml"),
                    size: Some(x.len() as u64),
                    packed_size: Some(x.len() as u64),
                    ..Entry::default()
                };
                let src = Source::Mem(Arc::from(x.as_slice()));
                self.push_entry(e, src, &mut by_stream, &mut by_solid);
            }
            for (i, im) in images.iter().enumerate() {
                if !im.empty_root {
                    let e = Entry {
                        name: (i + 1).to_string(),
                        is_dir: true,
                        ..Entry::default()
                    };
                    self.push_entry(e, Source::None, &mut by_stream, &mut by_solid);
                }
            }
        }
        // Solid units decode in resource order.
        for &u in by_solid.values() {
            let mut ents = std::mem::take(&mut self.units[u].entries);
            ents.sort_by_key(|&i| match self.sources[i] {
                Source::Blob(s) => {
                    let r = &self.streams[s].res;
                    (if r.solid_small() { r.offset } else { 0 }, i)
                }
                _ => (0, i),
            });
            self.units[u].entries = ents;
        }
        Ok(())
    }

    fn push_entry(
        &mut self,
        e: Entry,
        src: Source,
        by_stream: &mut HashMap<usize, usize>,
        by_solid: &mut HashMap<usize, usize>,
    ) {
        let i = self.entries.len();
        let unit = match &src {
            Source::None => None,
            Source::Blob(s) => Some(match self.streams[*s].solid {
                Some(si) => *by_solid.entry(si).or_insert_with(|| {
                    self.units.push(Unit::default());
                    self.units.len() - 1
                }),
                None => *by_stream.entry(*s).or_insert_with(|| {
                    self.units.push(Unit::default());
                    self.units.len() - 1
                }),
            }),
            Source::Missing | Source::Mem(_) => {
                self.units.push(Unit::default());
                Some(self.units.len() - 1)
            }
        };
        if let Some(u) = unit {
            self.units[u].entries.push(i);
        }
        self.entries.push(e);
        self.sources.push(src);
    }

    /// Turns a symbolic link or junction into a link entry whose data is the target.
    fn reparse(&self, it: &Item, e: &mut Entry, src: Source) -> Source {
        if it.alt || it.attrib & ATTR_REPARSE == 0 {
            return src;
        }
        let Source::Blob(s) = src else {
            return src;
        };
        let size = self.stream_size(s);
        if size >= 1 << 16 {
            return src;
        }
        let data = self.stream_src(s).and_then(|(src, start, len)| {
            Self::read_all(&src, start, len, Some(self.streams[s].hash), &e.name)
        });
        let Some(target) = data.ok().and_then(|d| reparse_target(it.reparse_tag, &d)) else {
            return src;
        };
        let bytes: Arc<[u8]> = Arc::from(target.as_bytes());
        if !it.is_dir {
            e.size = Some(bytes.len() as u64);
        }
        e.link = Some(Link::Symbolic(target));
        Source::Mem(bytes)
    }

    fn build_props(&mut self, phys: u64, images: &[Image], xmls: &[(u16, Vec<u8>)], xml: &str) {
        let h = &self.vols[1].as_ref().unwrap().header;
        let mut p: Vec<(&'static str, String)> = Vec::new();
        p.push(("Physical Size", phys.to_string()));
        let size: u64 = self.streams.iter().map(|s| s.res.size).sum();
        let packed: u64 = self.streams.iter().map(|s| s.res.packed).sum();
        p.push(("Size", size.to_string()));
        p.push(("Packed Size", packed.to_string()));
        let mut mask = 0u32;
        let mut bits = 0;
        for (part, _) in xmls {
            if let Some(Some(v)) = self.vols.get(*part as usize) {
                mask |= 1 << v.header.method;
                bits = bits.max(v.header.chunk_bits);
            }
        }
        let names: Vec<&str> = (0..4)
            .filter(|m| mask & (1 << m) != 0)
            .map(|m| METHOD_NAMES[m])
            .collect();
        let mut method = names.join(" ");
        if names.len() == 1 {
            method.push_str(&format!(":{bits}"));
        }
        p.push(("Method", method));
        p.push(("Cluster Size", (1u64 << h.chunk_bits).to_string()));
        let ximages = xml_images(xml);
        let fmt = crate::util::time::format_filetime;
        if xmls.len() == 1 {
            if let Some(t) = ximages
                .iter()
                .filter_map(|im| xml_time(im, "CREATIONTIME"))
                .min()
            {
                p.push(("Created", fmt(t)));
            }
            if let Some(t) = ximages
                .iter()
                .filter_map(|im| xml_time(im, "LASTMODIFICATIONTIME"))
                .max()
            {
                p.push(("Modified", fmt(t)));
            }
            if ximages.len() == 1 {
                if images.len() == 1 {
                    p.push(("Comment", xml.to_string()));
                } else if let Some(n) = xml_tag(ximages[0], "NAME") {
                    p.push(("Comment", n.to_string()));
                }
            }
        }
        let v = h.version;
        let mut ver = format!("{}.{}", v >> 16, (v >> 8) & 0xFF);
        if v & 0xFF != 0 {
            ver.push_str(&format!(".{}", v & 0xFF));
        }
        p.push(("Version", ver));
        p.push(("Multivolume", if h.parts > 1 { "+" } else { "-" }.into()));
        p.push(("Volume", h.part.to_string()));
        p.push(("Volumes", (self.vols.len() - 1).to_string()));
        p.push(("Images", images.len().to_string()));
        if h.boot_index != 0 {
            p.push(("Boot Image", h.boot_index.to_string()));
        }
        self.props = p;
    }
}

impl Archive for Wim {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let mut cache = Cache::new(ctx.threads);
        for &i in &self.units[unit].entries {
            let name = self.entries[i].name.as_str();
            let flow = match &self.sources[i] {
                Source::Blob(s) => {
                    let (src, start, len) = self.stream_src(*s)?;
                    let mut r = BlobReader {
                        src: &src,
                        cache: &mut cache,
                        pos: start,
                        end: start + len,
                        sha: Some((Sha1::new(), self.streams[*s].hash)),
                        name,
                    };
                    let flow = f(i, &mut r)?;
                    if flow == Flow::Continue {
                        super::data::skip(&mut r, u64::MAX)?;
                    }
                    flow
                }
                Source::Mem(d) => f(i, &mut &d[..])?,
                Source::Missing => {
                    return Err(corrupt(&format!(
                        "the data of {name} is not in the archive"
                    )))
                }
                Source::None => f(i, &mut io::empty())?,
            };
            if flow == Flow::Stop {
                break;
            }
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.props.clone()
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
