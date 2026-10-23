//! Nullsoft Scriptable Install System (NSIS) installers, read-only.
//!
//! An installer is the NSIS loader (a small PE executable) with the installer data appended
//! after the image. The data starts at a 512-byte boundary with the first header: flags
//! (bit 0 marks an uninstaller), `0xDEADBEEF`, `NullsoftInst`, the length of the script
//! header once decoded, and the length of all the data (the first header and the trailing
//! CRC32 included). What follows is one of two layouts:
//!
//! - solid: one compressed stream holding the header's length, the header, and then each
//!   file as a 32-bit length and its bytes;
//! - blocks: the header and then each file as a block, a 32-bit length whose top bit marks
//!   compressed data, and the bytes.
//!
//! The compressor is deflate, NSIS's bzip2, or LZMA (a properties byte and the dictionary
//! size, then raw data with an end marker), which may be preceded by a byte that turns on the
//! x86 branch filter. Deflate is RFC 1951 (NSIS 3) read by flate2, except that NSIS 2 writes a
//! stored block's length without its complement, so NSIS 2 streams keep a small inflater of
//! their own. NSIS's bzip2 is bzip2's block coding (`codec::bzip2par`) with one-byte block
//! and end markers, and no stream header, block magic, CRC or randomization bit. The layout
//! and compressor are found by decoding the header each way, and the same compressor is used
//! for every block.
//!
//! The header holds the compiled script: a table of instructions, a string table (ANSI or
//! UTF-16LE, with NSIS 2, NSIS 3 or Unicode-fork codes for variables, shell folders and
//! language strings) and the section, page and language tables. File names come from a walk
//! over the instructions in order: `SetOutPath` sets the output folder that relative `File`
//! names are joined to, and `WriteUninstaller` names the uninstaller, which is rebuilt from
//! the loader (with the uninstaller's icons patched in) and the uninstaller data, as the
//! installer itself writes it. Names keep NSIS variables and folders (`$PLUGINSDIR`,
//! `$SYSDIR`); a leading `$INSTDIR\` is dropped. A file extracted by several instructions is
//! listed once, and files are listed in the order of their data. A name that cannot be read
//! from the script becomes `[offset]`, and when the script cannot be read at all, every data
//! block is listed that way; `damage` reports both.
//!
//! A solid installer is one unit; in the block layout each file is its own unit. Sizes are
//! known before decoding only for stored files. Times come from the script; the CRC32 is not
//! checked.

use std::collections::HashSet;
use std::io::{self, Read};

use lzma_rust2::filter::bcj::BcjReader;
use lzma_rust2::LzmaReader;

use super::data::{self, Input, Slice};
use super::pe::Image;
use super::{Archive, CodePage, Columns, Ctx, Entry, EntryFn, Flow, Format, NameCoding};
use super::{OpenOptions, Unit};
use crate::codec::bzip2par::decode_nsis_block;
use crate::error::{Error, Result};

/// A payload format: no signature and no extension, recognized in a PE file's overlay by
/// [`looks_like_nsis`] on the whole file (see `format::payload_format`).
pub const FORMAT: Format = Format {
    name: "Nsis",
    aliases: &[],
    extensions: &[],
    signatures: &[],
    detect: Some(looks_like_nsis),
    write: false,
    stream: false,
    sequential: false,
    open,
};

const SIGINFO: u32 = 0xDEAD_BEEF;
const MAGIC: &[u8; 12] = b"NullsoftInst";
/// Flags, signature, magic, header length and data length.
const FIRST_HEADER_LEN: usize = 28;
/// The loader looks for the first header at multiples of this.
const ALIGN: usize = 512;
const FH_UNINSTALL: u32 = 1;
/// Without this flag the data ends with a CRC32.
const FH_NO_CRC: u32 = 4;
/// The top bit of a block length marks compressed data.
const COMPRESSED: u32 = 0x8000_0000;
/// Script headers are well under a megabyte in practice.
const MAX_HEADER: u32 = 64 << 20;
/// NSIS lengths are 31 bits, so no file decodes to more.
const MAX_FILE: u64 = 0x7FFF_FFFF;
/// Icon data patched into the loader of an uninstaller.
const MAX_ICON: u64 = 16 << 20;
/// Blocks walked when the script cannot be read, or to find the compressor.
const MAX_BLOCKS: usize = 1 << 16;
/// Solid data decoded at open to list the blocks of an installer whose script cannot be
/// read.
const MAX_WALK: u64 = 256 << 20;
/// How far past the PE image the first header is looked for. It normally sits right at
/// the end of the image; a signature or padding can come first.
const MAX_SCAN: usize = 64 << 20;
/// LZMA properties NSIS always writes: lc=3, lp=0, pb=2.
const LZMA_PROPS: u8 = 0x5D;

/// An instruction: an opcode and six parameters.
const ENTRY_LEN: usize = 28;
/// Flags and the eight `(offset, count)` table descriptors.
const HEADER_MIN: usize = 4 + 8 * 8;
const NB_ENTRIES: usize = 2;
const NB_STRINGS: usize = 3;
const NB_LANGTABLES: usize = 4;
/// Opcodes NSIS 2 and 3 share (logging builds insert theirs after these).
const EW_CREATEDIR: u32 = 11;
const EW_EXTRACTFILE: u32 = 20;
const EW_WRITEUNINSTALLER: u32 = 62;

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn truncated() -> Error {
    Error::corrupt("NSIS data is truncated")
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("NSIS: {msg}"))
}

fn eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "NSIS: compressed data is truncated",
    )
}

// ---------------------------------------------------------------- first header

#[derive(Clone, Copy)]
struct FirstHeader {
    /// File offset; the loader is everything before it.
    at: usize,
    flags: u32,
    header_len: u32,
    total_len: u32,
}

/// The first header, searched for at 512-byte steps from the end of the PE image (or from
/// the start of a file that is not a PE image).
fn first_header(file: &[u8]) -> Option<FirstHeader> {
    let start = Image::parse(file).map_or(0, |image| image.overlay);
    let mut at = start.checked_next_multiple_of(ALIGN)?;
    let stop = start.saturating_add(MAX_SCAN);
    while let Some(h) = file
        .get(at..at.checked_add(FIRST_HEADER_LEN)?)
        .filter(|_| at < stop)
    {
        if u32_at(h, 4) == Some(SIGINFO) && &h[8..20] == MAGIC {
            let header_len = u32_at(h, 20)?;
            let total_len = u32_at(h, 24)?;
            if header_len > 0 && header_len <= MAX_HEADER && total_len as usize > FIRST_HEADER_LEN {
                return Some(FirstHeader {
                    at,
                    flags: u32_at(h, 0)?,
                    header_len,
                    total_len,
                });
            }
        }
        at = at.checked_add(ALIGN)?;
    }
    None
}

pub(crate) fn looks_like_nsis(file: &[u8]) -> bool {
    first_header(file).is_some()
}

// ---------------------------------------------------------------- codecs

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codec {
    Deflate,
    Bzip2,
    Lzma,
}

/// The codec a compressed stream looks like. LZMA streams start with NSIS's properties and
/// a dictionary of whole 64 KiB units (a deflate stream cannot start that way), possibly
/// after a filter byte; NSIS bzip2 streams start with a block marker.
fn sniff(s: &[u8]) -> Codec {
    let lzma_at = |i: usize| {
        s.get(i) == Some(&LZMA_PROPS)
            && u32_at(s, i + 1).is_some_and(|d| d != 0 && d.is_multiple_of(1 << 16))
    };
    if lzma_at(0) || (matches!(s.first(), Some(0 | 1)) && lzma_at(1)) {
        Codec::Lzma
    } else if s.first() == Some(&BZ_BLOCK) {
        Codec::Bzip2
    } else {
        Codec::Deflate
    }
}

/// The LZMA filter flag and the stream without it.
fn lzma_parts(s: &[u8]) -> (bool, &[u8]) {
    match s {
        [f @ (0 | 1), LZMA_PROPS, ..] => (*f == 1, &s[1..]),
        _ => (false, s),
    }
}

/// The method as 7-Zip prints it: `Deflate`, `BZip2`, `LZMA:23`.
fn method_name(codec: Codec, stream: &[u8]) -> String {
    match codec {
        Codec::Deflate => "Deflate".into(),
        Codec::Bzip2 => "BZip2".into(),
        Codec::Lzma => {
            let (bcj, s) = lzma_parts(stream);
            let dict = u32_at(s, 1).unwrap_or(0) as u64;
            let name = format!("LZMA:{}", crate::util::fmt::dict_label(dict));
            if bcj {
                format!("{name} BCJ")
            } else {
                name
            }
        }
    }
}

/// How a deflate stored block gives its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stored {
    /// NSIS 2: 16 bits, without the complement.
    Short,
    /// NSIS 3, as in RFC 1951: the length and its complement.
    Full,
    /// Decided at the first stored block: a complement there means `Full`.
    Auto,
}

/// A decoder over one compressed stream held in memory.
fn decoder<'a>(codec: Codec, s: &'a [u8], stored: Stored) -> Result<Box<dyn Read + 'a>> {
    Ok(match codec {
        // NSIS 3 writes standard deflate, which flate2 reads. NSIS 2 leaves the complement out
        // of its stored blocks, so those streams keep the inflater below.
        Codec::Deflate if stored == Stored::Full => Box::new(flate2::read::DeflateDecoder::new(s)),
        Codec::Deflate => Box::new(Inflate::new(s, stored)),
        Codec::Bzip2 => Box::new(Bunzip {
            data: s,
            at: 0,
            out: Vec::new(),
            pos: 0,
            done: false,
        }),
        Codec::Lzma => {
            let (bcj, s) = lzma_parts(s);
            let (props, dict) = match s {
                [p, a, b, c, d, ..] => (*p, u32::from_le_bytes([*a, *b, *c, *d])),
                _ => return Err(truncated()),
            };
            // The window grows with the output, so a large declared dictionary costs
            // nothing up front.
            let lz = LzmaReader::new_with_props(&s[5..], u64::MAX, props, dict, None)
                .map_err(data::data_err)?;
            if bcj {
                Box::new(BcjReader::new_x86(lz, 0))
            } else {
                Box::new(lz)
            }
        }
    })
}

/// Reads all of `r`, failing past `limit` bytes.
fn read_limited(r: &mut dyn Read, limit: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    r.take(limit.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(data::data_err)?;
    if out.len() as u64 > limit {
        return Err(Error::corrupt("NSIS data decodes to more than its limit"));
    }
    Ok(out)
}

/// Fails instead of yielding more than `left` bytes.
struct Capped<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let lim = usize::try_from(self.left.saturating_add(1))
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = self.inner.read(&mut buf[..lim])?;
        if n as u64 > self.left {
            return Err(bad("file data decodes to more than 2 GiB"));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Exactly `left` bytes of `inner`; fails if it ends sooner.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let lim = usize::try_from(self.left)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = self.inner.read(&mut buf[..lim])?;
        if n == 0 {
            return Err(eof());
        }
        self.left -= n as u64;
        Ok(n)
    }
}

fn skip_exact(r: &mut dyn Read, n: u64) -> Result<()> {
    if data::skip(r, n)? != n {
        return Err(truncated());
    }
    Ok(())
}

fn read_u32(r: &mut dyn Read) -> Result<u32> {
    let mut b = [0u8; 4];
    data::read_exact(r, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

// ---------------------------------------------------------------- NSIS deflate

/// LSB-first bits over a byte slice.
struct LsbBits<'a> {
    d: &'a [u8],
    pos: usize,
    buf: u64,
    n: u32,
}

impl<'a> LsbBits<'a> {
    fn new(d: &'a [u8]) -> Self {
        LsbBits {
            d,
            pos: 0,
            buf: 0,
            n: 0,
        }
    }

    fn refill(&mut self) {
        while self.n <= 56 {
            let Some(&b) = self.d.get(self.pos) else {
                return;
            };
            self.buf |= (b as u64) << self.n;
            self.n += 8;
            self.pos += 1;
        }
    }

    fn bits(&mut self, k: u32) -> io::Result<u32> {
        if self.n < k {
            self.refill();
            if self.n < k {
                return Err(eof());
            }
        }
        let v = (self.buf & ((1u64 << k) - 1)) as u32;
        self.buf >>= k;
        self.n -= k;
        Ok(v)
    }

    fn align(&mut self) {
        let r = self.n % 8;
        self.buf >>= r;
        self.n -= r;
    }

    /// Appends `len` bytes from a byte-aligned position.
    fn copy_bytes(&mut self, mut len: usize, out: &mut Vec<u8>) -> io::Result<()> {
        while len > 0 && self.n >= 8 {
            out.push(self.buf as u8);
            self.buf >>= 8;
            self.n -= 8;
            len -= 1;
        }
        let end = self.pos.checked_add(len).ok_or_else(eof)?;
        out.extend_from_slice(self.d.get(self.pos..end).ok_or_else(eof)?);
        self.pos = end;
        Ok(())
    }
}

/// Bits of the direct lookup; longer codewords are decoded bit by bit.
const FAST: u32 = 10;

/// A canonical Huffman code (deflate or bzip2): codeword counts per length, the symbols in
/// codeword order, and for deflate a table indexed by the next `FAST` stream bits holding
/// `symbol << 4 | length` (0 for longer codewords).
struct Huff {
    count: [u16; 21],
    sym: Vec<u16>,
    fast: Vec<u16>,
}

impl Huff {
    /// Builds the code; fails when the lengths over-subscribe the code space. Incomplete
    /// codes are accepted, and their unused codewords fail to decode.
    fn new(lens: &[u8], lsb_table: bool) -> io::Result<Huff> {
        let mut count = [0u16; 21];
        for &l in lens {
            let c = count
                .get_mut(l as usize)
                .ok_or_else(|| bad("code is too long"))?;
            *c += 1;
        }
        count[0] = 0;
        let mut left = 1i64;
        for &c in &count[1..] {
            left = left * 2 - c as i64;
            if left < 0 {
                return Err(bad("over-subscribed code"));
            }
        }
        let mut offs = [0usize; 22];
        for len in 1..21 {
            offs[len + 1] = offs[len] + count[len] as usize;
        }
        let mut sym = vec![0u16; offs[21]];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                sym[offs[l as usize]] = s as u16;
                offs[l as usize] += 1;
            }
        }
        let mut fast = Vec::new();
        if lsb_table {
            fast = vec![0u16; 1 << FAST];
            let mut next = [0u32; 21];
            let mut code = 0u32;
            for len in 1..21 {
                code = (code + count[len - 1] as u32) << 1;
                next[len] = code;
            }
            for (s, &l) in lens.iter().enumerate() {
                if l == 0 {
                    continue;
                }
                let c = next[l as usize];
                next[l as usize] += 1;
                if l as u32 > FAST {
                    continue;
                }
                let rev = (c.reverse_bits() >> (32 - l as u32)) as usize;
                let mut i = rev;
                while i < fast.len() {
                    fast[i] = ((s as u16) << 4) | l as u16;
                    i += 1 << l;
                }
            }
        }
        Ok(Huff { count, sym, fast })
    }

    /// Canonical decoding, one bit at a time from `bit`.
    fn decode_slow(&self, mut bit: impl FnMut(u32) -> io::Result<u32>) -> io::Result<(u16, u32)> {
        let (mut code, mut first, mut index) = (0i64, 0i64, 0i64);
        for len in 1..21u32 {
            code |= bit(len)? as i64;
            let count = self.count[len as usize] as i64;
            if code - count < first {
                let s = self.sym.get((index + code - first) as usize);
                return s.map(|&s| (s, len)).ok_or_else(|| bad("invalid code"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(bad("invalid code"))
    }

    fn decode_lsb(&self, b: &mut LsbBits) -> io::Result<u16> {
        b.refill();
        let e = self.fast[(b.buf as usize) & ((1 << FAST) - 1)];
        let len = (e & 15) as u32;
        if e != 0 && len <= b.n {
            b.buf >>= len;
            b.n -= len;
            return Ok(e >> 4);
        }
        let (buf, n) = (b.buf, b.n);
        let (s, len) = self.decode_slow(|len| {
            if len > n {
                return Err(eof());
            }
            Ok(((buf >> (len - 1)) & 1) as u32)
        })?;
        b.buf >>= len;
        b.n -= len;
        Ok(s)
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const WINDOW: usize = 1 << 15;
/// Output decoded per refill.
const CHUNK: usize = 1 << 15;

#[derive(Clone, Copy)]
enum InfState {
    Header,
    Stored(usize),
    Codes,
    Done,
}

/// NSIS's deflate: RFC 1951, except that NSIS 2 writes a stored block's length without its
/// complement.
struct Inflate<'a> {
    bits: LsbBits<'a>,
    stored: Stored,
    st: InfState,
    last: bool,
    lit: Huff,
    dist: Huff,
    /// History and pending output; `win[pos..]` has not been returned yet.
    win: Vec<u8>,
    pos: usize,
}

impl<'a> Inflate<'a> {
    fn new(d: &'a [u8], stored: Stored) -> Self {
        let empty = || Huff {
            count: [0; 21],
            sym: Vec::new(),
            fast: vec![0; 1 << FAST],
        };
        Inflate {
            bits: LsbBits::new(d),
            stored,
            st: InfState::Header,
            last: false,
            lit: empty(),
            dist: empty(),
            win: Vec::new(),
            pos: 0,
        }
    }

    fn after_block(&self) -> InfState {
        if self.last {
            InfState::Done
        } else {
            InfState::Header
        }
    }

    fn fixed(&mut self) -> io::Result<()> {
        let mut lens = [8u8; 288];
        lens[144..256].fill(9);
        lens[256..280].fill(7);
        self.lit = Huff::new(&lens, true)?;
        self.dist = Huff::new(&[5u8; 30], true)?;
        Ok(())
    }

    fn dynamic(&mut self) -> io::Result<()> {
        let b = &mut self.bits;
        let hlit = b.bits(5)? as usize + 257;
        let hdist = b.bits(5)? as usize + 1;
        let hclen = b.bits(4)? as usize + 4;
        if hlit > 286 || hdist > 30 {
            return Err(bad("too many length or distance codes"));
        }
        let mut cl = [0u8; 19];
        for &i in CL_ORDER.iter().take(hclen) {
            cl[i] = b.bits(3)? as u8;
        }
        let clh = Huff::new(&cl, true)?;
        let total = hlit + hdist;
        let mut lens = [0u8; 286 + 30];
        let mut i = 0;
        while i < total {
            let (val, rep) = match clh.decode_lsb(b)? {
                s @ 0..=15 => (s as u8, 1),
                16 if i > 0 => (lens[i - 1], 3 + b.bits(2)? as usize),
                17 => (0, 3 + b.bits(3)? as usize),
                18 => (0, 11 + b.bits(7)? as usize),
                _ => return Err(bad("invalid code lengths")),
            };
            if i + rep > total {
                return Err(bad("invalid code lengths"));
            }
            lens[i..i + rep].fill(val);
            i += rep;
        }
        if lens[256] == 0 {
            return Err(bad("no end-of-block code"));
        }
        self.lit = Huff::new(&lens[..hlit], true)?;
        self.dist = Huff::new(&lens[hlit..total], true)?;
        Ok(())
    }

    /// The length of a stored block, after its header bits.
    fn stored_len(&mut self) -> io::Result<usize> {
        self.bits.align();
        let len = self.bits.bits(16)?;
        if self.stored == Stored::Auto {
            self.bits.refill();
            let next = (self.bits.buf & 0xFFFF) as u32;
            let complement = self.bits.n >= 16 && next == !len & 0xFFFF;
            self.stored = if complement {
                Stored::Full
            } else {
                Stored::Short
            };
        }
        if self.stored == Stored::Full && self.bits.bits(16)? != !len & 0xFFFF {
            return Err(bad("stored block length does not match its complement"));
        }
        Ok(len as usize)
    }

    /// One match or literal; `false` at the end of the block.
    fn symbol(&mut self) -> io::Result<bool> {
        let s = self.lit.decode_lsb(&mut self.bits)? as usize;
        if s < 256 {
            self.win.push(s as u8);
            return Ok(true);
        }
        if s == 256 {
            return Ok(false);
        }
        let k = s - 257;
        let (Some(&base), Some(&extra)) = (LEN_BASE.get(k), LEN_EXTRA.get(k)) else {
            return Err(bad("invalid length code"));
        };
        let len = base as usize + self.bits.bits(extra as u32)? as usize;
        let d = self.dist.decode_lsb(&mut self.bits)? as usize;
        let (Some(&base), Some(&extra)) = (DIST_BASE.get(d), DIST_EXTRA.get(d)) else {
            return Err(bad("invalid distance code"));
        };
        let dist = base as usize + self.bits.bits(extra as u32)? as usize;
        if dist > self.win.len() {
            return Err(bad("distance is too far back"));
        }
        let start = self.win.len() - dist;
        if dist >= len {
            self.win.extend_from_within(start..start + len);
        } else {
            for k in 0..len {
                let b = self.win[start + k];
                self.win.push(b);
            }
        }
        Ok(true)
    }

    /// Decodes up to `CHUNK` more bytes, or to the end of the stream.
    fn step(&mut self) -> io::Result<()> {
        let target = self.win.len() + CHUNK;
        while self.win.len() < target {
            match self.st {
                InfState::Done => return Ok(()),
                InfState::Header => {
                    self.last = self.bits.bits(1)? == 1;
                    self.st = match self.bits.bits(2)? {
                        0 => InfState::Stored(self.stored_len()?),
                        1 => {
                            self.fixed()?;
                            InfState::Codes
                        }
                        2 => {
                            self.dynamic()?;
                            InfState::Codes
                        }
                        _ => return Err(bad("invalid deflate block type")),
                    };
                }
                InfState::Stored(left) => {
                    let n = left.min(target - self.win.len());
                    self.bits.copy_bytes(n, &mut self.win)?;
                    self.st = if n == left {
                        self.after_block()
                    } else {
                        InfState::Stored(left - n)
                    };
                }
                InfState::Codes => {
                    if !self.symbol()? {
                        self.st = self.after_block();
                    }
                }
            }
        }
        Ok(())
    }
}

impl Read for Inflate<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos == self.win.len() {
            if self.win.len() > 2 * WINDOW {
                let cut = self.win.len() - WINDOW;
                self.win.drain(..cut);
                self.pos -= cut;
            }
            self.step()?;
        }
        let n = (self.win.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.win[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

// ---------------------------------------------------------------- NSIS bzip2

const BZ_BLOCK: u8 = 0x31;

/// NSIS's bzip2, one block at a time (see `bzip2par::decode_nsis_block`).
struct Bunzip<'a> {
    data: &'a [u8],
    /// Bit position of the next block's marker.
    at: u64,
    /// The current block's bytes, and how many have been returned.
    out: Vec<u8>,
    pos: usize,
    done: bool,
}

impl Read for Bunzip<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.out.len() {
            if self.done {
                return Ok(0);
            }
            match decode_nsis_block(self.data, self.at)? {
                Some((out, end)) => {
                    self.out = out;
                    self.pos = 0;
                    self.at = end;
                }
                None => self.done = true,
            }
        }
        let n = buf.len().min(self.out.len() - self.pos);
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

// ---------------------------------------------------------------- layout

#[derive(Clone, Copy)]
enum Layout {
    /// One stream; file offsets count from the end of the header in it.
    Solid(Codec),
    /// Blocks after the header block, which ends at `base` in the data. `codec` is unknown
    /// when no block is compressed.
    Blocks { base: usize, codec: Option<Codec> },
}

/// Decodes the header, trying a stored header block, a solid stream and a compressed
/// header block.
fn read_header(data: &[u8], header_len: u32) -> Result<(Layout, Vec<u8>)> {
    let hl = header_len as usize;
    let first = u32_at(data, 0).ok_or_else(truncated)?;
    if first == header_len {
        let header = data.get(4..4 + hl).ok_or_else(truncated)?.to_vec();
        let codec = first_codec(data, 4 + hl);
        return Ok((
            Layout::Blocks {
                base: 4 + hl,
                codec,
            },
            header,
        ));
    }
    let codec = sniff(data);
    if let Ok(header) = solid_header(codec, data, header_len) {
        return Ok((Layout::Solid(codec), header));
    }
    if first & COMPRESSED != 0 {
        let n = (first & !COMPRESSED) as usize;
        let block = data
            .get(4..4usize.saturating_add(n))
            .ok_or_else(truncated)?;
        let codec = sniff(block);
        let mut r = decoder(codec, block, Stored::Auto)?;
        let header = read_limited(&mut *r, header_len as u64)?;
        if header.len() == hl {
            let layout = Layout::Blocks {
                base: 4 + n,
                codec: Some(codec),
            };
            return Ok((layout, header));
        }
    }
    Err(Error::corrupt("NSIS header could not be decoded"))
}

/// A solid stream's header, after checking that the stream starts with its length.
fn solid_header(codec: Codec, data: &[u8], header_len: u32) -> Result<Vec<u8>> {
    let mut r = decoder(codec, data, Stored::Auto)?;
    if read_u32(&mut r)? != header_len {
        return Err(Error::NotArchive);
    }
    let mut header = Vec::new();
    (&mut r)
        .take(header_len as u64)
        .read_to_end(&mut header)
        .map_err(data::data_err)?;
    if header.len() != header_len as usize {
        return Err(truncated());
    }
    Ok(header)
}

/// The codec of the first compressed block from `at` (the installer uses one throughout).
fn first_codec(data: &[u8], mut at: usize) -> Option<Codec> {
    for _ in 0..MAX_BLOCKS {
        let len = u32_at(data, at)?;
        let n = (len & !COMPRESSED) as usize;
        if len & COMPRESSED != 0 {
            return Some(sniff(data.get(at + 4..)?));
        }
        at = at.checked_add(4 + n)?;
    }
    None
}

// ---------------------------------------------------------------- strings

/// How strings mark variables, shell folders and language strings.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Codes {
    /// ANSI NSIS 2: bytes 0xFC to 0xFF.
    Nsis2,
    /// NSIS 3, ANSI or UTF-16: characters 1 to 4.
    Nsis3,
    /// The Unicode fork of NSIS 2: characters 0xE000 to 0xE003.
    Park,
}

enum Special {
    Skip,
    Var,
    Shell,
    Lang,
}

/// `$0`..`$R9` come first, then these (`$CMDLINE` is 20); user variables follow, and are
/// written as 7-Zip writes them, `$_0_` for the first.
const VARS: [&str; 12] = [
    "CMDLINE",
    "INSTDIR",
    "OUTDIR",
    "EXEDIR",
    "LANGUAGE",
    "TEMP",
    "PLUGINSDIR",
    "EXEPATH",
    "EXEFILE",
    "HWNDPARENT",
    "_CLICK",
    "_OUTDIR",
];
const VAR_OUTDIR: u32 = 22;

fn var_name(v: u32) -> String {
    match v {
        0..=9 => format!("${v}"),
        10..=19 => format!("$R{}", v - 10),
        _ => match VARS.get(v as usize - 20) {
            Some(n) => format!("${n}"),
            None => format!("$_{}_", v - 20 - VARS.len() as u32),
        },
    }
}

/// NSIS's names for the shell folders (CSIDL values) it supports.
fn csidl_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0x00 | 0x10 | 0x19 => "DESKTOP",
        0x02 | 0x17 => "SMPROGRAMS",
        0x05 | 0x2E => "DOCUMENTS",
        0x06 | 0x1F => "FAVORITES",
        0x07 | 0x18 => "SMSTARTUP",
        0x08 => "RECENT",
        0x09 => "SENDTO",
        0x0B | 0x16 => "STARTMENU",
        0x0D | 0x35 => "MUSIC",
        0x0E | 0x37 => "VIDEOS",
        0x13 => "NETHOOD",
        0x14 => "FONTS",
        0x15 | 0x2D => "TEMPLATES",
        0x1A | 0x23 => "APPDATA",
        0x1B => "PRINTHOOD",
        0x1C => "LOCALAPPDATA",
        0x20 => "INTERNET_CACHE",
        0x21 => "COOKIES",
        0x22 => "HISTORY",
        0x24 => "WINDIR",
        0x25 => "SYSDIR",
        0x26 => "PROGRAMFILES",
        0x27 | 0x36 => "PICTURES",
        0x28 => "PROFILE",
        0x2B => "COMMONFILES",
        0x2F | 0x30 => "ADMINTOOLS",
        0x38 => "RESOURCES",
        0x39 => "RESOURCES_LOCALIZED",
        0x3B => "CDBURN_AREA",
        _ => return None,
    })
}

/// Which codes the strings use, from how often each set's variable and language codes appear
/// with a well-formed parameter (both bytes of an NSIS 2 or 3 parameter have the top bit
/// set; the fork sets the top bit of its 16-bit parameter).
fn detect_codes(table: &[u8], unicode: bool) -> Codes {
    if unicode {
        let (pairs, _) = table.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|&c| u16::from_le_bytes(c)).collect();
        let count = |codes: [u16; 2], mask: u16| {
            units
                .windows(2)
                .filter(|w| codes.contains(&w[0]) && w[1] & mask == mask)
                .count()
        };
        if count([0xE001, 0xE003], 0x8000) > count([1, 3], 0x8080) {
            Codes::Park
        } else {
            Codes::Nsis3
        }
    } else {
        let count = |codes: [u8; 2]| {
            table
                .windows(3)
                .filter(|w| codes.contains(&w[0]) && w[1] & w[2] & 0x80 != 0)
                .count()
        };
        if count([1, 3]) > count([0xFD, 0xFF]) {
            Codes::Nsis3
        } else {
            Codes::Nsis2
        }
    }
}

/// What a string starts with, which decides whether a file name is absolute.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lead {
    Text,
    Var(u32),
    Shell,
    Lang,
}

/// Raw characters of a string being decoded.
enum Raw {
    Ansi(Vec<u8>),
    Wide(Vec<u16>),
}

/// The string table.
#[derive(Clone, Copy)]
struct Strings<'a> {
    table: &'a [u8],
    unicode: bool,
    codes: Codes,
    page: Option<CodePage>,
}

impl<'a> Strings<'a> {
    fn new(table: &'a [u8], page: Option<CodePage>) -> Self {
        // The table starts with an empty string, and UTF-16 text of the mostly ASCII strings
        // at its start has a zero in most odd bytes.
        let sample = &table[..table.len().min(512)];
        let odd = sample.iter().skip(1).step_by(2);
        let zeros = odd.clone().filter(|&&b| b == 0).count();
        let unicode = table.starts_with(&[0, 0]) && zeros * 2 > odd.count();
        Strings {
            table,
            unicode,
            codes: detect_codes(table, unicode),
            page,
        }
    }

    fn unit(&self, i: usize) -> Option<u32> {
        if self.unicode {
            let b = self.table.get(2 * i..2 * i + 2)?;
            Some(u16::from_le_bytes([b[0], b[1]]) as u32)
        } else {
            self.table.get(i).map(|&b| b as u32)
        }
    }

    fn special(&self, c: u32) -> Option<Special> {
        Some(match (self.codes, c) {
            (Codes::Nsis2, 0xFC) | (Codes::Nsis3, 4) | (Codes::Park, 0xE000) => Special::Skip,
            (Codes::Nsis2, 0xFD) | (Codes::Nsis3, 3) | (Codes::Park, 0xE001) => Special::Var,
            (Codes::Nsis2, 0xFE) | (Codes::Nsis3, 2) | (Codes::Park, 0xE002) => Special::Shell,
            (Codes::Nsis2, 0xFF) | (Codes::Nsis3, 1) | (Codes::Park, 0xE003) => Special::Lang,
            _ => return None,
        })
    }

    fn flush(&self, raw: &mut Raw, out: &mut String) {
        match raw {
            Raw::Ansi(b) if !b.is_empty() => {
                out.push_str(&match self.page {
                    Some(p) => p.decode(b),
                    None => crate::util::text::ansi(b),
                });
                b.clear();
            }
            Raw::Wide(w) if !w.is_empty() => {
                out.push_str(&String::from_utf16_lossy(w));
                w.clear();
            }
            _ => {}
        }
    }

    /// The string at `off` (in characters), with variables written as `$NAME` and
    /// `$OUTDIR` replaced by `outdir`, and what it starts with. None when `off` is outside
    /// the table; a negative offset names a language string.
    fn get(&self, off: i32, outdir: &str) -> Option<(String, Lead)> {
        if off < 0 {
            return Some((format!("$(LSTR_{})", -(off as i64 + 1)), Lead::Lang));
        }
        let mut i = off as usize;
        self.unit(i)?;
        let mut lead = None;
        let mut raw = if self.unicode {
            Raw::Wide(Vec::new())
        } else {
            Raw::Ansi(Vec::new())
        };
        let mut out = String::new();
        while let Some(c) = self.unit(i) {
            i += 1;
            if c == 0 {
                break;
            }
            let push = |raw: &mut Raw, c: u32| match raw {
                Raw::Ansi(b) => b.push(c as u8),
                Raw::Wide(w) => w.push(c as u16),
            };
            let Some(kind) = self.special(c) else {
                lead.get_or_insert(Lead::Text);
                push(&mut raw, c);
                continue;
            };
            // The parameter: one more UTF-16 unit, or two bytes.
            let (b0, b1) = if self.unicode {
                let Some(p) = self.unit(i) else { break };
                i += 1;
                ((p & 0xFF) as u8, (p >> 8) as u8)
            } else {
                let (Some(p0), Some(p1)) = (self.unit(i), self.unit(i + 1)) else {
                    break;
                };
                i += 2;
                (p0 as u8, p1 as u8)
            };
            if let Special::Skip = kind {
                lead.get_or_insert(Lead::Text);
                // The escaped character is the parameter itself.
                if self.unicode {
                    push(&mut raw, b0 as u32 | ((b1 as u32) << 8));
                } else {
                    push(&mut raw, b0 as u32);
                    i -= 1;
                }
                continue;
            }
            self.flush(&mut raw, &mut out);
            let value = if self.codes == Codes::Park {
                (b0 as u32 | ((b1 as u32) << 8)) & 0x7FFF
            } else {
                (b0 & 0x7F) as u32 | (((b1 & 0x7F) as u32) << 7)
            };
            match kind {
                Special::Var => lead.get_or_insert(Lead::Var(value)),
                Special::Lang => lead.get_or_insert(Lead::Lang),
                _ => lead.get_or_insert(Lead::Shell),
            };
            match kind {
                Special::Var if value == VAR_OUTDIR && !outdir.is_empty() => out.push_str(outdir),
                Special::Var => out.push_str(&var_name(value)),
                Special::Lang => out.push_str(&format!("$(LSTR_{value})")),
                _ => out.push_str(&self.shell_name(b0, b1)),
            }
        }
        self.flush(&mut raw, &mut out);
        Some((out, lead.unwrap_or(Lead::Text)))
    }

    /// A shell folder: a CSIDL for the current user and one for all users, or (top bit) a
    /// folder read from the registry, whose value name is in the string table.
    fn shell_name(&self, b0: u8, b1: u8) -> String {
        if b0 & 0x80 != 0 {
            let key = self.plain((b0 & 0x3F) as usize);
            let base = match key.as_str() {
                "ProgramFilesDir" => "PROGRAMFILES",
                "CommonFilesDir" => "COMMONFILES",
                _ => return format!("$_{key}_"),
            };
            let bits = if b0 & 0x40 != 0 { "64" } else { "" };
            return format!("${base}{bits}");
        }
        match csidl_name(b0).or_else(|| csidl_name(b1)) {
            Some(n) => format!("${n}"),
            None => format!("$_SHELL_{b0:02X}{b1:02X}_"),
        }
    }

    /// The characters at `i` up to the next NUL, without decoding codes.
    fn plain(&self, mut i: usize) -> String {
        let mut raw = if self.unicode {
            Raw::Wide(Vec::new())
        } else {
            Raw::Ansi(Vec::new())
        };
        while let Some(c) = self.unit(i).filter(|&c| c != 0) {
            match &mut raw {
                Raw::Ansi(b) => b.push(c as u8),
                Raw::Wide(w) => w.push(c as u16),
            }
            i += 1;
        }
        let mut out = String::new();
        self.flush(&mut raw, &mut out);
        out
    }
}

// ---------------------------------------------------------------- script

/// A file the script extracts.
struct Item {
    /// The name as the script spells it (backslashes, variables).
    path: Option<String>,
    /// Offset of the file's data; for an uninstaller, of its icon data, which the
    /// uninstaller data follows.
    offset: u32,
    uninstaller: bool,
    mtime: Option<u64>,
}

/// What the script says about the installer.
struct Script {
    items: Vec<Item>,
    unicode: bool,
    codes: Codes,
    notes: Vec<String>,
}

/// The `(offset, count)` descriptor of header table `i`.
fn table(header: &[u8], i: usize) -> (usize, usize) {
    let off = u32_at(header, 4 + 8 * i).unwrap_or(0) as usize;
    let num = u32_at(header, 8 + 8 * i).unwrap_or(0) as usize;
    (off, num)
}

/// The output folder a relative name is joined to, unless it is already absolute: it starts
/// with a shell folder, a built-in folder variable (`$INSTDIR`, `$PLUGINSDIR`; `$OUTDIR`
/// was replaced by the folder), a drive or `\\`. Names starting with numbered or user
/// variables are taken as relative, as 7-Zip takes them.
fn join(outdir: &str, (name, lead): (String, Lead)) -> String {
    let absolute = match lead {
        Lead::Var(v) => (20..32).contains(&v),
        Lead::Shell | Lead::Lang => true,
        Lead::Text => name.starts_with("\\\\") || name.get(1..2) == Some(":"),
    };
    if absolute || outdir.is_empty() {
        name
    } else {
        format!("{}\\{name}", outdir.trim_end_matches('\\'))
    }
}

/// FILETIME from its two halves; both all-ones means none.
fn filetime(lo: u32, hi: u32) -> Option<u64> {
    (lo != u32::MAX || hi != u32::MAX).then_some(((hi as u64) << 32) | lo as u64)
}

impl Script {
    fn parse(header: &[u8], page: Option<CodePage>) -> Result<Script> {
        if header.len() < HEADER_MIN {
            return Err(Error::corrupt("NSIS header is too short"));
        }
        let (strings_at, _) = table(header, NB_STRINGS);
        let (lang_at, _) = table(header, NB_LANGTABLES);
        let strings_end = if lang_at > strings_at && lang_at <= header.len() {
            lang_at
        } else {
            header.len()
        };
        let text = header
            .get(strings_at..strings_end)
            .ok_or_else(|| Error::corrupt("NSIS string table is outside the header"))?;
        let strings = Strings::new(text, page);
        let (entries_at, count) = table(header, NB_ENTRIES);
        let avail = header.len().saturating_sub(entries_at) / ENTRY_LEN;
        if entries_at > header.len() || count == 0 {
            return Err(Error::corrupt("NSIS script has no instructions"));
        }
        let mut notes = Vec::new();
        if count > avail {
            notes.push(format!(
                "the script lists {count} instructions, but only {avail} fit in its header"
            ));
        }
        let mut items = Vec::new();
        let mut outdir = String::new();
        for k in 0..count.min(avail) {
            let at = entries_at + k * ENTRY_LEN;
            let p = |i: usize| u32_at(header, at + 4 + 4 * i).unwrap_or(0);
            let s = |i: usize, outdir: &str| strings.get(p(i) as i32, outdir);
            match u32_at(header, at).unwrap_or(0) {
                EW_CREATEDIR if p(1) != 0 => {
                    if let Some((dir, _)) = s(0, &outdir) {
                        outdir = dir;
                    }
                }
                EW_EXTRACTFILE => items.push(Item {
                    path: s(1, &outdir)
                        .filter(|(n, _)| !n.is_empty())
                        .map(|n| join(&outdir, n)),
                    offset: p(2),
                    uninstaller: false,
                    mtime: filetime(p(3), p(4)),
                }),
                EW_WRITEUNINSTALLER => {
                    let name = s(0, &outdir)
                        .filter(|(n, _)| !n.is_empty())
                        .or_else(|| s(3, &outdir).filter(|(n, _)| !n.is_empty()));
                    items.push(Item {
                        path: name.map(|n| join(&outdir, n)),
                        offset: p(1),
                        uninstaller: true,
                        mtime: None,
                    });
                }
                _ => {}
            }
        }
        let unnamed = items.iter().filter(|it| it.path.is_none()).count();
        if unnamed > 0 {
            notes.push(format!(
                "{unnamed} file names could not be read from the script"
            ));
        }
        // Each file once (the first instruction naming it), in the order of the data.
        items.sort_by_key(|it| it.offset);
        let mut seen = HashSet::new();
        items.retain(|it| seen.insert((it.offset, it.uninstaller, it.path.clone())));
        Ok(Script {
            items,
            unicode: strings.unicode,
            codes: strings.codes,
            notes,
        })
    }
}

/// The listed name: `/`-separated, without a leading `$INSTDIR\`.
fn display_name(it: &Item) -> String {
    let Some(p) = &it.path else {
        return format!("[{}]", it.offset);
    };
    let p = p.strip_prefix("$INSTDIR\\").unwrap_or(p);
    let name = p.replace('\\', "/");
    if name.is_empty() || name.ends_with('/') {
        format!("{name}[{}]", it.offset)
    } else {
        name
    }
}

/// The uninstaller as the installer writes it: the loader with the icon data patched in.
/// The icon data is a run of `(size, offset, bytes)` patches ending with a zero size.
fn patched_stub(stub: &[u8], icons: &[u8]) -> Result<Vec<u8>> {
    let mut out = stub.to_vec();
    let bad_icons = || Error::corrupt("NSIS uninstaller icon data is damaged");
    let mut q = 0usize;
    while let Some(size) = u32_at(icons, q).filter(|&s| s != 0) {
        let off = u32_at(icons, q + 4).ok_or_else(bad_icons)? as usize;
        let start = q + 8;
        let end = start.checked_add(size as usize).ok_or_else(bad_icons)?;
        let bytes = icons.get(start..end).ok_or_else(bad_icons)?;
        let dst = off.checked_add(bytes.len()).ok_or_else(bad_icons)?;
        out.get_mut(off..dst)
            .ok_or_else(bad_icons)?
            .copy_from_slice(bytes);
        q = end;
    }
    Ok(out)
}

// ---------------------------------------------------------------- archive

pub struct Nsis {
    file: Slice,
    fh: FirstHeader,
    /// The data after the first header, up to its end or the end of the file.
    data: Slice,
    layout: Layout,
    entries: Vec<Entry>,
    items: Vec<Item>,
    units: Vec<Unit>,
    method: String,
    /// How stored deflate blocks of file data give their length.
    stored: Stored,
    script: Option<(bool, Codes)>,
    page: Option<CodePage>,
    notes: Vec<String>,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let file = input.into_mem()?;
    let fh = first_header(&file).ok_or(Error::NotArchive)?;
    let start = (fh.at + FIRST_HEADER_LEN) as u64;
    let crc = if fh.flags & FH_NO_CRC == 0 { 4 } else { 0 };
    let end = (fh.at as u64 + fh.total_len as u64 - crc).min(file.len() as u64);
    let data = file.sub_clamped(start..end);
    let mut notes = Vec::new();
    if (fh.at as u64 + fh.total_len as u64) > file.len() as u64 {
        notes.push(format!(
            "the installer data is truncated: {} of {} bytes are present",
            file.len() - fh.at,
            fh.total_len
        ));
    }
    let (layout, header) = read_header(&data, fh.header_len)?;
    let (items, script) = match Script::parse(&header, opts.code_page) {
        Ok(s) => {
            notes.extend(s.notes);
            (s.items, Some((s.unicode, s.codes)))
        }
        Err(e) => {
            notes.push(format!("{e}; file data is listed by position"));
            let (items, whole) = by_position(&data, layout, fh.header_len);
            if !whole {
                notes.push(format!(
                    "blocks after the first {} MiB of solid data are not listed",
                    MAX_WALK >> 20
                ));
            }
            (items, None)
        }
    };
    let stored = match script {
        Some((_, Codes::Nsis2)) => Stored::Short,
        Some((_, Codes::Nsis3)) => Stored::Full,
        _ => Stored::Auto,
    };
    let mut nsis = Nsis {
        file,
        fh,
        data,
        layout,
        entries: Vec::new(),
        items,
        units: Vec::new(),
        method: String::new(),
        stored,
        script,
        page: opts.code_page,
        notes,
    };
    nsis.build();
    Ok(Box::new(nsis))
}

/// Every data block, unnamed, for an installer whose script cannot be read, and whether the
/// walk over a solid stream got to its end within `MAX_WALK`.
fn by_position(data: &[u8], layout: Layout, header_len: u32) -> (Vec<Item>, bool) {
    let mut offsets = Vec::new();
    let mut whole = true;
    match layout {
        Layout::Blocks { base, .. } => {
            let mut off = 0usize;
            while let Some(len) = base.checked_add(off).and_then(|at| u32_at(data, at)) {
                if offsets.len() >= MAX_BLOCKS || u32::try_from(off).is_err() {
                    break;
                }
                offsets.push(off as u32);
                off = off.saturating_add(4 + (len & !COMPRESSED) as usize);
            }
        }
        Layout::Solid(codec) => {
            let Ok(mut r) = decoder(codec, data, Stored::Auto) else {
                return (Vec::new(), true);
            };
            let mut off = 0u64;
            if skip_exact(&mut r, 4 + header_len as u64).is_ok() {
                while let Ok(len) = read_u32(&mut r) {
                    if offsets.len() >= MAX_BLOCKS || len & COMPRESSED != 0 {
                        break;
                    }
                    if off + 4 + len as u64 > MAX_WALK {
                        whole = false;
                        break;
                    }
                    let Ok(o) = u32::try_from(off) else { break };
                    offsets.push(o);
                    if skip_exact(&mut r, len as u64).is_err() {
                        break;
                    }
                    off += 4 + len as u64;
                }
            }
        }
    }
    let items = offsets
        .into_iter()
        .map(|offset| Item {
            path: None,
            offset,
            uninstaller: false,
            mtime: None,
        })
        .collect();
    (items, whole)
}

/// A block of the block layout: whether it is compressed, its bytes, and the offset of the
/// next block.
struct Block<'a> {
    compressed: bool,
    bytes: &'a [u8],
    next: u64,
}

impl Nsis {
    fn block(&self, offset: u64) -> Result<Block<'_>> {
        let Layout::Blocks { base, .. } = self.layout else {
            return Err(Error::corrupt("not a block layout"));
        };
        let at = usize::try_from(offset)
            .ok()
            .and_then(|o| o.checked_add(base))
            .ok_or_else(truncated)?;
        let len = u32_at(&self.data, at).ok_or_else(truncated)?;
        let n = (len & !COMPRESSED) as usize;
        let bytes = self
            .data
            .get(at + 4..(at + 4).saturating_add(n))
            .ok_or_else(truncated)?;
        Ok(Block {
            compressed: len & COMPRESSED != 0,
            bytes,
            next: offset + 4 + n as u64,
        })
    }

    fn codec_for(&self, bytes: &[u8]) -> Codec {
        match self.layout {
            Layout::Solid(c) | Layout::Blocks { codec: Some(c), .. } => c,
            Layout::Blocks { codec: None, .. } => sniff(bytes),
        }
    }

    fn open_block<'a>(&'a self, b: &Block<'a>) -> Result<Box<dyn Read + 'a>> {
        if !b.compressed {
            return Ok(Box::new(b.bytes));
        }
        let inner = decoder(self.codec_for(b.bytes), b.bytes, self.stored)?;
        Ok(Box::new(Capped {
            inner,
            left: MAX_FILE,
        }))
    }

    /// The loader, or nothing when the data was opened without one.
    fn stub(&self) -> &[u8] {
        &self.file[..self.fh.at]
    }

    fn uninstaller_stub(&self, icons: &[u8]) -> Result<Vec<u8>> {
        if self.stub().is_empty() {
            return Ok(Vec::new());
        }
        patched_stub(self.stub(), icons)
    }

    /// Size and packed size of an item, when the block layout stores them.
    fn sizes(&self, it: &Item) -> (Option<u64>, Option<u64>) {
        let Ok(b) = self.block(it.offset as u64) else {
            return (None, None);
        };
        let stored = |b: &Block| (!b.compressed).then_some(b.bytes.len() as u64);
        if !it.uninstaller {
            return (stored(&b), Some(b.bytes.len() as u64));
        }
        let Ok(body) = self.block(b.next) else {
            return (None, None);
        };
        let size = stored(&b).and(stored(&body)).map(|n| n + self.fh.at as u64);
        (size, Some((b.bytes.len() + body.bytes.len()) as u64))
    }

    fn build(&mut self) {
        let solid = matches!(self.layout, Layout::Solid(_));
        let mut compressed = None;
        for (i, it) in self.items.iter().enumerate() {
            let (size, packed, method) = if solid {
                (None, (i == 0).then_some(self.data.len() as u64), None)
            } else {
                let (size, packed) = self.sizes(it);
                let method = self.block(it.offset as u64).ok().map(|b| {
                    if !b.compressed {
                        return "Copy".to_string();
                    }
                    let m = method_name(self.codec_for(b.bytes), b.bytes);
                    compressed.get_or_insert_with(|| m.clone());
                    m
                });
                (size, packed, method)
            };
            let mut name = display_name(it);
            if it.uninstaller && self.fh.at == 0 {
                name.push_str(".nsis");
            }
            self.entries.push(Entry {
                name,
                size,
                packed_size: packed,
                mtime: it.mtime,
                method,
                ..Default::default()
            });
            if !solid {
                self.units.push(Unit {
                    entries: vec![i],
                    encrypted: false,
                });
            }
        }
        self.method = match self.layout {
            Layout::Solid(c) => method_name(c, &self.data),
            Layout::Blocks { .. } => compressed.unwrap_or_else(|| "Copy".into()),
        };
        if solid {
            for e in &mut self.entries {
                e.method = Some(self.method.clone());
            }
            // One pass over the stream reads each block once, so files sharing data with an
            // earlier one (under another name) go to passes of their own.
            let mut passes: Vec<(u32, Vec<usize>)> = Vec::new();
            for (i, it) in self.items.iter().enumerate() {
                match passes.iter_mut().find(|(last, _)| *last < it.offset) {
                    Some((last, entries)) => {
                        *last = it.offset;
                        entries.push(i);
                    }
                    None => passes.push((it.offset, vec![i])),
                }
            }
            self.units
                .extend(passes.into_iter().map(|(_, entries)| Unit {
                    entries,
                    encrypted: false,
                }));
        }
    }

    fn extract_block(&self, i: usize, f: &mut EntryFn<'_>) -> Result<()> {
        let it = &self.items[i];
        let b = self.block(it.offset as u64)?;
        if !it.uninstaller {
            let mut r = self.open_block(&b)?;
            f(i, &mut r)?;
            return Ok(());
        }
        let icons = read_limited(&mut *self.open_block(&b)?, MAX_ICON)?;
        let stub = self.uninstaller_stub(&icons)?;
        let body = self.block(b.next)?;
        let mut r = io::Cursor::new(stub).chain(self.open_block(&body)?);
        f(i, &mut r)?;
        Ok(())
    }

    fn extract_solid(&self, codec: Codec, unit: usize, f: &mut EntryFn<'_>) -> Result<()> {
        let mut r = decoder(codec, &self.data, self.stored)?;
        skip_exact(&mut r, 4 + self.fh.header_len as u64)?;
        // Stream position, counted from the end of the header.
        let mut pos = 0u64;
        for &i in &self.units[unit].entries {
            let it = &self.items[i];
            let off = it.offset as u64;
            if off < pos {
                return Err(Error::corrupt("NSIS file data overlaps the previous file"));
            }
            skip_exact(&mut r, off - pos)?;
            pos = off;
            let mut len = solid_len(&mut r)?;
            pos += 4;
            let mut stub = Vec::new();
            if it.uninstaller {
                if len > MAX_ICON {
                    return Err(Error::corrupt("NSIS uninstaller icon data is too large"));
                }
                let mut icons = Vec::new();
                (&mut r)
                    .take(len)
                    .read_to_end(&mut icons)
                    .map_err(data::data_err)?;
                if icons.len() as u64 != len {
                    return Err(truncated());
                }
                stub = self.uninstaller_stub(&icons)?;
                len = solid_len(&mut r)?;
                pos += icons.len() as u64 + 4;
            }
            let mut body = Exact {
                inner: &mut r,
                left: len,
            };
            let mut reader = io::Cursor::new(stub).chain(&mut body);
            let flow = f(i, &mut reader)?;
            pos += len - body.left;
            if flow == Flow::Stop {
                break;
            }
        }
        Ok(())
    }
}

/// A file length in a solid stream, which never has the compressed bit.
fn solid_len(r: &mut dyn Read) -> Result<u64> {
    let len = read_u32(r)?;
    if len & COMPRESSED != 0 {
        return Err(Error::corrupt("NSIS file length is invalid"));
    }
    Ok(len as u64)
}

impl Archive for Nsis {
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
        match self.layout {
            Layout::Solid(codec) => self.extract_solid(codec, unit, f),
            Layout::Blocks { .. } => self.extract_block(self.units[unit].entries[0], f),
        }
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let solid = matches!(self.layout, Layout::Solid(_));
        let mut sub = match self.script {
            Some((_, Codes::Nsis2)) => "NSIS-2".to_string(),
            Some((_, Codes::Park)) => "NSIS-Park".to_string(),
            _ => "NSIS-3".to_string(),
        };
        if self.script.is_some_and(|(unicode, _)| unicode) {
            sub.push_str(" Unicode");
        }
        if self.fh.flags & FH_UNINSTALL != 0 {
            sub.push_str(" (Uninstall)");
        }
        vec![
            (
                "Physical Size",
                (self.fh.at as u64 + self.fh.total_len as u64).to_string(),
            ),
            ("Method", self.method.clone()),
            ("Solid", if solid { "+" } else { "-" }.to_string()),
            ("Headers Size", self.fh.header_len.to_string()),
            ("Embedded Stub Size", self.fh.at.to_string()),
            ("SubType", sub),
        ]
    }

    fn columns(&self) -> Columns {
        Columns {
            method: true,
            ..Columns::default()
        }
    }

    fn name_coding(&self) -> Option<NameCoding> {
        let ansi = self.script.is_some_and(|(unicode, _)| !unicode);
        self.page.filter(|_| ansi).map(|page| NameCoding {
            page,
            detected: false,
        })
    }

    fn damage(&self) -> Vec<String> {
        self.notes.clone()
    }
}
