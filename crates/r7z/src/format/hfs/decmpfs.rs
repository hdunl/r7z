//! Transparently compressed files (decmpfs). The `com.apple.decmpfs` attribute holds a 16-byte
//! header (magic, compression type, uncompressed size). Types 3 (zlib) and 7 (LZVN) keep their
//! payload in the attribute, where a payload that starts with 0xFF is stored raw after that
//! byte. Types 4 and 8 keep their blocks in the resource fork: they are listed, but not decoded,
//! because 7-Zip rejected every block-table layout tried against it.

use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::io::{self, Cursor, Read};

use super::be::{le, utf16be, Be};
use super::btree::split_key;
use super::volume::Volume;
use crate::error::{Error, Result};
use crate::format::data::{data_err, read_exact};

const NAME: &str = "com.apple.decmpfs";
/// The magic `fpmc` as stored.
const MAGIC: &[u8; 4] = b"fpmc";
/// Bytes of the decmpfs header, and where the attribute value starts in its record (after the
/// record type, two reserved words and the value size).
const HEADER: usize = 16;
const VALUE_AT: usize = 16;
/// The attribute record type holding its value inline.
const INLINE: u32 = 0x10;
/// Largest inline LZVN value decoded in memory.
const MAX_INLINE_LZVN: u64 = 64 << 20;
/// First byte of a block stored raw.
const RAW: u8 = 0xFF;

/// The decoder for a block or inline payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Zlib,
    Lzvn,
}

/// The decoder for a decmpfs type whose payload is in the attribute.
pub fn codec(method: u32) -> Option<Codec> {
    match method {
        3 => Some(Codec::Zlib),
        7 => Some(Codec::Lzvn),
        _ => None,
    }
}

/// What a file's decmpfs attribute says about it.
pub enum Attr {
    Header {
        method: u32,
        /// Uncompressed size.
        size: u64,
        /// The inline payload: its logical offset in the attributes file and its length.
        inline: Option<(u64, usize)>,
    },
    /// The attribute exists but cannot be read; the reason is reported on extraction.
    Unreadable(String),
}

/// A compressed file's decoder inputs.
pub struct Compressed {
    pub codec: Codec,
    pub size: u64,
    /// The payload: its logical offset in the attributes file and its length.
    pub inline: (u64, usize),
}

/// The decmpfs attributes of every file that has one, by file ID.
pub fn scan(volume: &Volume) -> Result<HashMap<u32, Attr>> {
    let mut out = HashMap::new();
    let Some(tree) = volume.attributes() else {
        return Ok(out);
    };
    tree.for_each_record(&*volume.src(), |rec| {
        let (key, data) = split_key(rec.bytes)?;
        let mut k = Be::at(key, 4);
        let file_id = k.u32()?;
        k.skip(4)?; // start block
        let name_len = usize::from(k.u16()?);
        if utf16be(k.take(2 * name_len)?) == NAME {
            let data_at = rec.at + (rec.bytes.len() - data.len()) as u64;
            out.insert(file_id, attribute(data_at, data)?);
        }
        Ok(())
    })?;
    Ok(out)
}

/// The header of one decmpfs attribute record, whose data starts at logical `data_at`.
fn attribute(data_at: u64, data: &[u8]) -> Result<Attr> {
    let mut d = Be::at(data, 0);
    if d.u32()? != INLINE {
        return Ok(Attr::Unreadable(
            "the decmpfs attribute is stored outside its record".into(),
        ));
    }
    d.skip(8)?;
    let value_len = d.u32()? as usize;
    let Some(value) = data.get(VALUE_AT..VALUE_AT + value_len) else {
        return Ok(Attr::Unreadable(
            "the decmpfs attribute is truncated".into(),
        ));
    };
    let Some(header) = value.get(..HEADER) else {
        return Ok(Attr::Unreadable("the decmpfs header is truncated".into()));
    };
    if &header[..4] != MAGIC {
        return Ok(Attr::Unreadable("the decmpfs header is damaged".into()));
    }
    let method = le(&header[4..8]) as u32;
    let size = le(&header[8..16]);
    Ok(Attr::Header {
        method,
        size,
        inline: Some((data_at + (VALUE_AT + HEADER) as u64, value_len - HEADER)),
    })
}

/// A reader of a compressed file's uncompressed bytes.
pub fn open(volume: &Volume, c: &Compressed) -> Result<Box<dyn Read + Send>> {
    let (at, len) = c.inline;
    let mut payload = vec![0u8; len];
    volume.read_attributes(at, &mut payload)?;
    inline(c.codec, c.size, payload)
}

/// An inline payload: zlib streams, or a whole LZVN stream decoded in memory.
fn inline(codec: Codec, size: u64, mut payload: Vec<u8>) -> Result<Box<dyn Read + Send>> {
    if payload.first() == Some(&RAW) {
        payload.remove(0);
        return Ok(Box::new(Exact::new(Cursor::new(payload), size)));
    }
    match codec {
        Codec::Zlib => Ok(Box::new(Exact::new(
            ZlibDecoder::new(Cursor::new(payload)),
            size,
        ))),
        Codec::Lzvn => {
            if size > MAX_INLINE_LZVN {
                return Err(Error::unsupported("inline LZVN data larger than 64 MiB"));
            }
            let mut out = vec![0u8; size as usize];
            decode(codec, &payload, &mut out)?;
            Ok(Box::new(Cursor::new(out)))
        }
    }
}

/// Fills `out` from one compressed chunk: raw when `src` starts with 0xFF, else decoded.
fn decode(codec: Codec, src: &[u8], out: &mut [u8]) -> Result<()> {
    if src.first() == Some(&RAW) {
        let raw = src
            .get(1..1 + out.len())
            .ok_or_else(|| Error::corrupt("raw decmpfs block is shorter than its chunk"))?;
        out.copy_from_slice(raw);
        return Ok(());
    }
    match codec {
        Codec::Zlib => read_exact(&mut ZlibDecoder::new(src), out),
        Codec::Lzvn => match lzvn::decode_into(src, out) {
            Ok(n) if n == out.len() => Ok(()),
            Ok(_) => Err(Error::corrupt("LZVN block is shorter than its chunk")),
            Err(e) => Err(Error::corrupt(format!("LZVN block: {e}"))),
        },
    }
}

/// Yields exactly `left` bytes; a stream that ends early is corrupt, not a short file.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R> Exact<R> {
    fn new(inner: R, left: u64) -> Self {
        Exact { inner, left }
    }
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(self.left as usize);
        let n = self
            .inner
            .read(&mut buf[..want])
            .map_err(|e| data_err(e).into_io())?;
        if n == 0 {
            return Err(Error::corrupt("decmpfs data ends before its size").into_io());
        }
        self.left -= n as u64;
        Ok(n)
    }
}
