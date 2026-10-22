//! Recovery of damaged xz streams, block by block.
//!
//! Every xz block starts with a header of its own (sized and CRC-checked), carries one
//! LZMA2 stream that begins with a dictionary reset, and ends with a check value. Blocks
//! do not depend on each other, so a damaged block costs only itself: this module walks the
//! blocks from their headers (not the index, which damage often takes), skips a damaged
//! one by searching for the next header that checks out, and decodes each block alone
//! against its check. The index and footer are not needed.

use std::io::{self, Read};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::format::Notes;
use crate::util::crc64::Crc64;

const STREAM_HEADER: usize = 12;
const LZMA2: u64 = 0x21;
const BCJ_X86: u64 = 0x04;

fn vli(b: &[u8], p: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let c = *b.get(*p)?;
        *p += 1;
        v |= u64::from(c & 0x7F) << (7 * i);
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// What a block header says about its data.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Header size in bytes; the block's data starts right after it.
    pub size: usize,
    /// Dictionary size of the LZMA2 filter.
    pub dict: u32,
    /// An x86 BCJ filter runs before LZMA2 (applied after decoding).
    pub bcj: bool,
}

/// The header of the block at `pos`, when its size byte, CRC32 and filter list are sound.
pub fn block_header(data: &[u8], pos: usize) -> Option<BlockHeader> {
    let b0 = *data.get(pos)?;
    if b0 == 0 {
        return None;
    }
    let size = (b0 as usize + 1) * 4;
    let h = data.get(pos..pos + size)?;
    let stored = u32::from_le_bytes(h[size - 4..].try_into().ok()?);
    if crc32fast::hash(&h[..size - 4]) != stored {
        return None;
    }
    let flags = h[1];
    let filters = (flags & 3) as usize + 1;
    let mut p = 2;
    if flags & 0x40 != 0 {
        vli(h, &mut p)?;
    }
    if flags & 0x80 != 0 {
        vli(h, &mut p)?;
    }
    let (mut dict, mut bcj) = (None, false);
    for i in 0..filters {
        let id = vli(h, &mut p)?;
        let len = vli(h, &mut p)? as usize;
        if p + len > size - 4 {
            return None;
        }
        let props = &h[p..p + len];
        p += len;
        match id {
            LZMA2 if len == 1 && props[0] <= 40 => {
                let d = props[0] as u32;
                dict = Some(if d == 40 {
                    u32::MAX
                } else {
                    (2 | (d & 1)) << (d / 2 + 11)
                });
            }
            BCJ_X86 if i == 0 && len == 0 => bcj = true,
            _ => return None,
        }
    }
    Some(BlockHeader {
        size,
        dict: dict?,
        bcj,
    })
}

/// Length of the LZMA2 stream at `start` (through its end marker), when its chunk headers
/// chain together and the first chunk resets the dictionary.
pub fn lzma2_len(data: &[u8], start: usize) -> Option<usize> {
    let mut p = start;
    let mut first = true;
    loop {
        let c = *data.get(p)?;
        let len = match c {
            0 => return Some(p + 1 - start),
            1 | 2 if !first || c == 1 => {
                let n = u16::from_be_bytes([*data.get(p + 1)?, *data.get(p + 2)?]) as usize;
                3 + n + 1
            }
            0x80..=0xFF if !first || c >= 0xE0 => {
                let packed = u16::from_be_bytes([*data.get(p + 3)?, *data.get(p + 4)?]) as usize;
                let props = usize::from(c >= 0xC0);
                5 + props + packed + 1
            }
            _ => return None,
        };
        p = p.checked_add(len)?;
        if p > data.len() {
            return None;
        }
        first = false;
    }
}

/// Bytes of check value for a stream check type, or `None` for an unknown type.
fn check_len(kind: u8) -> Option<usize> {
    match kind {
        0 => Some(0),
        1 => Some(4),
        4 => Some(8),
        10 => Some(32),
        _ => None,
    }
}

/// Decodes the block whose data is `lz` (an LZMA2 stream) and checks its value
/// `check` against the output.
fn decode(h: &BlockHeader, lz: &[u8], kind: u8, check: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    lzma_rust2::Lzma2Reader::new(lz, h.dict, None).read_to_end(&mut out)?;
    if h.bcj {
        let mut filtered = Vec::with_capacity(out.len());
        lzma_rust2::filter::bcj::BcjReader::new_x86(&out[..], 0).read_to_end(&mut filtered)?;
        out = filtered;
    }
    let ok = match kind {
        0 => true,
        1 => &crc32fast::hash(&out).to_le_bytes()[..] == check,
        4 => {
            let mut crc = Crc64::new();
            crc.update(&out);
            &crc.finalize().to_le_bytes()[..] == check
        }
        _ => Sha256::digest(&out).as_slice() == check,
    };
    if ok {
        Ok(out)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "check value mismatch",
        ))
    }
}

/// Decodes the block at `pos`; `Err` says why it is lost, and the position of the next
/// block header to look at.
fn block_at(data: &[u8], pos: usize, kind: u8) -> Result<(Vec<u8>, usize), String> {
    let h = block_header(data, pos).ok_or("the block header is damaged")?;
    let lz_start = pos + h.size;
    let lz = lzma2_len(data, lz_start).ok_or("the compressed data is damaged")?;
    let pad = (4 - lz % 4) % 4;
    let check_at = lz_start + lz + pad;
    let n = check_len(kind).ok_or("unknown check type")?;
    let check = data
        .get(check_at..check_at + n)
        .ok_or("the block is cut off")?;
    let out = decode(&h, &data[lz_start..lz_start + lz], kind, check).map_err(|e| e.to_string())?;
    Ok((out, check_at + n))
}

/// Reads the recovered contents of a damaged xz stream. Each block that decodes is
/// returned; each one that does not is noted, and the search resumes at the next header.
pub struct XzRecovery {
    data: Arc<Vec<u8>>,
    kind: u8,
    /// Where to look for the next block header.
    pos: usize,
    current: Vec<u8>,
    read: usize,
    notes: Notes,
    done: bool,
    /// Blocks that could not be decoded.
    lost: usize,
    /// Whether the end-of-data error for `lost` has been returned.
    reported: bool,
}

impl XzRecovery {
    pub fn new(data: Arc<Vec<u8>>, notes: Notes) -> Self {
        let kind = data.get(7).map_or(0, |f| f & 0x0F);
        XzRecovery {
            data,
            kind,
            pos: STREAM_HEADER,
            current: Vec::new(),
            read: 0,
            notes,
            done: false,
            lost: 0,
            reported: false,
        }
    }

    fn note(&self, text: String) {
        self.notes.lock().unwrap().push(text);
    }

    /// Loads the next block that decodes; false at the index or the end of the data.
    fn next_block(&mut self) -> bool {
        while !self.done {
            let at = self.pos;
            if self.data.get(at) == Some(&0) || at >= self.data.len() {
                self.done = true;
                return false;
            }
            match block_at(&self.data, at, self.kind) {
                Ok((out, next)) => {
                    self.pos = next;
                    if !out.is_empty() {
                        self.current = out;
                        self.read = 0;
                        return true;
                    }
                }
                Err(why) => {
                    self.lost += 1;
                    let skip = self.resync(at + 1);
                    match skip {
                        Some(next) => {
                            self.note(format!(
                                "xz block at byte {at} lost ({why}); skipped {} bytes to the next block",
                                next - at
                            ));
                            self.pos = next;
                        }
                        None => {
                            self.note(format!(
                                "xz block at byte {at} lost ({why}); no later block header was found"
                            ));
                            self.done = true;
                            return false;
                        }
                    }
                }
            }
        }
        false
    }

    /// The next position from `from` where a block header checks out and its block decodes.
    fn resync(&self, from: usize) -> Option<usize> {
        (from..self.data.len()).find(|&q| {
            block_header(&self.data, q).is_some() && block_at(&self.data, q, self.kind).is_ok()
        })
    }
}

impl Read for XzRecovery {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.read == self.current.len() {
            if !self.next_block() {
                // Say once that blocks were lost, so the entry is reported as partial.
                if self.lost > 0 && !std::mem::replace(&mut self.reported, true) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} xz block(s) could not be decoded", self.lost),
                    ));
                }
                return Ok(0);
            }
        }
        let n = (self.current.len() - self.read).min(buf.len());
        buf[..n].copy_from_slice(&self.current[self.read..self.read + n]);
        self.read += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample(n: usize) -> Vec<u8> {
        let mut x = 5u32;
        (0..n)
            .map(|i| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if i % 4 == 0 {
                    (x >> 20) as u8
                } else {
                    b"xz block text\n"[i % 14]
                }
            })
            .collect()
    }

    /// An xz stream of several blocks (the writer starts a block every few MiB of input).
    fn xz_blocks(data: &[u8]) -> Vec<u8> {
        let mut w =
            crate::codec::xzwrite::XzLzma2Writer::new(Vec::new(), 1, 2, data.len() as u64).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn walks_every_block_of_an_intact_stream() {
        let data = sample(3_000_000);
        let z = xz_blocks(&data);
        assert!(block_starts(&z).len() >= 3);
        let notes: Notes = Default::default();
        let mut out = Vec::new();
        XzRecovery::new(Arc::new(z), notes.clone())
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data);
        assert!(notes.lock().unwrap().is_empty());
    }

    #[test]
    fn a_damaged_block_is_skipped_and_the_rest_comes_back() {
        let data = sample(3_000_000);
        let mut z = xz_blocks(&data);
        let starts = block_starts(&z);
        assert!(starts.len() >= 3);
        // Damage the middle of the second block's compressed data.
        let mid = starts[1] + 2000;
        for b in &mut z[mid..mid + 40] {
            *b ^= 0xA5;
        }
        let notes: Notes = Default::default();
        let mut out = Vec::new();
        // The lost block is reported at the end of the data, after everything else.
        assert!(XzRecovery::new(Arc::new(z), notes.clone())
            .read_to_end(&mut out)
            .is_err());
        assert_eq!(notes.lock().unwrap().len(), 1);
        assert!(out.len() < data.len() && out.len() > data.len() / 2);
        assert!(out[..1000] == data[..1000]);
        assert!(out.ends_with(&data[data.len() - 1000..]));
    }

    /// Where each block starts, found by walking the headers from the start.
    fn block_starts(z: &[u8]) -> Vec<usize> {
        let (mut pos, mut out) = (STREAM_HEADER, Vec::new());
        while let Some(h) = block_header(z, pos) {
            out.push(pos);
            let lz = lzma2_len(z, pos + h.size).unwrap();
            pos += h.size + lz + (4 - lz % 4) % 4 + 8;
        }
        out
    }

    #[test]
    fn header_checks_reject_noise() {
        assert_eq!(block_header(&[0, 0, 0, 0], 0), None);
        assert_eq!(block_header(&[0x05, 0, 0, 0, 0, 0, 0, 0], 0), None);
        assert_eq!(lzma2_len(&[0x00], 0), Some(1));
        assert_eq!(lzma2_len(&[0x80, 0, 0, 0, 0], 0), None);
    }
}
