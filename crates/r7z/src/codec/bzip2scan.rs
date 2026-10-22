//! Recovery of damaged bzip2 streams, block by block.
//!
//! bzip2 blocks are independent apart from the bit alignment: each starts with a 48-bit
//! magic at any bit offset and carries its own CRC. Damage therefore costs the blocks it
//! touches. This module finds every block by its magic, rebuilds each one as a one-block
//! stream (the header, the block bits, and an end-of-stream trailer whose combined CRC is
//! the block's own CRC), and decodes those streams one at a time. A block that fails its
//! CRC is reported and skipped; decoding resumes at the next block.

use std::io::{self, Read};
use std::sync::Arc;

use crate::format::Notes;

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;
const MASK48: u64 = (1 << 48) - 1;

/// Bit offsets of every occurrence of a 48-bit `magic` in `data`, bit 0 being the most
/// significant bit of the first byte.
fn find_magic(data: &[u8], magic: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut window = 0u64;
    let mut bits = 0u64;
    for &byte in data {
        for k in (0..8).rev() {
            window = ((window << 1) | u64::from((byte >> k) & 1)) & MASK48;
            bits += 1;
            if bits >= 48 && window == magic {
                out.push(bits - 48);
            }
        }
    }
    out
}

/// Bit `pos` of `data` (most significant bit first).
#[inline]
fn bit(data: &[u8], pos: u64) -> u32 {
    u32::from((data[(pos >> 3) as usize] >> (7 - (pos & 7))) & 1)
}

/// The bit range `[start, end)` of one block, where `start` is its magic's position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub start: u64,
    pub end: u64,
}

/// Every block in `data`, in order. Blocks end where the next block or end-of-stream
/// marker begins, so each one's bits are exact apart from a damaged tail.
pub fn blocks(data: &[u8]) -> Vec<Block> {
    let starts = find_magic(data, BLOCK_MAGIC);
    let ends = find_magic(data, END_MAGIC);
    let total = data.len() as u64 * 8;
    let mut out = Vec::with_capacity(starts.len());
    let mut e = 0;
    for (k, &start) in starts.iter().enumerate() {
        while e < ends.len() && ends[e] <= start {
            e += 1;
        }
        let next_start = starts.get(k + 1).copied().unwrap_or(total);
        let end = match ends.get(e) {
            Some(&stop) if stop < next_start => stop,
            _ => next_start,
        };
        out.push(Block { start, end });
    }
    out
}

/// Packs bits, most significant first, into bytes.
#[derive(Default)]
struct BitPacker {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitPacker {
    fn push(&mut self, value: u64, bits: u32) {
        for k in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((value >> k) & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

/// A complete bzip2 stream holding only `block`: the `BZh9` header, the block's bits, and
/// an end-of-stream marker carrying the block's CRC as the combined CRC.
pub fn one_block_stream(data: &[u8], block: Block) -> Vec<u8> {
    let mut p = BitPacker::default();
    p.push(u64::from(u32::from_be_bytes(*b"BZh9")), 32);
    for pos in block.start..block.end {
        p.push(u64::from(bit(data, pos)), 1);
    }
    p.push(END_MAGIC, 48);
    let crc = (block.start + 48..block.start + 80)
        .fold(0u64, |v, pos| (v << 1) | u64::from(bit(data, pos)));
    p.push(crc, 32);
    p.finish()
}

/// Decodes one block; `Err` names the reason it is lost.
pub fn decode_block(data: &[u8], block: Block) -> io::Result<Vec<u8>> {
    let stream = one_block_stream(data, block);
    let mut out = Vec::new();
    bzip2::read::BzDecoder::new(&stream[..]).read_to_end(&mut out)?;
    Ok(out)
}

/// Reads the recovered contents of a damaged bzip2 stream. Every block that decodes is
/// returned; each one that does not is reported through `lost`.
pub struct Bzip2Recovery {
    data: Arc<Vec<u8>>,
    blocks: std::vec::IntoIter<Block>,
    current: Vec<u8>,
    pos: usize,
    /// Damage notes of the archive, one per lost block.
    notes: Notes,
    /// Blocks that could not be decoded.
    lost: usize,
    /// Whether the end-of-data error for `lost` has been returned.
    reported: bool,
}

impl Bzip2Recovery {
    pub fn new(data: Arc<Vec<u8>>, notes: Notes) -> Self {
        let blocks = blocks(&data).into_iter();
        Bzip2Recovery {
            data,
            blocks,
            current: Vec::new(),
            pos: 0,
            notes,
            lost: 0,
            reported: false,
        }
    }

    fn next_block(&mut self) -> bool {
        let Some(block) = self.blocks.next() else {
            return false;
        };
        match decode_block(&self.data, block) {
            Ok(out) => {
                self.current = out;
                self.pos = 0;
            }
            Err(e) => {
                self.lost += 1;
                self.notes
                    .lock()
                    .unwrap()
                    .push(format!("bzip2 block at byte {} lost: {e}", block.start / 8));
            }
        }
        true
    }
}

impl Read for Bzip2Recovery {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos == self.current.len() {
            if !self.next_block() {
                // The data is complete apart from the lost blocks: say so once, so the
                // entry is reported as partial rather than verified.
                if self.lost > 0 && !std::mem::replace(&mut self.reported, true) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} bzip2 block(s) could not be decoded", self.lost),
                    ));
                }
                return Ok(0);
            }
        }
        let n = (self.current.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.current[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn compress(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn sample(n: usize) -> Vec<u8> {
        let mut x = 7u32;
        (0..n)
            .map(|i| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                if i % 5 == 0 {
                    (x >> 16) as u8
                } else {
                    b"line of text\n"[i % 12]
                }
            })
            .collect()
    }

    #[test]
    fn finds_every_block_of_an_intact_stream() {
        let data = sample(350_000);
        let z = compress(&data, 1);
        let found = blocks(&z);
        assert!(found.len() >= 3, "{} blocks", found.len());
        let mut out = Vec::new();
        for b in &found {
            out.extend(decode_block(&z, *b).unwrap());
        }
        assert_eq!(out, data);
    }

    #[test]
    fn a_damaged_block_is_skipped_and_the_rest_comes_back() {
        let data = sample(400_000);
        let mut z = compress(&data, 1);
        let found = blocks(&z);
        assert!(found.len() >= 4);
        // Damage the middle of the second block.
        let mid = ((found[1].start + found[1].end) / 2 / 8) as usize;
        for b in &mut z[mid..mid + 16] {
            *b ^= 0x5A;
        }
        let notes: Notes = Arc::default();
        let mut rec = Bzip2Recovery::new(Arc::new(z), notes.clone());
        let mut out = Vec::new();
        assert!(rec.read_to_end(&mut out).is_err());
        assert_eq!(
            notes.lock().unwrap().len(),
            1,
            "{:?}",
            notes.lock().unwrap()
        );
        assert!(
            out.len() < data.len() && out.len() > data.len() / 2,
            "{}",
            out.len()
        );
        // The first block and the last one come back, the damaged middle does not.
        assert_eq!(&out[..1000], &data[..1000]);
        assert!(out.ends_with(&data[data.len() - 1000..]));
    }
}
