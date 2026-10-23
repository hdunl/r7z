//! Bounds-checked reads of the big-endian fields in HFS+ structures.

use crate::error::{Error, Result};

/// A cursor over big-endian fields. Every read fails cleanly past the end of its bytes.
pub struct Be<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Be<'a> {
    pub fn at(bytes: &'a [u8], pos: usize) -> Self {
        Be { bytes, pos }
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or_else(|| Error::corrupt("HFS+ structure is truncated"))?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

/// Little-endian value of up to eight bytes (decmpfs headers are little-endian).
pub fn le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |v, &b| (v << 8) | u64::from(b))
}

/// UTF-16BE text; unpaired surrogates become U+FFFD.
pub fn utf16be(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_be_bytes(*p));
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}
