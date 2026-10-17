//! Primitive encodings: 7z variable-length NUMBER, bit vectors, little-endian integers.

use crate::error::{Error, Result};

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| Error::corrupt("unexpected end of header"))?;
        self.pos += 1;
        Ok(b)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::corrupt("unexpected end of header"));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    /// 7z NUMBER: the count of leading one bits in the first byte gives the count of
    /// following little-endian bytes; the remaining low bits are the most significant part.
    pub fn number(&mut self) -> Result<u64> {
        let first = self.u8()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = (first & mask.wrapping_sub(1)) as u64;
                value |= high << (8 * i);
                return Ok(value);
            }
            value |= (self.u8()? as u64) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    /// A NUMBER used as a count; rejects values above `limit` so corrupt input cannot
    /// trigger huge allocations.
    pub fn count(&mut self, limit: usize, what: &str) -> Result<usize> {
        let v = self.number()?;
        if v > limit as u64 {
            return Err(Error::corrupt(format!("{what} count {v} is out of range")));
        }
        Ok(v as usize)
    }

    pub fn bit_vector(&mut self, n: usize) -> Result<Vec<bool>> {
        let bytes = self.bytes(n.div_ceil(8))?;
        Ok((0..n)
            .map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0)
            .collect())
    }

    /// `AllAreDefined` byte followed by an optional bit vector.
    pub fn defined_vector(&mut self, n: usize) -> Result<Vec<bool>> {
        if self.u8()? != 0 {
            Ok(vec![true; n])
        } else {
            self.bit_vector(n)
        }
    }

    /// CRC digests: defined vector then a u32 per defined entry.
    pub fn digests(&mut self, n: usize) -> Result<Vec<Option<u32>>> {
        let defined = self.defined_vector(n)?;
        defined
            .into_iter()
            .map(|d| if d { self.u32().map(Some) } else { Ok(None) })
            .collect()
    }
}

pub fn write_number(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 {
        if value < (1u64 << (7 * (extra + 1))) {
            first |= (value >> (8 * extra)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        extra += 1;
    }
    out.push(first);
    for j in 0..extra {
        out.push((value >> (8 * j)) as u8);
    }
}

pub fn write_bit_vector(out: &mut Vec<u8>, bits: &[bool]) {
    let mut b = 0u8;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            b |= 0x80 >> (i % 8);
        }
        if i % 8 == 7 {
            out.push(b);
            b = 0;
        }
    }
    if bits.len() % 8 != 0 {
        out.push(b);
    }
}

pub fn write_defined_vector(out: &mut Vec<u8>, bits: &[bool]) {
    if bits.iter().all(|&b| b) {
        out.push(1);
    } else {
        out.push(0);
        write_bit_vector(out, bits);
    }
}

pub fn write_digests(out: &mut Vec<u8>, crcs: &[Option<u32>]) {
    let defined: Vec<bool> = crcs.iter().map(|c| c.is_some()).collect();
    write_defined_vector(out, &defined);
    for c in crcs.iter().flatten() {
        out.extend_from_slice(&c.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn number_roundtrip() {
        let values = [
            0u64,
            1,
            127,
            128,
            255,
            16383,
            16384,
            1 << 20,
            (1 << 21) - 1,
            1 << 35,
            (1 << 56) - 1,
            1 << 56,
            u64::MAX,
        ];
        for &v in &values {
            let mut buf = Vec::new();
            write_number(&mut buf, v);
            let mut r = Reader::new(&buf);
            assert_eq!(r.number().unwrap(), v, "value {v}");
            assert_eq!(r.remaining(), 0);
        }
    }
    #[test]
    fn bits_roundtrip() {
        let bits = vec![
            true, false, true, true, false, false, false, true, true, false,
        ];
        let mut buf = Vec::new();
        write_bit_vector(&mut buf, &bits);
        assert_eq!(Reader::new(&buf).bit_vector(bits.len()).unwrap(), bits);
    }
}
