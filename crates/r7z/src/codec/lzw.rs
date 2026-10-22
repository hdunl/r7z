//! Decoder for Unix `compress` (.Z) LZW streams.
//!
//! Codes are packed LSB-first, starting at 9 bits and growing to the header's maximum.
//! After a CLEAR code, `compress` skips to the end of the current group of eight codes
//! (one "section" is `bits` bytes), an artifact of its block I/O that decoders reproduce.

use std::io::{self, Read, Write};

const CLEAR: u32 = 256;

pub struct LzwReader<R: Read> {
    inner: R,
    block_mode: bool,
    max_bits: u32,
    bits: u32,
    acc: u64,
    avail: u32,
    bytes_in_section: u32,
    free_ent: u32,
    section_end: u32,
    old: Option<u32>,
    fin: u8,
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    /// Decoded bytes; `out[out_pos..]` is not yet returned.
    out: Vec<u8>,
    out_pos: usize,
    done: bool,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("Z: {msg}"))
}

impl<R: Read> LzwReader<R> {
    pub fn new(mut inner: R) -> crate::Result<Self> {
        let mut h = [0u8; 3];
        inner
            .read_exact(&mut h)
            .map_err(|_| crate::Error::NotArchive)?;
        if h[0] != 0x1F || h[1] != 0x9D {
            return Err(crate::Error::NotArchive);
        }
        let max_bits = (h[2] & 0x1F) as u32;
        if !(9..=16).contains(&max_bits) || h[2] & 0x60 != 0 {
            return Err(crate::Error::unsupported(format!(
                "Z stream with {max_bits}-bit codes"
            )));
        }
        let block_mode = h[2] & 0x80 != 0;
        let size = 1usize << max_bits;
        Ok(LzwReader {
            inner,
            block_mode,
            max_bits,
            bits: 9,
            acc: 0,
            avail: 0,
            bytes_in_section: 0,
            free_ent: if block_mode { 257 } else { 256 },
            section_end: 511,
            old: None,
            fin: 0,
            prefix: vec![0; size],
            suffix: (0..size).map(|i| i as u8).collect(),
            out: Vec::with_capacity(1 << 17),
            out_pos: 0,
            done: false,
        })
    }

    fn byte(&mut self) -> io::Result<Option<u8>> {
        let mut b = [0u8; 1];
        loop {
            match self.inner.read(&mut b) {
                Ok(0) => return Ok(None),
                Ok(_) => return Ok(Some(b[0])),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// The next `n`-bit code, or `None` at the end of input.
    fn getbits(&mut self, n: u32) -> io::Result<Option<u32>> {
        while self.avail < n {
            match self.byte()? {
                Some(b) => {
                    self.acc |= (b as u64) << self.avail;
                    self.avail += 8;
                    self.bytes_in_section += 1;
                }
                None => return Ok(None),
            }
        }
        let code = (self.acc & ((1u64 << n) - 1)) as u32;
        self.acc >>= n;
        self.avail -= n;
        Ok(Some(code))
    }

    /// Decodes one code onto `out`. Returns false at the end of input.
    fn step(&mut self) -> io::Result<bool> {
        let Some(mut code) = self.getbits(self.bits)? else {
            return Ok(false);
        };
        if code == CLEAR && self.block_mode {
            let skip = (self.bits - self.bytes_in_section % self.bits) % self.bits;
            self.acc = 0;
            self.avail = 0;
            for _ in 0..skip {
                if self.byte()?.is_none() {
                    return Ok(false);
                }
            }
            self.bytes_in_section = 0;
            self.bits = 9;
            self.section_end = 511;
            self.free_ent = 257;
            self.old = None;
            return Ok(true);
        }
        let Some(old) = self.old else {
            if code > 255 {
                return Err(bad("first code is not a literal"));
            }
            self.old = Some(code);
            self.fin = code as u8;
            self.out.push(code as u8);
            return Ok(true);
        };
        let incode = code;
        let base = self.out.len();
        if code >= self.free_ent {
            if code > self.free_ent {
                return Err(bad("invalid code"));
            }
            self.out.push(self.fin);
            code = old;
        }
        while code >= 256 {
            self.out.push(self.suffix[code as usize]);
            code = self.prefix[code as usize] as u32;
            if self.out.len() - base > (1 << 16) {
                return Err(bad("code chain too long"));
            }
        }
        self.fin = code as u8;
        self.out.push(self.fin);
        // The string was pushed last byte first; reverse it into reading order at the
        // bottom of the pending region.
        self.out[base..].reverse();
        if self.free_ent < (1 << self.max_bits) {
            self.prefix[self.free_ent as usize] = old as u16;
            self.suffix[self.free_ent as usize] = self.fin;
            self.free_ent += 1;
        }
        self.old = Some(incode);
        if self.free_ent > self.section_end && self.bits < self.max_bits {
            self.bits += 1;
            self.bytes_in_section = 0;
            self.section_end = (1 << self.bits) - 1;
        }
        Ok(true)
    }
}

impl<R: Read> Read for LzwReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
            if self.done {
                return Ok(0);
            }
            while self.out.len() < 1 << 16 {
                if !self.step()? {
                    self.done = true;
                    break;
                }
            }
        }
        let n = (self.out.len() - self.out_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        Ok(n)
    }
}

/// Unix `compress` output: block mode, codes from 9 bits up to `max_bits`, with a CLEAR
/// code when the table fills. It mirrors [`LzwReader`]: the code width grows one code after
/// the decoder's table would, and after a CLEAR the stream pads to a multiple of the
/// code width in bytes, as `compress` does.
pub struct LzwWriter<W: Write> {
    out: W,
    max_bits: u32,
    width: u32,
    /// Pending bits, least significant first.
    acc: u64,
    nacc: u32,
    /// Bits written to the code stream so far.
    bitpos: u64,
    /// Byte offset where the current padding section starts.
    section: u64,
    /// Codes since the last CLEAR (or the start).
    codes: u32,
    /// Hash table of (prefix << 8 | byte) keys, with the code each one maps to.
    keys: Vec<u32>,
    vals: Vec<u16>,
    /// The string being matched, as a dictionary code.
    cur: Option<u32>,
}

const EMPTY: u32 = u32::MAX;
const HASH_BITS: u32 = 17;

impl<W: Write> LzwWriter<W> {
    /// Writes the three-byte header; `max_bits` is 9 to 16.
    pub fn new(mut out: W, max_bits: u32) -> io::Result<Self> {
        let max_bits = max_bits.clamp(9, 16);
        out.write_all(&[0x1F, 0x9D, 0x80 | max_bits as u8])?;
        Ok(LzwWriter {
            out,
            max_bits,
            width: 9,
            acc: 0,
            nacc: 0,
            bitpos: 0,
            section: 0,
            codes: 0,
            keys: vec![EMPTY; 1 << HASH_BITS],
            vals: vec![0; 1 << HASH_BITS],
            cur: None,
        })
    }

    fn slot(key: u32) -> usize {
        (key.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
    }

    fn lookup(&self, prefix: u32, byte: u8) -> Option<u32> {
        let key = prefix << 8 | byte as u32;
        let mut i = Self::slot(key);
        loop {
            let k = self.keys[i];
            if k == EMPTY {
                return None;
            }
            if k == key {
                return Some(self.vals[i] as u32);
            }
            i = (i + 1) & ((1 << HASH_BITS) - 1);
        }
    }

    fn insert(&mut self, prefix: u32, byte: u8, code: u32) {
        let key = prefix << 8 | byte as u32;
        let mut i = Self::slot(key);
        while self.keys[i] != EMPTY {
            i = (i + 1) & ((1 << HASH_BITS) - 1);
        }
        self.keys[i] = key;
        self.vals[i] = code as u16;
    }

    fn put(&mut self, code: u32, width: u32) -> io::Result<()> {
        self.acc |= (code as u64) << self.nacc;
        self.nacc += width;
        self.bitpos += width as u64;
        while self.nacc >= 8 {
            self.out.write_all(&[self.acc as u8])?;
            self.acc >>= 8;
            self.nacc -= 8;
        }
        Ok(())
    }

    /// Writes the pending partial byte, zero-filled, so the stream is byte aligned.
    fn align(&mut self) -> io::Result<()> {
        if self.nacc > 0 {
            self.out.write_all(&[self.acc as u8])?;
            self.acc = 0;
            self.nacc = 0;
            self.bitpos = self.bitpos.div_ceil(8) * 8;
        }
        Ok(())
    }

    /// Emits a CLEAR code and the padding that ends its section, then starts a new table.
    fn clear(&mut self) -> io::Result<()> {
        self.put(256, self.width)?;
        self.align()?;
        let used = self.bitpos / 8 - self.section;
        let pad = (self.width as u64 - used % self.width as u64) % self.width as u64;
        for _ in 0..pad {
            self.out.write_all(&[0])?;
        }
        self.bitpos += pad * 8;
        self.section = self.bitpos / 8;
        self.width = 9;
        self.codes = 0;
        self.keys.fill(EMPTY);
        Ok(())
    }

    /// Writes one code for the string `prefix` and adds `prefix + byte` to the table.
    fn emit(&mut self, prefix: u32, byte: u8) -> io::Result<()> {
        self.put(prefix, self.width)?;
        self.codes += 1;
        // The decoder widens the codes one step after its table would need the bit.
        if self.codes >= 2 && 256 + self.codes > (1 << self.width) - 1 && self.width < self.max_bits
        {
            self.width += 1;
            self.section = self.bitpos.div_ceil(8);
        }
        // Code k adds entry 256 + k, the next free one; a full table ends with a CLEAR.
        if 256 + self.codes < 1 << self.max_bits {
            self.insert(prefix, byte, 256 + self.codes);
        } else {
            self.clear()?;
        }
        Ok(())
    }

    /// Ends the stream and returns the sink.
    pub fn finish(mut self) -> io::Result<W> {
        if let Some(code) = self.cur.take() {
            self.put(code, self.width)?;
        }
        self.align()?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for LzwWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        for &b in data {
            match self.cur {
                None => self.cur = Some(b as u32),
                Some(prefix) => match self.lookup(prefix, b) {
                    Some(code) => self.cur = Some(code),
                    None => {
                        self.emit(prefix, b)?;
                        self.cur = Some(b as u32);
                    }
                },
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_bsdtar_output() {
        // `printf 'hi\n' | compress` (block mode, 16 bits).
        let z = [0x1F, 0x9D, 0x90, 0x68, 0xD2, 0x28, 0x00];
        let mut out = Vec::new();
        LzwReader::new(&z[..])
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"hi\n");
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    fn pack(data: &[u8], bits: u32) -> Vec<u8> {
        let mut w = LzwWriter::new(Vec::new(), bits).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn unpack(z: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        LzwReader::new(z).unwrap().read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_through_the_reader() {
        let mut x = 99u32;
        let noisy: Vec<u8> = (0..200_000)
            .map(|i| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                if i % 7 < 3 {
                    b"abcab"[(x >> 16) as usize % 5]
                } else {
                    (x >> 16) as u8
                }
            })
            .collect();
        for bits in [9u32, 10, 12, 13, 16] {
            for data in [
                &b""[..],
                b"a",
                b"hi\n",
                b"TOBEORNOTTOBEORTOBEORNOT",
                &noisy[..],
            ] {
                assert_eq!(
                    unpack(&pack(data, bits)),
                    data,
                    "bits={bits} len={}",
                    data.len()
                );
            }
        }
    }

    #[test]
    fn repeated_text_shrinks() {
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(2000);
        let z = pack(&text, 16);
        assert!(z.len() < text.len() / 3, "{} bytes", z.len());
        assert_eq!(unpack(&z), text);
    }
}
