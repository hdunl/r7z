//! Decoder for Unix `compress` (.Z) LZW streams.
//!
//! Codes are packed LSB-first, starting at 9 bits and growing to the header's maximum.
//! After a CLEAR code, `compress` skips to the end of the current group of eight codes
//! (one "section" is `bits` bytes), an artifact of its block I/O that decoders reproduce.

use std::io::{self, Read};

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
