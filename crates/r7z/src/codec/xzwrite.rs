//! xz output from r7z's own LZMA2 encoder (the one 7z archives use: groups of 4x the
//! dictionary, each split into primed sub-blocks encoded in parallel).
//!
//! Each LZMA2 group becomes one xz block, so xz decoders that work per block (r7z's,
//! 7-Zip's, `xz -T0`) decode in parallel too. Blocks carry a CRC64 check.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use super::encode::{EncMethod, FolderEncoder};
use super::lzma2_prop_for_dict;
use crate::error::Error;
use crate::ops::create::{bench_method, CreateOptions};
use crate::util::crc64::Crc64;

/// Writes through a shared handle, so block encoders can come and go.
struct Shared<W: Write>(Arc<Mutex<W>>);

impl<W: Write> Write for Shared<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.lock().unwrap().write_all(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

fn vli(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn to_io(e: Error) -> io::Error {
    e.into_io()
}

pub struct XzLzma2Writer<W: Write + 'static> {
    out: Arc<Mutex<W>>,
    method: EncMethod,
    group: u64,
    dict_prop: u8,
    enc: Option<FolderEncoder<'static>>,
    block_in: u64,
    crc: Crc64,
    /// (unpadded size, uncompressed size) per block.
    index: Vec<(u64, u64)>,
}

const BLOCK_HEADER: u64 = 12;

impl<W: Write + 'static> XzLzma2Writer<W> {
    /// `size_hint` sizes the dictionary and the parallel plan (the total input, if known).
    pub fn new(out: W, level: u32, threads: usize, size_hint: u64) -> io::Result<Self> {
        let opts = CreateOptions {
            level: level.clamp(1, 9),
            threads: threads.max(1),
            ..Default::default()
        };
        let method = bench_method(&opts, size_hint.max(1 << 20), threads.max(1));
        let (dict, group) = match &method {
            EncMethod::Lzma2 { opts, group, .. } => (opts.dict_size, *group),
            _ => unreachable!("bench_method returns LZMA2"),
        };
        let mut w = out;
        let flags = [0x00, 0x04]; // CRC64
        let mut h = vec![0xFD, b'7', b'z', b'X', b'Z', 0];
        h.extend_from_slice(&flags);
        h.extend_from_slice(&crc32fast::hash(&flags).to_le_bytes());
        w.write_all(&h)?;
        Ok(XzLzma2Writer {
            out: Arc::new(Mutex::new(w)),
            method,
            group: group.max(1 << 16),
            dict_prop: lzma2_prop_for_dict(dict.max(4096)),
            enc: None,
            block_in: 0,
            crc: Crc64::new(),
            index: Vec::new(),
        })
    }

    fn start_block(&mut self) -> io::Result<()> {
        // Size byte, flags (one filter, no size fields), LZMA2 filter with its dictionary
        // property, padding, CRC32.
        let mut h = vec![
            (BLOCK_HEADER / 4 - 1) as u8,
            0x00,
            0x21,
            0x01,
            self.dict_prop,
            0,
            0,
            0,
        ];
        let crc = crc32fast::hash(&h);
        h.extend_from_slice(&crc.to_le_bytes());
        self.out.lock().unwrap().write_all(&h)?;
        self.enc = Some(
            FolderEncoder::new_owned(std::slice::from_ref(&self.method), Shared(self.out.clone()))
                .map_err(to_io)?,
        );
        self.block_in = 0;
        self.crc = Crc64::new();
        Ok(())
    }

    fn end_block(&mut self) -> io::Result<()> {
        let Some(enc) = self.enc.take() else {
            return Ok(());
        };
        let (_, packed) = enc.finish().map_err(to_io)?;
        let mut tail = vec![0u8; ((4 - packed % 4) % 4) as usize];
        tail.extend_from_slice(&self.crc.finalize().to_le_bytes());
        self.out.lock().unwrap().write_all(&tail)?;
        self.index.push((BLOCK_HEADER + packed + 8, self.block_in));
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.end_block()?;
        let mut ix = vec![0x00];
        vli(&mut ix, self.index.len() as u64);
        for &(unpadded, size) in &self.index {
            vli(&mut ix, unpadded);
            vli(&mut ix, size);
        }
        while ix.len() % 4 != 0 {
            ix.push(0);
        }
        let crc = crc32fast::hash(&ix);
        ix.extend_from_slice(&crc.to_le_bytes());
        let mut foot = Vec::with_capacity(12);
        let backward = (ix.len() as u32 / 4 - 1).to_le_bytes();
        let mut tail = backward.to_vec();
        tail.extend_from_slice(&[0x00, 0x04]);
        foot.extend_from_slice(&crc32fast::hash(&tail).to_le_bytes());
        foot.extend_from_slice(&tail);
        foot.extend_from_slice(b"YZ");
        let out = self.out.clone();
        drop(self);
        let mut w = Arc::try_unwrap(out)
            .map_err(|_| io::Error::other("xz writer still shared"))?
            .into_inner()
            .unwrap();
        w.write_all(&ix)?;
        w.write_all(&foot)?;
        w.flush()?;
        Ok(w)
    }
}

impl<W: Write + 'static> Write for XzLzma2Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.enc.is_none() {
            self.start_block()?;
        }
        let room = (self.group - self.block_in) as usize;
        let n = room.min(buf.len());
        self.enc.as_mut().unwrap().write_all(&buf[..n])?;
        self.crc.update(&buf[..n]);
        self.block_in += n as u64;
        if self.block_in >= self.group {
            self.end_block()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn decodes_with_lzma_rust2() {
        for n in [0usize, 1000, 3 << 20] {
            let data: Vec<u8> = (0..n)
                .map(|i| ((i * 7) % 251) as u8 ^ (i >> 12) as u8)
                .collect();
            let mut w = XzLzma2Writer::new(Vec::new(), 5, 4, n as u64).unwrap();
            w.write_all(&data).unwrap();
            let xz = w.finish().unwrap();
            let mut out = Vec::new();
            lzma_rust2::XzReader::new(&xz[..], true)
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, data, "n={n}");
        }
    }
}
