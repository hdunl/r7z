//! Parallel encoders for gzip, raw Deflate, bzip2 and xz output.
//!
//! * Deflate splits the input into 1 MiB chunks compressed on separate threads. Each chunk's
//!   compressor is first fed the previous 32 KiB (the Deflate window) and flushed, and that
//!   output is discarded; the chunk's own blocks start byte-aligned after the flush and may
//!   refer back into the window, so the concatenation is one valid stream with almost the
//!   ratio of a single-threaded encoder (pigz's technique).
//! * bzip2 blocks are independent, so chunks become separate bzip2 streams; concatenated
//!   streams are valid bzip2 that `bzip2 -d` and 7-Zip read.
//! * xz uses r7z's parallel LZMA2 encoder, one xz block per LZMA2 group (`xzwrite`).

use std::io::{self, Write};

use flate2::{Compress, Compression, FlushCompress, Status};
use rayon::prelude::*;

const WINDOW: usize = 32 << 10;
const CHUNK: usize = 1 << 20;

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Runs `input` through `c` with `flush`, appending to `out`.
fn deflate_into(
    c: &mut Compress,
    input: &[u8],
    out: &mut Vec<u8>,
    flush: FlushCompress,
) -> io::Result<()> {
    let mut pos = 0usize;
    loop {
        if out.capacity() - out.len() < 1 << 16 {
            out.reserve((input.len() - pos) / 2 + (1 << 17));
        }
        let before = c.total_in();
        let st = c.compress_vec(&input[pos..], out, flush).map_err(io_err)?;
        pos += (c.total_in() - before) as usize;
        let done = match flush {
            FlushCompress::Finish => st == Status::StreamEnd,
            _ => pos == input.len() && out.capacity() - out.len() >= 64,
        };
        if done {
            return Ok(());
        }
    }
}

/// Compresses one chunk as raw Deflate, primed with `dict`; ends with a sync flush, or a
/// final block when `last`.
pub fn deflate_chunk(dict: &[u8], data: &[u8], level: u32, last: bool) -> io::Result<Vec<u8>> {
    thread_local! {
        // A compressor's state is ~300 KiB; allocating one per small file dominated zip
        // creation of source trees.
        static CACHE: std::cell::RefCell<Option<(u32, Compress)>> = const { std::cell::RefCell::new(None) };
    }
    let level = level.min(9);
    let cached = CACHE.with(|c| c.borrow_mut().take());
    let mut c = match cached {
        Some((l, mut c)) if l == level => {
            c.reset();
            c
        }
        _ => Compress::new(Compression::new(level), false),
    };
    let r = deflate_with(&mut c, dict, data, last);
    CACHE.with(|cache| *cache.borrow_mut() = Some((level, c)));
    r
}

fn deflate_with(c: &mut Compress, dict: &[u8], data: &[u8], last: bool) -> io::Result<Vec<u8>> {
    if !dict.is_empty() {
        let mut scratch = Vec::with_capacity(dict.len() + 1024);
        deflate_into(c, dict, &mut scratch, FlushCompress::Sync)?;
    }
    let mut out = Vec::with_capacity(data.len() / 2 + 1024);
    deflate_into(
        c,
        data,
        &mut out,
        if last {
            FlushCompress::Finish
        } else {
            FlushCompress::Sync
        },
    )?;
    Ok(out)
}

/// A streaming raw-Deflate encoder that compresses chunks in parallel.
pub struct ParDeflate<W: Write> {
    out: W,
    level: u32,
    batch: usize,
    pending: Vec<u8>,
    /// The last `WINDOW` bytes before `pending`.
    tail: Vec<u8>,
    crc: crc32fast::Hasher,
    pub total_in: u64,
    pub total_out: u64,
}

impl<W: Write> ParDeflate<W> {
    pub fn new(out: W, level: u32, threads: usize) -> Self {
        ParDeflate {
            out,
            level,
            batch: CHUNK * threads.max(1),
            pending: Vec::new(),
            tail: Vec::new(),
            crc: crc32fast::Hasher::new(),
            total_in: 0,
            total_out: 0,
        }
    }

    fn flush_batch(&mut self, last: bool) -> io::Result<()> {
        if self.pending.is_empty() && !last {
            return Ok(());
        }
        let data = std::mem::take(&mut self.pending);
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(CHUNK).collect()
        };
        let n = chunks.len();
        let tail = &self.tail;
        let level = self.level;
        let outs: Vec<io::Result<Vec<u8>>> = (0..n)
            .into_par_iter()
            .map(|i| {
                let dict: &[u8] = if i == 0 {
                    tail
                } else {
                    let p = chunks[i - 1];
                    &p[p.len().saturating_sub(WINDOW)..]
                };
                deflate_chunk(dict, chunks[i], level, last && i + 1 == n)
            })
            .collect();
        for o in outs {
            let o = o?;
            self.out.write_all(&o)?;
            self.total_out += o.len() as u64;
        }
        self.crc.update(&data);
        self.total_in += data.len() as u64;
        if data.len() >= WINDOW {
            self.tail = data[data.len() - WINDOW..].to_vec();
        } else {
            self.tail.extend_from_slice(&data);
            let excess = self.tail.len().saturating_sub(WINDOW);
            self.tail.drain(..excess);
        }
        self.pending = data;
        self.pending.clear();
        Ok(())
    }

    /// Ends the stream; returns the sink, CRC32 and size of the input.
    pub fn finish(mut self) -> io::Result<(W, u32, u64)> {
        self.flush_batch(true)?;
        self.out.flush()?;
        Ok((self.out, self.crc.finalize(), self.total_in))
    }
}

impl<W: Write> Write for ParDeflate<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let room = self.batch - self.pending.len();
        let n = room.min(buf.len());
        self.pending.extend_from_slice(&buf[..n]);
        if self.pending.len() >= self.batch {
            self.flush_batch(false)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// gzip framing around [`ParDeflate`].
pub struct GzipWriter<W: Write> {
    inner: ParDeflate<W>,
}

impl<W: Write> GzipWriter<W> {
    /// `name` goes into the FNAME field; `mtime` is Unix seconds (0 = unknown).
    pub fn new(
        mut out: W,
        level: u32,
        threads: usize,
        name: Option<&str>,
        mtime: u32,
    ) -> io::Result<Self> {
        let mut h = vec![0x1F, 0x8B, 8, if name.is_some() { 8 } else { 0 }];
        h.extend_from_slice(&mtime.to_le_bytes());
        h.push(match level {
            9 => 2,
            1 => 4,
            _ => 0,
        });
        h.push(if cfg!(windows) { 0 } else { 3 });
        if let Some(n) = name {
            // FNAME is Latin-1; replace what it cannot hold.
            h.extend(n.chars().map(|c| {
                if (c as u32) < 256 && c != '\0' {
                    c as u8
                } else {
                    b'_'
                }
            }));
            h.push(0);
        }
        out.write_all(&h)?;
        Ok(GzipWriter {
            inner: ParDeflate::new(out, level, threads),
        })
    }

    pub fn finish(self) -> io::Result<W> {
        let (mut out, crc, size) = self.inner.finish()?;
        out.write_all(&crc.to_le_bytes())?;
        out.write_all(&(size as u32).to_le_bytes())?;
        out.flush()?;
        Ok(out)
    }
}

impl<W: Write> Write for GzipWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// bzip2 as concatenated streams, one per chunk, compressed in parallel.
pub struct Bzip2Writer<W: Write> {
    out: W,
    level: u32,
    chunk: usize,
    batch: usize,
    pending: Vec<u8>,
    wrote_any: bool,
}

impl<W: Write> Bzip2Writer<W> {
    pub fn new(out: W, level: u32, threads: usize) -> Self {
        let level = level.clamp(1, 9);
        // Just under one block of the chosen size, so each stream holds one block.
        let chunk = level as usize * 100_000 - 1000;
        Bzip2Writer {
            out,
            level,
            chunk,
            batch: chunk * threads.max(1),
            pending: Vec::new(),
            wrote_any: false,
        }
    }

    fn flush_batch(&mut self, last: bool) -> io::Result<()> {
        if self.pending.is_empty() && (self.wrote_any || !last) {
            return Ok(());
        }
        let level = self.level;
        let outs: Vec<io::Result<Vec<u8>>> = self
            .pending
            .par_chunks(self.chunk.max(1))
            .map(|c| {
                let mut e = bzip2::write::BzEncoder::new(
                    Vec::with_capacity(c.len() / 3),
                    bzip2::Compression::new(level),
                );
                e.write_all(c)?;
                e.finish()
            })
            .collect();
        if self.pending.is_empty() {
            // An empty input still needs one (empty) stream.
            let e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level));
            self.out.write_all(&e.finish()?)?;
        }
        for o in outs {
            self.out.write_all(&o?)?;
        }
        self.wrote_any = true;
        self.pending.clear();
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.flush_batch(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for Bzip2Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let room = self.batch - self.pending.len();
        let n = room.min(buf.len());
        self.pending.extend_from_slice(&buf[..n]);
        if self.pending.len() >= self.batch {
            self.flush_batch(false)?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// xz through r7z's parallel LZMA2 encoder (see `xzwrite`).
pub type XzWriter<W> = super::xzwrite::XzLzma2Writer<W>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x = 12345u32;
        while v.len() < n {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            let w = ["alpha ", "beta ", "gamma ", "delta\n"][(x >> 16) as usize % 4];
            v.extend_from_slice(w.as_bytes());
            if x % 7 == 0 {
                v.push((x >> 8) as u8);
            }
        }
        v.truncate(n);
        v
    }

    #[test]
    fn parallel_gzip_roundtrip() {
        for n in [0usize, 10, CHUNK - 1, CHUNK * 3 + 17] {
            let data = sample(n);
            let mut w = GzipWriter::new(Vec::new(), 6, 4, Some("x"), 0).unwrap();
            w.write_all(&data).unwrap();
            let gz = w.finish().unwrap();
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(&gz[..])
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, data, "n={n}");
        }
    }

    #[test]
    fn parallel_bzip2_roundtrip() {
        for n in [0usize, 5, 2_500_000] {
            let data = sample(n);
            let mut w = Bzip2Writer::new(Vec::new(), 9, 4);
            w.write_all(&data).unwrap();
            let bz = w.finish().unwrap();
            let mut out = Vec::new();
            bzip2::read::MultiBzDecoder::new(&bz[..])
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, data, "n={n}");
        }
    }
}
