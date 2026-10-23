//! Archive bytes: memory-mapped or owned buffers shared by reference count, plus
//! re-openable sequential streams for archives nested inside compressed streams.

use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{Error, Result};

/// Backing storage for archive bytes.
pub enum Data {
    Map(memmap2::Mmap),
    Owned(Vec<u8>),
    /// A spilled temporary file, deleted when dropped.
    Temp(TempMap),
}

/// A mapped temporary file that is unmapped and deleted on drop.
pub struct TempMap {
    map: Option<memmap2::Mmap>,
    path: PathBuf,
}

impl Drop for TempMap {
    fn drop(&mut self) {
        // Unmap before deleting: Windows refuses to delete a mapped file.
        self.map.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Data::Map(m) => m,
            Data::Temp(t) => t.map.as_deref().unwrap_or(&[]),
            Data::Owned(v) => v,
        }
    }
}

/// A shared, cheaply cloned byte range.
#[derive(Clone)]
pub struct Slice {
    data: Arc<Data>,
    start: usize,
    end: usize,
}

impl Slice {
    pub fn new(data: Data) -> Self {
        let end = data.len();
        Slice {
            data: Arc::new(data),
            start: 0,
            end,
        }
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        Slice::new(Data::Owned(v))
    }

    /// Memory-maps `path` (reads it when mapping fails or the file is empty).
    pub fn map_file(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len == 0 {
            return Ok(Slice::from_vec(Vec::new()));
        }
        // SAFETY: the map is read-only; concurrent modification of the archive by another
        // process is outside r7z's contract (same as any reader of a changing file).
        Ok(match unsafe { memmap2::Mmap::map(&file) } {
            Ok(m) => Slice::new(Data::Map(m)),
            Err(_) => Slice::from_vec(std::fs::read(path)?),
        })
    }

    /// A sub-range relative to this slice; fails if it runs past the end.
    pub fn sub(&self, r: Range<u64>) -> Result<Slice> {
        let len = (self.end - self.start) as u64;
        if r.start > r.end || r.end > len {
            return Err(Error::corrupt("data range is past the end of the archive"));
        }
        Ok(Slice {
            data: self.data.clone(),
            start: self.start + r.start as usize,
            end: self.start + r.end as usize,
        })
    }

    /// Like `sub`, clamped to the available bytes.
    pub fn sub_clamped(&self, r: Range<u64>) -> Slice {
        let len = (self.end - self.start) as u64;
        let s = r.start.min(len);
        let e = r.end.clamp(s, len);
        self.sub(s..e).unwrap()
    }

    pub fn reader(&self) -> SliceReader {
        SliceReader {
            slice: self.clone(),
            pos: 0,
        }
    }
}

impl Deref for Slice {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }
}

impl AsRef<[u8]> for Slice {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// An owning reader over a `Slice`.
pub struct SliceReader {
    slice: Slice,
    pos: usize,
}

impl Read for SliceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rest = &self.slice[self.pos..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.pos += n;
        Ok(n)
    }
}

/// Random-access bytes. Disk images often compute their sectors on demand (a compressed
/// DMG, a partition inside one), so readers ask for exact ranges and never assume the whole
/// image is in memory.
pub trait ReadAt: Send + Sync {
    /// The total size in bytes.
    fn size(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Fills `buf` from byte `offset`. Fails when the range runs past the end.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

impl ReadAt for Slice {
    fn size(&self) -> u64 {
        let bytes: &[u8] = self;
        bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let bytes: &[u8] = self;
        let start = usize::try_from(offset).ok();
        let end = start.and_then(|s| s.checked_add(buf.len()));
        match (start, end) {
            (Some(s), Some(e)) if e <= bytes.len() => {
                buf.copy_from_slice(&bytes[s..e]);
                Ok(())
            }
            _ => Err(Error::corrupt("read past the end of the archive")),
        }
    }
}

/// Reads a list of `(offset, length)` ranges of a [`ReadAt`] as one stream, in order. Each
/// `read` call reads only what the caller asks for, so memory use does not depend on the
/// size of the ranges.
pub struct Runs {
    src: Arc<dyn ReadAt>,
    runs: std::vec::IntoIter<(u64, u64)>,
    pos: u64,
    left: u64,
}

impl Runs {
    pub fn new(src: Arc<dyn ReadAt>, runs: Vec<(u64, u64)>) -> Self {
        Runs {
            src,
            runs: runs.into_iter(),
            pos: 0,
            left: 0,
        }
    }

    /// Every byte of `src`.
    pub fn whole(src: Arc<dyn ReadAt>) -> Self {
        let len = src.size();
        Runs::new(src, vec![(0, len)])
    }
}

impl Read for Runs {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.left == 0 {
            let Some((offset, len)) = self.runs.next() else {
                return Ok(0);
            };
            self.pos = offset;
            self.left = len;
        }
        let n = (buf.len() as u64).min(self.left) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.src
            .read_at(self.pos, &mut buf[..n])
            .map_err(Error::into_io)?;
        self.pos += n as u64;
        self.left -= n as u64;
        Ok(n)
    }
}

pub type BoxRead = Box<dyn Read + Send>;

/// Opens a fresh sequential reader over some data each time it is called.
pub type Opener = Arc<dyn Fn() -> Result<BoxRead> + Send + Sync>;

/// What a format handler is opened over.
#[derive(Clone)]
pub enum Input {
    /// Random-access bytes.
    Mem(Slice),
    /// Random-access bytes that may be computed on demand (a partition inside a disk
    /// image). Only formats with `Format::sequential` receive these, without a copy.
    Volume(Arc<dyn ReadAt>),
    /// A stream that can only be read front to back (decompressed output of an outer
    /// archive). Only formats with `Format::sequential` receive this.
    Stream {
        open: Opener,
        size_hint: Option<u64>,
    },
}

impl Input {
    /// Random-access bytes, decoding a stream into memory (or a temp file) if needed.
    pub fn into_mem(self) -> Result<Slice> {
        match self {
            Input::Mem(s) => Ok(s),
            Input::Volume(v) => {
                let len = v.size();
                materialize(&mut Runs::whole(v), Some(len))
            }
            Input::Stream { open, size_hint } => materialize(&mut *open()?, size_hint),
        }
    }

    /// Random-access bytes, without a copy when the input already is.
    pub fn volume(self) -> Result<Arc<dyn ReadAt>> {
        match self {
            Input::Mem(s) => Ok(Arc::new(s) as Arc<dyn ReadAt>),
            Input::Volume(v) => Ok(v),
            other => Ok(Arc::new(other.into_mem()?) as Arc<dyn ReadAt>),
        }
    }

    pub fn opener(&self) -> Opener {
        match self {
            Input::Mem(s) => {
                let s = s.clone();
                Arc::new(move || Ok(Box::new(s.reader()) as BoxRead))
            }
            Input::Volume(v) => {
                let v = v.clone();
                Arc::new(move || Ok(Box::new(Runs::whole(v.clone())) as BoxRead))
            }
            Input::Stream { open, .. } => open.clone(),
        }
    }
}

/// Bytes of decoded data r7z keeps in memory before spilling to a temporary file.
pub fn memory_budget() -> u64 {
    let avail = crate::util::mem::memory()
        .map(|(_, avail)| avail)
        .unwrap_or(4 << 30);
    (avail / 4).clamp(64 << 20, 2 << 30)
}

/// Reads `r` to the end into memory, or into a temporary file once it outgrows the budget.
pub fn materialize(r: &mut dyn Read, size_hint: Option<u64>) -> Result<Slice> {
    let budget = memory_budget();
    let mut buf = Vec::with_capacity(size_hint.unwrap_or(0).min(budget) as usize);
    let mut chunk = vec![0u8; 1 << 20];
    loop {
        let n = read_some(r, &mut chunk)?;
        if n == 0 {
            return Ok(Slice::from_vec(buf));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() as u64 > budget {
            break;
        }
    }
    let path = std::env::temp_dir().join(format!(
        "r7z-spill-{}-{:x}.tmp",
        std::process::id(),
        crate::util::random_u64()
    ));
    let mut f = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    let res = (|| -> Result<memmap2::Mmap> {
        f.write_all(&buf)?;
        drop(std::mem::take(&mut buf));
        loop {
            let n = read_some(r, &mut chunk)?;
            if n == 0 {
                break;
            }
            f.write_all(&chunk[..n])?;
        }
        f.flush()?;
        // SAFETY: the file is private to this process and deleted when the map drops.
        Ok(unsafe { memmap2::Mmap::map(&f)? })
    })();
    match res {
        Ok(m) => Ok(Slice::new(Data::Temp(TempMap { map: Some(m), path }))),
        Err(e) => {
            drop(f);
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

/// One `read` call that retries on `Interrupted` and maps decoder errors to typed errors.
pub fn read_some(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    loop {
        match r.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(data_err(e)),
        }
    }
}

/// Decoder input is archive data, so an untyped I/O error from a decoder is a data error.
pub fn data_err(e: io::Error) -> Error {
    match Error::from_codec(e) {
        Error::Io(x) if x.kind() != io::ErrorKind::NotFound => Error::corrupt(x.to_string()),
        other => other,
    }
}

/// Reads exactly `buf.len()` bytes or fails with a truncation error.
pub fn read_exact(r: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
    let mut n = 0;
    while n < buf.len() {
        let k = read_some(r, &mut buf[n..])?;
        if k == 0 {
            return Err(Error::corrupt("unexpected end of data"));
        }
        n += k;
    }
    Ok(())
}

/// Discards `n` bytes; returns how many were actually available.
pub fn skip(r: &mut dyn Read, mut n: u64) -> Result<u64> {
    let mut buf = [0u8; 16384];
    let want = n;
    while n > 0 {
        let k = read_some(r, &mut buf[..(n.min(16384) as usize)])?;
        if k == 0 {
            break;
        }
        n -= k as u64;
    }
    Ok(want - n)
}
