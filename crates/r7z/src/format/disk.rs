//! Shared pieces of the disk-image and file-system readers: byte windows into a larger disk,
//! file data as runs (holes read as zeros), a bounded page cache for tables, the
//! little-endian readers for on-disk structures, and the image archive that a virtual disk
//! exposes its raw contents through.
//!
//! Nothing here copies a whole disk: every reader asks its source for the bytes it needs.

use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use super::data::{check_range, ReadAt, Runs};
use super::{Archive, Ctx, Entry, EntryFn, Format, Unit};
use crate::error::{Error, Result};

/// Largest metadata structure a reader loads at once.
pub const MAX_META: usize = 16 << 20;

/// `len` bytes at `offset`, as an owned buffer, for a metadata structure.
pub fn read_vec(src: &dyn ReadAt, offset: u64, len: usize) -> Result<Vec<u8>> {
    if len > MAX_META {
        return Err(Error::corrupt("metadata structure is too large"));
    }
    let mut buf = vec![0u8; len];
    src.read_at(offset, &mut buf)?;
    Ok(buf)
}

/// The `N` bytes at `at` in `b`, or a truncation error.
pub fn bytes<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N]> {
    at.checked_add(N)
        .and_then(|end| b.get(at..end))
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::corrupt("structure is truncated"))
}

pub fn u8_at(b: &[u8], at: usize) -> Result<u8> {
    Ok(bytes::<1>(b, at)?[0])
}

pub fn le16(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(b, at)?))
}

pub fn le32(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(b, at)?))
}

pub fn le64(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(b, at)?))
}

pub fn be16(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(bytes(b, at)?))
}

pub fn be32(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(bytes(b, at)?))
}

pub fn be64(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(bytes(b, at)?))
}

/// A byte range of another source, read as a source of its own: a partition on a disk. The
/// range is cut short where the source ends, so a truncated image still lists what it has.
pub struct Window {
    inner: Arc<dyn ReadAt>,
    base: u64,
    len: u64,
}

impl Window {
    pub fn new(inner: Arc<dyn ReadAt>, base: u64, len: u64) -> Self {
        let avail = inner.size().saturating_sub(base);
        Window {
            base,
            len: len.min(avail),
            inner,
        }
    }
}

impl ReadAt for Window {
    fn size(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        self.inner.read_at(self.base + offset, buf)
    }
}

/// Parts laid end to end: a disk made of several extents.
pub struct Concat {
    /// Start offset and source of each non-empty part, in order.
    parts: Vec<(u64, Arc<dyn ReadAt>)>,
    len: u64,
}

impl Concat {
    pub fn new(parts: Vec<Arc<dyn ReadAt>>) -> Self {
        let mut start = 0u64;
        let mut out = Vec::new();
        for p in parts {
            let n = p.size();
            if n > 0 {
                out.push((start, p));
                start += n;
            }
        }
        Concat {
            parts: out,
            len: start,
        }
    }
}

impl ReadAt for Concat {
    fn size(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let i = self.parts.partition_point(|(s, _)| *s <= at) - 1;
            let (start, part) = &self.parts[i];
            let inside = at - start;
            let n = (buf.len() - done).min((part.size() - inside) as usize);
            part.read_at(inside, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}

/// `len` zero bytes: an extent that is not stored, or an unallocated part of a disk.
pub struct Zeros(pub u64);

impl ReadAt for Zeros {
    fn size(&self) -> u64 {
        self.0
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.0)?;
        buf.fill(0);
        Ok(())
    }
}

/// A page size and the most pages a [`Cached`] source keeps.
const PAGE: u64 = 4096;
const MAX_PAGES: usize = 256;

/// Caches 4 KiB pages of a source, for tables read a few bytes at a time. At most
/// `MAX_PAGES` pages (1 MiB) are kept; the cache is emptied when it fills.
pub struct Cached {
    inner: Arc<dyn ReadAt>,
    pages: Mutex<HashMap<u64, Arc<[u8]>>>,
}

impl Cached {
    pub fn new(inner: Arc<dyn ReadAt>) -> Self {
        Cached {
            inner,
            pages: Mutex::new(HashMap::new()),
        }
    }

    fn page(&self, no: u64) -> Result<Arc<[u8]>> {
        if let Some(p) = self.pages.lock().unwrap().get(&no) {
            return Ok(p.clone());
        }
        let start = no * PAGE;
        let n = (self.inner.size() - start).min(PAGE) as usize;
        let mut buf = vec![0u8; n];
        self.inner.read_at(start, &mut buf)?;
        let page: Arc<[u8]> = buf.into();
        let mut pages = self.pages.lock().unwrap();
        if pages.len() >= MAX_PAGES {
            pages.clear();
        }
        pages.insert(no, page.clone());
        Ok(page)
    }
}

impl ReadAt for Cached {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size())?;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let page = self.page(at / PAGE)?;
            let inside = (at % PAGE) as usize;
            let n = (page.len() - inside).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&page[inside..inside + n]);
            done += n;
        }
        Ok(())
    }
}

/// A run of file data: `len` bytes at logical offset `at`, stored at disk offset `phys`, or
/// a hole (zeros) when `phys` is `None`. Runs are sorted by `at` and do not overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    pub at: u64,
    pub len: u64,
    pub phys: Option<u64>,
}

/// Fills `buf` with the bytes at `offset` of data made of `runs`. Logical bytes no run
/// covers are zeros.
pub fn read_runs(src: &dyn ReadAt, runs: &[Run], offset: u64, buf: &mut [u8]) -> Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let at = offset
            .checked_add(done as u64)
            .ok_or_else(|| Error::corrupt("file offset overflows"))?;
        let i = runs.partition_point(|r| r.at.saturating_add(r.len) <= at);
        let (end, phys) = match runs.get(i) {
            Some(r) if r.at <= at => {
                let phys = match r.phys {
                    Some(p) => Some(
                        p.checked_add(at - r.at)
                            .ok_or_else(|| Error::corrupt("run offset overflows"))?,
                    ),
                    None => None,
                };
                (r.at.saturating_add(r.len), phys)
            }
            Some(r) => (r.at, None),
            None => (u64::MAX, None),
        };
        let n = (end - at).min((buf.len() - done) as u64) as usize;
        match phys {
            Some(p) => src.read_at(p, &mut buf[done..done + n])?,
            None => buf[done..done + n].fill(0),
        }
        done += n;
    }
    Ok(())
}

/// Reads a file of `size` bytes whose data is `runs`.
pub struct RunReader {
    src: Arc<dyn ReadAt>,
    runs: Vec<Run>,
    size: u64,
    pos: u64,
}

impl RunReader {
    pub fn new(src: Arc<dyn ReadAt>, runs: Vec<Run>, size: u64) -> Self {
        RunReader {
            src,
            runs,
            size,
            pos: 0,
        }
    }
}

impl Read for RunReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.size.saturating_sub(self.pos);
        let n = left.min(buf.len() as u64) as usize;
        read_runs(&*self.src, &self.runs, self.pos, &mut buf[..n]).map_err(Error::into_io)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// The first 64 KiB of `src`, for detecting what it holds.
pub fn head(src: &dyn ReadAt) -> Result<Vec<u8>> {
    let n = src.size().min(1 << 16) as usize;
    read_vec(src, 0, n)
}

/// The short name of a file system found in a partition: `fat`, `ntfs`, `exfat`, `ext`, or
/// `img` for anything r7z does not recognise. This is the extension 7-Zip gives a
/// partition's item.
pub fn partition_ext(head: &[u8]) -> String {
    super::detect_format(head, "")
        .map(|f| f.name.to_ascii_lowercase())
        .unwrap_or_else(|| "img".to_string())
}

/// A GUID as its text form, from the 16 bytes a GPT or VHDX stores (the first three
/// fields little-endian).
pub fn guid_text(b: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// An archive whose one entry is a disk image: it lists as that image and opens what the
/// image holds (a partition table or a file system) as the next level.
pub struct ImageArchive {
    fmt: &'static Format,
    image: Arc<dyn ReadAt>,
    entries: [Entry; 1],
    units: [Unit; 1],
    props: Vec<(&'static str, String)>,
}

impl ImageArchive {
    /// `name` is the entry's name, usually the archive's stem and a type extension.
    pub fn boxed(
        fmt: &'static Format,
        image: Arc<dyn ReadAt>,
        name: String,
        props: Vec<(&'static str, String)>,
    ) -> Box<dyn Archive> {
        let size = image.size();
        Box::new(ImageArchive {
            fmt,
            entries: [Entry {
                name,
                size: Some(size),
                ..Default::default()
            }],
            units: [Unit {
                entries: vec![0],
                encrypted: false,
            }],
            image,
            props,
        })
    }
}

impl Archive for ImageArchive {
    fn format(&self) -> &'static Format {
        self.fmt
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, _unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let mut r = Runs::whole(self.image.clone());
        f(0, &mut r)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.props.clone()
    }

    fn volume(&self, i: usize) -> Option<Arc<dyn ReadAt>> {
        (i == 0).then(|| self.image.clone())
    }

    fn main_entry(&self) -> Option<usize> {
        Some(0)
    }

    fn verifies_data(&self) -> bool {
        true
    }
}

/// One partition of a partition table: its place on the disk, and the label a GPT gives it.
pub struct Part {
    pub label: Option<String>,
    pub start: u64,
    pub len: u64,
}

/// A partition table's partitions. Each lists as one entry, numbered from 0 in table order
/// and named `number.label.ext` (or `number.ext` without a label), where `ext` is the file
/// system found in it, as 7-Zip names them. Each partition is a window of the disk; when the table holds exactly one, that
/// window is the main entry, so a file system in it opens as the next level.
pub struct Partitions {
    fmt: &'static Format,
    disk: Arc<dyn ReadAt>,
    ranges: Vec<(u64, u64)>,
    entries: Vec<Entry>,
    units: Vec<Unit>,
    props: Vec<(&'static str, String)>,
}

impl Partitions {
    pub fn boxed(
        fmt: &'static Format,
        disk: Arc<dyn ReadAt>,
        parts: Vec<Part>,
        props: Vec<(&'static str, String)>,
    ) -> Result<Box<dyn Archive>> {
        let mut entries = Vec::with_capacity(parts.len());
        let mut ranges = Vec::with_capacity(parts.len());
        for (number, p) in parts.iter().enumerate() {
            let window = Window::new(disk.clone(), p.start, p.len);
            let ext = partition_ext(&head(&window)?);
            let name = match &p.label {
                Some(label) => format!("{number}.{}.{ext}", clean_label(label)),
                None => format!("{number}.{ext}"),
            };
            entries.push(Entry {
                name,
                size: Some(window.size()),
                ..Default::default()
            });
            ranges.push((p.start, p.len));
        }
        let units = (0..entries.len())
            .map(|i| Unit {
                entries: vec![i],
                encrypted: false,
            })
            .collect();
        Ok(Box::new(Partitions {
            fmt,
            disk,
            ranges,
            entries,
            units,
            props,
        }))
    }

    fn window(&self, i: usize) -> Window {
        let (start, len) = self.ranges[i];
        Window::new(self.disk.clone(), start, len)
    }
}

/// A partition label as an entry name component: path separators and control characters
/// become `_`.
fn clean_label(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\') || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect()
}

impl Archive for Partitions {
    fn format(&self) -> &'static Format {
        self.fmt
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let i = self.units[unit].entries[0];
        let mut r = Runs::whole(Arc::new(self.window(i)));
        f(i, &mut r)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.props.clone()
    }

    fn volume(&self, i: usize) -> Option<Arc<dyn ReadAt>> {
        (i < self.ranges.len()).then(|| Arc::new(self.window(i)) as Arc<dyn ReadAt>)
    }

    fn main_entry(&self) -> Option<usize> {
        (self.entries.len() == 1).then_some(0)
    }

    fn verifies_data(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ram(v: Vec<u8>) -> Arc<dyn ReadAt> {
        Arc::new(crate::format::data::Slice::from_vec(v))
    }

    #[test]
    fn runs_read_holes_as_zeros() {
        let src = ram((0u8..32).collect());
        let runs = [
            Run {
                at: 0,
                len: 4,
                phys: Some(8),
            },
            Run {
                at: 10,
                len: 4,
                phys: None,
            },
            Run {
                at: 20,
                len: 4,
                phys: Some(0),
            },
        ];
        let mut out = vec![0xFFu8; 26];
        read_runs(&*src, &runs, 0, &mut out).unwrap();
        assert_eq!(&out[..4], &[8, 9, 10, 11]);
        assert!(out[4..10].iter().all(|&b| b == 0));
        assert!(out[10..14].iter().all(|&b| b == 0));
        assert!(out[14..20].iter().all(|&b| b == 0));
        assert_eq!(&out[20..24], &[0, 1, 2, 3]);
        assert!(out[24..].iter().all(|&b| b == 0));
    }

    #[test]
    fn concat_and_window_bound_reads() {
        let a = ram(vec![1, 2, 3]);
        let b = ram(vec![4, 5]);
        let c = Concat::new(vec![a, Arc::new(Zeros(2)), b]);
        assert_eq!(c.size(), 7);
        let mut out = [0u8; 7];
        c.read_at(0, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 0, 0, 4, 5]);
        let w = Window::new(Arc::new(c), 2, 100);
        assert_eq!(w.size(), 5);
        assert!(w.read_at(4, &mut [0u8; 2]).is_err());
    }

    #[test]
    fn cached_source_matches_direct_reads() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7) as u8).collect();
        let c = Cached::new(ram(data.clone()));
        let mut out = vec![0u8; 9000];
        c.read_at(3000, &mut out).unwrap();
        assert_eq!(&out[..], &data[3000..12000]);
    }

    #[test]
    fn guid_text_is_mixed_endian() {
        let b = [
            0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD,
            0x4A, 0x08,
        ];
        assert_eq!(guid_text(&b), "2DC27766-F623-4200-9D64-115E9BFD4A08");
    }
}
