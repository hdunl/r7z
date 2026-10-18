//! Creating archives in formats other than 7z: zip, tar, and tar or single files inside
//! gzip, bzip2 and xz.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;

use crate::codec::pcompress::{Bzip2Writer, GzipWriter, XzWriter};
use crate::error::{Error, Result};
use crate::ops::create::{temp_path, Item, Progress, Summary};
use crate::util::time::filetime_to_unix;

/// What `a` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    SevenZ,
    Zip,
    Tar,
    /// One file compressed (`x.gz`).
    Single(Compressor),
    /// A tar compressed in one step (`x.tar.gz`).
    TarIn(Compressor),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compressor {
    Gzip,
    Bzip2,
    Xz,
}

impl Compressor {
    fn ext(self) -> &'static str {
        match self {
            Compressor::Gzip => "gz",
            Compressor::Bzip2 => "bz2",
            Compressor::Xz => "xz",
        }
    }
}

/// Picks the output kind from `-t` and the archive name.
pub fn kind_for(archive: &Path, forced: Option<&str>) -> Result<Kind> {
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let (ext, compound) = super::extensions_of(&name);
    let tar_in = |c| {
        if compound.as_deref().is_some_and(|c| c.starts_with("tar.")) {
            Kind::TarIn(c)
        } else {
            Kind::Single(c)
        }
    };
    let by_ext = || match ext.as_str() {
        "zip" | "zipx" | "jar" | "xpi" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "epub"
        | "apk" => Some(Kind::Zip),
        "tar" => Some(Kind::Tar),
        "tgz" | "tpz" => Some(Kind::TarIn(Compressor::Gzip)),
        "tbz" | "tbz2" => Some(Kind::TarIn(Compressor::Bzip2)),
        "txz" => Some(Kind::TarIn(Compressor::Xz)),
        "gz" | "gzip" => Some(tar_in(Compressor::Gzip)),
        "bz2" | "bzip2" => Some(tar_in(Compressor::Bzip2)),
        "xz" => Some(tar_in(Compressor::Xz)),
        "7z" => Some(Kind::SevenZ),
        _ => None,
    };
    let Some(t) = forced else {
        return Ok(by_ext().unwrap_or(Kind::SevenZ));
    };
    let f =
        super::find_format(t).ok_or_else(|| Error::usage(format!("unknown archive type '{t}'")))?;
    if !f.write {
        return Err(Error::unsupported(format!(
            "r7z cannot create {} archives",
            f.name
        )));
    }
    Ok(match f.name {
        "7z" => Kind::SevenZ,
        "zip" => Kind::Zip,
        "tar" => Kind::Tar,
        "gzip" => match by_ext() {
            Some(Kind::TarIn(Compressor::Gzip)) => Kind::TarIn(Compressor::Gzip),
            _ if t.eq_ignore_ascii_case("tgz") => Kind::TarIn(Compressor::Gzip),
            _ => Kind::Single(Compressor::Gzip),
        },
        "bzip2" => match by_ext() {
            Some(Kind::TarIn(Compressor::Bzip2)) => Kind::TarIn(Compressor::Bzip2),
            _ => Kind::Single(Compressor::Bzip2),
        },
        "xz" => match by_ext() {
            Some(Kind::TarIn(Compressor::Xz)) => Kind::TarIn(Compressor::Xz),
            _ => Kind::Single(Compressor::Xz),
        },
        other => {
            return Err(Error::unsupported(format!(
                "r7z cannot create {other} archives"
            )))
        }
    })
}

/// Settings shared by the non-7z writers.
#[derive(Clone, Debug)]
pub struct WriteOptions {
    /// 0-9 as in `-mx`.
    pub level: u32,
    pub threads: usize,
    pub password: Option<String>,
    /// zip: store instead of deflate.
    pub store: bool,
    pub store_mtime: bool,
    pub store_ctime: bool,
    pub store_atime: bool,
}

/// zlib-style level for a 7-Zip `-mx` level. The default (mx5) is zlib level 7: with the
/// zlib-rs encoder that matches the size of the previous encoder's level 6 on source
/// trees and is still about twice as fast.
pub fn deflate_level(mx: u32) -> u32 {
    match mx {
        0 => 0,
        1..=4 => mx,
        5 => 7,
        6 => 8,
        _ => 9,
    }
}

enum Sink<W: Write + 'static> {
    Plain(W),
    Gzip(GzipWriter<W>),
    Bzip2(Bzip2Writer<W>),
    Xz(XzWriter<W>),
}

impl<W: Write + 'static> Sink<W> {
    /// `total` is the expected input size (it sizes the xz dictionary and threads).
    fn new(
        c: Option<Compressor>,
        out: W,
        opts: &WriteOptions,
        name: Option<&str>,
        mtime: u32,
        total: u64,
    ) -> Result<Self> {
        let level = opts.level.max(1);
        Ok(match c {
            None => Sink::Plain(out),
            Some(Compressor::Gzip) => Sink::Gzip(GzipWriter::new(
                out,
                deflate_level(level),
                opts.threads,
                name,
                mtime,
            )?),
            Some(Compressor::Bzip2) => Sink::Bzip2(Bzip2Writer::new(out, level, opts.threads)),
            Some(Compressor::Xz) => Sink::Xz(XzWriter::new(out, level, opts.threads, total)?),
        })
    }

    fn finish(self) -> Result<W> {
        Ok(match self {
            Sink::Plain(w) => w,
            Sink::Gzip(w) => w.finish()?,
            Sink::Bzip2(w) => w.finish()?,
            Sink::Xz(w) => w.finish()?,
        })
    }
}

impl<W: Write + 'static> Write for Sink<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Sink::Plain(w) => w.write(buf),
            Sink::Gzip(w) => w.write(buf),
            Sink::Bzip2(w) => w.write(buf),
            Sink::Xz(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writes `archive` atomically: into a temporary file renamed into place on success.
fn atomically(
    archive: &Path,
    f: impl FnOnce(BufWriter<File>) -> Result<(File, Summary)>,
) -> Result<Summary> {
    let tmp = temp_path(archive);
    let file = File::create(&tmp)
        .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp.display())))?;
    match f(BufWriter::with_capacity(1 << 20, file)) {
        Ok((file, mut s)) => {
            s.archive_bytes = file.metadata()?.len();
            let _ = file.sync_all();
            drop(file);
            if archive.exists() {
                std::fs::remove_file(archive)?;
            }
            std::fs::rename(&tmp, archive)?;
            Ok(s)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Creates a non-7z archive.
pub fn create(
    archive: &Path,
    kind: Kind,
    items: &[Item],
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<Summary> {
    match kind {
        Kind::SevenZ => Err(Error::Other("internal: 7z goes through ops::create".into())),
        Kind::Zip => super::zip::write(archive, items, opts, progress),
        Kind::Tar => write_tar(archive, None, items, opts, progress),
        Kind::TarIn(c) => write_tar(archive, Some(c), items, opts, progress),
        Kind::Single(c) => write_single(archive, c, items, opts, progress),
    }
}

fn write_tar(
    archive: &Path,
    c: Option<Compressor>,
    items: &[Item],
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<Summary> {
    atomically(archive, |out| {
        let total = items.iter().map(|i| i.size + 1024).sum();
        let sink = Sink::new(c, out, opts, None, 0, total)?;
        let mut tw = super::tar::TarWriter::new(sink);
        let mut s = Summary {
            threads_used: if c.is_some() { opts.threads } else { 1 },
            ..Default::default()
        };
        for it in items {
            if it.is_dir {
                tw.add_dir(it)?;
                s.dirs += 1;
                continue;
            }
            let mut f = match File::open(&it.src) {
                Ok(f) => f,
                Err(e) => {
                    progress.warn(&format!("cannot open {}: {e}", it.src.display()));
                    s.skipped += 1;
                    continue;
                }
            };
            let got = tw.add_file(it, &mut f, &|n| progress.add(n))?;
            if progress.cancelled() {
                return Err(Error::Cancelled);
            }
            if got != it.size {
                progress.warn(&format!(
                    "{} changed size while being read",
                    it.src.display()
                ));
            }
            s.files += 1;
            s.input_bytes += got;
        }
        let sink = tw.finish()?;
        let out = sink.finish()?;
        let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        Ok((file, s))
    })
}

fn write_single(
    archive: &Path,
    c: Compressor,
    items: &[Item],
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<Summary> {
    let files: Vec<&Item> = items.iter().filter(|i| !i.is_dir).collect();
    if files.len() != 1 || items.len() != 1 {
        return Err(Error::usage(format!(
            "a .{ext} file holds exactly one file; use .tar.{ext} for several files or directories",
            ext = c.ext()
        )));
    }
    let it = files[0];
    atomically(archive, |out| {
        let name = it.name.rsplit('/').next().unwrap_or(&it.name);
        let mtime = it
            .mtime
            .map(filetime_to_unix)
            .unwrap_or(0)
            .clamp(0, u32::MAX as i64) as u32;
        let mtime = if opts.store_mtime { mtime } else { 0 };
        let mut sink = Sink::new(Some(c), out, opts, Some(name), mtime, it.size)?;
        let mut f = File::open(&it.src)
            .map_err(|e| Error::Other(format!("cannot open {}: {e}", it.src.display())))?;
        let mut buf = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Other(format!("reading {}: {e}", it.src.display()))),
            };
            sink.write_all(&buf[..n])?;
            progress.add(n as u64);
            if progress.cancelled() {
                return Err(Error::Cancelled);
            }
            total += n as u64;
        }
        let out = sink.finish()?;
        let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        Ok((
            file,
            Summary {
                files: 1,
                input_bytes: total,
                threads_used: opts.threads,
                ..Default::default()
            },
        ))
    })
}
