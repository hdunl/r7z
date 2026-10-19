//! Encoder chains. A folder is encoded by writing plain data into the outermost coder;
//! each stage counts the bytes it receives, which become the folder's unpack sizes.

use std::io::{self, Write};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lzma_rust2::filter::bcj::BcjWriter;
use lzma_rust2::filter::delta::DeltaWriter;
use lzma_rust2::{Lzma2Options, Lzma2Writer, LzmaOptions, LzmaWriter};

use super::aes::{AesProps, AesWriter};
use super::lzma2par::{ParLzma2Writer, ParPlan};
use super::{lzma2_dict_from_prop, lzma2_prop_for_dict, method};
use crate::error::{Error, Result};
use crate::sevenz::{BindPair, Coder, Folder};

/// Caller hooks for long-running encoders.
#[derive(Clone, Copy, Default)]
pub struct Hooks<'a> {
    /// Polled while waiting on encoder threads; true stops with `Error::Cancelled`.
    pub cancel: Option<&'a (dyn Fn() -> bool + Sync)>,
    /// Receives input bytes as encoder threads finish them. When an encoder stage takes
    /// this, [`FolderEncoder::reports_progress`] is true and the caller should not count
    /// bytes on write as well.
    pub progress: Option<&'a (dyn Fn(u64) + Sync)>,
}

/// A write stage that must be explicitly finished to flush trailing state.
pub trait Sink: Write {
    fn finish(self: Box<Self>) -> io::Result<()>;
}

#[derive(Clone, Debug)]
pub enum EncMethod {
    Copy,
    Lzma(LzmaOptions),
    /// `group`: bytes between dictionary resets; `par`: parallel primed encoding plan.
    Lzma2 {
        opts: LzmaOptions,
        group: u64,
        par: Option<ParPlan>,
    },
    BcjX86,
    Delta(u32),
    Aes {
        key: [u8; 32],
        props: AesProps,
    },
}

impl EncMethod {
    /// Normalizes options so the stored properties describe exactly what the encoder uses.
    fn normalized(&self) -> EncMethod {
        match self {
            EncMethod::Lzma2 { opts, group, par } => {
                let mut o = opts.clone();
                o.dict_size =
                    lzma2_dict_from_prop(lzma2_prop_for_dict(o.dict_size.max(4096))).unwrap();
                EncMethod::Lzma2 {
                    opts: o,
                    group: *group,
                    par: *par,
                }
            }
            EncMethod::Lzma(opts) => {
                let mut o = opts.clone();
                o.dict_size = o.dict_size.max(4096);
                EncMethod::Lzma(o)
            }
            other => other.clone(),
        }
    }

    pub fn coder(&self) -> Coder {
        let (id, props) = match self {
            EncMethod::Copy => (method::COPY, vec![]),
            EncMethod::Lzma(o) => {
                let mut p = vec![o.get_props()];
                p.extend_from_slice(&o.dict_size.to_le_bytes());
                (method::LZMA, p)
            }
            EncMethod::Lzma2 { opts, .. } => {
                (method::LZMA2, vec![lzma2_prop_for_dict(opts.dict_size)])
            }
            EncMethod::BcjX86 => (method::BCJ_X86, vec![]),
            EncMethod::Delta(d) => (method::DELTA, vec![(d - 1) as u8]),
            EncMethod::Aes { props, .. } => (method::AES, props.serialize()),
        };
        Coder {
            method: id,
            num_in: 1,
            num_out: 1,
            props,
        }
    }

    /// Whether this stage reports completion progress (threaded LZMA2).
    fn reports_progress(&self) -> bool {
        matches!(self, EncMethod::Lzma2 { par: Some(p), .. } if p.workers > 1)
    }

    fn wrap<'a>(&self, inner: Box<dyn Sink + 'a>, hooks: Hooks<'a>) -> Result<Box<dyn Sink + 'a>> {
        Ok(match self {
            EncMethod::Copy => inner,
            EncMethod::Lzma(o) => Box::new(LzmaEnc(Some(
                LzmaWriter::new_no_header(inner, o, false).map_err(Error::from_codec)?,
            ))),
            EncMethod::Lzma2 { opts, group, par } => match par {
                Some(plan) if plan.workers > 1 => {
                    Box::new(ParLzma2Writer::new(inner, opts.clone(), *plan, hooks))
                }
                _ => {
                    let options = Lzma2Options {
                        lzma_options: opts.clone(),
                        chunk_size: NonZeroU64::new(*group),
                    };
                    Box::new(Lzma2Enc(Some(Lzma2Writer::new(inner, options))))
                }
            },
            EncMethod::BcjX86 => Box::new(BcjEnc(Some(BcjWriter::new_x86(inner, 0)))),
            EncMethod::Delta(d) => Box::new(DeltaEnc(Some(DeltaWriter::new(inner, *d as usize)))),
            EncMethod::Aes { key, props } => Box::new(AesWriter::new(inner, key, props.iv)),
        })
    }
}

/// Writes into the archive file and counts packed bytes.
pub struct PackSink<'a, W: Write> {
    out: &'a mut W,
    count: Arc<AtomicU64>,
}

impl<W: Write> Write for PackSink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.out.write_all(buf)?;
        self.count.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

impl<W: Write> Sink for PackSink<'_, W> {
    fn finish(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}

/// `PackSink` that owns its writer.
struct OwnedPackSink<W: Write> {
    out: W,
    count: Arc<AtomicU64>,
}

impl<W: Write> Write for OwnedPackSink<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

impl<W: Write> Sink for OwnedPackSink<W> {
    fn finish(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}

struct Counted<'a> {
    inner: Box<dyn Sink + 'a>,
    count: Arc<AtomicU64>,
}

impl Write for Counted<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)?;
        self.count.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Sink for Counted<'_> {
    fn finish(self: Box<Self>) -> io::Result<()> {
        self.inner.finish()
    }
}

struct LzmaEnc<'a>(Option<LzmaWriter<Box<dyn Sink + 'a>>>);
impl Write for LzmaEnc<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.as_mut().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Sink for LzmaEnc<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.0.take().unwrap().finish()?.finish()
    }
}

struct Lzma2Enc<'a>(Option<Lzma2Writer<Box<dyn Sink + 'a>>>);
impl Write for Lzma2Enc<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.as_mut().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Sink for Lzma2Enc<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.0.take().unwrap().finish()?.finish()
    }
}

struct BcjEnc<'a>(Option<BcjWriter<Box<dyn Sink + 'a>>>);
impl Write for BcjEnc<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.as_mut().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Sink for BcjEnc<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.0.take().unwrap().finish()?.finish()
    }
}

struct DeltaEnc<'a>(Option<DeltaWriter<Box<dyn Sink + 'a>>>);
impl Write for DeltaEnc<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.as_mut().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Sink for DeltaEnc<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.0.take().unwrap().into_inner().finish()
    }
}

/// An in-progress folder. Write plain data into it, then `finish` for the folder record.
pub struct FolderEncoder<'a> {
    top: Option<Box<dyn Sink + 'a>>,
    coders: Vec<Coder>,
    counters: Vec<Arc<AtomicU64>>,
    pack: Arc<AtomicU64>,
    reports_progress: bool,
}

impl<'a> FolderEncoder<'a> {
    /// `methods` is outermost first, e.g. `[BcjX86, Lzma2, Aes]`.
    pub fn new<W: Write>(methods: &[EncMethod], out: &'a mut W) -> Result<Self> {
        Self::with_hooks(methods, out, Hooks::default())
    }

    /// Like `new`, with cancellation and completion-progress hooks for threaded encoders.
    pub fn with_hooks<W: Write>(
        methods: &[EncMethod],
        out: &'a mut W,
        hooks: Hooks<'a>,
    ) -> Result<Self> {
        let methods: Vec<EncMethod> = methods.iter().map(|m| m.normalized()).collect();
        let pack = Arc::new(AtomicU64::new(0));
        let mut sink: Box<dyn Sink + 'a> = Box::new(PackSink {
            out,
            count: pack.clone(),
        });
        let mut counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(methods.len());
        for m in methods.iter().rev() {
            let count = Arc::new(AtomicU64::new(0));
            sink = Box::new(Counted {
                inner: m.wrap(sink, hooks)?,
                count: count.clone(),
            });
            counters.push(count);
        }
        counters.reverse();
        let reports_progress =
            hooks.progress.is_some() && methods.iter().any(|m| m.reports_progress());
        Ok(FolderEncoder {
            top: Some(sink),
            coders: methods.iter().map(|m| m.coder()).collect(),
            counters,
            pack,
            reports_progress,
        })
    }

    /// Like `new`, but owning the output (for encoders kept across calls).
    pub fn new_owned<W: Write + 'a>(methods: &[EncMethod], out: W) -> Result<Self> {
        let methods: Vec<EncMethod> = methods.iter().map(|m| m.normalized()).collect();
        let pack = Arc::new(AtomicU64::new(0));
        let mut sink: Box<dyn Sink + 'a> = Box::new(OwnedPackSink {
            out,
            count: pack.clone(),
        });
        let mut counters: Vec<Arc<AtomicU64>> = Vec::with_capacity(methods.len());
        for m in methods.iter().rev() {
            let count = Arc::new(AtomicU64::new(0));
            sink = Box::new(Counted {
                inner: m.wrap(sink, Hooks::default())?,
                count: count.clone(),
            });
            counters.push(count);
        }
        counters.reverse();
        Ok(FolderEncoder {
            top: Some(sink),
            coders: methods.iter().map(|m| m.coder()).collect(),
            counters,
            pack,
            reports_progress: false,
        })
    }

    /// True when an encoder stage reports progress through `Hooks::progress`.
    pub fn reports_progress(&self) -> bool {
        self.reports_progress
    }

    /// Bytes accepted so far (the folder's unpack size).
    pub fn written(&self) -> u64 {
        self.counters[0].load(Ordering::Relaxed)
    }

    /// Bytes emitted to the archive so far.
    pub fn packed(&self) -> u64 {
        self.pack.load(Ordering::Relaxed)
    }

    /// Flushes every stage and returns the folder description and its packed size.
    pub fn finish(mut self) -> Result<(Folder, u64)> {
        self.top
            .take()
            .unwrap()
            .finish()
            .map_err(Error::from_codec)?;
        let n = self.coders.len();
        let folder = Folder {
            coders: std::mem::take(&mut self.coders),
            bind_pairs: (0..n - 1)
                .map(|i| BindPair {
                    in_index: i,
                    out_index: i + 1,
                })
                .collect(),
            packed_streams: vec![n - 1],
            unpack_sizes: self
                .counters
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .collect(),
            crc: None,
        };
        Ok((folder, self.pack.load(Ordering::Relaxed)))
    }
}

impl Write for FolderEncoder<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.top.as_mut().unwrap().write(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.top.as_mut().unwrap().write_all(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
