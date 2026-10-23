//! Encoder chains. A folder is encoded by writing plain data into the outermost coder;
//! each stage counts the bytes it receives, which become the folder's unpack sizes.
//!
//! A BCJ2 folder is the exception: its data is split into four streams. The main stream
//! goes straight to the archive; the call, jump and range coder streams are held in memory
//! and returned with the folder, to be written after the main stream.

use std::io::{self, Write};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lzma_rust2::filter::bcj::BcjWriter;
use lzma_rust2::filter::bcj2::{Bcj2Options, Bcj2Writer};
use lzma_rust2::filter::delta::DeltaWriter;

use super::aes::{AesProps, AesWriter};
use super::lzenc::{Lzma2Options, Lzma2Writer, LzmaOptions, LzmaWriter};
use super::lzma2par::{ParLzma2Writer, ParPlan};
use super::{lzma2_dict_from_prop, lzma2_prop_for_dict, method, Branch};
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
    /// `group`: bytes between dictionary resets; `par`: parallel primed encoding plan;
    /// `mt`: binary tree match finding on a thread of its own (single encoder only).
    Lzma2 {
        opts: LzmaOptions,
        group: u64,
        par: Option<ParPlan>,
        mt: bool,
    },
    /// A branch converter: BCJ (x86), ARM, ARM64, and so on.
    Branch(Branch),
    /// BCJ2 for x86 code. `main` encodes the main stream and `side` the call and jump
    /// streams. Only as the sole coder of a folder.
    Bcj2 {
        main: Box<EncMethod>,
        side: LzmaOptions,
    },
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
            EncMethod::Lzma2 {
                opts,
                group,
                par,
                mt,
            } => {
                let mut o = opts.clone();
                o.dict_size =
                    lzma2_dict_from_prop(lzma2_prop_for_dict(o.dict_size.max(4096))).unwrap();
                EncMethod::Lzma2 {
                    opts: o,
                    group: *group,
                    par: *par,
                    mt: *mt,
                }
            }
            EncMethod::Lzma(opts) => {
                let mut o = opts.clone();
                o.dict_size = o.dict_size.max(4096);
                EncMethod::Lzma(o)
            }
            EncMethod::Bcj2 { main, side } => {
                let mut s = side.clone();
                s.dict_size = s.dict_size.max(4096);
                EncMethod::Bcj2 {
                    main: Box::new(main.normalized()),
                    side: s,
                }
            }
            other => other.clone(),
        }
    }

    pub fn coder(&self) -> Coder {
        let (id, props, num_in) = match self {
            EncMethod::Copy => (method::COPY, vec![], 1),
            EncMethod::Lzma(o) => {
                let mut p = vec![o.get_props()];
                p.extend_from_slice(&o.dict_size.to_le_bytes());
                (method::LZMA, p, 1)
            }
            EncMethod::Lzma2 { opts, .. } => {
                (method::LZMA2, vec![lzma2_prop_for_dict(opts.dict_size)], 1)
            }
            EncMethod::Branch(b) => (b.method(), vec![], 1),
            EncMethod::Bcj2 { .. } => (method::BCJ2, vec![], 4),
            EncMethod::Delta(d) => (method::DELTA, vec![(d - 1) as u8], 1),
            EncMethod::Aes { props, .. } => (method::AES, props.serialize(), 1),
        };
        Coder {
            method: id,
            num_in,
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
            EncMethod::Lzma2 {
                opts,
                group,
                par,
                mt,
            } => match par {
                Some(plan) if plan.workers > 1 => {
                    Box::new(ParLzma2Writer::new(inner, opts.clone(), *plan, hooks))
                }
                _ => {
                    let options = Lzma2Options {
                        lzma_options: opts.clone(),
                        chunk_size: NonZeroU64::new(*group),
                    };
                    let writer = if *mt {
                        Lzma2Writer::new_threaded(inner, options).map_err(Error::from_codec)?
                    } else {
                        Lzma2Writer::new(inner, options)
                    };
                    Box::new(Lzma2Enc(Some(writer)))
                }
            },
            EncMethod::Branch(b) => Box::new(BranchEnc(Some(branch_writer(*b, inner)))),
            EncMethod::Bcj2 { .. } => {
                return Err(Error::unsupported("BCJ2 outside a folder of its own"))
            }
            EncMethod::Delta(d) => Box::new(DeltaEnc(Some(DeltaWriter::new(inner, *d as usize)))),
            EncMethod::Aes { key, props } => Box::new(AesWriter::new(inner, key, props.iv)),
        })
    }
}

fn branch_writer<'a>(b: Branch, inner: Box<dyn Sink + 'a>) -> BcjWriter<Box<dyn Sink + 'a>> {
    match b {
        Branch::X86 => BcjWriter::new_x86(inner, 0),
        Branch::Arm => BcjWriter::new_arm(inner, 0),
        Branch::ArmThumb => BcjWriter::new_arm_thumb(inner, 0),
        Branch::Arm64 => BcjWriter::new_arm64(inner, 0),
        Branch::Ppc => BcjWriter::new_ppc(inner, 0),
        Branch::Sparc => BcjWriter::new_sparc(inner, 0),
        Branch::Ia64 => BcjWriter::new_ia64(inner, 0),
        Branch::RiscV => BcjWriter::new_riscv(inner, 0),
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

/// An in-memory stream that the caller takes once the folder is finished.
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink for SharedBuf {
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

struct BranchEnc<'a>(Option<BcjWriter<Box<dyn Sink + 'a>>>);
impl Write for BranchEnc<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.as_mut().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Sink for BranchEnc<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.0.take().unwrap().finish()?.finish()
    }
}

struct Bcj2Enc<'a>(Option<Bcj2Writer<Box<dyn Sink + 'a>>>);
impl Write for Bcj2Enc<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.as_mut().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Sink for Bcj2Enc<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        // The four outputs are finished in MAIN, CALL, JUMP, RC order.
        let outputs = self.0.take().unwrap().finish()?;
        for out in outputs {
            out.finish()?;
        }
        Ok(())
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

/// A finished folder: its description, the packed size of each of its pack streams, and
/// the pack streams held back until after the main stream (BCJ2's call, jump and range
/// coder streams). The main stream has already been written.
pub struct FinishedFolder {
    pub folder: Folder,
    pub pack_sizes: Vec<u64>,
    pub tail: Vec<Vec<u8>>,
}

/// An in-progress folder. Write plain data into it, then `finish` for the folder record.
pub struct FolderEncoder<'a> {
    top: Option<Box<dyn Sink + 'a>>,
    coders: Vec<Coder>,
    /// Bytes entering each stage, outermost first (BCJ2: the BCJ2 input, then its main,
    /// call and jump outputs).
    counters: Vec<Arc<AtomicU64>>,
    pack: Arc<AtomicU64>,
    /// BCJ2 only: call, jump and range coder streams.
    side: Vec<SharedBuf>,
    reports_progress: bool,
}

impl<'a> FolderEncoder<'a> {
    /// `methods` is outermost first, e.g. `[Branch(X86), Lzma2, Aes]`.
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
        let sink: Box<dyn Sink + 'a> = Box::new(PackSink {
            out,
            count: pack.clone(),
        });
        if let [EncMethod::Bcj2 { main, side }] = methods.as_slice() {
            return Self::bcj2(main, side, sink, pack, hooks);
        }
        if methods.iter().any(|m| matches!(m, EncMethod::Bcj2 { .. })) {
            return Err(Error::unsupported(
                "BCJ2 must be the only coder of a folder",
            ));
        }
        let mut sink = sink;
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
            side: Vec::new(),
            reports_progress,
        })
    }

    /// Splits the data for BCJ2. Coders in the folder: BCJ2 (4 inputs), the main coder,
    /// then an LZMA coder for each of the call and jump streams. The range coder stream
    /// is stored raw.
    fn bcj2(
        main: &EncMethod,
        side: &LzmaOptions,
        main_sink: Box<dyn Sink + 'a>,
        pack: Arc<AtomicU64>,
        hooks: Hooks<'a>,
    ) -> Result<Self> {
        let side_method = EncMethod::Lzma(side.clone());
        let call = SharedBuf::default();
        let jump = SharedBuf::default();
        let rc = SharedBuf::default();
        let main_count = Arc::new(AtomicU64::new(0));
        let call_count = Arc::new(AtomicU64::new(0));
        let jump_count = Arc::new(AtomicU64::new(0));
        let outputs: [Box<dyn Sink + 'a>; 4] = [
            Box::new(Counted {
                inner: main.wrap(main_sink, hooks)?,
                count: main_count.clone(),
            }),
            Box::new(Counted {
                inner: side_method.wrap(Box::new(call.clone()), hooks)?,
                count: call_count.clone(),
            }),
            Box::new(Counted {
                inner: side_method.wrap(Box::new(jump.clone()), hooks)?,
                count: jump_count.clone(),
            }),
            Box::new(rc.clone()),
        ];
        let top_count = Arc::new(AtomicU64::new(0));
        let bcj2 = Bcj2Writer::new(outputs, &Bcj2Options::default()).map_err(Error::from_codec)?;
        let top: Box<dyn Sink + 'a> = Box::new(Counted {
            inner: Box::new(Bcj2Enc(Some(bcj2))),
            count: top_count.clone(),
        });
        Ok(FolderEncoder {
            top: Some(top),
            coders: vec![
                EncMethod::Bcj2 {
                    main: Box::new(main.clone()),
                    side: side.clone(),
                }
                .coder(),
                main.coder(),
                side_method.coder(),
                side_method.coder(),
            ],
            counters: vec![top_count, main_count, call_count, jump_count],
            pack,
            side: vec![call, jump, rc],
            reports_progress: hooks.progress.is_some() && main.reports_progress(),
        })
    }

    /// Like `new`, but owning the output (for encoders kept across calls).
    pub fn new_owned<W: Write + 'a>(methods: &[EncMethod], out: W) -> Result<Self> {
        let methods: Vec<EncMethod> = methods.iter().map(|m| m.normalized()).collect();
        if methods.iter().any(|m| matches!(m, EncMethod::Bcj2 { .. })) {
            return Err(Error::unsupported("BCJ2 needs a borrowed output"));
        }
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
            side: Vec::new(),
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

    /// Flushes every stage and returns the folder description and its pack streams.
    pub fn finish(mut self) -> Result<FinishedFolder> {
        self.top
            .take()
            .unwrap()
            .finish()
            .map_err(Error::from_codec)?;
        let unpack_sizes: Vec<u64> = self
            .counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        let main_packed = self.pack.load(Ordering::Relaxed);
        if self.side.is_empty() {
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
                unpack_sizes,
                crc: None,
            };
            return Ok(FinishedFolder {
                folder,
                pack_sizes: vec![main_packed],
                tail: Vec::new(),
            });
        }
        // BCJ2: BCJ2 input 0..=2 are bound to the main, call and jump outputs (out 1..=3);
        // its input 3 (range coder) is raw. Pack streams: main, call, jump, range coder.
        let folder = Folder {
            coders: std::mem::take(&mut self.coders),
            bind_pairs: (0..3)
                .map(|i| BindPair {
                    in_index: i,
                    out_index: i + 1,
                })
                .collect(),
            packed_streams: vec![4, 5, 6, 3],
            unpack_sizes,
            crc: None,
        };
        let tail: Vec<Vec<u8>> = self.side.iter().map(SharedBuf::take).collect();
        let mut pack_sizes = vec![main_packed];
        pack_sizes.extend(tail.iter().map(|t| t.len() as u64));
        Ok(FinishedFolder {
            folder,
            pack_sizes,
            tail,
        })
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
