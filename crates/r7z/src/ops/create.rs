//! Archive creation.
//!
//! Speed policy relative to 7-Zip 25.01:
//! * LZMA2 blocks are sized so that every core gets work. The block is never smaller than
//!   the dictionary (7-Zip uses 4x dictionary, which leaves cores idle on medium inputs).
//!   Every block starts with a dictionary reset, so the result is also parallel-decodable.
//! * Non-solid archives compress many folders concurrently.
//! * The 7zAES key is derived once per archive.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use rayon::prelude::*;

use crate::codec::aes::{derive_key, random_iv, AesProps, DEFAULT_CYCLES_POWER};
use crate::codec::encode::{EncMethod, FolderEncoder, Hooks};
use crate::codec::lzenc::{EncodeMode, LzmaOptions, MfType};
use crate::codec::lzma2par::ParPlan;
use crate::codec::Branch;
use crate::codec::{lzma2_dict_from_prop, lzma2_prop_for_dict};
use crate::error::{Error, Result};
use crate::sevenz::write::{signature_header, write_encoded_header, write_header};
use crate::sevenz::{Entry, Folder, StreamsInfo, SIGNATURE_HEADER_SIZE};
use crate::util::mem::encoder_budget;
use crate::util::tempfile::TempFile;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainMethod {
    Lzma2,
    Lzma,
    Copy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterMode {
    /// The converter 7-Zip would use for each file, from its type (see `plan_jobs`).
    Auto,
    Off,
    /// BCJ (x86) for every file.
    Bcj,
    /// BCJ2 (x86, four streams) for every file.
    Bcj2,
    /// One branch converter for every file.
    Branch(Branch),
    Delta(u32),
}

#[derive(Clone, Debug)]
pub struct CreateOptions {
    pub level: u32,
    pub method: MainMethod,
    pub dict_size: Option<u32>,
    pub fast_bytes: Option<u32>,
    pub block_size: Option<u64>,
    pub threads: usize,
    /// `None` = non-solid; `Some(n)` = solid blocks of at most n bytes.
    pub solid_limit: Option<u64>,
    pub filter: FilterMode,
    pub password: Option<String>,
    pub encrypt_header: bool,
    pub compress_header: bool,
    pub store_mtime: bool,
    pub store_ctime: bool,
    pub store_atime: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions {
            level: 5,
            method: MainMethod::Lzma2,
            dict_size: None,
            fast_bytes: None,
            block_size: None,
            threads: crate::util::default_threads(),
            solid_limit: Some(default_solid_limit(5)),
            filter: FilterMode::Auto,
            password: None,
            encrypt_header: false,
            compress_header: true,
            store_mtime: true,
            store_ctime: false,
            store_atime: false,
        }
    }
}

pub fn default_solid_limit(level: u32) -> u64 {
    match level {
        0..=1 => 64 << 20,
        2..=3 => 512 << 20,
        4..=6 => 2 << 30,
        _ => 4 << 30,
    }
}

/// Dictionary size for a level. Matches what 7-Zip 25.01 x64 stores (measured with
/// `7z a -mx{N}` on a 600 MB input): 2^18, 2^20, 2^22, 2^24 for levels 1-4, then
/// 2^(level+20) up to 2^28 at level 9.
pub fn level_dict_size(level: u32) -> u32 {
    match level {
        0..=4 => 1 << (level.max(1) * 2 + 16),
        5..=8 => 1 << (level + 20),
        _ => 1 << 28,
    }
}

/// One thing to store: a file or directory on disk and its name inside the archive.
#[derive(Clone, Debug)]
pub struct Item {
    pub src: PathBuf,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<u64>,
    pub ctime: Option<u64>,
    pub atime: Option<u64>,
    pub attrib: Option<u32>,
}

pub trait Progress: Sync {
    fn add(&self, _bytes: u64) {}
    fn warn(&self, _msg: &str) {}
    /// Polled between data blocks; returning true stops with `Error::Cancelled`.
    fn cancelled(&self) -> bool {
        false
    }
}

pub struct NoProgress;
impl Progress for NoProgress {}

#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub input_bytes: u64,
    pub archive_bytes: u64,
    pub folders: usize,
    pub skipped: u64,
    pub threads_used: usize,
}

const EXE_EXTS: &[&str] = &[
    "exe", "dll", "sys", "ocx", "cpl", "scr", "drv", "efi", "com", "so", "dylib", "o", "obj",
    "lib", "a", "node", "pyd",
];

pub(crate) fn is_executable_name(name: &str) -> bool {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    EXE_EXTS.contains(&ext.as_str())
}

/// Orders a solid block by path, like 7-Zip. Measured on a 87 MB JavaScript tree, path
/// order beat extension-first order by 5.4%: files of one package share the most content.
fn sort_for_solid(items: &[Item], group: &mut [usize]) {
    group.sort_by(|&a, &b| items[a].name.cmp(&items[b].name));
}

/// The filter a folder's data goes through before its main coder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Filter {
    None,
    Branch(Branch),
    Bcj2,
    Delta(u32),
}

pub(crate) struct Job {
    pub(crate) items: Vec<usize>,
    pub(crate) filter: Filter,
    pub(crate) total: u64,
}

pub(crate) struct FolderResult {
    pub(crate) folder: Folder,
    /// Packed size of each of the folder's pack streams, in archive order.
    pub(crate) pack_sizes: Vec<u64>,
    /// (item index, bytes, crc) for each stored stream, in order.
    pub(crate) streams: Vec<(usize, u64, u32)>,
}

fn lzma_options(opts: &CreateOptions, data_size: u64) -> LzmaOptions {
    let level = opts.level.clamp(1, 9);
    let mut dict = opts.dict_size.unwrap_or_else(|| level_dict_size(level));
    // A dictionary larger than the data only costs memory.
    if data_size < dict as u64 {
        dict = lzma2_dict_from_prop(lzma2_prop_for_dict((data_size as u32).max(4096))).unwrap();
    }
    let fb = opts.fast_bytes.unwrap_or(if level < 7 { 32 } else { 64 });
    let mut o = LzmaOptions::with_preset(6);
    o.dict_size = dict;
    o.nice_len = fb.clamp(LzmaOptions::NICE_LEN_MIN, LzmaOptions::NICE_LEN_MAX);
    if level < 5 {
        o.mode = EncodeMode::Fast;
        o.mf = MfType::Hc4;
        o.depth_limit = 0;
    } else {
        o.mode = EncodeMode::Normal;
        o.mf = MfType::Bt4;
        o.depth_limit = 0;
    }
    o
}

/// Plans LZMA2 for a folder of `total` bytes.
///
/// Groups (dictionary resets) are 4x the dictionary, the block size 7-Zip uses, so the
/// parallel-decode structure matches 7-Zip. How a group is split for parallel encoding
/// depends on the level (measured on JS, binary and mixed corpora against 7-Zip 25.01):
/// * mx1-4: independent sub-blocks, fastest; costs 2-25% ratio on redundant trees.
/// * mx5-6: sub-blocks of at least 8 MiB primed with 8 MiB of preceding data; measured
///   1.3-1.75x faster than 7-Zip for 0.1-5.7% larger output.
/// * mx7-9: no splitting inside a group; ratio equals single-threaded LZMA2, and
///   parallelism comes only from multiple groups and folders.
fn lzma2_plan(
    opts: &CreateOptions,
    lz: &LzmaOptions,
    total: u64,
    threads: usize,
) -> (u64, Option<ParPlan>) {
    let dict = lz.dict_size as u64;
    let group = opts
        .block_size
        .unwrap_or((dict * 4).max(1 << 20))
        .max(1 << 16);
    if threads <= 1 {
        return (group, None);
    }
    let per_thread = total.div_ceil(threads as u64);
    let (sub, prime) = match opts.level {
        0..=4 => (per_thread.clamp(1 << 20, group), 0u64),
        5..=6 => (per_thread.max(8 << 20).min(group), (8u64 << 20).min(dict)),
        _ => (group, 0),
    };
    let jobs = total.div_ceil(sub).max(1);
    let mut job_lz = lz.clone();
    job_lz.dict_size = job_lz
        .dict_size
        .min((prime + sub).min(u32::MAX as u64) as u32)
        .max(4096);
    let per_worker = job_lz.get_memory_usage() as u64 * 1024 + prime + sub * 3;
    let by_mem = (encoder_budget() / per_worker.max(1)).max(1);
    let workers = (threads as u64).min(jobs).min(by_mem).max(1) as usize;
    (
        group,
        Some(ParPlan {
            group,
            sub: sub as usize,
            prime: prime as usize,
            workers,
        }),
    )
}

/// LZMA options of the call and jump streams of a BCJ2 folder. 7-Zip uses lc0 lp2 pb2 and
/// a dictionary of about 1 MiB for them: the streams are a few percent of the folder, and a
/// bigger dictionary costs a hash table and tree each, sized by the whole folder.
fn side_options(opts: &CreateOptions, total: u64) -> LzmaOptions {
    let mut lz = lzma_options(opts, total);
    lz.lc = 0;
    lz.lp = 2;
    lz.pb = 2;
    lz.dict_size = lz.dict_size.min(1 << 20);
    lz
}

fn main_method(opts: &CreateOptions, total: u64, threads: usize) -> EncMethod {
    match opts.method {
        MainMethod::Copy => EncMethod::Copy,
        MainMethod::Lzma => EncMethod::Lzma(lzma_options(opts, total)),
        MainMethod::Lzma2 => {
            let lz = lzma_options(opts, total);
            let (group, par) = lzma2_plan(opts, &lz, total, threads);
            // A single encoder thread can hand its match finding to a second thread. With
            // parallel sub-blocks every core already has an encoder, so they stay inline.
            let single = par.is_none_or(|p| p.workers <= 1);
            let mt = threads > 1 && single && lz.mf == MfType::Bt4 && lz.mode == EncodeMode::Normal;
            EncMethod::Lzma2 {
                opts: lz,
                group,
                par,
                mt,
            }
        }
    }
}

/// Files up to this size are read ahead by helper threads; opening and closing many small
/// files costs more than reading them, especially on Windows.
const PREFETCH_MAX_FILE: u64 = 256 << 10;
const PREFETCH_AHEAD: usize = 512;

/// Ordered read-ahead of small files for one folder.
struct Prefetch {
    state: Mutex<PrefetchState>,
    cv: Condvar,
    /// Files too large to prefetch; the consumer streams these.
    large: Vec<bool>,
}

struct PrefetchState {
    ready: HashMap<usize, std::io::Result<Vec<u8>>>,
    consumed: usize,
    stopped: bool,
}

impl Prefetch {
    fn start<'s, 'e>(
        scope: &'s std::thread::Scope<'s, 'e>,
        paths: &'e [&'e Path],
        sizes: &'e [u64],
        readers: usize,
    ) -> Option<std::sync::Arc<Prefetch>> {
        if readers == 0 {
            return None;
        }
        let p = std::sync::Arc::new(Prefetch {
            state: Mutex::new(PrefetchState {
                ready: HashMap::new(),
                consumed: 0,
                stopped: false,
            }),
            cv: Condvar::new(),
            large: sizes.iter().map(|&s| s > PREFETCH_MAX_FILE).collect(),
        });
        let next = std::sync::Arc::new(AtomicUsize::new(0));
        for _ in 0..readers {
            let (p, next) = (p.clone(), next.clone());
            scope.spawn(move || loop {
                let k = next.fetch_add(1, Ordering::Relaxed);
                if k >= paths.len() {
                    return;
                }
                if sizes[k] > PREFETCH_MAX_FILE {
                    continue;
                }
                {
                    let mut st = p.state.lock().unwrap();
                    while !st.stopped && k >= st.consumed + PREFETCH_AHEAD {
                        st = p.cv.wait(st).unwrap();
                    }
                    if st.stopped {
                        return;
                    }
                }
                let r = std::fs::read(paths[k]);
                p.state.lock().unwrap().ready.insert(k, r);
                p.cv.notify_all();
            });
        }
        Some(p)
    }

    /// The prefetched contents of file `k`, or `None` if the caller should stream it itself.
    fn take(&self, k: usize) -> Option<std::io::Result<Vec<u8>>> {
        if self.large[k] {
            return None;
        }
        let mut st = self.state.lock().unwrap();
        st.consumed = k;
        self.cv.notify_all();
        loop {
            if let Some(r) = st.ready.remove(&k) {
                return Some(r);
            }
            st = self.cv.wait(st).unwrap();
        }
    }

    fn stop(&self) {
        self.state.lock().unwrap().stopped = true;
        self.cv.notify_all();
    }
}

/// The main coder a folder of `total` bytes would get (shared with the benchmark).
pub fn bench_method(opts: &CreateOptions, total: u64, threads: usize) -> EncMethod {
    main_method(opts, total, threads)
}

/// Where a folder's file data comes from.
pub(crate) enum Feed<'r> {
    /// The files named by the items.
    Disk,
    /// Consecutive entries of an already decoded folder, each `size` bytes long.
    Decoded(&'r mut dyn Read),
}

/// Reads up to `buf.len()` bytes of decoded folder data, failing when the data ends early.
fn read_decoded(src: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    loop {
        match src.read(buf) {
            Ok(0) => return Err(Error::corrupt("folder data ends early")),
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::corrupt(format!("folder data is damaged: {e}"))),
        }
    }
}

/// Encodes one folder's files into `out`. Unreadable files are skipped with a warning.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_folder<W: Write>(
    job: &Job,
    items: &[Item],
    opts: &CreateOptions,
    aes_key: Option<&[u8; 32]>,
    threads: usize,
    out: &mut W,
    progress: &dyn Progress,
    feed: Feed<'_>,
) -> Result<FolderResult> {
    let main = main_method(opts, job.total, threads);
    let mut methods = Vec::new();
    match job.filter {
        Filter::None | Filter::Bcj2 => {}
        Filter::Branch(b) => methods.push(EncMethod::Branch(b)),
        Filter::Delta(d) => methods.push(EncMethod::Delta(d)),
    }
    if job.filter == Filter::Bcj2 {
        methods.push(EncMethod::Bcj2 {
            main: Box::new(main),
            side: side_options(opts, job.total),
        });
    } else {
        methods.push(main);
    }
    if let Some(key) = aes_key {
        methods.push(EncMethod::Aes {
            key: *key,
            props: AesProps {
                cycles_power: DEFAULT_CYCLES_POWER,
                salt: Vec::new(),
                iv: random_iv(),
            },
        });
    }
    let cancel = || progress.cancelled();
    let done = |n: u64| progress.add(n);
    let hooks = Hooks {
        cancel: Some(&cancel),
        progress: Some(&done),
    };
    let mut enc = FolderEncoder::with_hooks(&methods, out, hooks)?;
    // Threaded LZMA2 reports bytes as blocks finish; otherwise count bytes as they are read.
    let count_reads = !enc.reports_progress();
    let mut buf = vec![0u8; 1 << 20];
    let mut streams = Vec::with_capacity(job.items.len());
    let paths: Vec<&Path> = job.items.iter().map(|&i| items[i].src.as_path()).collect();
    let sizes: Vec<u64> = job.items.iter().map(|&i| items[i].size).collect();
    let mut feed = feed;
    let readers = if matches!(feed, Feed::Disk) && job.items.len() >= 16 {
        threads.clamp(2, 8)
    } else {
        0
    };
    std::thread::scope(|scope| -> Result<()> {
        let pre = Prefetch::start(scope, &paths, &sizes, readers);
        for (k, &i) in job.items.iter().enumerate() {
            let item = &items[i];
            if let Feed::Decoded(src) = &mut feed {
                let mut crc = crc32fast::Hasher::new();
                let mut left = item.size;
                while left > 0 {
                    let want = left.min(buf.len() as u64) as usize;
                    let n = read_decoded(&mut **src, &mut buf[..want])?;
                    crc.update(&buf[..n]);
                    enc.write_all(&buf[..n]).map_err(Error::from_codec)?;
                    left -= n as u64;
                    if count_reads {
                        progress.add(n as u64);
                    }
                    if progress.cancelled() {
                        return Err(Error::Cancelled);
                    }
                }
                streams.push((i, item.size, crc.finalize()));
                continue;
            }
            let mut crc = crc32fast::Hasher::new();
            let mut n = 0u64;
            match pre.as_ref().and_then(|p| p.take(k)) {
                Some(Ok(data)) => {
                    crc.update(&data);
                    enc.write_all(&data).map_err(Error::from_codec)?;
                    n = data.len() as u64;
                    if count_reads {
                        progress.add(n);
                    }
                    if progress.cancelled() {
                        return Err(Error::Cancelled);
                    }
                }
                Some(Err(e)) => {
                    progress.warn(&format!("cannot read {}: {e}", item.src.display()));
                    continue;
                }
                None => {
                    let mut f = match File::open(&item.src) {
                        Ok(f) => f,
                        Err(e) => {
                            progress.warn(&format!("cannot open {}: {e}", item.src.display()));
                            continue;
                        }
                    };
                    loop {
                        let r = match f.read(&mut buf) {
                            Ok(0) => break,
                            Ok(r) => r,
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) => {
                                return Err(Error::Other(format!(
                                    "reading {}: {e}",
                                    item.src.display()
                                )))
                            }
                        };
                        crc.update(&buf[..r]);
                        enc.write_all(&buf[..r]).map_err(Error::from_codec)?;
                        n += r as u64;
                        if count_reads {
                            progress.add(r as u64);
                        }
                        if progress.cancelled() {
                            return Err(Error::Cancelled);
                        }
                    }
                }
            }
            streams.push((i, n, crc.finalize()));
        }
        if let Some(p) = pre {
            p.stop();
        }
        Ok(())
    })?;
    let done = enc.finish()?;
    // BCJ2's call, jump and range coder streams follow the main stream.
    for part in &done.tail {
        out.write_all(part)?;
    }
    Ok(FolderResult {
        folder: done.folder,
        pack_sizes: done.pack_sizes,
        streams,
    })
}

/// The branch converter each file's type selects, for `plan_jobs`. Only executables, and
/// only with `Auto`, are opened to read their headers.
pub(crate) fn branches_for(items: &[Item], opts: &CreateOptions) -> Vec<Option<Branch>> {
    items
        .iter()
        .map(|it| {
            if opts.filter == FilterMode::Auto
                && opts.method != MainMethod::Copy
                && !it.is_dir
                && it.size > 0
                && is_executable_name(&it.name)
            {
                file_branch(&it.src)
            } else {
                None
            }
        })
        .collect()
}

/// Appends the folders of one filter group. Solid blocks are capped at `solid_limit`.
fn push_jobs(
    items: &[Item],
    group: &mut [usize],
    filter: Filter,
    solid_limit: Option<u64>,
    jobs: &mut Vec<Job>,
) {
    if group.is_empty() {
        return;
    }
    match solid_limit {
        None => {
            for &i in group.iter() {
                jobs.push(Job {
                    items: vec![i],
                    filter,
                    total: items[i].size,
                });
            }
        }
        Some(limit) => {
            // Grouping by extension puts similar data next to each other in the block.
            sort_for_solid(items, group);
            let mut cur = Job {
                items: Vec::new(),
                filter,
                total: 0,
            };
            for &i in group.iter() {
                if !cur.items.is_empty() && cur.total + items[i].size > limit {
                    jobs.push(std::mem::replace(
                        &mut cur,
                        Job {
                            items: Vec::new(),
                            filter,
                            total: 0,
                        },
                    ));
                }
                cur.total += items[i].size;
                cur.items.push(i);
            }
            if !cur.items.is_empty() {
                jobs.push(cur);
            }
        }
    }
}

/// Groups the files into folders, one filter per folder.
///
/// `branches` holds the converter each file's type selects (`Auto` only). BCJ2 is used for
/// x86 code at levels 8 and up, and only without encryption (its streams are not
/// encrypted here).
pub(crate) fn plan_jobs(
    items: &[Item],
    stream_items: &[usize],
    branches: &[Option<Branch>],
    opts: &CreateOptions,
) -> Vec<Job> {
    let compressing = opts.method != MainMethod::Copy;
    let bcj2_ok = opts.password.is_none();
    let filter_of = |i: usize| -> Filter {
        if !compressing {
            return Filter::None;
        }
        match opts.filter {
            FilterMode::Off => Filter::None,
            FilterMode::Auto => match branches[i] {
                Some(Branch::X86) if bcj2_ok && opts.level >= 8 => Filter::Bcj2,
                Some(b) => Filter::Branch(b),
                None => Filter::None,
            },
            FilterMode::Bcj => Filter::Branch(Branch::X86),
            FilterMode::Bcj2 if bcj2_ok => Filter::Bcj2,
            FilterMode::Bcj2 => Filter::Branch(Branch::X86),
            FilterMode::Branch(b) => Filter::Branch(b),
            FilterMode::Delta(d) => Filter::Delta(d),
        }
    };
    let mut groups: Vec<(Filter, Vec<usize>)> = Vec::new();
    for &i in stream_items {
        let filter = filter_of(i);
        match groups.iter_mut().find(|(f, _)| *f == filter) {
            Some((_, v)) => v.push(i),
            None => groups.push((filter, vec![i])),
        }
    }
    let mut jobs = Vec::new();
    for (filter, mut group) in groups {
        push_jobs(items, &mut group, filter, opts.solid_limit, &mut jobs);
    }
    jobs
}

/// Encodes every job into `out`, in job order. Non-solid jobs are compressed concurrently in
/// batches; large jobs get the multithreaded encoder. Returns the folders and the number of
/// threads used.
pub(crate) fn encode_jobs<W: Write>(
    jobs: &[Job],
    items: &[Item],
    opts: &CreateOptions,
    aes_key: Option<&[u8; 32]>,
    progress: &dyn Progress,
    out: &mut W,
) -> Result<(Vec<FolderResult>, usize)> {
    let threads = opts.threads.max(1);
    let mut results: Vec<FolderResult> = Vec::with_capacity(jobs.len());
    let mut threads_used = 1usize;
    if opts.solid_limit.is_none() && jobs.len() > 1 {
        // Non-solid: many small folders. Compress batches of them concurrently into memory,
        // then append in order. Large files use the multithreaded encoder.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| Error::Other(e.to_string()))?;
        let big = 32u64 << 20;
        let batch_limit = (256u64 << 20).max(big * threads as u64);
        let mut i = 0;
        while i < jobs.len() {
            if jobs[i].total >= big {
                results.push(encode_folder(
                    &jobs[i],
                    items,
                    opts,
                    aes_key,
                    threads,
                    out,
                    progress,
                    Feed::Disk,
                )?);
                threads_used = threads_used.max(threads);
                i += 1;
                continue;
            }
            let start = i;
            let mut acc = 0u64;
            while i < jobs.len()
                && jobs[i].total < big
                && (acc == 0 || acc + jobs[i].total <= batch_limit)
            {
                acc += jobs[i].total;
                i += 1;
            }
            let batch: Vec<Result<(Vec<u8>, FolderResult)>> = pool.install(|| {
                jobs[start..i]
                    .par_iter()
                    .map(|job| {
                        let mut buf = Vec::with_capacity((job.total / 2) as usize + 64);
                        let r = encode_folder(
                            job,
                            items,
                            opts,
                            aes_key,
                            1,
                            &mut buf,
                            progress,
                            Feed::Disk,
                        )?;
                        Ok((buf, r))
                    })
                    .collect()
            });
            threads_used = threads_used.max(threads.min(i - start));
            for r in batch {
                let (buf, fr) = r?;
                out.write_all(&buf)?;
                results.push(fr);
            }
        }
    } else {
        for job in jobs {
            results.push(encode_folder(
                job,
                items,
                opts,
                aes_key,
                threads,
                out,
                progress,
                Feed::Disk,
            )?);
        }
        threads_used = threads;
    }
    Ok((results, threads_used))
}

/// The branch converter for an executable image, from its header (reads at most 4 KiB).
fn file_branch(path: &Path) -> Option<Branch> {
    let mut head = Vec::with_capacity(4096);
    File::open(path)
        .ok()?
        .take(4096)
        .read_to_end(&mut head)
        .ok()?;
    crate::codec::branch_for_image(&head)
}

/// Creates `archive` from `items`. Writes to a temporary file and renames it into place.
pub fn create(
    archive: &Path,
    items: &[Item],
    opts: &CreateOptions,
    progress: &dyn Progress,
) -> Result<Summary> {
    let aes_key = match &opts.password {
        Some(p) => Some(derive_key(p, &[], DEFAULT_CYCLES_POWER)?),
        None => None,
    };

    let mut empty_items: Vec<usize> = Vec::new();
    let mut stream_items: Vec<usize> = Vec::new();
    for (i, it) in items.iter().enumerate() {
        if it.is_dir || it.size == 0 {
            empty_items.push(i);
        } else {
            stream_items.push(i);
        }
    }
    let branches = branches_for(items, opts);
    let jobs = plan_jobs(items, &stream_items, &branches, opts);

    let tmp_path = temp_path(archive);
    let file = File::create(&tmp_path)
        .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp_path.display())))?;
    let result = (|| -> Result<Summary> {
        let mut out = BufWriter::with_capacity(1 << 20, file);
        out.write_all(&[0u8; SIGNATURE_HEADER_SIZE as usize])?;

        let (results, threads_used) =
            encode_jobs(&jobs, items, opts, aes_key.as_ref(), progress, &mut out)?;

        // Assemble metadata: empty entries first, then streams in folder order.
        let mut entries: Vec<Entry> = Vec::new();
        let mut si = StreamsInfo::default();
        let mut summary = Summary {
            threads_used,
            ..Default::default()
        };
        let mut sorted_empty = empty_items.clone();
        sorted_empty.sort_by(|&a, &b| items[a].name.cmp(&items[b].name));
        for &i in &sorted_empty {
            let it = &items[i];
            entries.push(make_entry(it, opts, false, 0, None));
            if it.is_dir {
                summary.dirs += 1;
            } else {
                summary.files += 1;
            }
        }
        for fr in results {
            // A folder whose files all vanished keeps zero substreams so pack offsets stay valid.
            for &(i, n, crc) in &fr.streams {
                entries.push(make_entry(&items[i], opts, n > 0, n, Some(crc)));
                si.substream_sizes.push(n);
                si.substream_crcs.push(Some(crc));
                summary.files += 1;
                summary.input_bytes += n;
            }
            si.num_unpack_streams.push(fr.streams.len());
            si.pack_sizes.extend(fr.pack_sizes);
            si.folders.push(fr.folder);
        }
        summary.skipped = (stream_items.len() as u64 + empty_items.len() as u64)
            .saturating_sub(summary.files + summary.dirs);
        let data_end = out.stream_position()?;
        if si.pack_sizes.iter().sum::<u64>() + SIGNATURE_HEADER_SIZE != data_end {
            return Err(Error::Other(
                "internal error: pack stream sizes do not match output".into(),
            ));
        }
        summary.folders = si.folders.len();

        finish_archive(&mut out, &si, &entries, data_end, opts, aes_key.as_ref())?;
        let f = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        summary.archive_bytes = f.metadata()?.len();
        f.sync_all().ok();
        Ok(summary)
    })();

    match result {
        Ok(s) => {
            if archive.exists() {
                std::fs::remove_file(archive)?;
            }
            std::fs::rename(&tmp_path, archive)?;
            Ok(s)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Writes the header for `si` and `entries` after the pack streams, which end at `data_end`,
/// then the signature header at the start of the file. The header is encrypted with
/// `aes_key` when `opts.encrypt_header` is set. An archive with no entries gets no header.
pub(crate) fn finish_archive(
    out: &mut BufWriter<File>,
    si: &StreamsInfo,
    entries: &[Entry],
    data_end: u64,
    opts: &CreateOptions,
    aes_key: Option<&[u8; 32]>,
) -> Result<()> {
    if entries.is_empty() && si.folders.is_empty() {
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&signature_header(0, 0, 0))?;
        out.flush()?;
        return Ok(());
    }
    let header = write_header(si, entries);
    let (next_off, block) = if opts.compress_header || (opts.encrypt_header && aes_key.is_some()) {
        let header_key = if opts.encrypt_header { aes_key } else { None };
        encode_header(&header, header_key, opts.compress_header, data_end, out)?
    } else {
        (data_end - SIGNATURE_HEADER_SIZE, header)
    };
    out.write_all(&block)?;
    let sig = signature_header(next_off, block.len() as u64, crc32fast::hash(&block));
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&sig)?;
    out.flush()?;
    Ok(())
}

/// Writes the header as its own packed stream and returns the `kEncodedHeader` block.
pub(crate) fn encode_header<W: Write>(
    header: &[u8],
    key: Option<&[u8; 32]>,
    compress: bool,
    data_end: u64,
    out: &mut W,
) -> Result<(u64, Vec<u8>)> {
    let mut methods = Vec::new();
    if compress {
        let mut lz = LzmaOptions::with_preset(6);
        lz.dict_size = (header.len() as u32)
            .next_power_of_two()
            .clamp(1 << 16, 1 << 24);
        lz.nice_len = 64;
        methods.push(EncMethod::Lzma(lz));
    }
    if let Some(k) = key {
        methods.push(EncMethod::Aes {
            key: *k,
            props: AesProps {
                cycles_power: DEFAULT_CYCLES_POWER,
                salt: Vec::new(),
                iv: random_iv(),
            },
        });
    }
    let mut enc = FolderEncoder::new(&methods, out)?;
    enc.write_all(header).map_err(Error::from_codec)?;
    let done = enc.finish()?;
    let (mut folder, pack_size) = (done.folder, done.pack_sizes[0]);
    folder.crc = Some(crc32fast::hash(header));
    let si = StreamsInfo {
        pack_pos: data_end - SIGNATURE_HEADER_SIZE,
        pack_sizes: vec![pack_size],
        pack_crcs: vec![None],
        folders: vec![folder],
        ..Default::default()
    };
    Ok((
        data_end + pack_size - SIGNATURE_HEADER_SIZE,
        write_encoded_header(&si),
    ))
}

pub(crate) fn make_entry(
    it: &Item,
    opts: &CreateOptions,
    has_stream: bool,
    size: u64,
    crc: Option<u32>,
) -> Entry {
    Entry {
        name: it.name.clone(),
        has_stream,
        is_dir: it.is_dir,
        is_anti: false,
        size,
        crc: if has_stream { crc } else { None },
        mtime: if opts.store_mtime { it.mtime } else { None },
        ctime: if opts.store_ctime { it.ctime } else { None },
        atime: if opts.store_atime { it.atime } else { None },
        attrib: it.attrib,
        folder: None,
    }
}

/// The temporary file `archive` is written to before it is renamed into place. It is
/// removed if the console ends r7z first.
pub fn temp_path(archive: &Path) -> TempFile {
    let mut name = archive
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".r7z-tmp-{}", std::process::id()));
    TempFile::new(archive.with_file_name(name))
}
