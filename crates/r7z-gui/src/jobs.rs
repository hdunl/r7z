//! Work off the UI thread.
//!
//! *Jobs* (extract, test, create, batch, convert) run one at a time and report progress
//! through `Shared`. *Tasks* (previews, opening archives, hashing) are small, independent
//! and cancellable, so browsing stays responsive while a job runs. Both turn panics into
//! errors instead of taking the app down.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;
use r7z::error::{Error, Result};
use r7z::format::write::{self, Kind, WriteOptions};
use r7z::format::{self, Archive, CodePage, OpenRequest, Opened};
use r7z::ops::create::{self, default_solid_limit, CreateOptions, MainMethod, Progress, Summary};
use r7z::ops::extract::{
    self, Callbacks, ExtractOptions, Overwrite, OverwriteAnswer, Report, Target,
};

fn panic_message(p: Box<dyn Any + Send>) -> Error {
    let msg = p
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown failure".into());
    Error::Other(format!("internal error: {msg}"))
}

fn guarded<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|p| Err(panic_message(p)))
}

pub fn threads() -> usize {
    r7z::util::default_threads()
}

// ------------------------------------------------------------------ tasks

pub struct Task<T> {
    handle: Option<JoinHandle<Result<T>>>,
    cancel: Arc<AtomicBool>,
}

impl<T: Send + 'static> Task<T> {
    pub fn spawn(
        ctx: &egui::Context,
        f: impl FnOnce(&AtomicBool) -> Result<T> + Send + 'static,
    ) -> Task<T> {
        let cancel = Arc::new(AtomicBool::new(false));
        let c = cancel.clone();
        let ctx = ctx.clone();
        let handle = std::thread::spawn(move || {
            let r = guarded(|| f(&c));
            ctx.request_repaint();
            r
        });
        Task {
            handle: Some(handle),
            cancel,
        }
    }

    pub fn ready(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| h.is_finished())
    }

    pub fn take(&mut self) -> Option<Result<T>> {
        if !self.ready() {
            return None;
        }
        self.handle
            .take()
            .map(|h| h.join().unwrap_or_else(|p| Err(panic_message(p))))
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// `code_page` decodes names the archive does not mark as Unicode; `None` detects it.
pub fn open_disk(
    ctx: &egui::Context,
    path: PathBuf,
    password: Option<String>,
    code_page: Option<CodePage>,
) -> Task<Opened> {
    Task::spawn(ctx, move |_| {
        format::open(
            &path,
            &OpenRequest {
                password,
                code_page,
                ..Default::default()
            },
        )
    })
}

/// Opens `path` as `format`, whatever its content suggests ("Open as archive").
pub fn open_disk_as(
    ctx: &egui::Context,
    path: PathBuf,
    format: &'static r7z::format::Format,
) -> Task<Opened> {
    Task::spawn(ctx, move |_| {
        format::open(
            &path,
            &OpenRequest {
                format: Some(format),
                ..Default::default()
            },
        )
    })
}

pub fn open_nested(
    ctx: &egui::Context,
    parent: Arc<dyn Archive>,
    entry: usize,
    name: String,
    password: Option<String>,
    code_page: Option<CodePage>,
) -> Task<Opened> {
    Task::spawn(ctx, move |cancel| {
        // A disk image or partition is opened where it lies: copying it out would read the
        // whole disk into memory first.
        if let Some(src) = parent.volume(entry) {
            let req = OpenRequest {
                password,
                code_page,
                ..Default::default()
            };
            return format::open_volume(src, &name, &req);
        }
        let peeked =
            r7z::ops::peek::read_entry(&*parent, entry, password.as_deref(), 4 << 30, &|| {
                cancel.load(Ordering::Relaxed)
            })?;
        format::open_bytes(
            peeked.data,
            &name,
            &OpenRequest {
                password,
                code_page,
                ..Default::default()
            },
        )
    })
}

/// Extracts one entry to `dir` and returns the file's path (the UI thread launches it).
pub fn stage_entry(
    ctx: &egui::Context,
    archive: Arc<dyn Archive>,
    password: Option<String>,
    entry: usize,
    dir: PathBuf,
) -> Task<PathBuf> {
    Task::spawn(ctx, move |cancel| {
        let name = archive.entries()[entry].name.clone();
        let base = name.rsplit(['/', '\\']).next().unwrap_or(&name).to_string();
        let safe =
            r7z::ops::extract::safe_relative_path(&base).unwrap_or_else(|| PathBuf::from("file"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(safe.file_name().unwrap_or_default());
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path)?);
        r7z::ops::peek::stream_entry(
            &*archive,
            entry,
            password.as_deref(),
            &|| cancel.load(Ordering::Relaxed),
            &mut |b| std::io::Write::write_all(&mut out, b).map_err(Error::from),
        )?;
        std::io::Write::flush(&mut out)?;
        Ok(path)
    })
}

// ------------------------------------------------------------------ jobs

pub struct Shared {
    pub total: AtomicU64,
    pub done: AtomicU64,
    pub cancel: AtomicBool,
    pub current: Mutex<String>,
    pub phase: Mutex<String>,
    pub warnings: Mutex<Vec<String>>,
    pub prompt: Mutex<Option<PathBuf>>,
    /// Set by extract jobs that wrote something: the id of their undo record.
    pub undo: Mutex<Option<String>>,
    answer: Mutex<Option<OverwriteAnswer>>,
    cv: Condvar,
    pub started: Instant,
    ctx: egui::Context,
}

impl Shared {
    fn new(ctx: &egui::Context, total: u64) -> Arc<Self> {
        Arc::new(Shared {
            total: AtomicU64::new(total),
            done: AtomicU64::new(0),
            cancel: AtomicBool::new(false),
            current: Mutex::new(String::new()),
            phase: Mutex::new(String::new()),
            warnings: Mutex::new(Vec::new()),
            prompt: Mutex::new(None),
            undo: Mutex::new(None),
            answer: Mutex::new(None),
            cv: Condvar::new(),
            started: Instant::now(),
            ctx: ctx.clone(),
        })
    }

    pub fn fraction(&self) -> f32 {
        let t = self.total.load(Ordering::Relaxed);
        if t == 0 {
            return 0.0;
        }
        (self.done.load(Ordering::Relaxed) as f64 / t as f64).min(1.0) as f32
    }

    pub fn answer(&self, a: OverwriteAnswer) {
        *self.answer.lock().unwrap() = Some(a);
        self.cv.notify_all();
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.cv.notify_all();
    }

    fn set_phase(&self, s: String) {
        *self.phase.lock().unwrap() = s;
        self.ctx.request_repaint();
    }
}

struct Cb(Arc<Shared>);

impl Callbacks for Cb {
    fn add(&self, bytes: u64) {
        self.0.done.fetch_add(bytes, Ordering::Relaxed);
    }
    fn confirm_overwrite(&self, path: &Path) -> OverwriteAnswer {
        *self.0.prompt.lock().unwrap() = Some(path.to_path_buf());
        self.0.ctx.request_repaint();
        let mut ans = self.0.answer.lock().unwrap();
        loop {
            if let Some(a) = ans.take() {
                *self.0.prompt.lock().unwrap() = None;
                return a;
            }
            if self.0.cancel.load(Ordering::Relaxed) {
                *self.0.prompt.lock().unwrap() = None;
                return OverwriteAnswer::Quit;
            }
            ans = self
                .0
                .cv
                .wait_timeout(ans, Duration::from_millis(200))
                .unwrap()
                .0;
        }
    }
    fn file_done(&self, name: &str) {
        if let Ok(mut c) = self.0.current.try_lock() {
            c.clear();
            c.push_str(name);
        }
    }
    fn cancelled(&self) -> bool {
        self.0.cancel.load(Ordering::Relaxed)
    }
}

/// Passes an extract's callbacks through and records what it writes, for undo.
struct Tracked<'a, C> {
    inner: C,
    rec: &'a crate::undo::Recorder,
}

impl<C: Callbacks> Callbacks for Tracked<'_, C> {
    fn add(&self, bytes: u64) {
        self.inner.add(bytes)
    }
    fn confirm_overwrite(&self, path: &Path) -> OverwriteAnswer {
        self.inner.confirm_overwrite(path)
    }
    fn file_done(&self, name: &str) {
        self.inner.file_done(name)
    }
    fn will_write(&self, path: &Path, dir: bool, existed: bool) -> Result<()> {
        self.rec.will_write(path, dir, existed)
    }
    fn cancelled(&self) -> bool {
        self.inner.cancelled()
    }
}

impl Progress for Cb {
    fn add(&self, bytes: u64) {
        self.0.done.fetch_add(bytes, Ordering::Relaxed);
    }
    fn warn(&self, msg: &str) {
        self.0.warnings.lock().unwrap().push(msg.to_string());
    }
    fn cancelled(&self) -> bool {
        self.0.cancel.load(Ordering::Relaxed)
    }
}

pub enum Outcome {
    Extracted {
        report: Report,
        dest: PathBuf,
    },
    Tested(Report),
    Recovered {
        report: r7z::ops::recover::RecoverReport,
        dest: PathBuf,
        name: String,
    },
    Created {
        summary: Summary,
        path: PathBuf,
    },
    Batch {
        done: Vec<(PathBuf, PathBuf)>,
        failed: Vec<(PathBuf, String)>,
        files: u64,
        bytes: u64,
    },
    Undone(crate::undo::UndoReport),
    /// Files extracted to a scratch folder for a drag or the clipboard.
    Staged {
        report: Report,
        paths: Vec<PathBuf>,
        clipboard: Option<u32>,
        /// The drag ended without a drop, so the work was dropped too.
        aborted: bool,
    },
}

pub struct Job {
    pub title: String,
    pub verb: &'static str,
    pub shared: Arc<Shared>,
    handle: Option<JoinHandle<Result<Outcome>>>,
}

impl Job {
    fn spawn(
        ctx: &egui::Context,
        title: String,
        verb: &'static str,
        total: u64,
        f: impl FnOnce(Arc<Shared>) -> Result<Outcome> + Send + 'static,
    ) -> Job {
        let shared = Shared::new(ctx, total);
        let s = shared.clone();
        let ctx = ctx.clone();
        let handle = std::thread::spawn(move || {
            let r = guarded(|| f(s));
            ctx.request_repaint();
            r
        });
        Job {
            title,
            verb,
            shared,
            handle: Some(handle),
        }
    }

    pub fn finished(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| h.is_finished())
    }

    pub fn join(&mut self) -> Result<Outcome> {
        match self.handle.take().map(|h| h.join()) {
            Some(Ok(r)) => r,
            Some(Err(p)) => Err(panic_message(p)),
            None => Err(Error::Other("job already collected".into())),
        }
    }
}

pub struct ExtractRequest {
    pub archive: Arc<dyn Archive>,
    pub password: Option<String>,
    pub selected: Option<Vec<bool>>,
    pub base: Option<String>,
    pub dest: PathBuf,
    pub full_paths: bool,
    pub overwrite: Overwrite,
    pub total: u64,
}

pub fn extract(ctx: &egui::Context, title: String, req: ExtractRequest) -> Job {
    Job::spawn(ctx, title.clone(), "Extracting", req.total, move |s| {
        let what = title.strip_prefix("Extracting ").unwrap_or(&title);
        let label = format!("{what} into {}", req.dest.display());
        let rec = crate::undo::Recorder::new(crate::undo::Store::user(), &label, &req.dest);
        rec.note_dir(&req.dest);
        let result = std::fs::create_dir_all(&req.dest)
            .map_err(Error::from)
            .and_then(|_| {
                let opts = ExtractOptions {
                    base: req.base,
                    password: req.password,
                    threads: threads(),
                    target: Target::Disk {
                        dir: req.dest.clone(),
                        full_paths: req.full_paths,
                        overwrite: req.overwrite,
                    },
                    selected: req.selected,
                };
                let cb = Tracked {
                    inner: Cb(s.clone()),
                    rec: &rec,
                };
                extract::extract(&*req.archive, &opts, &cb)
            });
        *s.undo.lock().unwrap() = rec.finish();
        let report = result?;
        Ok(Outcome::Extracted {
            report,
            dest: req.dest,
        })
    })
}

pub struct StageRequest {
    pub extract: ExtractRequest,
    /// The top-level paths the selection lands on inside `extract.dest`.
    pub paths: Vec<PathBuf>,
    /// Clipboard sequence number when Copy was chosen; `None` for a drag.
    pub clipboard: Option<u32>,
    /// Set when the drag ends without a drop.
    pub abort: Arc<AtomicBool>,
    /// Told when every file is written, so a waiting drop can go ahead.
    pub ready: mpsc::Sender<()>,
}

/// Extracts a selection into a scratch folder so it can be dropped or pasted elsewhere.
pub fn stage(ctx: &egui::Context, title: String, req: StageRequest) -> Job {
    let StageRequest {
        extract: x,
        paths,
        clipboard,
        abort,
        ready,
    } = req;
    Job::spawn(ctx, title, "Extracting", x.total, move |s| {
        let aborted = Outcome::Staged {
            report: Report::default(),
            paths: Vec::new(),
            clipboard,
            aborted: true,
        };
        if abort.load(Ordering::Relaxed) {
            return Ok(aborted);
        }
        let dest = x.dest.clone();
        std::fs::create_dir_all(&dest)?;
        let opts = ExtractOptions {
            base: x.base,
            password: x.password,
            threads: threads(),
            target: Target::Disk {
                dir: x.dest,
                full_paths: true,
                overwrite: Overwrite::All,
            },
            selected: x.selected,
        };
        let cb = StageCb {
            inner: Cb(s),
            abort: abort.clone(),
        };
        let result = extract::extract(&*x.archive, &opts, &cb);
        if abort.load(Ordering::Relaxed) {
            let _ = std::fs::remove_dir_all(&dest);
            return Ok(aborted);
        }
        match result {
            Err(e) => Err(e),
            Ok(report) => {
                if report.errors.is_empty() {
                    let _ = ready.send(());
                }
                Ok(Outcome::Staged {
                    report,
                    paths,
                    clipboard,
                    aborted: false,
                })
            }
        }
    })
}

struct StageCb {
    inner: Cb,
    abort: Arc<AtomicBool>,
}

impl Callbacks for StageCb {
    fn add(&self, bytes: u64) {
        Callbacks::add(&self.inner, bytes)
    }
    fn file_done(&self, name: &str) {
        self.inner.file_done(name)
    }
    fn cancelled(&self) -> bool {
        Callbacks::cancelled(&self.inner) || self.abort.load(Ordering::Relaxed)
    }
}

pub fn test(
    ctx: &egui::Context,
    title: String,
    archive: Arc<dyn Archive>,
    password: Option<String>,
    total: u64,
) -> Job {
    Job::spawn(ctx, title, "Testing", total, move |s| {
        let opts = ExtractOptions {
            base: None,
            password,
            threads: threads(),
            target: Target::Test,
            selected: None,
        };
        Ok(Outcome::Tested(extract::extract(&*archive, &opts, &Cb(s))?))
    })
}

/// Reopens the archive at `path` in recovery mode and extracts what is readable into
/// `dest`. Progress is measured against the archive's size, since a damaged archive's
/// unpacked total is not known up front.
pub fn recover(ctx: &egui::Context, path: PathBuf, password: Option<String>, dest: PathBuf) -> Job {
    let total = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let name = file_name(&path);
    let title = format!("Recovering {name}");
    Job::spawn(ctx, title, "Recovery", total, move |s| {
        let opts = ExtractOptions {
            base: None,
            password: password.clone(),
            threads: threads(),
            target: Target::Disk {
                dir: dest.clone(),
                full_paths: true,
                overwrite: Overwrite::RenameNew,
            },
            selected: None,
        };
        let report = r7z::ops::recover::recover_file(
            &path,
            password,
            &opts,
            r7z::ops::recover::RecoverOptions::default(),
            &Cb(s),
        )?;
        Ok(Outcome::Recovered { report, dest, name })
    })
}

/// Where "Extract here" puts an archive's contents: straight next to the archive when it
/// holds a single top-level item, otherwise in a new folder named after the archive.
pub fn smart_destination(entries: &[r7z::format::Entry], archive: &Path) -> PathBuf {
    let parent = archive.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut roots = std::collections::HashSet::new();
    for e in entries.iter().filter(|e| !e.is_anti) {
        let norm = e.name.replace('\\', "/");
        if let Some(first) = norm
            .split('/')
            .find(|p| !p.is_empty() && *p != "." && *p != "..")
        {
            roots.insert(first.to_lowercase());
        }
        if roots.len() > 1 {
            break;
        }
    }
    if roots.len() == 1 {
        return parent;
    }
    let stem = crate::app::stem_of(archive);
    let mut dest = parent.join(&stem);
    let mut n = 2;
    while dest.exists()
        && std::fs::read_dir(&dest)
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        dest = parent.join(format!("{stem} ({n})"));
        n += 1;
    }
    dest
}

pub enum BatchDest {
    Smart,
    Into(PathBuf),
}

pub fn batch_extract(
    ctx: &egui::Context,
    archives: Vec<PathBuf>,
    dest: BatchDest,
    overwrite: Overwrite,
    password: Option<String>,
) -> Job {
    let total: u64 = archives
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    let title = format!("Extracting {} archives", archives.len());
    let what = match archives.as_slice() {
        [one] => file_name(one),
        _ => format!("{} archives", archives.len()),
    };
    let (label, undo_dest) = match &dest {
        BatchDest::Into(d) => (format!("{what} into {}", d.display()), d.clone()),
        BatchDest::Smart => {
            let parent = archives
                .first()
                .and_then(|p| p.parent())
                .map(Path::to_path_buf)
                .unwrap_or_default();
            (format!("{what} in {}", parent.display()), parent)
        }
    };
    Job::spawn(ctx, title, "Extracting", total, move |s| {
        let rec = crate::undo::Recorder::new(crate::undo::Store::user(), &label, &undo_dest);
        let result = batch_run(&s, &rec, archives, &dest, overwrite, password);
        *s.undo.lock().unwrap() = rec.finish();
        result
    })
}

fn batch_run(
    s: &Arc<Shared>,
    rec: &crate::undo::Recorder,
    archives: Vec<PathBuf>,
    dest: &BatchDest,
    overwrite: Overwrite,
    password: Option<String>,
) -> Result<Outcome> {
    let (mut done, mut failed) = (Vec::new(), Vec::new());
    let (mut files, mut bytes) = (0u64, 0u64);
    let count = archives.len();
    for (k, path) in archives.into_iter().enumerate() {
        if s.cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        s.set_phase(format!("{} of {count} · {}", k + 1, file_name(&path)));
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let base_done = s.done.load(Ordering::Relaxed);
        let result = (|| -> Result<(PathBuf, Report)> {
            let opened = format::open(
                &path,
                &OpenRequest {
                    password: password.clone(),
                    ..Default::default()
                },
            )?;
            let a = opened.arc();
            let target = match dest {
                BatchDest::Smart => smart_destination(a.entries(), &path),
                BatchDest::Into(d) => d.join(crate::app::stem_of(&path)),
            };
            rec.note_dir(&target);
            std::fs::create_dir_all(&target)?;
            let unpacked: u64 = a
                .entries()
                .iter()
                .map(|e| e.size_or_zero())
                .sum::<u64>()
                .max(1);
            let scaled = Tracked {
                inner: ScaledCb {
                    inner: Cb(s.clone()),
                    num: size,
                    den: unpacked,
                },
                rec,
            };
            let opts = ExtractOptions {
                base: None,
                password: password.clone(),
                threads: threads(),
                target: Target::Disk {
                    dir: target.clone(),
                    full_paths: true,
                    overwrite,
                },
                selected: None,
            };
            let rep = extract::extract(&*a, &opts, &scaled)?;
            Ok((target, rep))
        })();
        s.done.store(base_done + size, Ordering::Relaxed);
        match result {
            Ok((target, rep)) if rep.errors.is_empty() => {
                files += rep.files;
                bytes += rep.bytes;
                done.push((path, target));
            }
            Ok((_, rep)) => {
                let first = rep
                    .errors
                    .first()
                    .map(|(n, e)| format!("{n}: {e}"))
                    .unwrap_or_default();
                failed.push((path, format!("{} errors, first: {first}", rep.errors.len())));
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(e) => failed.push((path, e.to_string())),
        }
    }
    Ok(Outcome::Batch {
        done,
        failed,
        files,
        bytes,
    })
}

/// Reverses the extract recorded as `id` (see `undo`).
pub fn undo(ctx: &egui::Context, id: String) -> Job {
    Job::spawn(ctx, "Undoing extract".into(), "Undo", 0, move |_| {
        let store = crate::undo::Store::user()
            .ok_or_else(|| Error::Other("there is no settings folder to read from".into()))?;
        Ok(Outcome::Undone(crate::undo::undo(&store, &id)?))
    })
}

/// Reports extraction progress in another unit (archive bytes instead of file bytes).
struct ScaledCb {
    inner: Cb,
    num: u64,
    den: u64,
}

impl Callbacks for ScaledCb {
    fn add(&self, bytes: u64) {
        let v = (bytes as u128 * self.num as u128 / self.den as u128) as u64;
        self.inner.0.done.fetch_add(v, Ordering::Relaxed);
    }
    fn confirm_overwrite(&self, path: &Path) -> OverwriteAnswer {
        self.inner.confirm_overwrite(path)
    }
    fn file_done(&self, name: &str) {
        self.inner.file_done(name)
    }
    fn cancelled(&self) -> bool {
        Callbacks::cancelled(&self.inner)
    }
}

#[derive(Clone)]
pub struct CreateRequest {
    pub paths: Vec<PathBuf>,
    pub archive: PathBuf,
    pub level: u32,
    pub password: Option<String>,
    pub encrypt_names: bool,
    pub solid: bool,
}

fn write_archive(
    s: &Arc<Shared>,
    req: &CreateRequest,
    items: &[r7z::ops::create::Item],
) -> Result<Summary> {
    let kind = write::kind_for(&req.archive, None)?;
    let cb = Cb(s.clone());
    if kind == Kind::SevenZ {
        let opts = CreateOptions {
            level: req.level.max(1),
            method: if req.level == 0 {
                MainMethod::Copy
            } else {
                MainMethod::Lzma2
            },
            threads: threads(),
            solid_limit: if req.solid {
                Some(default_solid_limit(req.level))
            } else {
                None
            },
            password: req.password.clone(),
            encrypt_header: req.encrypt_names && req.password.is_some(),
            ..Default::default()
        };
        create::create(&req.archive, items, &opts, &cb)
    } else {
        let opts = WriteOptions {
            level: req.level,
            threads: threads(),
            password: if kind == Kind::Zip {
                req.password.clone()
            } else {
                None
            },
            store: req.level == 0,
            zstd: false,
            store_mtime: true,
            store_ctime: false,
            store_atime: false,
        };
        write::create(&req.archive, kind, items, &opts, &cb)
    }
}

pub fn create(ctx: &egui::Context, req: CreateRequest) -> Job {
    let title = format!("Creating {}", file_name(&req.archive));
    Job::spawn(ctx, title, "Compressing", 0, move |s| {
        s.set_phase("Scanning files".into());
        let names: Vec<String> = req
            .paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let scan = r7z::ops::scan::scan(&names, false, &[], &req.archive);
        s.warnings.lock().unwrap().extend(scan.warnings);
        if scan.items.is_empty() {
            return Err(Error::Other("there is nothing to add".into()));
        }
        s.total
            .store(scan.items.iter().map(|i| i.size).sum(), Ordering::Relaxed);
        s.set_phase(String::new());
        let summary = write_archive(&s, &req, &scan.items)?;
        Ok(Outcome::Created {
            summary,
            path: req.archive,
        })
    })
}

/// Repacks an archive into another format by way of a scratch folder.
pub fn convert(
    ctx: &egui::Context,
    archive: Arc<dyn Archive>,
    password: Option<String>,
    req: CreateRequest,
    scratch: PathBuf,
) -> Job {
    let unpacked: u64 = archive.entries().iter().map(|e| e.size_or_zero()).sum();
    let title = format!("Converting to {}", file_name(&req.archive));
    Job::spawn(ctx, title, "Converting", unpacked * 2, move |s| {
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch)?;
        let result = (|| {
            s.set_phase("Unpacking".into());
            let opts = ExtractOptions {
                base: None,
                password,
                threads: threads(),
                target: Target::Disk {
                    dir: scratch.clone(),
                    full_paths: true,
                    overwrite: Overwrite::All,
                },
                selected: None,
            };
            let rep = extract::extract(&*archive, &opts, &Cb(s.clone()))?;
            if let Some((n, e)) = rep.errors.into_iter().next() {
                return Err(Error::Other(format!("{n}: {e}")));
            }
            s.set_phase("Packing".into());
            let names: Vec<String> = std::fs::read_dir(&scratch)?
                .filter_map(|e| e.ok())
                .map(|e| e.path().to_string_lossy().into_owned())
                .collect();
            let scan = r7z::ops::scan::scan(&names, false, &[], &req.archive);
            let summary = write_archive(&s, &req, &scan.items)?;
            Ok(Outcome::Created {
                summary,
                path: req.archive.clone(),
            })
        })();
        let _ = std::fs::remove_dir_all(&scratch);
        result
    })
}

pub fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}
