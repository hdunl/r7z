//! Undo for extraction.
//!
//! Each extract job keeps a manifest of what it wrote: the folders and files it created,
//! and the files it replaced. A file about to be replaced is first moved into a backup
//! folder instead of being overwritten in place. Undo then:
//!
//! - deletes each created file, but only while its size and modification time are still
//!   the ones it was written with (anything changed since is left alone),
//! - puts every backup back (beside the file instead, when that file was changed),
//! - removes the created folders that are empty.
//!
//! The manifest is written as a journal while the job plans its writes, so a backup is on
//! record before its file is moved, even if the app dies halfway. When the job ends it is
//! rewritten whole, with the size and time of everything written.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use r7z::error::{Error, Result};

/// How many finished extracts can still be undone.
pub const KEEP: usize = 5;

const HEADER: &str = "r7z undo 1";
/// A manifest still marked running after this long was left by an app that died.
const STALE_SECS: u64 = 12 * 3600;

/// Where manifests and backups live.
#[derive(Clone, Debug)]
pub struct Store {
    pub manifests: PathBuf,
    pub backups: PathBuf,
}

impl Store {
    pub fn user() -> Option<Store> {
        Some(Store {
            manifests: crate::shell::config_dir()?.join("undo"),
            backups: crate::shell::undo_backups(),
        })
    }

    fn manifest(&self, id: &str) -> PathBuf {
        self.manifests.join(format!("{id}.txt"))
    }

    fn backup_dir(&self, id: &str) -> PathBuf {
        self.backups.join(id)
    }

    /// Manifest ids, newest first.
    fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = fs::read_dir(&self.manifests)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let name = e.file_name().into_string().ok()?;
                        name.strip_suffix(".txt").map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        ids.sort_by(|a, b| b.cmp(a));
        ids
    }

    fn forget(&self, id: &str) {
        let _ = fs::remove_file(self.manifest(id));
        let _ = fs::remove_dir_all(self.backup_dir(id));
    }
}

/// Size and modification time of a file, as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub size: u64,
    /// Nanoseconds from the Unix epoch (negative before it).
    pub mtime: i128,
}

enum Probe {
    Missing,
    File(Stamp),
    /// A folder, or something that can't be read.
    Other,
}

fn probe(p: &Path) -> Probe {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Probe::Missing,
        Err(_) => Probe::Other,
        Ok(m) if m.is_dir() => Probe::Other,
        Ok(m) => match m.modified() {
            Ok(t) => Probe::File(Stamp {
                size: m.len(),
                mtime: nanos(t),
            }),
            Err(_) => Probe::Other,
        },
    }
}

fn nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

fn stamp_of(p: &Path) -> Option<Stamp> {
    match probe(p) {
        Probe::File(s) => Some(s),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Replaced {
    pub path: PathBuf,
    /// File name inside the job's backup folder.
    pub backup: String,
    /// What the extract wrote over it; `None` if it never finished.
    pub written: Option<Stamp>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Manifest {
    pub id: String,
    pub title: String,
    pub dest: PathBuf,
    /// Unix seconds when the job started.
    pub time: u64,
    pub pid: u32,
    pub finished: bool,
    pub dirs: Vec<PathBuf>,
    pub created: Vec<(PathBuf, Option<Stamp>)>,
    pub replaced: Vec<Replaced>,
}

/// Manifests are tab-separated lines. Tabs and line breaks can't appear in Windows file
/// names; a path that has them, or isn't valid Unicode, is not tracked.
fn line_path(p: &Path) -> Option<&str> {
    p.to_str().filter(|s| !s.contains(['\t', '\n', '\r']))
}

fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn stamp_fields(s: Option<Stamp>) -> String {
    match s {
        Some(s) => format!("{}\t{}", s.size, s.mtime),
        None => "-\t-".into(),
    }
}

fn header_text(m: &Manifest) -> String {
    format!(
        "{HEADER}\ntitle\t{}\ndest\t{}\ntime\t{}\npid\t{}\nstate\t{}\n",
        one_line(&m.title),
        one_line(&m.dest.to_string_lossy()),
        m.time,
        m.pid,
        if m.finished { "done" } else { "running" }
    )
}

fn dir_line(p: &str) -> String {
    format!("dir\t{p}\n")
}

fn new_line(p: &str, s: Option<Stamp>) -> String {
    format!("new\t{}\t{p}\n", stamp_fields(s))
}

fn old_line(r: &Replaced, p: &str) -> String {
    format!("old\t{}\t{}\t{p}\n", r.backup, stamp_fields(r.written))
}

impl Manifest {
    pub fn to_text(&self) -> String {
        let mut s = header_text(self);
        for d in &self.dirs {
            if let Some(p) = line_path(d) {
                s.push_str(&dir_line(p));
            }
        }
        for (f, st) in &self.created {
            if let Some(p) = line_path(f) {
                s.push_str(&new_line(p, *st));
            }
        }
        for r in &self.replaced {
            if let Some(p) = line_path(&r.path) {
                s.push_str(&old_line(r, p));
            }
        }
        s
    }

    /// Reads a manifest; with `header_only`, stops at the first record.
    pub fn parse(id: &str, text: &str, header_only: bool) -> Option<Manifest> {
        let mut lines = text.lines();
        if lines.next()? != HEADER {
            return None;
        }
        let mut m = Manifest {
            id: id.to_string(),
            ..Default::default()
        };
        let stamp = |size: &str, mtime: &str| -> Option<Stamp> {
            Some(Stamp {
                size: size.parse().ok()?,
                mtime: mtime.parse().ok()?,
            })
        };
        for line in lines {
            let (tag, rest) = line.split_once('\t').unwrap_or((line, ""));
            match tag {
                "title" => m.title = rest.to_string(),
                "dest" => m.dest = PathBuf::from(rest),
                "time" => m.time = rest.parse().unwrap_or(0),
                "pid" => m.pid = rest.parse().unwrap_or(0),
                "state" => m.finished = rest == "done",
                _ if header_only => break,
                "dir" => m.dirs.push(PathBuf::from(rest)),
                "new" => {
                    let mut f = rest.splitn(3, '\t');
                    let (size, mtime, path) = (f.next()?, f.next()?, f.next()?);
                    m.created.push((PathBuf::from(path), stamp(size, mtime)));
                }
                "old" => {
                    let mut f = rest.splitn(4, '\t');
                    let (backup, size, mtime, path) = (f.next()?, f.next()?, f.next()?, f.next()?);
                    m.replaced.push(Replaced {
                        path: PathBuf::from(path),
                        backup: backup.to_string(),
                        written: stamp(size, mtime),
                    });
                }
                _ => {}
            }
        }
        // A path written twice (duplicate entries) is a replaced file if it was one at all.
        let olds: HashSet<&PathBuf> = m.replaced.iter().map(|r| &r.path).collect();
        let mut seen = HashSet::new();
        let created: Vec<_> = m
            .created
            .iter()
            .filter(|(p, _)| !olds.contains(p) && seen.insert(p.clone()))
            .cloned()
            .collect();
        m.created = created;
        Some(m)
    }

    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty() && self.created.is_empty() && self.replaced.is_empty()
    }

    /// A manifest marked running belongs to a job in progress, unless it is from an app
    /// that has since died: another process, and old.
    fn undoable(&self) -> bool {
        if self.finished {
            return true;
        }
        let age = now_secs().saturating_sub(self.time);
        self.pid != std::process::id() && age > STALE_SECS
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load(store: &Store, id: &str, header_only: bool) -> Option<Manifest> {
    let text = fs::read_to_string(store.manifest(id)).ok()?;
    Manifest::parse(id, &text, header_only)
}

fn save(store: &Store, m: &Manifest) -> io::Result<()> {
    fs::create_dir_all(&store.manifests)?;
    let tmp = store.manifests.join(format!("{}.tmp", m.id));
    fs::write(&tmp, m.to_text())?;
    fs::rename(&tmp, store.manifest(&m.id))
}

fn clear_readonly(p: &Path) {
    if let Ok(m) = fs::symlink_metadata(p) {
        let mut perm = m.permissions();
        if perm.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            let _ = fs::set_permissions(p, perm);
        }
    }
}

/// Renames, or copies and deletes when the two are on different drives. `fs::copy` keeps
/// the modification time and attributes on Windows.
fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    fs::copy(from, to)?;
    clear_readonly(from);
    if let Err(e) = fs::remove_file(from) {
        clear_readonly(to);
        let _ = fs::remove_file(to);
        return Err(e);
    }
    Ok(())
}

/// `report (before extract).pdf`, then `report (before extract 2).pdf`, ...
fn beside(p: &Path) -> PathBuf {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let mut n = 1;
    loop {
        let tag = if n == 1 {
            "before extract".to_string()
        } else {
            format!("before extract {n}")
        };
        let cand = p.with_file_name(format!("{stem} ({tag}){ext}"));
        if fs::symlink_metadata(&cand).is_err() {
            return cand;
        }
        n += 1;
    }
}

fn new_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!(
        "{ms:013}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

// ------------------------------------------------------------------ recording

/// Records one job's writes. Shared by the extractor's planning thread through
/// `jobs::Tracked`; every call happens before the file or folder is written.
pub struct Recorder {
    store: Option<Store>,
    state: Mutex<State>,
}

struct State {
    m: Manifest,
    journal: Option<BufWriter<File>>,
    /// The manifest couldn't be written: nothing is tracked and files are replaced in place.
    off: bool,
    /// Folders known to exist or already on record.
    known: HashSet<PathBuf>,
    paths: HashSet<PathBuf>,
}

impl Recorder {
    pub fn new(store: Option<Store>, title: &str, dest: &Path) -> Recorder {
        let off = store.is_none();
        Recorder {
            store,
            state: Mutex::new(State {
                m: Manifest {
                    id: new_id(),
                    title: title.to_string(),
                    dest: dest.to_path_buf(),
                    time: now_secs(),
                    pid: std::process::id(),
                    ..Default::default()
                },
                journal: None,
                off,
                known: HashSet::new(),
                paths: HashSet::new(),
            }),
        }
    }

    /// Appends to the journal, creating it on first use. False when tracking is off.
    fn journal(&self, st: &mut State, text: &str, flush: bool) -> bool {
        if st.off {
            return false;
        }
        let store = self.store.as_ref().unwrap();
        if st.journal.is_none() {
            let opened = fs::create_dir_all(&store.manifests)
                .and_then(|_| File::create(store.manifest(&st.m.id)))
                .and_then(|f| {
                    let mut w = BufWriter::new(f);
                    w.write_all(header_text(&st.m).as_bytes())?;
                    w.flush()?;
                    Ok(w)
                });
            match opened {
                Ok(w) => st.journal = Some(w),
                Err(_) => {
                    st.off = true;
                    return false;
                }
            }
        }
        let w = st.journal.as_mut().unwrap();
        let ok = w.write_all(text.as_bytes()).is_ok() && (!flush || w.flush().is_ok());
        if !ok {
            st.off = true;
        }
        ok
    }

    /// Notes `dir` and any missing folders above it, before they are made.
    pub fn note_dir(&self, dir: &Path) {
        let mut st = self.state.lock().unwrap();
        self.note_dir_locked(&mut st, dir);
    }

    fn note_dir_locked(&self, st: &mut State, dir: &Path) {
        let mut missing = Vec::new();
        let mut p = Some(dir);
        while let Some(d) = p {
            if d.as_os_str().is_empty() || st.known.contains(d) {
                break;
            }
            st.known.insert(d.to_path_buf());
            if fs::symlink_metadata(d).is_ok() {
                break;
            }
            missing.push(d.to_path_buf());
            p = d.parent();
        }
        for d in missing.into_iter().rev() {
            if let Some(s) = line_path(&d) {
                if self.journal(st, &dir_line(s), false) {
                    st.m.dirs.push(d);
                }
            }
        }
    }

    /// The extractor's `will_write` hook.
    pub fn will_write(&self, path: &Path, dir: bool, existed: bool) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if dir {
            self.note_dir_locked(&mut st, path);
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            self.note_dir_locked(&mut st, parent);
        }
        if !st.paths.insert(path.to_path_buf()) {
            return Ok(());
        }
        let Some(s) = line_path(path) else {
            return Ok(());
        };
        // A folder in the way fails in the extractor, as before; it is never moved.
        let is_file = fs::symlink_metadata(path).is_ok_and(|m| !m.is_dir());
        if !(existed && is_file) {
            if self.journal(&mut st, &new_line(s, None), false) {
                st.m.created.push((path.to_path_buf(), None));
            }
            return Ok(());
        }
        // Every path is seen once (`paths`), so its count names a backup no other uses.
        let r = Replaced {
            path: path.to_path_buf(),
            backup: st.paths.len().to_string(),
            written: None,
        };
        if !self.journal(&mut st, &old_line(&r, s), true) {
            // Without a manifest there is no undo; replace in place as before.
            return Ok(());
        }
        let dir = self.store.as_ref().unwrap().backup_dir(&st.m.id);
        let moved = fs::create_dir_all(&dir).and_then(|_| move_file(path, &dir.join(&r.backup)));
        match moved {
            Ok(()) => {
                st.m.replaced.push(r);
                Ok(())
            }
            Err(e) => Err(Error::Other(format!(
                "couldn't set the existing file aside, so it was left as is: {e}"
            ))),
        }
    }

    /// Records what was written and saves the manifest. Backups of files that were never
    /// written (the job stopped first) go straight back. Returns the manifest id, or
    /// `None` when there is nothing to undo.
    pub fn finish(&self) -> Option<String> {
        let mut st = self.state.lock().unwrap();
        let store = self.store.clone()?;
        // Closing the journal; the manifest is rewritten whole below.
        st.journal.take()?;
        let id = st.m.id.clone();
        let backups = store.backup_dir(&id);
        let mut replaced = Vec::new();
        for mut r in std::mem::take(&mut st.m.replaced) {
            match probe(&r.path) {
                Probe::Missing => {
                    if move_file(&backups.join(&r.backup), &r.path).is_err() {
                        replaced.push(r);
                    }
                }
                p => {
                    r.written = match p {
                        Probe::File(s) => Some(s),
                        _ => None,
                    };
                    replaced.push(r);
                }
            }
        }
        st.m.replaced = replaced;
        for (p, s) in st.m.created.iter_mut() {
            *s = stamp_of(p);
        }
        st.m.finished = true;
        if st.m.is_empty() {
            store.forget(&id);
            return None;
        }
        if save(&store, &st.m).is_err() {
            return None;
        }
        prune(&store);
        Some(id)
    }
}

// ------------------------------------------------------------------ undo

#[derive(Debug, Default)]
pub struct UndoReport {
    pub removed: u64,
    pub restored: u64,
    pub dirs: u64,
    /// Created files changed since the extract, left in place.
    pub kept: Vec<PathBuf>,
    /// Originals put back under a new name because the file there was changed.
    pub beside: Vec<PathBuf>,
    pub errors: Vec<(PathBuf, String)>,
}

/// Reverses the extract recorded as `id`. Whatever fails stays in the manifest, so the
/// undo can be tried again.
pub fn undo(store: &Store, id: &str) -> Result<UndoReport> {
    let m = load(store, id, false)
        .ok_or_else(|| Error::Other("there is no record of that extract any more".into()))?;
    if !m.undoable() {
        return Err(Error::Other("that extract is still running".into()));
    }
    let backups = store.backup_dir(id);
    let mut rep = UndoReport::default();
    let mut left = Manifest {
        dirs: Vec::new(),
        created: Vec::new(),
        replaced: Vec::new(),
        ..m.clone()
    };

    for r in &m.replaced {
        let saved = backups.join(&r.backup);
        if fs::symlink_metadata(&saved).is_err() {
            rep.errors
                .push((r.path.clone(), "the saved copy is gone".into()));
            continue;
        }
        let result = match probe(&r.path) {
            Probe::Missing => move_file(&saved, &r.path).map(|_| None),
            Probe::File(now) if Some(now) == r.written => {
                clear_readonly(&r.path);
                fs::remove_file(&r.path).and_then(|_| move_file(&saved, &r.path).map(|_| None))
            }
            _ => {
                let to = beside(&r.path);
                move_file(&saved, &to).map(|_| Some(to))
            }
        };
        match result {
            Ok(None) => rep.restored += 1,
            Ok(Some(to)) => rep.beside.push(to),
            Err(e) => {
                rep.errors.push((r.path.clone(), e.to_string()));
                left.replaced.push(r.clone());
            }
        }
    }

    for (p, written) in &m.created {
        match probe(p) {
            Probe::Missing => {}
            Probe::File(now) if Some(now) == *written => {
                clear_readonly(p);
                match fs::remove_file(p) {
                    Ok(()) => rep.removed += 1,
                    Err(e) => {
                        rep.errors.push((p.clone(), e.to_string()));
                        left.created.push((p.clone(), *written));
                    }
                }
            }
            _ => rep.kept.push(p.clone()),
        }
    }

    let mut dirs = m.dirs.clone();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for d in dirs {
        // Only succeeds on an empty folder.
        if fs::remove_dir(&d).is_ok() {
            rep.dirs += 1;
        }
    }

    if left.created.is_empty() && left.replaced.is_empty() {
        store.forget(id);
    } else {
        let _ = save(store, &left);
    }
    Ok(rep)
}

/// The most recent extract that can be undone: (id, title).
pub fn latest(store: &Store) -> Option<(String, String)> {
    store
        .ids()
        .into_iter()
        .filter_map(|id| load(store, &id, true))
        .find(Manifest::undoable)
        .map(|m| (m.id, m.title))
}

/// Keeps the newest `KEEP` manifests and removes backups no manifest refers to.
pub fn prune(store: &Store) {
    let mut kept = 0;
    let mut live = HashSet::new();
    for id in store.ids() {
        let m = load(store, &id, true);
        // Unreadable and recent: possibly a journal another instance is just starting.
        let young = || {
            fs::metadata(store.manifest(&id))
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age.as_secs() < STALE_SECS)
        };
        let running = match &m {
            Some(m) => !m.undoable(),
            None => young(),
        };
        if running || (m.is_some() && kept < KEEP) {
            if !running {
                kept += 1;
            }
            live.insert(id);
        } else {
            store.forget(&id);
        }
    }
    // Leftover temporary files from a save that didn't finish.
    if let Ok(rd) = fs::read_dir(&store.manifests) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".tmp") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    // A job creates its manifest before its backup folder, so a folder without one is
    // left over from a manifest that was pruned or removed by hand.
    if let Ok(rd) = fs::read_dir(&store.backups) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !live.contains(&name) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
}

/// Toast text for a finished undo.
pub fn headline(r: &UndoReport) -> String {
    let mut parts = Vec::new();
    if r.removed > 0 {
        parts.push(format!(
            "removed {}",
            crate::ui::count(r.removed as usize, "file", "files")
        ));
    }
    if r.restored > 0 {
        parts.push(format!(
            "put back {}",
            crate::ui::count(r.restored as usize, "replaced file", "replaced files")
        ));
    }
    if parts.is_empty() && r.dirs > 0 {
        parts.push(format!(
            "removed {}",
            crate::ui::count(r.dirs as usize, "folder", "folders")
        ));
    }
    let mut s = if parts.is_empty() {
        "Nothing left to undo".to_string()
    } else {
        format!("Undone: {}", parts.join(", "))
    };
    if !r.kept.is_empty() {
        s.push_str(&format!(
            " · left {} you changed",
            crate::ui::count(r.kept.len(), "file", "files")
        ));
    }
    if !r.beside.is_empty() {
        s.push_str(&format!(
            " · {} put back under a new name",
            crate::ui::count(r.beside.len(), "original", "originals")
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let p = std::env::temp_dir().join(format!(
                "r7z-undo-test-{tag}-{}-{}",
                std::process::id(),
                new_id()
            ));
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
        fn store(&self) -> Store {
            Store {
                manifests: self.0.join("config"),
                backups: self.0.join("backups"),
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Plays the extractor's part: hook first, then the write.
    fn write(rec: &Recorder, path: &Path, data: &[u8]) {
        let existed = path.exists();
        rec.will_write(path, false, existed).unwrap();
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(path, data).unwrap();
    }

    fn set_mtime(p: &Path, secs: u64) {
        let f = File::options().write(true).open(p).unwrap();
        f.set_modified(UNIX_EPOCH + std::time::Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn undo_removes_only_untouched_files() {
        let s = Scratch::new("touch");
        let store = s.store();
        let dest = s.0.join("out");
        let rec = Recorder::new(Some(store.clone()), "Extracting a.7z", &dest);
        rec.note_dir(&dest);
        fs::create_dir_all(&dest).unwrap();
        rec.will_write(&dest.join("sub"), true, false).unwrap();
        fs::create_dir_all(dest.join("sub")).unwrap();
        write(&rec, &dest.join("sub/a.txt"), b"one");
        write(&rec, &dest.join("deep/er/b.txt"), b"two");
        write(&rec, &dest.join("c.txt"), b"three");
        let id = rec.finish().unwrap();

        // Changed afterwards: same size, different time; and different size.
        set_mtime(&dest.join("sub/a.txt"), 1_000_000);
        fs::write(dest.join("c.txt"), b"three and more").unwrap();
        // A file the user added inside a created folder keeps that folder.
        fs::write(dest.join("deep/mine.txt"), b"x").unwrap();

        let r = undo(&store, &id).unwrap();
        assert_eq!(r.removed, 1);
        assert_eq!(r.kept.len(), 2);
        assert!(dest.join("sub/a.txt").exists());
        assert!(dest.join("c.txt").exists());
        assert!(!dest.join("deep/er").exists());
        assert!(dest.join("deep/mine.txt").exists());
        assert!(dest.join("sub").exists());
        assert!(r.errors.is_empty());
        // Nothing failed, so the record is gone.
        assert!(latest(&store).is_none());
    }

    #[test]
    fn undo_removes_created_folders_and_keeps_existing_ones() {
        let s = Scratch::new("dirs");
        let store = s.store();
        let had = s.0.join("had");
        fs::create_dir_all(had.join("empty")).unwrap();
        let rec = Recorder::new(Some(store.clone()), "t", &had);
        rec.note_dir(&had);
        rec.will_write(&had.join("empty"), true, true).unwrap();
        write(&rec, &had.join("empty/x.bin"), b"x");
        write(&rec, &had.join("new/y.bin"), b"y");
        let id = rec.finish().unwrap();
        let r = undo(&store, &id).unwrap();
        assert_eq!(r.removed, 2);
        assert_eq!(r.dirs, 1);
        assert!(had.join("empty").is_dir());
        assert!(!had.join("new").exists());
    }

    #[test]
    fn replaced_files_are_backed_up_and_restored() {
        let s = Scratch::new("replace");
        let store = s.store();
        let dest = s.0.join("out");
        fs::create_dir_all(&dest).unwrap();
        let f = dest.join("notes.txt");
        let g = dest.join("other.txt");
        fs::write(&f, b"original").unwrap();
        fs::write(&g, b"original g").unwrap();
        set_mtime(&f, 1_500_000_000);
        let rec = Recorder::new(Some(store.clone()), "t", &dest);
        write(&rec, &f, b"from archive");
        write(&rec, &g, b"from archive g");
        let id = rec.finish().unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"from archive");

        // The user edits one of them afterwards.
        fs::write(&g, b"edited by hand, longer").unwrap();
        let r = undo(&store, &id).unwrap();
        assert_eq!(r.restored, 1);
        assert_eq!(fs::read(&f).unwrap(), b"original");
        assert_eq!(stamp_of(&f).unwrap().mtime, 1_500_000_000 * 1_000_000_000);
        assert_eq!(fs::read(&g).unwrap(), b"edited by hand, longer");
        assert_eq!(r.beside.len(), 1);
        assert_eq!(r.beside[0], dest.join("other (before extract).txt"));
        assert_eq!(fs::read(&r.beside[0]).unwrap(), b"original g");
        assert!(!store.backup_dir(&id).exists());
    }

    #[test]
    fn backups_of_unwritten_files_go_back_at_finish() {
        let s = Scratch::new("stopped");
        let store = s.store();
        let dest = s.0.join("out");
        fs::create_dir_all(&dest).unwrap();
        let f = dest.join("a.txt");
        fs::write(&f, b"keep me").unwrap();
        let rec = Recorder::new(Some(store.clone()), "t", &dest);
        rec.will_write(&f, false, true).unwrap();
        assert!(!f.exists());
        // The job stops before writing anything.
        assert!(rec.finish().is_none());
        assert_eq!(fs::read(&f).unwrap(), b"keep me");
        assert!(latest(&store).is_none());
    }

    #[test]
    fn running_jobs_are_not_undone() {
        let s = Scratch::new("running");
        let store = s.store();
        let dest = s.0.join("out");
        let rec = Recorder::new(Some(store.clone()), "t", &dest);
        write(&rec, &dest.join("a.txt"), b"a");
        let id = store.ids().pop().unwrap();
        assert!(latest(&store).is_none());
        assert!(undo(&store, &id).is_err());
        assert_eq!(rec.finish().as_deref(), Some(id.as_str()));
        assert_eq!(latest(&store).map(|l| l.0), Some(id));
    }

    #[test]
    fn only_the_newest_manifests_are_kept() {
        let s = Scratch::new("prune");
        let store = s.store();
        let dest = s.0.join("out");
        fs::create_dir_all(&dest).unwrap();
        let mut ids = Vec::new();
        for i in 0..KEEP + 2 {
            let f = dest.join(format!("{i}.txt"));
            fs::write(&f, b"old").unwrap();
            let rec = Recorder::new(Some(store.clone()), &format!("job {i}"), &dest);
            write(&rec, &f, b"new");
            ids.push(rec.finish().unwrap());
        }
        let left = store.ids();
        assert_eq!(left.len(), KEEP);
        assert_eq!(left[0], *ids.last().unwrap());
        for old in &ids[..2] {
            assert!(!store.manifest(old).exists());
            assert!(!store.backup_dir(old).exists());
        }
        // An orphaned backup folder is swept.
        fs::create_dir_all(store.backups.join("stray")).unwrap();
        prune(&store);
        assert!(!store.backups.join("stray").exists());
        assert!(store.backup_dir(&ids[KEEP + 1]).exists());
    }

    #[test]
    fn manifest_round_trip() {
        let m = Manifest {
            id: "1".into(),
            title: "Extracting a\tb.zip".into(),
            dest: PathBuf::from("D:/x"),
            time: 5,
            pid: 7,
            finished: true,
            dirs: vec![PathBuf::from("D:/x/d")],
            created: vec![(
                PathBuf::from("D:/x/d/f e.txt"),
                Some(Stamp {
                    size: 3,
                    mtime: -12,
                }),
            )],
            replaced: vec![Replaced {
                path: PathBuf::from("D:/x/g.txt"),
                backup: "0".into(),
                written: None,
            }],
        };
        let back = Manifest::parse("1", &m.to_text(), false).unwrap();
        assert_eq!(back.title, "Extracting a b.zip");
        assert_eq!(
            back,
            Manifest {
                title: back.title.clone(),
                ..m.clone()
            }
        );
        let head = Manifest::parse("1", &m.to_text(), true).unwrap();
        assert!(head.finished && head.created.is_empty());
        assert!(Manifest::parse("1", "something else", false).is_none());
    }
}
