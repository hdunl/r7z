//! "Open as folder": an archive shown as a real, read-only folder in Explorer through
//! Windows Projected File System, without extracting it first.
//!
//! Each mount is a virtualization root under `%LOCALAPPDATA%\r7z\mounts\<archive name>`.
//! ProjFS asks us for directory listings, file metadata and file data as programs touch
//! them; data comes from the archive on demand and ProjFS keeps what it has read in the
//! root (those copies go away on eject). Writes, deletes and renames are refused from the
//! notification callback.
//!
//! A `<name>.lock` file next to each root is held open without sharing for as long as the
//! mount lives, so a later run can tell a root left by a crash from one in use by another
//! running copy of the app.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AO};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use r7z::error::{Error, Result};
use r7z::format::{Archive, Ctx, Flow};

use crate::model::{Tree, ROOT};
use crate::projfs::{self as pf, Api, CallbackData, FileBasicInfo, GUID, HRESULT};

/// What the GUI shows when ProjFS is missing.
pub const ENABLE_HELP: &str = "Open as folder uses Windows Projected File System (ProjFS), \
an optional Windows feature that is turned off on this PC.\n\n\
To turn it on, open PowerShell as administrator and run:\n\n\
Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS\n\n\
Windows may ask to restart. r7z never changes this setting itself.";

/// Most decoded data kept on disk per mount for solid blocks; less when the drive is
/// short of space (a quarter of what is free).
const CACHE_BYTES: u64 = 1 << 30;
const CACHE_MIN: u64 = 64 << 20;
/// Entries larger than this are never cached; reading them again decodes again.
const CACHE_ENTRY_MAX: u64 = 128 << 20;
/// After serving a file from a solid block, decoding continues this far into the block so
/// that the files after it (which Explorer tends to open next) are ready.
const READ_AHEAD: u64 = 256 << 20;
/// Size of each write into ProjFS.
const WRITE_CHUNK: usize = 1 << 20;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const PRJ_FLAG_USE_NEGATIVE_PATH_CACHE: u32 = 0x1;

/// Ok when ProjFS can be used; otherwise the text to show the user.
pub fn available() -> std::result::Result<(), String> {
    pf::api().map(|_| ()).map_err(|e| {
        if e == pf::NOT_ENABLED {
            ENABLE_HELP.to_string()
        } else {
            e
        }
    })
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn mounts_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("r7z").join("mounts"))
}

// ------------------------------------------------------------------ names

/// Compares two NUL-terminated names the way ProjFS orders them.
fn name_cmp(a: &[u16], b: &[u16]) -> Ordering {
    match pf::api() {
        // SAFETY: both slices end in NUL.
        Ok(api) => unsafe { (api.name_compare)(a.as_ptr(), b.as_ptr()) }.cmp(&0),
        Err(_) => fold(a).cmp(&fold(b)),
    }
}

/// Upper-cased UTF-16, for ordering when ProjFS is not loaded (tests).
fn fold(s: &[u16]) -> Vec<u16> {
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    String::from_utf16_lossy(s)
        .chars()
        .flat_map(char::to_uppercase)
        .collect::<String>()
        .encode_utf16()
        .collect()
}

fn name_matches(api: &Api, name: &[u16], pattern: &[u16]) -> bool {
    if pattern.len() <= 1 {
        return true;
    }
    // SAFETY: both slices end in NUL.
    unsafe { (api.name_match)(name.as_ptr(), pattern.as_ptr()) != 0 }
}

// ------------------------------------------------------------------ projection

struct PNode {
    /// NUL-terminated.
    name: Vec<u16>,
    is_dir: bool,
    size: u64,
    time: i64,
    entry: Option<usize>,
    parent: usize,
    /// Sorted in ProjFS order, no two equal names.
    children: Vec<usize>,
}

/// The folder tree ProjFS sees: the GUI's `Tree` with names made valid for Windows and
/// each folder's children sorted and made unique the way ProjFS requires.
pub struct Projection {
    nodes: Vec<PNode>,
}

impl Projection {
    pub fn empty() -> Projection {
        Projection {
            nodes: vec![PNode {
                name: vec![0],
                is_dir: true,
                size: 0,
                time: 0,
                entry: None,
                parent: ROOT,
                children: Vec::new(),
            }],
        }
    }

    /// `fallback_time` (FILETIME) is used for entries and folders without a time.
    pub fn build(tree: &Tree, fallback_time: u64) -> Projection {
        let mut nodes: Vec<PNode> = tree
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let name = if i == ROOT {
                    String::new()
                } else {
                    // The extractor's rules, so a mounted name matches the extracted one.
                    r7z::ops::extract::safe_relative_path(&n.name)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "_".into())
                };
                PNode {
                    name: wide(std::ffi::OsStr::new(&name)),
                    is_dir: n.is_dir,
                    size: if n.is_dir { 0 } else { n.size },
                    time: n.mtime.unwrap_or(fallback_time) as i64,
                    entry: if n.is_dir { None } else { n.entry },
                    parent: n.parent,
                    children: n.children.clone(),
                }
            })
            .collect();
        // Parents come before children in `Tree`, so folders merged into a later folder
        // are handled before that folder is sorted.
        for d in 0..nodes.len() {
            if !nodes[d].is_dir {
                continue;
            }
            let mut kids = std::mem::take(&mut nodes[d].children);
            kids.sort_by(|&a, &b| name_cmp(&nodes[a].name, &nodes[b].name));
            let mut out: Vec<usize> = Vec::with_capacity(kids.len());
            for k in kids {
                let Some(&last) = out.last() else {
                    out.push(k);
                    continue;
                };
                if name_cmp(&nodes[last].name, &nodes[k].name) != Ordering::Equal {
                    out.push(k);
                    continue;
                }
                // Same name twice: folders win over files and a later file replaces an
                // earlier one, as when extracting. Two folders are merged.
                match (nodes[last].is_dir, nodes[k].is_dir) {
                    (true, true) => {
                        let moved = std::mem::take(&mut nodes[k].children);
                        for &m in &moved {
                            nodes[m].parent = last;
                        }
                        nodes[last].children.extend(moved);
                    }
                    (true, false) => {}
                    (false, true) => *out.last_mut().unwrap() = k,
                    (false, false) => {
                        if nodes[k].entry > nodes[last].entry {
                            *out.last_mut().unwrap() = k;
                        }
                    }
                }
            }
            nodes[d].children = out;
        }
        Projection { nodes }
    }

    /// Finds the node for a root-relative path (`a\b.txt`, empty for the root).
    fn lookup(&self, path: &[u16]) -> Option<usize> {
        let mut node = ROOT;
        for part in path.split(|&c| c == b'\\' as u16 || c == b'/' as u16) {
            if part.is_empty() {
                continue;
            }
            let mut key = part.to_vec();
            key.push(0);
            let n = &self.nodes[node];
            if !n.is_dir {
                return None;
            }
            let at = n
                .children
                .binary_search_by(|&c| name_cmp(&self.nodes[c].name, &key))
                .ok()?;
            node = n.children[at];
        }
        Some(node)
    }

    /// The root-relative path with our own spelling, NUL-terminated.
    fn path_of(&self, mut node: usize) -> Vec<u16> {
        let mut parts = Vec::new();
        while node != ROOT {
            parts.push(node);
            node = self.nodes[node].parent;
        }
        let mut out = Vec::new();
        for (k, &n) in parts.iter().rev().enumerate() {
            if k > 0 {
                out.push(b'\\' as u16);
            }
            let name = &self.nodes[n].name;
            out.extend_from_slice(&name[..name.len() - 1]);
        }
        out.push(0);
        out
    }

    fn basic_info(&self, n: usize) -> FileBasicInfo {
        let nd = &self.nodes[n];
        FileBasicInfo {
            IsDirectory: nd.is_dir as u8,
            FileSize: nd.size as i64,
            CreationTime: nd.time,
            LastAccessTime: nd.time,
            LastWriteTime: nd.time,
            ChangeTime: nd.time,
            FileAttributes: if nd.is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_READONLY
            },
        }
    }
}

// ------------------------------------------------------------------ data

struct CacheEntry {
    size: u64,
    used: u64,
}

/// Decoded entries from solid blocks, as files in a scratch folder, least recently used
/// dropped first once `cap` is reached.
struct Cache {
    dir: PathBuf,
    cap: u64,
    files: HashMap<usize, CacheEntry>,
    total: u64,
    clock: u64,
}

impl Cache {
    fn path(&self, entry: usize) -> PathBuf {
        self.dir.join(format!("{entry}.bin"))
    }

    fn get(&mut self, entry: usize) -> Option<PathBuf> {
        self.clock += 1;
        let clock = self.clock;
        let e = self.files.get_mut(&entry)?;
        e.used = clock;
        Some(self.dir.join(format!("{entry}.bin")))
    }

    fn insert(&mut self, entry: usize, size: u64) {
        while self.total + size > self.cap {
            let Some((&old, _)) = self.files.iter().min_by_key(|(_, e)| e.used) else {
                break;
            };
            let e = self.files.remove(&old).unwrap();
            self.total -= e.size;
            let _ = std::fs::remove_file(self.path(old));
        }
        self.clock += 1;
        self.total += size;
        self.files.insert(
            entry,
            CacheEntry {
                size,
                used: self.clock,
            },
        );
    }
}

enum Msg {
    Data(Vec<u8>),
    Done(Result<()>),
}

/// Serves entry bytes. Entries alone in their unit are streamed straight from the archive;
/// entries in solid blocks go through the cache, with one decoder per block at a time.
struct Data {
    archive: Arc<dyn Archive>,
    password: Option<String>,
    unit_of: Vec<Option<usize>>,
    solid: Vec<bool>,
    cache: Mutex<Cache>,
    busy: Mutex<HashSet<usize>>,
    changed: Condvar,
    stopping: AtomicBool,
}

impl Data {
    fn new(archive: Arc<dyn Archive>, password: Option<String>, cache_dir: PathBuf) -> Data {
        let mut unit_of = vec![None; archive.entries().len()];
        let mut solid = Vec::with_capacity(archive.units().len());
        for (u, unit) in archive.units().iter().enumerate() {
            let mut files = 0;
            for &e in &unit.entries {
                if let Some(slot) = unit_of.get_mut(e) {
                    *slot = Some(u);
                }
                if archive.entries().get(e).is_some_and(|x| !x.is_dir) {
                    files += 1;
                }
            }
            solid.push(files > 1);
        }
        Data {
            archive,
            password,
            unit_of,
            solid,
            cache: Mutex::new(Cache {
                cap: cache_cap(&cache_dir),
                dir: cache_dir,
                files: HashMap::new(),
                total: 0,
                clock: 0,
            }),
            busy: Mutex::new(HashSet::new()),
            changed: Condvar::new(),
            stopping: AtomicBool::new(false),
        }
    }

    fn cancelled(&self) -> bool {
        self.stopping.load(AO::Relaxed)
    }

    /// Streams entry `entry` from its start to `sink`; `sink` returns `Cancelled` to stop.
    fn read(
        self: &Arc<Self>,
        entry: usize,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let unit = self.unit_of.get(entry).copied().flatten();
        if unit.is_none()
            && self
                .archive
                .entries()
                .get(entry)
                .is_some_and(|e| e.size_or_zero() == 0)
        {
            // Empty files have no data in the archive.
            return Ok(());
        }
        let Some(unit) = unit.filter(|&u| self.solid[u]) else {
            return r7z::ops::peek::stream_entry(
                &*self.archive,
                entry,
                self.password.as_deref(),
                &|| self.cancelled(),
                sink,
            )
            .map(|_| ());
        };
        loop {
            if self.cancelled() {
                return Err(Error::Cancelled);
            }
            let cached = self.cache.lock().unwrap().get(entry);
            // A file evicted between the lookup and the open is decoded again.
            if let Some(f) = cached.and_then(|p| File::open(p).ok()) {
                return match serve_file(f, sink) {
                    Ok(()) | Err(Error::Cancelled) => Ok(()),
                    Err(e) => Err(e),
                };
            }
            let mut busy = self.busy.lock().unwrap();
            if busy.contains(&unit) {
                // Another request is decoding this block; it may well pass our entry.
                let _ = self
                    .changed
                    .wait_timeout(busy, Duration::from_millis(500))
                    .unwrap();
                continue;
            }
            busy.insert(unit);
            drop(busy);
            return self.decode(unit, entry, sink);
        }
    }

    /// Decodes block `unit` on a worker thread. Bytes of `target` come back through a
    /// channel; the worker keeps caching the entries around it and frees the block when done.
    fn decode(
        self: &Arc<Self>,
        unit: usize,
        target: usize,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let (tx, rx) = mpsc::sync_channel::<Msg>(8);
        let me = self.clone();
        std::thread::Builder::new()
            .name("mount-decode".into())
            .spawn(move || {
                me.walk(unit, target, tx);
                me.busy.lock().unwrap().remove(&unit);
                me.changed.notify_all();
            })
            .map_err(Error::Io)?;
        for msg in rx {
            match msg {
                Msg::Data(b) => match sink(&b) {
                    Ok(()) => {}
                    Err(Error::Cancelled) => return Ok(()),
                    Err(e) => return Err(e),
                },
                Msg::Done(r) => return r,
            }
        }
        Err(Error::Other("the entry was not found in its block".into()))
    }

    fn walk(&self, unit: usize, target: usize, tx: mpsc::SyncSender<Msg>) {
        let entries = self.archive.entries();
        let ctx = Ctx {
            password: self.password.clone(),
            threads: r7z::util::default_threads(),
        };
        let encrypted = self.archive.units()[unit].encrypted;
        let verify = !self.archive.verifies_data();
        // Files just before the target are cached too, but not a whole large block's worth.
        let mut behind: u64 = self.archive.units()[unit]
            .entries
            .iter()
            .take_while(|&&i| i != target)
            .map(|&i| entries[i].size_or_zero())
            .sum();
        let cap = self.cache.lock().unwrap().cap;
        let mut tx = Some(tx);
        let mut past = false;
        let mut ahead = 0u64;
        let mut chunk = vec![0u8; 256 << 10];
        let result = self.archive.extract_unit(unit, &ctx, &mut |i, reader| {
            if self.cancelled() {
                return Err(Error::Cancelled);
            }
            let e = &entries[i];
            let far_behind = !past && behind > cap / 2;
            if past {
                if ahead >= READ_AHEAD {
                    return Ok(Flow::Stop);
                }
                ahead += e.size_or_zero();
            } else if i != target {
                behind = behind.saturating_sub(e.size_or_zero());
            }
            if i == target {
                let mut crc = crc32fast::Hasher::new();
                let mut whole = true;
                loop {
                    let n = reader.read(&mut chunk).map_err(Error::from_codec)?;
                    if n == 0 {
                        break;
                    }
                    crc.update(&chunk[..n]);
                    let sent = tx
                        .as_ref()
                        .is_some_and(|t| t.send(Msg::Data(chunk[..n].to_vec())).is_ok());
                    if !sent {
                        // The request has what it needs.
                        whole = false;
                        break;
                    }
                }
                let mut r = Ok(());
                if whole && verify {
                    if let Some(expected) = e.crc {
                        if crc.finalize() != expected {
                            r = Err(if encrypted {
                                Error::WrongPassword
                            } else {
                                Error::Checksum(e.name.clone())
                            });
                        }
                    }
                }
                if let Some(t) = tx.take() {
                    let _ = t.send(Msg::Done(r));
                }
                past = true;
                return Ok(Flow::Continue);
            }
            if far_behind || e.is_dir || e.size_or_zero() > CACHE_ENTRY_MAX.min(cap / 4) {
                return Ok(Flow::Continue);
            }
            if self.cache.lock().unwrap().files.contains_key(&i) {
                return Ok(Flow::Continue);
            }
            let path = self.cache.lock().unwrap().path(i);
            match fill_cache_file(&path, reader, &mut chunk, if verify { e.crc } else { None }) {
                Ok(size) => {
                    self.cache.lock().unwrap().insert(i, size);
                    self.changed.notify_all();
                }
                Err(err @ Error::Cancelled) => return Err(err),
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                }
            }
            Ok(Flow::Continue)
        });
        if let (Err(e), Some(t)) = (result, tx.take()) {
            let e = if encrypted && matches!(e, Error::Corrupt(_) | Error::Checksum(_)) {
                Error::WrongPassword
            } else {
                e
            };
            let _ = t.send(Msg::Done(Err(e)));
        }
    }
}

fn cache_cap(dir: &Path) -> u64 {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            dir: *const u16,
            avail: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
    }
    // The folder may not exist yet; its drive is what matters.
    let probe = dir.ancestors().find(|a| a.exists()).unwrap_or(dir);
    let w = wide(probe.as_os_str());
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY: NUL-terminated path and valid out pointers.
    if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) } == 0 {
        return CACHE_MIN;
    }
    (avail / 4).clamp(CACHE_MIN, CACHE_BYTES)
}

fn fill_cache_file(
    path: &Path,
    reader: &mut dyn Read,
    chunk: &mut [u8],
    crc: Option<u32>,
) -> Result<u64> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::io::BufWriter::new(File::create(path)?);
    let mut h = crc32fast::Hasher::new();
    let mut size = 0u64;
    loop {
        let n = reader.read(chunk).map_err(Error::from_codec)?;
        if n == 0 {
            break;
        }
        h.update(&chunk[..n]);
        f.write_all(&chunk[..n])?;
        size += n as u64;
    }
    f.flush()?;
    if crc.is_some_and(|c| c != h.finalize()) {
        return Err(Error::Checksum(path.display().to_string()));
    }
    Ok(size)
}

fn serve_file(mut f: File, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut buf = vec![0u8; 256 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        sink(&buf[..n])?;
    }
}

// ------------------------------------------------------------------ provider

struct Enumeration {
    dir: Option<usize>,
    pos: usize,
    /// The search expression of this scan, NUL-terminated.
    pattern: Option<Vec<u16>>,
}

struct Provider {
    api: &'static Api,
    proj: Projection,
    data: Option<Arc<Data>>,
    /// Ejecting: the projection is hidden and deletes are allowed, so what ProjFS keeps on
    /// disk can be removed.
    purge: AtomicBool,
    enums: Mutex<HashMap<u128, Enumeration>>,
    align: AtomicU32,
    /// Bytes served so far, for the sidebar.
    served: AtomicU64,
}

impl Provider {
    fn start_enum(&self, cb: &CallbackData, id: &GUID) -> HRESULT {
        let dir = if self.purge.load(AO::Relaxed) {
            None
        } else {
            // SAFETY: ProjFS passes a NUL-terminated path.
            let path = unsafe { pf::wide_slice(cb.FilePathName) };
            match self.proj.lookup(path) {
                Some(n) if self.proj.nodes[n].is_dir => Some(n),
                _ => return pf::from_win32(pf::ERROR_FILE_NOT_FOUND),
            }
        };
        self.enums.lock().unwrap().insert(
            id.key(),
            Enumeration {
                dir,
                pos: 0,
                pattern: None,
            },
        );
        pf::S_OK
    }

    fn end_enum(&self, id: &GUID) -> HRESULT {
        self.enums.lock().unwrap().remove(&id.key());
        pf::S_OK
    }

    fn get_enum(
        &self,
        cb: &CallbackData,
        id: &GUID,
        pattern: *const u16,
        buffer: pf::DirEntryBuffer,
    ) -> HRESULT {
        let mut enums = self.enums.lock().unwrap();
        let Some(st) = enums.get_mut(&id.key()) else {
            return pf::E_FAIL;
        };
        if cb.Flags & pf::CB_DATA_FLAG_ENUM_RESTART_SCAN != 0 {
            st.pos = 0;
            st.pattern = None;
        }
        if st.pattern.is_none() {
            // SAFETY: null or NUL-terminated.
            let mut p = unsafe { pf::wide_slice(pattern) }.to_vec();
            p.push(0);
            st.pattern = Some(p);
        }
        let Some(dir) = st.dir else { return pf::S_OK };
        if self.purge.load(AO::Relaxed) {
            return pf::S_OK;
        }
        let pattern = st.pattern.as_deref().unwrap_or(&[0]);
        let kids = &self.proj.nodes[dir].children;
        let mut added = 0;
        while st.pos < kids.len() {
            let c = kids[st.pos];
            let name = &self.proj.nodes[c].name;
            if !name_matches(self.api, name, pattern) {
                st.pos += 1;
                continue;
            }
            let info = self.proj.basic_info(c);
            // SAFETY: valid name and info; `buffer` comes from this callback.
            let hr = unsafe { (self.api.fill_dir_entry)(name.as_ptr(), &info, buffer) };
            if hr != pf::S_OK {
                // The buffer is full; the rest goes in the next call.
                return if added == 0 { hr } else { pf::S_OK };
            }
            added += 1;
            st.pos += 1;
            if cb.Flags & pf::CB_DATA_FLAG_ENUM_RETURN_SINGLE_ENTRY != 0 {
                break;
            }
        }
        pf::S_OK
    }

    fn placeholder(&self, cb: &CallbackData) -> HRESULT {
        if self.purge.load(AO::Relaxed) {
            return pf::from_win32(pf::ERROR_FILE_NOT_FOUND);
        }
        // SAFETY: ProjFS passes a NUL-terminated path.
        let path = unsafe { pf::wide_slice(cb.FilePathName) };
        let Some(n) = self.proj.lookup(path) else {
            return pf::from_win32(pf::ERROR_FILE_NOT_FOUND);
        };
        let info = pf::PlaceholderInfo {
            FileBasicInfo: self.proj.basic_info(n),
            EaInformation: Default::default(),
            SecurityInformation: Default::default(),
            StreamsInformation: Default::default(),
            VersionInfo: Default::default(),
            VariableData: [0],
        };
        let name = self.proj.path_of(n);
        // SAFETY: the context comes from this callback; name and info are valid.
        unsafe {
            (self.api.write_placeholder)(
                cb.NamespaceVirtualizationContext,
                name.as_ptr(),
                &info,
                std::mem::size_of::<pf::PlaceholderInfo>() as u32,
            )
        }
    }

    fn file_data(&self, cb: &CallbackData, offset: u64, length: u32) -> HRESULT {
        let Some(data) = &self.data else {
            return pf::from_win32(pf::ERROR_FILE_NOT_FOUND);
        };
        // SAFETY: ProjFS passes a NUL-terminated path.
        let path = unsafe { pf::wide_slice(cb.FilePathName) };
        let Some(entry) = self
            .proj
            .lookup(path)
            .and_then(|n| self.proj.nodes[n].entry)
        else {
            return pf::from_win32(pf::ERROR_FILE_NOT_FOUND);
        };
        let size = self
            .proj
            .lookup(path)
            .map(|n| self.proj.nodes[n].size)
            .unwrap_or(0);
        // Writes must start and end on the alignment ProjFS reports, except at the end of
        // the file.
        let align = self.align.load(AO::Relaxed).max(1) as u64;
        let start = offset / align * align;
        let end = (offset + length as u64)
            .div_ceil(align)
            .saturating_mul(align)
            .min(size);
        if start >= end {
            return pf::S_OK;
        }
        let ctx = cb.NamespaceVirtualizationContext;
        let mut w = match Writer::new(self.api, ctx, cb.DataStreamId, start, align) {
            Some(w) => w,
            None => return pf::E_OUTOFMEMORY,
        };
        let mut pos = 0u64;
        let result = data.read(entry, &mut |mut b: &[u8]| {
            let here = pos;
            pos += b.len() as u64;
            if pos <= start {
                return Ok(());
            }
            if here < start {
                b = &b[(start - here) as usize..];
            }
            let room = (end - here.max(start)) as usize;
            let stop = b.len() >= room;
            w.push(&b[..b.len().min(room)])?;
            if stop {
                Err(Error::Cancelled)
            } else {
                Ok(())
            }
        });
        let result = result.and_then(|()| w.finish());
        match result {
            Ok(()) => {
                self.served.fetch_add(end - start, AO::Relaxed);
                pf::S_OK
            }
            Err(Error::Cancelled) => pf::from_win32(pf::ERROR_OPERATION_ABORTED),
            Err(Error::WrongPassword | Error::PasswordRequired) => pf::E_ACCESSDENIED,
            Err(Error::Corrupt(_) | Error::Checksum(_)) => pf::from_win32(pf::ERROR_CRC),
            Err(Error::Io(e)) => e
                .raw_os_error()
                .map(|c| pf::from_win32(c as u32))
                .unwrap_or(pf::E_FAIL),
            Err(_) => pf::E_FAIL,
        }
    }

    fn notification(&self, kind: u32) -> HRESULT {
        if self.purge.load(AO::Relaxed) {
            return pf::S_OK;
        }
        match kind {
            pf::NOTIFY_NEW_FILE_CREATED
            | pf::NOTIFY_FILE_OVERWRITTEN
            | pf::NOTIFY_PRE_DELETE
            | pf::NOTIFY_PRE_RENAME
            | pf::NOTIFY_PRE_SET_HARDLINK
            | pf::NOTIFY_FILE_PRE_CONVERT_TO_FULL => pf::E_ACCESSDENIED,
            _ => pf::S_OK,
        }
    }
}

/// Collects bytes into ProjFS's aligned buffer and writes them in `WRITE_CHUNK` pieces.
struct Writer {
    api: &'static Api,
    ctx: pf::Context,
    stream: GUID,
    buf: *mut u8,
    cap: usize,
    filled: usize,
    at: u64,
}

impl Writer {
    fn new(
        api: &'static Api,
        ctx: pf::Context,
        stream: GUID,
        at: u64,
        align: u64,
    ) -> Option<Writer> {
        let cap = (WRITE_CHUNK as u64).div_ceil(align) * align;
        // SAFETY: `ctx` is the live virtualization context of the current callback.
        let buf = unsafe { (api.alloc)(ctx, cap as usize) } as *mut u8;
        (!buf.is_null()).then_some(Writer {
            api,
            ctx,
            stream,
            buf,
            cap: cap as usize,
            filled: 0,
            at,
        })
    }

    fn push(&mut self, mut b: &[u8]) -> Result<()> {
        while !b.is_empty() {
            let n = b.len().min(self.cap - self.filled);
            // SAFETY: `filled + n <= cap`, inside the allocation.
            unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), self.buf.add(self.filled), n) };
            self.filled += n;
            b = &b[n..];
            if self.filled == self.cap {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.filled == 0 {
            return Ok(());
        }
        // SAFETY: buffer from PrjAllocateAlignedBuffer holding `filled` bytes.
        let hr = unsafe {
            (self.api.write_data)(
                self.ctx,
                &self.stream,
                self.buf as *const c_void,
                self.at,
                self.filled as u32,
            )
        };
        if hr != pf::S_OK {
            return Err(Error::Other(format!(
                "PrjWriteFileData failed (0x{:08X})",
                hr as u32
            )));
        }
        self.at += self.filled as u64;
        self.filled = 0;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.flush()
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // SAFETY: allocated by PrjAllocateAlignedBuffer and not freed before.
        unsafe { (self.api.free)(self.buf as *mut c_void) };
    }
}

// ------------------------------------------------------------------ callbacks

/// Runs a callback body against the provider in the instance context. Panics become E_FAIL.
unsafe fn with_provider(
    cb: *const CallbackData,
    f: impl FnOnce(&Provider, &CallbackData) -> HRESULT,
) -> HRESULT {
    if cb.is_null() || (*cb).InstanceContext.is_null() {
        return pf::E_FAIL;
    }
    let cb = &*cb;
    let p = &*(cb.InstanceContext as *const Provider);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(p, cb))).unwrap_or(pf::E_FAIL)
}

unsafe extern "system" fn cb_start_enum(cb: *const CallbackData, id: *const GUID) -> HRESULT {
    with_provider(cb, |p, cb| p.start_enum(cb, &*id))
}

unsafe extern "system" fn cb_end_enum(cb: *const CallbackData, id: *const GUID) -> HRESULT {
    with_provider(cb, |p, _| p.end_enum(&*id))
}

unsafe extern "system" fn cb_get_enum(
    cb: *const CallbackData,
    id: *const GUID,
    pattern: *const u16,
    buffer: pf::DirEntryBuffer,
) -> HRESULT {
    with_provider(cb, |p, cb| p.get_enum(cb, &*id, pattern, buffer))
}

unsafe extern "system" fn cb_placeholder(cb: *const CallbackData) -> HRESULT {
    with_provider(cb, |p, cb| p.placeholder(cb))
}

unsafe extern "system" fn cb_file_data(
    cb: *const CallbackData,
    offset: u64,
    length: u32,
) -> HRESULT {
    with_provider(cb, |p, cb| p.file_data(cb, offset, length))
}

unsafe extern "system" fn cb_notification(
    cb: *const CallbackData,
    _is_dir: u8,
    kind: u32,
    _dest: *const u16,
    _params: *mut c_void,
) -> HRESULT {
    with_provider(cb, |p, _| p.notification(kind))
}

const CALLBACKS: pf::Callbacks = pf::Callbacks {
    StartDirectoryEnumerationCallback: Some(cb_start_enum),
    EndDirectoryEnumerationCallback: Some(cb_end_enum),
    GetDirectoryEnumerationCallback: Some(cb_get_enum),
    GetPlaceholderInfoCallback: Some(cb_placeholder),
    GetFileDataCallback: Some(cb_file_data),
    QueryFileNameCallback: None,
    NotificationCallback: Some(cb_notification),
    CancelCommandCallback: None,
};

// ------------------------------------------------------------------ virtualizing

/// A running virtualization instance. The provider lives until `stop` returns, since
/// ProjFS calls into it until then.
struct Instance {
    api: &'static Api,
    ctx: pf::Context,
    provider: *const Provider,
}

// SAFETY: the ProjFS context may be used from any thread; the provider is Sync.
unsafe impl Send for Instance {}

impl Instance {
    fn start(
        api: &'static Api,
        root: &Path,
        provider: Provider,
    ) -> std::result::Result<Instance, String> {
        let provider = Box::into_raw(Box::new(provider));
        let root_w = wide(root.as_os_str());
        let here: [u16; 1] = [0];
        let mut mapping = pf::NotificationMapping {
            NotificationBitMask: pf::NOTIFY_NEW_FILE_CREATED
                | pf::NOTIFY_FILE_OVERWRITTEN
                | pf::NOTIFY_PRE_DELETE
                | pf::NOTIFY_PRE_RENAME
                | pf::NOTIFY_PRE_SET_HARDLINK
                | pf::NOTIFY_FILE_PRE_CONVERT_TO_FULL,
            NotificationRoot: here.as_ptr(),
        };
        let opts = pf::StartOptions {
            Flags: PRJ_FLAG_USE_NEGATIVE_PATH_CACHE,
            PoolThreadCount: 0,
            ConcurrentThreadCount: 0,
            NotificationMappings: &mut mapping,
            NotificationMappingsCount: 1,
        };
        let mut ctx: pf::Context = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the call; the provider outlives the instance.
        let hr = unsafe {
            (api.start)(
                root_w.as_ptr(),
                &CALLBACKS,
                provider as *const c_void,
                &opts,
                &mut ctx,
            )
        };
        if hr != pf::S_OK {
            // SAFETY: ProjFS refused to start, so nothing else refers to the provider.
            drop(unsafe { Box::from_raw(provider) });
            return Err(start_error(hr));
        }
        let mut info = pf::InstanceInfo::default();
        // SAFETY: live context and a valid out pointer.
        if unsafe { (api.instance_info)(ctx, &mut info) } == pf::S_OK {
            // SAFETY: the provider is alive while the instance is.
            unsafe { &*provider }
                .align
                .store(info.WriteAlignment, AO::Relaxed);
        }
        Ok(Instance { api, ctx, provider })
    }

    fn provider(&self) -> &Provider {
        // SAFETY: freed only in `stop`, which consumes the instance.
        unsafe { &*self.provider }
    }

    /// Removes everything ProjFS stored under `root`, then stops.
    fn purge_and_stop(self, root: &Path) {
        let p = self.provider();
        p.purge.store(true, AO::Relaxed);
        if let Some(d) = &p.data {
            d.stopping.store(true, AO::Relaxed);
            d.changed.notify_all();
        }
        let mut items = Vec::new();
        collect(root, &mut items);
        // Deepest first, so folders are empty when their turn comes.
        items.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, is_dir) in items {
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let rel_w = wide(rel.as_os_str());
            let mut cause = 0u32;
            // SAFETY: live context, NUL-terminated relative path, valid out pointer.
            let hr = unsafe {
                (self.api.delete_file)(
                    self.ctx,
                    rel_w.as_ptr(),
                    pf::UPDATE_ALLOW_DIRTY_METADATA
                        | pf::UPDATE_ALLOW_DIRTY_DATA
                        | pf::UPDATE_ALLOW_TOMBSTONE
                        | pf::UPDATE_ALLOW_READ_ONLY,
                    &mut cause,
                )
            };
            if hr != pf::S_OK {
                remove_plain(&path, is_dir);
            }
        }
        // SAFETY: the context is live; after this returns ProjFS no longer calls us.
        unsafe { (self.api.stop)(self.ctx) };
        // SAFETY: created by Box::into_raw in `start`; nothing refers to it any more.
        drop(unsafe { Box::from_raw(self.provider as *mut Provider) });
    }
}

fn start_error(hr: HRESULT) -> String {
    match hr as u32 {
        // ERROR_NOT_SUPPORTED: the folder is not on NTFS, or the driver is not running.
        0x8007_0032 => {
            "ProjFS can't run here (it needs an NTFS drive and its driver loaded)".into()
        }
        0x8007_0005 => "access to the mount folder was denied".into(),
        0x8007_0003 | 0x8007_0002 => "the mount folder does not exist".into(),
        h => format!("ProjFS refused to start (0x{h:08X})"),
    }
}

fn collect(dir: &Path, out: &mut Vec<(PathBuf, bool)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        if is_dir {
            collect(&path, out);
        }
        out.push((path, is_dir));
    }
}

fn remove_plain(path: &Path, is_dir: bool) {
    if is_dir {
        let _ = std::fs::remove_dir(path);
    } else {
        if let Ok(m) = std::fs::metadata(path) {
            let mut perm = m.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            let _ = std::fs::set_permissions(path, perm);
        }
        let _ = std::fs::remove_file(path);
    }
}

// ------------------------------------------------------------------ mounts

/// Holds `<root>.lock` open without sharing, so other copies of the app leave the root alone.
fn take_lock(path: &Path) -> Option<File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
        .ok()
}

fn lock_path(root: &Path) -> PathBuf {
    let mut s = root.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// Removes a root nobody is serving any more: ProjFS is started on it with nothing
/// projected, so what it stored there can be deleted. True when the folder is gone.
fn clean_root(root: &Path) -> bool {
    if let Ok(api) = pf::api() {
        let empty = Provider {
            api,
            proj: Projection::empty(),
            data: None,
            purge: AtomicBool::new(true),
            enums: Mutex::new(HashMap::new()),
            align: AtomicU32::new(0),
            served: AtomicU64::new(0),
        };
        if let Ok(inst) = Instance::start(api, root, empty) {
            inst.purge_and_stop(root);
        }
    }
    if std::fs::remove_dir(root).is_err() {
        // Not a virtualization root (a mount that failed half way), or plain leftovers.
        let _ = std::fs::remove_dir_all(root);
    }
    !root.exists()
}

/// Cleans up roots left by runs that ended without ejecting. Roots whose lock is held
/// belong to another running copy and are left alone.
pub fn sweep_stale() {
    let Some(dir) = mounts_dir() else { return };
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().is_some_and(|x| x == "lock") {
            // A lock without its folder.
            let root = path.with_extension("");
            if !root.exists() {
                if let Some(l) = take_lock(&path) {
                    drop(l);
                    let _ = std::fs::remove_file(&path);
                }
            }
            continue;
        }
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let lp = lock_path(&path);
        let Some(lock) = take_lock(&lp) else { continue };
        clean_root(&path);
        drop(lock);
        let _ = std::fs::remove_file(&lp);
    }
}

/// What to mount.
pub struct Source {
    pub archive: Arc<dyn Archive>,
    /// Folder name, normally the archive's file name.
    pub name: String,
    /// Identifies the archive (and nested level) so it is not mounted twice.
    pub key: String,
    pub password: Option<String>,
    /// FILETIME for entries without a time of their own.
    pub time: u64,
}

pub struct Mount {
    pub name: String,
    pub root: PathBuf,
    pub key: String,
    pub files: u64,
    instance: Option<Instance>,
    lock: Option<File>,
    cache_dir: PathBuf,
}

impl Mount {
    /// Builds the projection and starts serving it. Slow for large archives; run it off the
    /// UI thread.
    pub fn start(src: Source, cache_dir: PathBuf) -> std::result::Result<Mount, String> {
        let api = pf::api()?;
        let base_dir = mounts_dir().ok_or("LOCALAPPDATA is not set")?;
        std::fs::create_dir_all(&base_dir)
            .map_err(|e| format!("can't create {}: {e}", base_dir.display()))?;
        let base = r7z::ops::extract::safe_relative_path(&src.name)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "archive".into());
        let mut picked = None;
        for k in 1..100 {
            let name = if k == 1 {
                base.clone()
            } else {
                format!("{base} ({k})")
            };
            let root = base_dir.join(&name);
            let Some(lock) = take_lock(&lock_path(&root)) else {
                continue;
            };
            if root.exists() && !clean_root(&root) {
                continue;
            }
            picked = Some((name, root, lock));
            break;
        }
        let (name, root, lock) = picked.ok_or("no free mount folder name")?;
        std::fs::create_dir(&root).map_err(|e| format!("can't create {}: {e}", root.display()))?;
        let root_w = wide(root.as_os_str());
        let version = pf::PlaceholderVersionInfo::default();
        let id = GUID::new();
        // SAFETY: NUL-terminated root path; valid version info and GUID.
        let hr = unsafe { (api.mark_root)(root_w.as_ptr(), std::ptr::null(), &version, &id) };
        if hr != pf::S_OK {
            let _ = std::fs::remove_dir(&root);
            return Err(start_error(hr));
        }
        let tree = Tree::build(src.archive.entries(), &src.name);
        let files = tree.nodes[ROOT].files;
        let provider = Provider {
            api,
            proj: Projection::build(&tree, src.time),
            data: Some(Arc::new(Data::new(
                src.archive,
                src.password,
                cache_dir.clone(),
            ))),
            purge: AtomicBool::new(false),
            enums: Mutex::new(HashMap::new()),
            align: AtomicU32::new(0),
            served: AtomicU64::new(0),
        };
        drop(tree);
        let instance = match Instance::start(api, &root, provider) {
            Ok(i) => i,
            Err(e) => {
                let _ = std::fs::remove_dir(&root);
                return Err(e);
            }
        };
        Ok(Mount {
            name,
            root,
            key: src.key,
            files,
            instance: Some(instance),
            lock: Some(lock),
            cache_dir,
        })
    }

    pub fn served(&self) -> u64 {
        self.instance
            .as_ref()
            .map(|i| i.provider().served.load(AO::Relaxed))
            .unwrap_or(0)
    }

    /// Stops serving and removes the folder. Explorer windows still showing it keep it open
    /// for a while, so removal is retried for up to `patience`; whatever is left after
    /// that is cleaned up by the next start.
    pub fn eject(mut self, patience: Duration) {
        if let Some(inst) = self.instance.take() {
            inst.purge_and_stop(&self.root);
            let _ = std::fs::remove_dir(&self.root);
        }
        let until = std::time::Instant::now() + patience;
        while self.root.exists() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_secs(2));
            clean_root(&self.root);
        }
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(inst) = self.instance.take() {
            inst.purge_and_stop(&self.root);
            let _ = std::fs::remove_dir(&self.root);
        }
        let _ = std::fs::remove_dir_all(&self.cache_dir);
        if self.lock.take().is_some() && !self.root.exists() {
            let _ = std::fs::remove_file(lock_path(&self.root));
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r7z::format::Entry;

    fn entry(name: &str, dir: bool, size: u64) -> Entry {
        Entry {
            name: name.into(),
            is_dir: dir,
            size: Some(size),
            ..Default::default()
        }
    }

    fn names(p: &Projection, n: usize) -> Vec<String> {
        p.nodes[n]
            .children
            .iter()
            .map(|&c| {
                let w = &p.nodes[c].name;
                String::from_utf16_lossy(&w[..w.len() - 1])
            })
            .collect()
    }

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn projection_sorts_dedupes_and_finds() {
        let entries = vec![
            entry("b.txt", false, 1),
            entry("A/x.txt", false, 2),
            entry("a/Y.txt", false, 3),
            entry("b.txt", false, 4),
            entry("bad:name?.txt", false, 5),
            entry("c", false, 6),
            entry("c/inner", false, 7),
        ];
        let tree = Tree::build(&entries, "t.7z");
        let p = Projection::build(&tree, 0);
        assert_eq!(names(&p, ROOT), vec!["A", "b.txt", "bad_name_.txt", "c"]);
        let a = p.lookup(&w("a")).unwrap();
        assert!(p.nodes[a].is_dir);
        assert_eq!(names(&p, a), vec!["x.txt", "Y.txt"]);
        // The later of two same-named files wins.
        let b = p.lookup(&w("B.TXT")).unwrap();
        assert_eq!(p.nodes[b].entry, Some(3));
        assert_eq!(p.nodes[b].size, 4);
        // A folder wins over a file with its name.
        let c = p.lookup(&w("c")).unwrap();
        assert!(p.nodes[c].is_dir);
        assert!(p.lookup(&w("c\\inner")).is_some());
        let y = p.lookup(&w("a\\y.txt")).unwrap();
        assert_eq!(String::from_utf16_lossy(&p.path_of(y)), "A\\Y.txt\0");
        assert_eq!(p.lookup(&w("")), Some(ROOT));
        assert!(p.lookup(&w("missing")).is_none());
        assert!(p.lookup(&w("b.txt\\under-a-file")).is_none());
        let info = p.basic_info(b);
        assert_eq!(info.FileSize, 4);
        assert_eq!(info.FileAttributes, FILE_ATTRIBUTE_READONLY);
    }

    fn archive_of(dir: &Path, files: &[(&str, Vec<u8>)], solid: bool) -> Arc<dyn Archive> {
        use r7z::ops::create::{create, CreateOptions, Item, NoProgress};
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        let items: Vec<Item> = files
            .iter()
            .map(|(n, d)| {
                let p = src.join(n);
                std::fs::write(&p, d).unwrap();
                Item {
                    src: p,
                    name: n.to_string(),
                    is_dir: false,
                    size: d.len() as u64,
                    mtime: None,
                    ctime: None,
                    atime: None,
                    attrib: None,
                }
            })
            .collect();
        let out = dir.join("a.7z");
        let opts = CreateOptions {
            solid_limit: if solid { Some(1 << 30) } else { None },
            ..Default::default()
        };
        create(&out, &items, &opts, &NoProgress).unwrap();
        r7z::format::open(&out, &Default::default()).unwrap().arc()
    }

    fn read_all(d: &Arc<Data>, entry: usize) -> Vec<u8> {
        let mut v = Vec::new();
        d.read(entry, &mut |b| {
            v.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        v
    }

    #[test]
    fn solid_reads_go_through_the_cache() {
        let tmp = std::env::temp_dir().join(format!("r7z-mount-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let files: Vec<(String, Vec<u8>)> = (0..6)
            .map(|i| {
                (
                    format!("f{i}.bin"),
                    (0..50_000u32).map(|x| (x * (i + 7)) as u8).collect(),
                )
            })
            .collect();
        let refs: Vec<(&str, Vec<u8>)> =
            files.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
        let a = archive_of(&tmp, &refs, true);
        let d = Arc::new(Data::new(a.clone(), None, tmp.join("cache")));
        let index = |name: &str| {
            a.entries()
                .iter()
                .position(|e| e.name.ends_with(name))
                .unwrap()
        };
        assert!(d.solid.iter().any(|&s| s));
        let third = index("f3.bin");
        assert_eq!(read_all(&d, third), files[3].1);
        // The worker caches the rest of the block in the background.
        for _ in 0..200 {
            if !d.busy.lock().unwrap().is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let cached = d.cache.lock().unwrap().files.len();
        assert!(cached >= 5, "{cached} entries cached");
        for (k, (n, data)) in files.iter().enumerate() {
            assert_eq!(&read_all(&d, index(n)), data, "file {k}");
        }
        // Stopping early through the sink is not an error.
        let mut got = 0;
        d.read(index("f5.bin"), &mut |b| {
            got += b.len();
            Err(Error::Cancelled)
        })
        .unwrap();
        assert!(got > 0);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn files_under(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                files_under(&p, base, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().to_path_buf());
            }
        }
    }

    fn extract_to(a: &dyn Archive, out: &Path) {
        struct Quiet;
        impl r7z::ops::extract::Callbacks for Quiet {}
        let report = r7z::ops::extract::extract(
            a,
            &r7z::ops::extract::ExtractOptions {
                password: None,
                threads: r7z::util::default_threads(),
                target: r7z::ops::extract::Target::Disk {
                    dir: out.to_path_buf(),
                    full_paths: true,
                    overwrite: r7z::ops::extract::Overwrite::All,
                },
                selected: None,
                base: None,
            },
            &Quiet,
        )
        .unwrap();
        assert!(report.errors.is_empty());
    }

    /// The archive named by R7Z_MOUNT_TEST, or None (the test is skipped) when it is unset.
    fn test_archive() -> Option<PathBuf> {
        let path = std::env::var_os("R7Z_MOUNT_TEST").map(PathBuf::from);
        if path.is_none() {
            eprintln!("skipped: set R7Z_MOUNT_TEST to an archive to run this test");
        }
        path
    }

    /// The data path without ProjFS: every file of a real archive read in name order (as
    /// Explorer opens them) through the provider's reader and compared with an extraction.
    #[test]
    #[ignore = "needs a test archive in R7Z_MOUNT_TEST"]
    fn serves_a_real_archive_in_name_order() {
        let Some(path) = test_archive() else { return };
        let tmp = path.with_file_name(format!("r7z-mount-data-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let opened = r7z::format::open(&path, &Default::default()).unwrap();
        let out = tmp.join("out");
        let t = std::time::Instant::now();
        extract_to(opened.archive(), &out);
        eprintln!("full extraction: {:?}", t.elapsed());
        let tree = Tree::build(opened.archive().entries(), "x");
        let proj = Projection::build(&tree, 0);
        let data = Arc::new(Data::new(opened.arc(), None, tmp.join("cache")));
        let mut order = Vec::new();
        files_under(&out, &out, &mut order);
        order.sort();
        let t = std::time::Instant::now();
        let mut bytes = 0u64;
        for rel in &order {
            let key: Vec<u16> = rel.as_os_str().encode_wide().collect();
            let node = proj
                .lookup(&key)
                .unwrap_or_else(|| panic!("{} is not projected", rel.display()));
            let got = read_all(&data, proj.nodes[node].entry.unwrap());
            let want = std::fs::read(out.join(rel)).unwrap();
            assert!(got == want, "{} differs", rel.display());
            bytes += got.len() as u64;
        }
        let cached = data.cache.lock().unwrap().total;
        eprintln!(
            "{} files, {bytes} bytes through the reader in {:?} (cache {} MiB)",
            order.len(),
            t.elapsed(),
            cached >> 20
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// End to end against real ProjFS: `cargo test -p r7z-gui --release -- --ignored mount`.
    /// Set R7Z_MOUNT_TEST to the archive to mount.
    #[test]
    #[ignore = "needs the Client-ProjFS Windows feature and a test archive"]
    fn mounts_an_archive_read_only() {
        if let Err(e) = available() {
            eprintln!("skipped: {e}");
            return;
        }
        let Some(path) = test_archive() else { return };
        let tmp = path.with_file_name(format!("r7z-mount-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let opened = r7z::format::open(&path, &Default::default()).unwrap();
        let out = tmp.join("out");
        extract_to(opened.archive(), &out);

        let t = std::time::Instant::now();
        let m = Mount::start(
            Source {
                archive: opened.arc(),
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                key: path.display().to_string(),
                password: None,
                time: 0,
            },
            tmp.join("cache"),
        )
        .unwrap();
        eprintln!("mounted at {} in {:?}", m.root.display(), t.elapsed());
        let root = m.root.clone();

        let mut want = Vec::new();
        files_under(&out, &out, &mut want);
        let mut got = Vec::new();
        files_under(&root, &root, &mut got);
        want.sort();
        got.sort();
        assert_eq!(got, want, "listing");

        let t = std::time::Instant::now();
        let mut bytes = 0u64;
        for rel in &want {
            let a = std::fs::read(out.join(rel)).unwrap();
            let b = std::fs::read(root.join(rel)).unwrap();
            assert!(a == b, "{} differs", rel.display());
            bytes += b.len() as u64;
        }
        eprintln!(
            "read {} files, {bytes} bytes, in {:?}",
            want.len(),
            t.elapsed()
        );

        let some = root.join(&want[0]);
        assert!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&some)
                .is_err(),
            "write"
        );
        assert!(
            std::fs::write(root.join("new.txt"), b"x").is_err(),
            "create"
        );
        assert!(std::fs::create_dir(root.join("new dir")).is_err(), "mkdir");
        assert!(std::fs::remove_file(&some).is_err(), "delete");
        assert!(
            std::fs::rename(&some, root.join("renamed")).is_err(),
            "rename"
        );
        assert!(some.exists());

        m.eject(Duration::from_secs(10));
        assert!(!root.exists(), "root removed on eject");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
