//! The app side of "Open as folder": mounting the archive being browsed, keeping the list
//! of mounts the sidebar shows, and ejecting them (from the sidebar and when the app closes).

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;
use r7z::error::Error;

use crate::app::{App, Loc};
use crate::dialogs::{Dialog, PwFor};
use crate::jobs::Task;
use crate::mount::{self, Mount, Source};
use crate::shell;

#[derive(Default)]
pub struct Mounts {
    pub active: Vec<Mount>,
    /// A mount being set up, with its key and folder name.
    pub pending: Option<(Task<Mount>, String, String)>,
    ejecting: Vec<JoinHandle<()>>,
    /// Mount this archive once it has been opened (Open as folder on a file on disk).
    after_open: Option<PathBuf>,
    seq: u32,
}

impl Mounts {
    pub fn busy(&self) -> bool {
        self.pending.is_some()
    }
}

/// Encrypted archives are checked with one small file first, so a wrong password shows up
/// here and not as unreadable files in Explorer.
fn check_password(src: &Source, cancel: &std::sync::atomic::AtomicBool) -> r7z::Result<()> {
    let a = &*src.archive;
    let probe = a
        .units()
        .iter()
        .filter(|u| u.encrypted)
        .filter_map(|u| u.entries.iter().copied().find(|&e| !a.entries()[e].is_dir))
        .filter(|&e| a.entries()[e].size_or_zero() <= 4 << 20)
        .min_by_key(|&e| a.entries()[e].size_or_zero());
    let Some(e) = probe else { return Ok(()) };
    r7z::ops::peek::read_entry(a, e, src.password.as_deref(), 4 << 20, &|| {
        cancel.load(Ordering::Relaxed)
    })
    .map(|_| ())
}

impl App {
    fn mount_key(&self, depth: usize) -> String {
        let mut key = self.stack[0].disk.display().to_string();
        for l in &self.stack[1..=depth] {
            key.push('|');
            key.push_str(&l.name);
        }
        key
    }

    /// The archive being browsed is open as a folder.
    pub fn level_is_mounted(&self) -> bool {
        let Loc::Archive { depth, .. } = self.loc else {
            return false;
        };
        let key = self.mount_key(depth);
        self.mounts.active.iter().any(|m| m.key == key)
    }

    /// Shows the archive being browsed as a folder in Explorer, mounting it first.
    pub fn open_as_folder(&mut self, ctx: &egui::Context) {
        if let Err(e) = mount::available() {
            self.message("Open as folder isn't available", &e, true);
            return;
        }
        let Loc::Archive { depth, .. } = self.loc else {
            return;
        };
        let key = self.mount_key(depth);
        if let Some(m) = self.mounts.active.iter().find(|m| m.key == key) {
            shell::open_path(&m.root);
            return;
        }
        if self
            .mounts
            .pending
            .as_ref()
            .is_some_and(|(_, k, _)| *k == key)
        {
            return;
        }
        let level = &self.stack[depth];
        if level.encrypted() && level.password.is_none() {
            self.dialog = Some(Dialog::password(PwFor::Mount, None));
            return;
        }
        let time = std::fs::metadata(&level.disk)
            .and_then(|m| m.modified())
            .map(r7z::util::time::to_filetime)
            .unwrap_or(0);
        let src = Source {
            archive: level.archive(),
            name: level.name.clone(),
            key: key.clone(),
            password: level.password.clone(),
            time,
        };
        self.mounts.seq += 1;
        let cache = shell::temp_dir().join(format!("mount-{}", self.mounts.seq));
        let name = level.name.clone();
        let task = Task::spawn(ctx, move |cancel| {
            check_password(&src, cancel)?;
            Mount::start(src, cache).map_err(Error::Other)
        });
        self.mounts.pending = Some((task, key, name));
    }

    /// Open as folder on an archive file on disk: open it here, then mount it.
    pub fn open_as_folder_from_disk(&mut self, ctx: &egui::Context, path: PathBuf) {
        if let Err(e) = mount::available() {
            self.message("Open as folder isn't available", &e, true);
            return;
        }
        self.mounts.after_open = Some(path.clone());
        self.open_disk_archive(ctx, path, None);
    }

    /// Called after an archive from disk opened.
    pub fn mount_if_asked(&mut self, ctx: &egui::Context) {
        let asked = self.mounts.after_open.take();
        if asked.is_some() && asked.as_ref() == self.stack.first().map(|l| &l.disk) {
            self.open_as_folder(ctx);
        }
    }

    pub fn finish_mount(&mut self) {
        self.mounts.ejecting.retain(|h| !h.is_finished());
        let Some((task, _, _)) = &mut self.mounts.pending else {
            return;
        };
        let Some(result) = task.take() else { return };
        self.mounts.pending = None;
        match result {
            Ok(m) => {
                shell::open_path(&m.root);
                self.toast(
                    format!("{} is open in Explorer (read-only)", m.name),
                    true,
                    None,
                );
                self.mounts.active.push(m);
            }
            Err(Error::Cancelled) => {}
            Err(Error::WrongPassword) => {
                self.dialog = Some(Dialog::password(
                    PwFor::Mount,
                    Some("That password is not correct.".into()),
                ));
            }
            Err(e) => self.message("Can't open as folder", &e.to_string(), true),
        }
    }

    /// Unmounts in the background; the folder disappears once Explorer lets go of it.
    pub fn eject(&mut self, index: usize) {
        if index >= self.mounts.active.len() {
            return;
        }
        let m = self.mounts.active.remove(index);
        if let Ok(h) = std::thread::Builder::new()
            .name("eject".into())
            .spawn(move || m.eject(Duration::from_secs(30)))
        {
            self.mounts.ejecting.push(h);
        }
    }

    /// On exit: eject everything and wait for it.
    pub fn eject_all(&mut self) {
        if let Some((mut task, _, _)) = self.mounts.pending.take() {
            let until = Instant::now() + Duration::from_secs(10);
            while !task.ready() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(20));
            }
            if let Some(Ok(m)) = task.take() {
                self.mounts.active.push(m);
            }
        }
        for m in std::mem::take(&mut self.mounts.active) {
            m.eject(Duration::ZERO);
        }
        for h in std::mem::take(&mut self.mounts.ejecting) {
            let _ = h.join();
        }
    }
}
