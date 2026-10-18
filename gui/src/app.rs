//! Application state: where the user is (a disk folder or a folder inside an archive,
//! possibly nested), what is listed and selected, and the work running in the background.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use eframe::egui;
use r7z::error::Error;
use r7z::format::{self, Archive, CodePage, Opened};
use r7z::ops::inspect::{inspect, Finding};

use crate::dialogs::Dialog;
use crate::dnd;
use crate::icons::{classify, FileClass};
use crate::jobs::{self, Job, Task};
use crate::model::{self, Row, SortCol, Target, Tree, ROOT};
use crate::preview::Preview;
use crate::shell::{self, Drive, Known};
use crate::theme;

pub enum Startup {
    None,
    Open(PathBuf),
    ExtractHere(PathBuf),
    ExtractTo(PathBuf),
    /// Several archives selected in Explorer: each goes next to itself, in one batch.
    ExtractHereAll(Vec<PathBuf>),
    /// Several archives selected in Explorer: the batch dialog asks where.
    ExtractToAll(Vec<PathBuf>),
    Add(Vec<PathBuf>),
    /// Compress right away into a new archive next to the items, with default settings.
    Compress(Vec<PathBuf>, crate::dialogs::Fmt),
    Test(PathBuf),
    Convert(PathBuf),
    /// Started from Settings → Installed apps: confirm, then remove r7z.
    Uninstall,
}

/// What to do once the archive r7z was started with has opened.
#[derive(Clone, Copy)]
pub enum Pending {
    ExtractHere,
    ExtractTo,
    Test,
    Convert,
}

/// One opened archive. Nested archives sit on top of the archive that contains them.
pub struct Level {
    pub opened: Opened,
    pub tree: Tree,
    pub name: String,
    /// The archive file on disk that this chain started from.
    pub disk: PathBuf,
    pub password: Option<String>,
    pub findings: Vec<Finding>,
    pub physical: u64,
    pub method: Option<String>,
    pub solid: bool,
    /// For nested archives: the folder node in the containing archive.
    pub parent_node: usize,
    /// A test found damage, so the archive card offers recovery.
    pub damaged: bool,
}

impl Level {
    pub fn archive(&self) -> Arc<dyn Archive> {
        self.opened.arc()
    }
    pub fn encrypted(&self) -> bool {
        self.opened.archive().has_encrypted_data()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Loc {
    Disk(PathBuf),
    /// A folder node of the archive on top of the stack.
    Archive {
        depth: usize,
        node: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    List,
    Map,
}

pub enum Opening {
    Disk(PathBuf),
    Nested { node: usize, name: String },
}

pub enum ToastAct {
    OpenArchive(PathBuf),
    Go(PathBuf),
    /// Salvage what is readable from the damaged archive at this path.
    Recover(PathBuf),
    /// Reverse the extract with this undo record.
    Undo(String),
    /// Download and install the update that was found.
    Update,
    /// Start the updated program and close this one.
    Restart,
    /// Open a web page.
    Link(String),
    /// Install r7z (Start menu, Installed apps, right-click menu).
    Install,
}

pub struct Toast {
    pub text: String,
    pub ok: bool,
    pub until: Instant,
    pub actions: Vec<(String, ToastAct)>,
}

type QueuedJob = Box<dyn FnOnce(&egui::Context) -> Job>;

/// Archive items on their way to a scratch folder for a drag or the clipboard.
struct Staged {
    /// Where the selected items will be, top level only.
    paths: Vec<PathBuf>,
    dir: PathBuf,
    ready: mpsc::Receiver<()>,
    abort: Arc<AtomicBool>,
}

pub struct App {
    pub stack: Vec<Level>,
    pub loc: Loc,
    pub back: Vec<Loc>,
    pub forward: Vec<Loc>,
    pub rows: Vec<Row>,
    pub rows_dirty: bool,
    pub list_error: Option<String>,
    pub selection: HashSet<Target>,
    pub anchor: Option<Target>,
    pub sort: (SortCol, bool),
    pub search: String,
    pub class_filter: Option<FileClass>,
    pub view: View,
    pub show_preview: bool,
    pub show_hidden: bool,
    pub show_protected: bool,
    pub update_check: Option<Task<crate::update::Check>>,
    pub update_install: Option<Task<String>>,
    /// A newer release whose signed manifest checked out.
    pub update_offer: Option<crate::update::Manifest>,
    /// The version installed by an update, waiting for a restart.
    pub update_ready: Option<String>,
    /// One line for the Updates section of Settings.
    pub update_note: Option<String>,
    update_manual: bool,
    update_due: bool,
    pub opening: Option<(Task<Opened>, Opening, Option<String>)>,
    pub staging: Vec<Task<PathBuf>>,
    pub job: Option<Job>,
    pub queue: VecDeque<QueuedJob>,
    pub job_reveal: bool,
    pub preview: Preview,
    pub dialog: Option<Dialog>,
    pub finder: Option<crate::finder::FinderState>,
    pub toasts: Vec<Toast>,
    /// The newest extract that can be undone: (record id, job title).
    pub last_undo: Option<(String, String)>,
    pub recent: Vec<PathBuf>,
    pub places: Vec<(Known, PathBuf)>,
    pub drives: Vec<Drive>,
    drives_at: Instant,
    pub theme_pref: egui::ThemePreference,
    pub cjk: bool,
    cjk_pending: bool,
    title: String,
    pub pending: Option<Pending>,
    pub exit_when_done: bool,
    pub explorer: Option<bool>,
    /// Windows 11 main-menu registration, checked in the background when Settings opens.
    pub modern_menu: Option<shell::ModernMenu>,
    pub modern_task: Option<Task<shell::ModernMenu>>,
    /// Whether and where r7z is installed; read when first needed.
    pub install_state: Option<crate::install::State>,
    pub install_task: Option<Task<PathBuf>>,
    /// The welcome tour, while it is open.
    pub tour: Option<crate::tour::Tour>,
    pub focus_search: bool,
    pub scroll_to: Option<usize>,
    title_dark: Option<bool>,
    pub hwnd: isize,
    /// A drag out of the list in progress, with the scratch folder for archive items.
    pub drag: Option<(dnd::Drag, Option<PathBuf>)>,
    /// A drag already started during the current mouse press.
    pub drag_spent: bool,
    /// OLE swallowed the button release; egui gets a synthetic one next frame.
    release_pointer: bool,
    pub paste_down: bool,
    pub pastes: Vec<Task<()>>,
    stage_seq: u32,
    /// Archives open as folders in Explorer.
    pub mounts: crate::open_folder::Mounts,
}

pub fn stem_of(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    for ext in [
        ".tar.gz",
        ".tar.xz",
        ".tar.bz2",
        ".tar.zst",
        ".tar.lz4",
        ".tar.lzma",
        ".tar.z",
    ] {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return name[..name.len() - ext.len()].to_string();
        }
    }
    path.file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or(name)
}

pub fn looks_like_archive(path: &Path) -> bool {
    use std::io::Read;
    if classify(&path.to_string_lossy()) == FileClass::Archive {
        return true;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = vec![0u8; 1 << 16];
    let n = f.read(&mut head).unwrap_or(0);
    head.truncate(n);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format::detect_format(&head, &name).is_some()
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, startup: Startup) -> App {
        let theme_pref = match shell::load_setting("theme").as_deref() {
            Some("light") => egui::ThemePreference::Light,
            Some("dark") => egui::ThemePreference::Dark,
            _ => egui::ThemePreference::System,
        };
        theme::install_fonts(&cc.egui_ctx, false);
        theme::apply(&cc.egui_ctx, theme_pref);
        std::thread::spawn(shell::sweep_stale_temp);
        std::thread::spawn(crate::mount::sweep_stale);
        std::thread::spawn(crate::update::cleanup);
        let places: Vec<(Known, PathBuf)> = [
            Known::Home,
            Known::Desktop,
            Known::Downloads,
            Known::Documents,
            Known::Pictures,
        ]
        .into_iter()
        .filter_map(|k| {
            shell::known_folder(k)
                .filter(|p| p.is_dir())
                .map(|p| (k, p))
        })
        .collect();
        let start_dir = shell::load_setting("last_dir")
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .or_else(|| {
                places
                    .iter()
                    .find(|(k, _)| *k == Known::Downloads)
                    .map(|(_, p)| p.clone())
            })
            .or_else(|| places.first().map(|(_, p)| p.clone()))
            .unwrap_or_else(|| PathBuf::from("C:\\"));
        let mut app = App {
            stack: Vec::new(),
            loc: Loc::Disk(start_dir),
            back: Vec::new(),
            forward: Vec::new(),
            rows: Vec::new(),
            rows_dirty: true,
            list_error: None,
            selection: HashSet::new(),
            anchor: None,
            sort: (SortCol::Name, true),
            search: String::new(),
            class_filter: None,
            view: View::List,
            show_preview: shell::load_setting("preview").as_deref() != Some("off"),
            show_hidden: shell::load_setting("hidden").as_deref() == Some("on"),
            show_protected: shell::load_setting("protected").as_deref() == Some("on"),
            update_check: None,
            update_install: None,
            update_offer: None,
            update_ready: None,
            update_note: None,
            update_manual: false,
            update_due: auto_updates() && update_due(),
            opening: None,
            staging: Vec::new(),
            job: None,
            queue: VecDeque::new(),
            job_reveal: false,
            preview: Preview::default(),
            dialog: None,
            finder: None,
            toasts: Vec::new(),
            last_undo: crate::undo::Store::user().and_then(|s| crate::undo::latest(&s)),
            recent: shell::load_recent(),
            places,
            drives: shell::drives(),
            drives_at: Instant::now(),
            theme_pref,
            cjk: false,
            cjk_pending: false,
            title: String::new(),
            pending: None,
            exit_when_done: false,
            explorer: None,
            modern_menu: None,
            modern_task: None,
            install_state: None,
            install_task: None,
            tour: None,
            focus_search: false,
            scroll_to: None,
            title_dark: None,
            hwnd: 0,
            drag: None,
            drag_spent: false,
            release_pointer: false,
            paste_down: false,
            pastes: Vec::new(),
            stage_seq: 0,
            mounts: Default::default(),
        };
        let ctx = &cc.egui_ctx;
        // The tour opens by itself on a normal first launch, not when r7z was started
        // from the Explorer menu to extract or compress something.
        let normal = matches!(startup, Startup::None | Startup::Open(_));
        if normal && crate::tour::first_run() {
            crate::tour::open(&mut app);
        } else if normal {
            crate::install::refresh();
            app.offer_install();
        }
        match startup {
            Startup::Uninstall => app.dialog = Some(Dialog::Uninstall { from_windows: true }),
            Startup::None => {}
            Startup::Open(p) if p.is_dir() => app.loc = Loc::Disk(p),
            Startup::Open(p) => app.open_disk_archive(ctx, p, None),
            Startup::ExtractHere(p)
            | Startup::ExtractTo(p)
            | Startup::Test(p)
            | Startup::Convert(p)
                if !p.exists() =>
            {
                app.message(
                    "Can't find the file",
                    &format!("{} does not exist.", p.display()),
                    true,
                );
            }
            Startup::ExtractHere(p) => {
                app.exit_when_done = true;
                app.pending = Some(Pending::ExtractHere);
                app.open_disk_archive(ctx, p, None);
            }
            Startup::ExtractTo(p) => {
                app.exit_when_done = true;
                app.pending = Some(Pending::ExtractTo);
                app.open_disk_archive(ctx, p, None);
            }
            // The result of a test stays on screen, so the window stays open.
            Startup::Test(p) => {
                app.pending = Some(Pending::Test);
                app.open_disk_archive(ctx, p, None);
            }
            Startup::Convert(p) => {
                app.exit_when_done = true;
                app.pending = Some(Pending::Convert);
                app.open_disk_archive(ctx, p, None);
            }
            Startup::ExtractHereAll(archives) => {
                if let Some(dir) = archives.first().and_then(|p| p.parent()) {
                    app.loc = Loc::Disk(dir.to_path_buf());
                }
                app.exit_when_done = true;
                app.enqueue(ctx, move |ctx| {
                    jobs::batch_extract(
                        ctx,
                        archives,
                        jobs::BatchDest::Smart,
                        r7z::ops::extract::Overwrite::Ask,
                        None,
                    )
                });
            }
            Startup::ExtractToAll(archives) => {
                if let Some(dir) = archives.first().and_then(|p| p.parent()) {
                    app.loc = Loc::Disk(dir.to_path_buf());
                }
                app.exit_when_done = true;
                app.dialog = Some(Dialog::batch(archives));
            }
            Startup::Add(paths) => {
                if let Some(dir) = paths.first().and_then(|p| p.parent()) {
                    app.loc = Loc::Disk(dir.to_path_buf());
                }
                app.exit_when_done = true;
                app.dialog = Some(Dialog::pack(paths));
            }
            Startup::Compress(paths, format) => {
                if let Some(dir) = paths.first().and_then(|p| p.parent()) {
                    app.loc = Loc::Disk(dir.to_path_buf());
                }
                app.exit_when_done = true;
                let req = jobs::CreateRequest {
                    archive: PathBuf::from(crate::dialogs::default_archive_path(&paths, format)),
                    paths,
                    level: 5,
                    password: None,
                    encrypt_names: false,
                    solid: true,
                };
                app.enqueue(ctx, move |ctx| jobs::create(ctx, req));
            }
        }
        app
    }

    pub fn message(&mut self, title: &str, body: &str, error: bool) {
        self.dialog = Some(Dialog::Message {
            title: title.into(),
            body: body.into(),
            error,
        });
    }

    /// A toast that stays up long enough to be acted on later.
    pub fn toast_long(&mut self, text: String, ok: bool, actions: Vec<(String, ToastAct)>) {
        self.toast_with(text, ok, actions);
        if let Some(t) = self.toasts.last_mut() {
            t.until = Instant::now() + Duration::from_secs(60);
        }
    }

    /// Runs a Windows 11 menu action (status, install, uninstall) off the UI thread.
    pub fn install_state(&mut self) -> crate::install::State {
        self.install_state
            .get_or_insert_with(crate::install::state)
            .clone()
    }

    /// Copies r7z to its install folder and registers it, in the background.
    pub fn start_install(&mut self, ctx: &egui::Context) {
        if self.install_task.is_none() {
            self.install_task = Some(Task::spawn(ctx, |_| {
                crate::install::install().map_err(Error::Other)
            }));
        }
    }

    /// Once, for people who had r7z before it could be installed: a toast that offers it.
    fn offer_install(&mut self) {
        if !cfg!(windows) || shell::load_setting("install_offer").is_some() {
            return;
        }
        if self.install_state() == crate::install::State::NotInstalled {
            shell::save_setting("install_offer", "shown");
            self.toast_long(
                "Install r7z to find it in the Start menu and Windows search".into(),
                true,
                vec![("Install".into(), ToastAct::Install)],
            );
        }
    }

    fn poll_install(&mut self, ctx: &egui::Context) {
        let Some(result) = self.install_task.as_mut().and_then(|t| t.take()) else {
            return;
        };
        self.install_task = None;
        self.install_state = None;
        self.explorer = None;
        self.modern_menu = None;
        match result {
            Ok(exe) => {
                let current = std::env::current_exe().ok();
                let moved =
                    current.is_none_or(|c| c.canonicalize().ok() != exe.canonicalize().ok());
                // Carry on in the installed copy, so updates go there.
                if moved && std::process::Command::new(&exe).spawn().is_ok() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                } else {
                    self.toast(
                        "r7z is installed. Find it in the Start menu or Windows search".into(),
                        true,
                        None,
                    );
                }
            }
            Err(e) => self.message("Couldn't install r7z", &e.to_string(), true),
        }
    }

    pub fn modern_menu_job(&mut self, ctx: &egui::Context, f: fn() -> shell::ModernMenu) {
        if self.modern_task.is_none() {
            self.modern_task = Some(Task::spawn(ctx, move |_| Ok(f())));
        }
    }

    pub fn check_for_updates(&mut self, ctx: &egui::Context, manual: bool) {
        if self.update_check.is_some() || self.update_install.is_some() {
            return;
        }
        self.update_manual = manual;
        if manual {
            self.update_note = Some("Checking…".into());
        }
        self.update_check = Some(Task::spawn(ctx, crate::update::check));
    }

    pub fn install_update(&mut self, ctx: &egui::Context) {
        let Some(m) = self.update_offer.clone() else {
            return;
        };
        if self.update_install.is_some() {
            return;
        }
        self.update_note = Some(format!("Downloading r7z {}…", m.version));
        self.update_install = Some(Task::spawn(ctx, move |cancel| {
            crate::update::download_and_install(&m, cancel)
        }));
    }

    pub fn restart(&mut self, ctx: &egui::Context) {
        match crate::update::relaunch() {
            Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(e) => self.toast(format!("Couldn't restart r7z: {e}"), false, None),
        }
    }

    fn poll_updates(&mut self, ctx: &egui::Context) {
        if std::mem::take(&mut self.update_due) {
            self.check_for_updates(ctx, false);
        }
        if let Some(result) = self.update_check.as_mut().and_then(|t| t.take()) {
            self.update_check = None;
            let manual = self.update_manual;
            match result {
                Ok(crate::update::Check::Available(m)) => {
                    mark_update_checked();
                    let (version, url) = (m.version.clone(), m.release_url());
                    self.update_note = Some(format!("r7z {version} is available"));
                    self.update_offer = Some(m);
                    if shell::load_setting("update_install").as_deref() == Some("auto") {
                        self.install_update(ctx);
                    } else {
                        self.toast_long(
                            format!("r7z {version} is available"),
                            true,
                            vec![
                                ("Update".into(), ToastAct::Update),
                                ("What's new".into(), ToastAct::Link(url)),
                            ],
                        );
                    }
                }
                Ok(crate::update::Check::UpToDate) => {
                    mark_update_checked();
                    self.update_note = Some("You have the latest version".into());
                    if manual {
                        self.toast(
                            format!("r7z {} is the latest version", crate::update::CURRENT),
                            true,
                            None,
                        );
                    }
                }
                Err(e) => {
                    self.update_note = Some(format!("Couldn't check: {e}"));
                    if manual {
                        self.toast(format!("Couldn't check for updates: {e}"), false, None);
                    }
                }
            }
        }
        if let Some(result) = self.update_install.as_mut().and_then(|t| t.take()) {
            self.update_install = None;
            match result {
                Ok(version) => {
                    self.update_offer = None;
                    self.update_note =
                        Some(format!("r7z {version} is installed; restart to use it"));
                    self.update_ready = Some(version.clone());
                    self.toast_long(
                        format!("Updated to r7z {version}"),
                        true,
                        vec![("Restart now".into(), ToastAct::Restart)],
                    );
                }
                Err(e) => {
                    self.update_note = Some(format!("Update failed: {e}"));
                    let url = self.update_offer.as_ref().map(|m| m.release_url());
                    self.toast_long(
                        format!("The update didn't install: {e}"),
                        false,
                        url.map(|u| ("Download page".to_string(), ToastAct::Link(u)))
                            .into_iter()
                            .collect(),
                    );
                }
            }
        }
    }

    pub fn toast(&mut self, text: String, ok: bool, action: Option<(String, ToastAct)>) {
        self.toast_with(text, ok, action.into_iter().collect());
    }

    pub fn toast_with(&mut self, text: String, ok: bool, actions: Vec<(String, ToastAct)>) {
        self.toasts.push(Toast {
            text,
            ok,
            until: Instant::now() + Duration::from_secs(8),
            actions,
        });
        if self.toasts.len() > 4 {
            self.toasts.remove(0);
        }
    }

    pub fn level(&self) -> Option<&Level> {
        self.stack.last()
    }

    pub fn in_archive(&self) -> bool {
        matches!(self.loc, Loc::Archive { .. })
    }

    /// The disk folder relevant right now: the listed folder, or the one holding the archive.
    pub fn disk_dir(&self) -> PathBuf {
        match &self.loc {
            Loc::Disk(d) => d.clone(),
            Loc::Archive { .. } => self
                .stack
                .first()
                .and_then(|l| l.disk.parent().map(Path::to_path_buf))
                .unwrap_or_default(),
        }
    }

    // ------------------------------------------------------------------ navigation

    fn set_loc(&mut self, loc: Loc) {
        if loc == self.loc {
            return;
        }
        if let Loc::Disk(d) = &loc {
            shell::save_setting("last_dir", &d.display().to_string());
        }
        self.loc = loc;
        self.selection.clear();
        self.anchor = None;
        self.search.clear();
        self.class_filter = None;
        self.rows_dirty = true;
        self.preview.clear();
        if !self.in_archive() {
            self.view = View::List;
        }
    }

    pub fn go(&mut self, loc: Loc) {
        if loc == self.loc {
            return;
        }
        let prev = self.loc.clone();
        self.back.push(prev);
        self.forward.clear();
        self.leave_archives_for(&loc);
        self.set_loc(loc);
    }

    /// Drops archive levels the new location no longer needs, and history entries into them.
    fn leave_archives_for(&mut self, loc: &Loc) {
        let keep = match loc {
            Loc::Disk(_) => 0,
            Loc::Archive { depth, .. } => depth + 1,
        };
        if self.stack.len() > keep {
            self.stack.truncate(keep);
            let valid = |l: &Loc| match l {
                Loc::Disk(_) => true,
                Loc::Archive { depth, .. } => *depth < keep,
            };
            self.back.retain(valid);
            self.forward.retain(valid);
        }
    }

    pub fn go_back(&mut self) {
        if let Some(prev) = self.back.pop() {
            self.forward.push(self.loc.clone());
            self.leave_archives_for(&prev);
            self.set_loc(prev);
        }
    }

    pub fn go_forward(&mut self) {
        if let Some(next) = self.forward.pop() {
            self.back.push(self.loc.clone());
            self.leave_archives_for(&next);
            self.set_loc(next);
        }
    }

    pub fn parent_loc(&self) -> Option<Loc> {
        match &self.loc {
            Loc::Disk(d) => d.parent().map(|p| Loc::Disk(p.to_path_buf())),
            Loc::Archive { depth, node } => {
                let level = &self.stack[*depth];
                if *node != ROOT {
                    Some(Loc::Archive {
                        depth: *depth,
                        node: level.tree.nodes[*node].parent,
                    })
                } else if *depth > 0 {
                    Some(Loc::Archive {
                        depth: depth - 1,
                        node: level.parent_node,
                    })
                } else {
                    level.disk.parent().map(|p| Loc::Disk(p.to_path_buf()))
                }
            }
        }
    }

    pub fn go_up(&mut self) {
        if let Some(l) = self.parent_loc() {
            self.go(l);
        }
    }

    // ------------------------------------------------------------------ listing

    pub fn refresh_rows(&mut self) {
        if !self.rows_dirty {
            return;
        }
        self.rows_dirty = false;
        self.list_error = None;
        let q = self.search.trim().to_lowercase();
        let mut rows = match &self.loc {
            Loc::Disk(dir) => match model::list_dir(dir) {
                Ok(r) => r
                    .into_iter()
                    .filter(|r| self.show_hidden || !r.hidden)
                    .filter(|r| (self.show_hidden && self.show_protected) || !r.protected)
                    .filter(|r| q.is_empty() || r.name.to_lowercase().contains(&q))
                    .collect(),
                Err(e) => {
                    self.list_error = Some(e.to_string());
                    Vec::new()
                }
            },
            Loc::Archive { depth, node } => {
                let t = &self.stack[*depth].tree;
                if q.is_empty() {
                    t.nodes[*node]
                        .children
                        .iter()
                        .map(|&c| model::node_row(t, c, false))
                        .collect()
                } else {
                    let mut out = Vec::new();
                    let mut stack = vec![*node];
                    while let Some(n) = stack.pop() {
                        for &c in &t.nodes[n].children {
                            if t.nodes[c].name.to_lowercase().contains(&q) {
                                out.push(model::node_row(t, c, true));
                            }
                            stack.push(c);
                        }
                        if out.len() >= 50_000 {
                            break;
                        }
                    }
                    out
                }
            }
        };
        if let Some(c) = self.class_filter {
            rows.retain(|r| r.is_dir || r.class == c);
            if self.search.trim().is_empty() {
                rows.retain(|r| !r.is_dir);
            }
        }
        model::sort_rows(&mut rows, self.sort.0, self.sort.1);
        self.rows = rows;
        let present: HashSet<&Target> = self.rows.iter().map(|r| &r.target).collect();
        self.selection.retain(|t| present.contains(t));
        self.check_fonts_for_rows();
    }

    fn check_fonts_for_rows(&mut self) {
        if self.cjk {
            return;
        }
        if self
            .rows
            .iter()
            .take(5000)
            .any(|r| r.name.chars().any(|c| c >= '\u{2E80}'))
        {
            self.cjk = true;
            self.cjk_pending = true;
        }
    }

    pub fn selected_rows(&self) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|r| self.selection.contains(&r.target))
            .collect()
    }

    pub fn single_selected(&self) -> Option<&Row> {
        let mut it = self
            .rows
            .iter()
            .filter(|r| self.selection.contains(&r.target));
        let first = it.next()?;
        if it.next().is_some() {
            None
        } else {
            Some(first)
        }
    }

    /// Entry selection for extracting what is selected in the current archive folder.
    pub fn selected_entries(&self) -> Option<Vec<bool>> {
        let Loc::Archive { depth, .. } = self.loc else {
            return None;
        };
        let level = &self.stack[depth];
        if self.selection.is_empty() {
            return None;
        }
        let mut idx = Vec::new();
        for t in &self.selection {
            if let Target::Node(n) = t {
                level.tree.collect_entries(*n, &mut idx);
            }
        }
        let mut sel = vec![false; level.opened.archive().entries().len()];
        for i in idx {
            sel[i] = true;
        }
        Some(sel)
    }

    pub fn bytes_of(&self, sel: &Option<Vec<bool>>) -> u64 {
        let Some(l) = self.level() else { return 0 };
        l.opened
            .archive()
            .entries()
            .iter()
            .enumerate()
            .filter(|(i, _)| sel.as_ref().is_none_or(|s| s[*i]))
            .map(|(_, e)| e.size_or_zero())
            .sum()
    }

    /// The archive path of the folder being viewed (`a/b`), used as the extraction base.
    pub fn archive_base(&self) -> Option<String> {
        match self.loc {
            Loc::Archive { depth, node } if node != ROOT => {
                Some(self.stack[depth].tree.nodes[node].path.clone())
            }
            _ => None,
        }
    }

    // ------------------------------------------------------------------ opening

    pub fn open_disk_archive(
        &mut self,
        ctx: &egui::Context,
        path: PathBuf,
        password: Option<String>,
    ) {
        let task = jobs::open_disk(ctx, path.clone(), password.clone(), None);
        self.opening = Some((task, Opening::Disk(path), password));
    }

    pub fn open_nested(&mut self, ctx: &egui::Context, node: usize, password: Option<String>) {
        self.open_nested_as(ctx, node, password, None);
    }

    /// Opens the current archive again with its names decoded in `code_page` (`None`:
    /// detected), from the top of its listing.
    pub fn relist_with_code_page(&mut self, ctx: &egui::Context, code_page: Option<CodePage>) {
        let Loc::Archive { depth, .. } = self.loc else {
            return;
        };
        let level = &self.stack[depth];
        let password = level.password.clone();
        if depth == 0 {
            let path = level.disk.clone();
            let task = jobs::open_disk(ctx, path.clone(), password.clone(), code_page);
            self.opening = Some((task, Opening::Disk(path), password));
            return;
        }
        // A nested archive is opened again from the folder that holds it.
        let parent = level.parent_node;
        let tree = &self.stack[depth - 1].tree;
        let Some(node) = tree.nodes[parent]
            .children
            .iter()
            .copied()
            .find(|&c| tree.nodes[c].name == level.name)
        else {
            return;
        };
        self.stack.truncate(depth);
        self.set_loc(Loc::Archive {
            depth: depth - 1,
            node: parent,
        });
        self.open_nested_as(ctx, node, password, code_page);
    }

    fn open_nested_as(
        &mut self,
        ctx: &egui::Context,
        node: usize,
        password: Option<String>,
        code_page: Option<CodePage>,
    ) {
        let Loc::Archive { depth, .. } = self.loc else {
            return;
        };
        let level = &self.stack[depth];
        let Some(entry) = level.tree.nodes[node].entry else {
            return;
        };
        let name = level.tree.nodes[node].name.clone();
        let pw = password.or_else(|| level.password.clone());
        let task = jobs::open_nested(
            ctx,
            level.archive(),
            entry,
            name.clone(),
            pw.clone(),
            code_page,
        );
        self.opening = Some((task, Opening::Nested { node, name }, pw));
    }

    fn add_recent(&mut self, path: &Path) {
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_path_buf());
        self.recent.truncate(12);
        shell::save_recent(&self.recent);
    }

    fn build_level(
        opened: Opened,
        name: String,
        disk: PathBuf,
        password: Option<String>,
        physical: u64,
        parent_node: usize,
    ) -> Level {
        let a = opened.archive();
        let tree = Tree::build(a.entries(), &name);
        let props = a.properties();
        let prop = |k: &str| props.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        Level {
            findings: inspect(a.entries(), Some(physical)),
            method: prop("Method"),
            solid: prop("Solid").as_deref() == Some("+"),
            tree,
            name,
            disk,
            password,
            physical,
            parent_node,
            opened,
            damaged: false,
        }
    }

    fn finish_open(&mut self, ctx: &egui::Context) {
        let Some((task, _, _)) = &mut self.opening else {
            return;
        };
        let Some(result) = task.take() else { return };
        let (_, what, password) = self.opening.take().unwrap();
        match (result, what) {
            (Ok(opened), Opening::Disk(path)) => {
                let name = jobs::file_name(&path);
                let physical = opened
                    .levels
                    .first()
                    .and_then(|l| l.physical_size)
                    .unwrap_or(0);
                let level = Self::build_level(opened, name, path.clone(), password, physical, ROOT);
                self.add_recent(&path);
                let from = self.loc.clone();
                self.stack = vec![level];
                self.back.retain(|l| matches!(l, Loc::Disk(_)));
                self.forward.clear();
                if let Loc::Disk(_) = from {
                    self.back.push(from);
                }
                self.set_loc(Loc::Archive {
                    depth: 0,
                    node: ROOT,
                });
                self.after_open(ctx);
            }
            (Ok(opened), Opening::Nested { name, .. }) => {
                let Some(outer) = self.stack.last() else {
                    return;
                };
                let disk = outer.disk.clone();
                let physical = opened
                    .levels
                    .first()
                    .and_then(|l| l.physical_size)
                    .unwrap_or(0);
                let parent = match self.loc {
                    Loc::Archive { node: n, .. } => n,
                    _ => ROOT,
                };
                let level = Self::build_level(opened, name, disk, password, physical, parent);
                self.stack.push(level);
                let depth = self.stack.len() - 1;
                self.back.push(self.loc.clone());
                self.forward.clear();
                self.set_loc(Loc::Archive { depth, node: ROOT });
            }
            (Err(Error::PasswordRequired), what) => {
                self.dialog = Some(Dialog::password(crate::dialogs::PwFor::Open(what), None));
            }
            (Err(Error::WrongPassword), what) => {
                self.dialog = Some(Dialog::password(
                    crate::dialogs::PwFor::Open(what),
                    Some("That password is not correct.".into()),
                ));
            }
            (Err(Error::NotArchive), Opening::Disk(path)) => {
                self.exit_when_done = false;
                shell::open_path(&path);
            }
            (Err(Error::Cancelled), _) => {}
            (Err(e @ (Error::Corrupt(_) | Error::Checksum(_))), Opening::Disk(path)) => {
                self.exit_when_done = false;
                self.toast(
                    format!("Can't open {}: {e}", jobs::file_name(&path)),
                    false,
                    Some(("Recover files…".into(), ToastAct::Recover(path))),
                );
            }
            (Err(e), what) => {
                self.exit_when_done = false;
                let name = match &what {
                    Opening::Disk(p) => p.display().to_string(),
                    Opening::Nested { name, .. } => name.clone(),
                };
                self.message("Can't open this archive", &format!("{name}\n\n{e}"), true);
            }
        }
    }

    fn after_open(&mut self, ctx: &egui::Context) {
        self.mount_if_asked(ctx);
        let here = match self.pending.take() {
            None => return,
            Some(Pending::Test) => return self.start_test(ctx),
            Some(Pending::Convert) => return self.open_convert(),
            Some(Pending::ExtractHere) => true,
            Some(Pending::ExtractTo) => false,
        };
        let Some(level) = self.stack.first() else {
            return;
        };
        let dest = if here {
            jobs::smart_destination(level.opened.archive().entries(), &level.disk)
        } else {
            level
                .disk
                .parent()
                .map(|p| p.join(stem_of(&level.disk)))
                .unwrap_or_default()
        };
        let mut form = crate::dialogs::ExtractForm::new(self);
        form.dest = dest.display().to_string();
        form.selected_only = false;
        form.open_after = false;
        self.start_extract(ctx, form);
    }

    /// Double-click / Enter on a row.
    pub fn activate(&mut self, ctx: &egui::Context, target: &Target) {
        match target {
            Target::Disk(p) => {
                if p.is_dir() {
                    self.go(Loc::Disk(p.clone()));
                } else if looks_like_archive(p) {
                    self.open_disk_archive(ctx, p.clone(), None);
                } else {
                    shell::open_path(p);
                }
            }
            Target::Node(n) => {
                let Loc::Archive { depth, .. } = self.loc else {
                    return;
                };
                let level = &self.stack[depth];
                let node = &level.tree.nodes[*n];
                if node.is_dir {
                    self.go(Loc::Archive { depth, node: *n });
                } else if classify(&node.name) == FileClass::Archive {
                    self.open_nested(ctx, *n, None);
                } else {
                    self.launch(ctx, *n);
                }
            }
        }
    }

    pub fn launch(&mut self, ctx: &egui::Context, node: usize) {
        let Loc::Archive { depth, .. } = self.loc else {
            return;
        };
        let level = &self.stack[depth];
        let Some(entry) = level.tree.nodes[node].entry else {
            return;
        };
        if level.opened.archive().entries()[entry].encrypted && level.password.is_none() {
            self.dialog = Some(Dialog::password(crate::dialogs::PwFor::Launch(node), None));
            return;
        }
        let dir = shell::temp_dir().join(format!("{depth}-{entry}"));
        self.staging.push(jobs::stage_entry(
            ctx,
            level.archive(),
            level.password.clone(),
            entry,
            dir,
        ));
        self.toast(
            format!("Opening {}", level.tree.nodes[node].name),
            true,
            None,
        );
    }

    // ------------------------------------------------------------------ jobs

    /// Runs `make` now, or after the current job.
    pub fn enqueue(
        &mut self,
        ctx: &egui::Context,
        make: impl FnOnce(&egui::Context) -> Job + 'static,
    ) {
        if self.job.is_none() {
            self.job = Some(make(ctx));
        } else {
            self.queue.push_back(Box::new(make));
            self.toast(
                "Queued; it starts when the current task finishes".into(),
                true,
                None,
            );
        }
    }

    pub fn start_extract(&mut self, ctx: &egui::Context, mut form: crate::dialogs::ExtractForm) {
        let Some(level) = self.stack.last_mut() else {
            return;
        };
        if !form.password.is_empty() {
            level.password = Some(form.password.clone());
        }
        if level.encrypted() && level.password.is_none() {
            self.dialog = Some(Dialog::password(crate::dialogs::PwFor::Extract(form), None));
            return;
        }
        if form.dest.trim().is_empty() {
            form.error = Some("Choose where to put the files.".into());
            self.dialog = Some(Dialog::Extract(form));
            return;
        }
        let selected = if form.selected_only {
            self.selected_entries()
        } else {
            None
        };
        let base = if form.selected_only && form.full_paths {
            self.archive_base()
        } else {
            None
        };
        let total = self.bytes_of(&selected);
        let level = self.stack.last().unwrap();
        let req = jobs::ExtractRequest {
            archive: level.archive(),
            password: level.password.clone(),
            selected,
            base,
            dest: PathBuf::from(form.dest.trim()),
            full_paths: form.full_paths,
            overwrite: form.overwrite,
            total,
        };
        let title = format!("Extracting {}", level.name);
        self.job_reveal = form.open_after;
        self.enqueue(ctx, move |ctx| jobs::extract(ctx, title, req));
    }

    pub fn open_convert(&mut self) {
        let Some(level) = self.stack.last() else {
            return;
        };
        let disk = &self.stack[0].disk;
        let dir = disk.parent().map(Path::to_path_buf).unwrap_or_default();
        let stem = stem_of(Path::new(&level.name));
        let current = crate::icons::extension(&level.name);
        let format = if current == "7z" {
            crate::dialogs::Fmt::Zip
        } else {
            crate::dialogs::Fmt::SevenZ
        };
        let mut path = dir.join(format!("{stem}.{}", format.ext()));
        let mut n = 2;
        while path.exists() {
            path = dir.join(format!("{stem} ({n}).{}", format.ext()));
            n += 1;
        }
        self.dialog = Some(Dialog::Convert(crate::dialogs::ConvertForm {
            format,
            level: 5,
            archive: path.display().to_string(),
            error: None,
        }));
    }

    pub fn smart_extract_here(&mut self, ctx: &egui::Context) {
        let Some(level) = self.stack.first() else {
            return;
        };
        let dest = if self.selection.is_empty() {
            jobs::smart_destination(level.opened.archive().entries(), &level.disk)
        } else {
            level
                .disk
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default()
        };
        let mut form = crate::dialogs::ExtractForm::new(self);
        form.dest = dest.display().to_string();
        form.open_after = false;
        self.start_extract(ctx, form);
    }

    pub fn start_test(&mut self, ctx: &egui::Context) {
        let Some(level) = self.stack.last() else {
            return;
        };
        if level.encrypted() && level.password.is_none() {
            self.dialog = Some(Dialog::password(crate::dialogs::PwFor::Test, None));
            return;
        }
        let total = self.bytes_of(&None);
        let (a, pw, title) = (
            level.archive(),
            level.password.clone(),
            format!("Testing {}", level.name),
        );
        self.enqueue(ctx, move |ctx| jobs::test(ctx, title, a, pw, total));
    }

    fn finish_job(&mut self, ctx: &egui::Context) {
        if !self.job.as_ref().is_some_and(|j| j.finished()) {
            return;
        }
        let mut job = self.job.take().unwrap();
        let warnings = std::mem::take(&mut *job.shared.warnings.lock().unwrap());
        let mut undo_id = job.shared.undo.lock().unwrap().take();
        let elapsed = job.shared.started.elapsed();
        let mut success = false;
        match job.join() {
            Ok(jobs::Outcome::Extracted { report, dest }) => {
                self.rows_dirty = true;
                if report.errors.is_empty() {
                    success = true;
                    let mut text = if report.files == 0 && report.skipped > 0 {
                        "Nothing new to extract".to_string()
                    } else {
                        format!(
                            "Extracted {} in {}",
                            crate::ui::summary(report.files, report.dirs, report.bytes),
                            crate::ui::secs(elapsed)
                        )
                    };
                    if report.skipped > 0 {
                        text.push_str(&format!(" · skipped {} existing", report.skipped));
                    }
                    let mut actions = vec![("Show".into(), ToastAct::Go(dest.clone()))];
                    actions.extend(undo_id.take().map(|id| ("Undo".into(), ToastAct::Undo(id))));
                    self.toast_with(text, true, actions);
                    if self.job_reveal {
                        shell::open_path(&dest);
                    }
                } else if report
                    .errors
                    .iter()
                    .all(|(_, e)| matches!(e, Error::WrongPassword))
                {
                    self.retry_with_password();
                } else {
                    self.report_errors(
                        "Some files could not be extracted",
                        &report.errors,
                        report.files,
                    );
                }
            }
            Ok(jobs::Outcome::Tested(report)) => {
                if report.errors.is_empty() {
                    success = true;
                    self.toast(
                        format!(
                            "No errors · {} checked in {}",
                            crate::ui::summary(report.files, 0, report.bytes),
                            crate::ui::secs(elapsed)
                        ),
                        true,
                        None,
                    );
                } else if report
                    .errors
                    .iter()
                    .all(|(_, e)| matches!(e, Error::WrongPassword))
                {
                    if let Some(l) = self.stack.last_mut() {
                        l.password = None;
                    }
                    self.dialog = Some(Dialog::password(
                        crate::dialogs::PwFor::Test,
                        Some("That password is not correct.".into()),
                    ));
                } else {
                    self.report_errors("This archive is damaged", &report.errors, report.files);
                    if let Some(l) = self.stack.last_mut() {
                        l.damaged = true;
                        let disk = l.disk.clone();
                        if self.stack.len() == 1 {
                            self.toast(
                                "Some files are damaged".into(),
                                false,
                                Some(("Recover files…".into(), ToastAct::Recover(disk))),
                            );
                        }
                    }
                }
            }
            Ok(jobs::Outcome::Recovered { report, dest, name }) => {
                self.rows_dirty = true;
                success = report.lost() == 0 && report.partial() == 0;
                self.toast(
                    crate::recover::headline(&report),
                    success,
                    Some(("Show".into(), ToastAct::Go(dest.clone()))),
                );
                self.dialog = Some(Dialog::Recovered(crate::recover::RecoverView {
                    name,
                    dest,
                    report,
                }));
            }
            Ok(jobs::Outcome::Created { summary: s, path }) => {
                success = true;
                self.rows_dirty = true;
                let ratio = if s.input_bytes > 0 {
                    format!(
                        " ({:.0}%)",
                        s.archive_bytes as f64 * 100.0 / s.input_bytes as f64
                    )
                } else {
                    String::new()
                };
                self.toast(
                    format!(
                        "{} · {} → {}{ratio} in {}",
                        jobs::file_name(&path),
                        r7z::util::fmt::human_size(s.input_bytes),
                        r7z::util::fmt::human_size(s.archive_bytes),
                        crate::ui::secs(elapsed)
                    ),
                    true,
                    Some(("Open".into(), ToastAct::OpenArchive(path))),
                );
                if !warnings.is_empty() {
                    let body = warnings
                        .iter()
                        .take(30)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.message(
                        &format!("{} items were skipped", warnings.len()),
                        &body,
                        false,
                    );
                }
            }
            Ok(jobs::Outcome::Batch {
                done,
                failed,
                files,
                bytes,
            }) => {
                self.rows_dirty = true;
                success = failed.is_empty();
                if !done.is_empty() {
                    let last = done.last().map(|(_, d)| d.clone()).unwrap_or_default();
                    let mut actions = vec![("Show".into(), ToastAct::Go(last))];
                    actions.extend(undo_id.take().map(|id| ("Undo".into(), ToastAct::Undo(id))));
                    self.toast_with(
                        format!(
                            "Extracted {} archives · {}",
                            done.len(),
                            crate::ui::summary(files, 0, bytes)
                        ),
                        true,
                        actions,
                    );
                }
                if !failed.is_empty() {
                    let body = failed
                        .iter()
                        .map(|(p, e)| format!("{}: {e}", jobs::file_name(p)))
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.message(
                        &format!("{} archives could not be extracted", failed.len()),
                        &body,
                        true,
                    );
                }
            }
            Ok(jobs::Outcome::Undone(r)) => {
                self.rows_dirty = true;
                success = r.errors.is_empty();
                self.toast(crate::undo::headline(&r), success, None);
                if !r.errors.is_empty() || !r.beside.is_empty() {
                    let mut body = String::new();
                    for (p, e) in r.errors.iter().take(20) {
                        body.push_str(&format!("{}\n    {e}\n", p.display()));
                    }
                    if !r.beside.is_empty() {
                        if !body.is_empty() {
                            body.push('\n');
                        }
                        body.push_str(
                            "These files were changed after the extract, so they were left \
                             alone and the originals were put back next to them:\n",
                        );
                        for p in r.beside.iter().take(20) {
                            body.push_str(&format!("    {}\n", p.display()));
                        }
                    }
                    let title = if r.errors.is_empty() {
                        "Some originals were put back under a new name"
                    } else {
                        "Some changes could not be undone"
                    };
                    self.message(title, body.trim_end(), !r.errors.is_empty());
                }
            }
            Ok(jobs::Outcome::Staged { aborted: true, .. }) => {}
            Ok(jobs::Outcome::Staged {
                report,
                paths,
                clipboard,
                ..
            }) => {
                if report.errors.is_empty() {
                    success = true;
                    // Something else was copied while the files were extracted: keep it.
                    if clipboard.is_some_and(|s| s == dnd::clipboard_sequence())
                        && dnd::set_clipboard(self.hwnd, &paths)
                    {
                        let what = crate::ui::count(paths.len(), "item", "items");
                        self.toast(format!("Copied {what}"), true, None);
                    }
                } else if report
                    .errors
                    .iter()
                    .all(|(_, e)| matches!(e, Error::WrongPassword))
                {
                    if let Some(l) = self.stack.last_mut() {
                        l.password = None;
                    }
                    let purpose = if clipboard.is_some() {
                        crate::dialogs::PwFor::Copy
                    } else {
                        crate::dialogs::PwFor::Drag
                    };
                    self.dialog = Some(Dialog::password(
                        purpose,
                        Some("That password is not correct.".into()),
                    ));
                } else {
                    self.report_errors(
                        "Some files could not be extracted",
                        &report.errors,
                        report.files,
                    );
                }
            }
            Err(Error::Cancelled) => self.toast("Stopped".into(), false, None),
            Err(Error::WrongPassword) => self.retry_with_password(),
            Err(e) => {
                self.exit_when_done = false;
                self.message(&format!("{} failed", job.verb), &e.to_string(), true);
            }
        }
        // Stopped or partly failed extracts can still be undone.
        if let Some(id) = undo_id {
            self.toast(
                "Files from the unfinished extract are still there".into(),
                false,
                Some(("Undo".into(), ToastAct::Undo(id))),
            );
        }
        self.last_undo = crate::undo::Store::user().and_then(|s| crate::undo::latest(&s));
        if self.exit_when_done && success && self.queue.is_empty() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if let Some(next) = self.queue.pop_front() {
            self.job = Some(next(ctx));
        } else if !success {
            self.exit_when_done = false;
        }
    }

    /// Reverses the extract recorded as `id`.
    pub fn start_undo(&mut self, ctx: &egui::Context, id: String) {
        self.enqueue(ctx, move |ctx| jobs::undo(ctx, id));
    }

    /// Recovers the damaged archive at `path` into a new folder beside it.
    pub fn start_recover(&mut self, ctx: &egui::Context, path: PathBuf) {
        let password = self
            .stack
            .first()
            .filter(|l| l.disk == path)
            .and_then(|l| l.password.clone());
        let dest = crate::recover::destination(&path);
        self.enqueue(ctx, move |ctx| jobs::recover(ctx, path, password, dest));
    }

    fn retry_with_password(&mut self) {
        if let Some(l) = self.stack.last_mut() {
            l.password = None;
        }
        let form = crate::dialogs::ExtractForm::new(self);
        self.dialog = Some(Dialog::password(
            crate::dialogs::PwFor::Extract(form),
            Some("That password is not correct.".into()),
        ));
    }

    /// Groups errors by cause: a damaged solid block fails every file after the damage
    /// with the same message, which reads better as one line with examples.
    pub fn report_errors(&mut self, title: &str, errors: &[(String, Error)], ok_files: u64) {
        self.exit_when_done = false;
        let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
        for (n, e) in errors {
            let msg = e.to_string();
            match groups.iter_mut().find(|(m, _)| *m == msg) {
                Some((_, names)) => names.push(n),
                None => groups.push((msg, vec![n])),
            }
        }
        let mut body = String::new();
        for (msg, names) in groups.iter().take(12) {
            if names.len() == 1 {
                body.push_str(&format!("{}\n    {msg}\n", names[0]));
            } else {
                body.push_str(&format!("{msg} · {} files\n", names.len()));
                for n in names.iter().take(4) {
                    body.push_str(&format!("    {n}\n"));
                }
                if names.len() > 4 {
                    body.push_str(&format!("    and {} more\n", names.len() - 4));
                }
            }
        }
        body.push_str(&format!(
            "\n{} {} fine.",
            ok_files,
            if ok_files == 1 {
                "file was"
            } else {
                "files were"
            }
        ));
        self.message(title, &body, true);
    }

    fn finish_staging(&mut self) {
        let mut i = 0;
        while i < self.staging.len() {
            if let Some(r) = self.staging[i].take() {
                self.staging.remove(i);
                match r {
                    Ok(path) => shell::open_path(&path),
                    Err(Error::Cancelled) => {}
                    Err(e) => self.toast(format!("Couldn't open the file: {e}"), false, None),
                }
            } else {
                i += 1;
            }
        }
    }

    // ------------------------------------------------------------------ drag and clipboard

    fn selected_disk_paths(&self) -> Vec<PathBuf> {
        self.selected_rows()
            .iter()
            .filter_map(|r| match &r.target {
                Target::Disk(p) => Some(p.clone()),
                _ => None,
            })
            .collect()
    }

    /// Queues extraction of the selected archive items into a fresh scratch folder.
    /// `clipboard` is the clipboard sequence number for a Copy, `None` for a drag.
    fn stage_selection(&mut self, ctx: &egui::Context, clipboard: Option<u32>) -> Option<Staged> {
        let Loc::Archive { depth, .. } = self.loc else {
            return None;
        };
        let selected = self.selected_entries()?;
        let level = &self.stack[depth];
        let locked = level.password.is_none()
            && level
                .opened
                .archive()
                .entries()
                .iter()
                .zip(&selected)
                .any(|(e, s)| *s && e.encrypted);
        if locked {
            let purpose = if clipboard.is_some() {
                crate::dialogs::PwFor::Copy
            } else {
                crate::dialogs::PwFor::Drag
            };
            self.dialog = Some(Dialog::password(purpose, None));
            return None;
        }
        self.stage_seq += 1;
        let kind = if clipboard.is_some() { "copy" } else { "drag" };
        let dest = shell::temp_dir().join(format!("{kind}-{}", self.stage_seq));
        let base = self.archive_base();
        let prefix = base
            .as_ref()
            .map(|b| format!("{}/", b.trim_end_matches('/')));
        let level = &self.stack[depth];
        let mut paths: Vec<PathBuf> = self
            .selected_rows()
            .iter()
            .filter_map(|r| match r.target {
                Target::Node(n) => Some(level.tree.nodes[n].path.as_str()),
                _ => None,
            })
            .filter_map(|path| match &prefix {
                Some(p) => path.strip_prefix(p.as_str()),
                None => Some(path),
            })
            .filter_map(r7z::ops::extract::safe_relative_path)
            .map(|rel| dest.join(rel))
            .collect();
        paths.sort();
        paths.dedup();
        // Search results can hold a folder and things inside it; the folder covers both.
        let all = paths.clone();
        paths.retain(|p| !all.iter().any(|q| q != p && p.starts_with(q)));
        if paths.is_empty() {
            return None;
        }
        let total = self.bytes_of(&Some(selected.clone()));
        let level = &self.stack[depth];
        let (tx, rx) = mpsc::channel();
        let abort = Arc::new(AtomicBool::new(false));
        let req = jobs::StageRequest {
            extract: jobs::ExtractRequest {
                archive: level.archive(),
                password: level.password.clone(),
                selected: Some(selected),
                base,
                dest: dest.clone(),
                full_paths: true,
                overwrite: r7z::ops::extract::Overwrite::All,
                total,
            },
            paths: paths.clone(),
            clipboard,
            abort: abort.clone(),
            ready: tx,
        };
        let what = crate::ui::count(paths.len(), "item", "items");
        let title = if clipboard.is_some() {
            format!("Extracting {what} to copy")
        } else {
            format!("Extracting {what} to drop")
        };
        self.enqueue(ctx, move |ctx| jobs::stage(ctx, title, req));
        Some(Staged {
            paths,
            dir: dest,
            ready: rx,
            abort,
        })
    }

    /// Starts dragging the selection out of the window. Disk files go as they are; archive
    /// items are extracted to the temp folder while the drag is under way.
    pub fn start_drag(&mut self, ctx: &egui::Context) {
        if self.drag.is_some() {
            return;
        }
        if self.in_archive() {
            if let Some(st) = self.stage_selection(ctx, None) {
                let d = dnd::start(dnd::DragRequest {
                    paths: st.paths,
                    effects: dnd::COPY | dnd::MOVE,
                    preferred: dnd::MOVE,
                    ready: Some(st.ready),
                    abort: st.abort,
                });
                self.drag = Some((d, Some(st.dir)));
            }
        } else {
            let paths = self.selected_disk_paths();
            if !paths.is_empty() {
                let d = dnd::start(dnd::DragRequest {
                    paths,
                    effects: dnd::COPY | dnd::MOVE | dnd::LINK,
                    preferred: 0,
                    ready: None,
                    abort: Arc::new(AtomicBool::new(false)),
                });
                self.drag = Some((d, None));
            }
        }
    }

    fn finish_drag(&mut self, ctx: &egui::Context) {
        if !ctx.input(|i| i.pointer.primary_down()) {
            self.drag_spent = false;
        }
        if !self.drag.as_ref().is_some_and(|(d, _)| d.finished()) {
            return;
        }
        let Some((mut drag, staged)) = self.drag.take() else {
            return;
        };
        let effect = drag.join();
        match staged {
            // A move or a drop into the folder being shown changes the listing.
            None if effect != 0 => self.rows_dirty = true,
            None => {}
            // Nothing was dropped: the scratch copies are not needed. Extraction that is
            // still running sees the abort flag and clears up after itself.
            Some(dir) if effect == 0 => {
                std::thread::spawn(move || std::fs::remove_dir_all(dir));
            }
            Some(_) => {}
        }
        self.release_pointer = true;
        ctx.request_repaint();
    }

    /// Puts the selection on the clipboard as files. Archive items are extracted to the
    /// temp folder first; the clipboard is filled when that finishes.
    pub fn copy_selection(&mut self, ctx: &egui::Context) {
        if self.selection.is_empty() {
            return;
        }
        if self.in_archive() {
            let seq = dnd::clipboard_sequence();
            self.stage_selection(ctx, Some(seq));
            return;
        }
        let paths = self.selected_disk_paths();
        if dnd::set_clipboard(self.hwnd, &paths) {
            let what = crate::ui::count(paths.len(), "item", "items");
            self.toast(format!("Copied {what}"), true, None);
        } else {
            self.toast("The clipboard is busy; try again".into(), false, None);
        }
    }

    pub fn can_paste(&self) -> bool {
        !self.in_archive() && dnd::clipboard_has_files()
    }

    /// Pastes files from the clipboard into the disk folder being shown.
    pub fn paste(&mut self, ctx: &egui::Context) {
        let Loc::Disk(dir) = &self.loc else {
            return;
        };
        let Some((files, cut)) = dnd::clipboard_files() else {
            return;
        };
        let (hwnd, dir) = (self.hwnd, dir.clone());
        self.pastes.push(Task::spawn(ctx, move |_| {
            dnd::paste(hwnd, &files, &dir, cut).map_err(Error::Other)
        }));
    }

    fn finish_pastes(&mut self) {
        let mut i = 0;
        while i < self.pastes.len() {
            if let Some(r) = self.pastes[i].take() {
                self.pastes.remove(i);
                self.rows_dirty = true;
                if let Err(e) = r {
                    self.toast(format!("Couldn't paste: {e}"), false, None);
                }
            } else {
                i += 1;
            }
        }
    }

    // ------------------------------------------------------------------ preview

    pub fn update_preview(&mut self, ctx: &egui::Context) {
        if !self.show_preview {
            return;
        }
        let Some(row) = self.single_selected().cloned() else {
            if self.preview.key.is_some() {
                self.preview.clear();
            }
            return;
        };
        if row.is_dir {
            if self.preview.key.is_some() {
                self.preview.clear();
            }
            return;
        }
        match &row.target {
            Target::Disk(p) => {
                let key = format!("disk:{}", p.display());
                self.preview.show(
                    ctx,
                    key,
                    crate::preview::Source::Disk(p.clone()),
                    &row.name,
                    row.size,
                );
            }
            Target::Node(n) => {
                let Loc::Archive { depth, .. } = self.loc else {
                    return;
                };
                let level = &self.stack[depth];
                let Some(entry) = level.tree.nodes[*n].entry else {
                    return;
                };
                if level.opened.archive().entries()[entry].encrypted && level.password.is_none() {
                    let key = format!("locked:{depth}:{entry}");
                    if self.preview.key.as_deref() != Some(key.as_str()) {
                        self.preview.clear();
                        self.preview.key = Some(key);
                        self.preview.body = Some(Ok(crate::preview::Body::Locked));
                    }
                    return;
                }
                let key = format!(
                    "arc:{}:{depth}:{entry}:{}",
                    self.stack.len(),
                    level.password.is_some()
                );
                let source = crate::preview::Source::Entry {
                    archive: level.archive(),
                    index: entry,
                    password: level.password.clone(),
                };
                self.preview.show(ctx, key, source, &row.name, row.size);
            }
        }
    }

    // ------------------------------------------------------------------ drops

    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        // Our own drag passing over the window; such drops are cancelled anyway.
        if dropped.is_empty() || self.drag.is_some() {
            return;
        }
        if let Some(Dialog::Pack(form)) = &mut self.dialog {
            form.add(dropped);
            return;
        }
        let archives: Vec<PathBuf> = dropped
            .iter()
            .filter(|p| p.is_file() && looks_like_archive(p))
            .cloned()
            .collect();
        if archives.len() == dropped.len() {
            if archives.len() == 1 {
                self.open_disk_archive(ctx, archives[0].clone(), None);
            } else {
                self.dialog = Some(Dialog::batch(archives));
            }
        } else {
            self.dialog = Some(Dialog::pack(dropped));
        }
    }

    pub fn set_theme(&mut self, ctx: &egui::Context, pref: egui::ThemePreference) {
        self.theme_pref = pref;
        theme::apply(ctx, pref);
        let key = match pref {
            egui::ThemePreference::Light => "light",
            egui::ThemePreference::Dark => "dark",
            egui::ThemePreference::System => "system",
        };
        shell::save_setting("theme", key);
    }

    pub fn toggle_preview(&mut self) {
        self.show_preview = !self.show_preview;
        shell::save_setting("preview", if self.show_preview { "on" } else { "off" });
    }

    pub fn toggle_hidden(&mut self) {
        self.show_hidden = !self.show_hidden;
        self.rows_dirty = true;
        shell::save_setting("hidden", if self.show_hidden { "on" } else { "off" });
    }

    pub fn toggle_protected(&mut self) {
        self.show_protected = !self.show_protected;
        self.rows_dirty = true;
        shell::save_setting("protected", if self.show_protected { "on" } else { "off" });
    }

    fn update_title(&mut self, ctx: &egui::Context) {
        let title = match &self.loc {
            Loc::Disk(d) => {
                let name = d
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| d.display().to_string());
                format!("{name} - r7z")
            }
            Loc::Archive { depth, .. } => format!("{} - r7z", self.stack[*depth].name),
        };
        if title != self.title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
            self.title = title;
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = &root.ctx().clone();
        let dark = ctx.global_style().visuals.dark_mode;
        if self.title_dark != Some(dark) || self.hwnd == 0 {
            use raw_window_handle::{HasWindowHandle, RawWindowHandle};
            if let Ok(h) = frame.window_handle() {
                if let RawWindowHandle::Win32(w) = h.as_raw() {
                    self.hwnd = w.hwnd.get();
                    shell::set_title_bar_dark(self.hwnd, dark);
                    self.title_dark = Some(dark);
                }
            }
        }
        self.poll_updates(ctx);
        self.poll_install(ctx);
        if let Some(Ok(state)) = self.modern_task.as_mut().and_then(|t| t.take()) {
            self.modern_task = None;
            self.modern_menu = Some(state);
        }
        if self.cjk_pending {
            self.cjk_pending = false;
            theme::install_fonts(ctx, true);
        }
        self.finish_open(ctx);
        self.finish_job(ctx);
        self.finish_staging();
        self.finish_drag(ctx);
        self.finish_pastes();
        self.finish_mount();
        self.preview.poll(ctx);
        self.handle_drops(ctx);
        if self.drives_at.elapsed() > Duration::from_secs(20) {
            self.drives = shell::drives();
            self.drives_at = Instant::now();
        }
        self.refresh_rows();
        self.update_preview(ctx);
        self.update_title(ctx);
        crate::ui::shortcuts(self, ctx);
        crate::ui::frame(self, root);
        crate::dialogs::show(self, ctx);
        crate::finder::show(self, ctx);
        crate::tour::show(self, ctx);

        let animating = self.job.is_some()
            || self.opening.is_some()
            || !self.staging.is_empty()
            || self.drag.is_some()
            || !self.pastes.is_empty()
            || self.mounts.busy()
            || self.preview.loading()
            || self.preview.hashing();
        if animating {
            ctx.request_repaint_after(Duration::from_millis(80));
        } else if !self.toasts.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(400));
        }
    }

    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        if !std::mem::take(&mut self.release_pointer) {
            return;
        }
        let (down, pos) = ctx.input(|i| (i.pointer.primary_down(), i.pointer.latest_pos()));
        if let (true, Some(pos)) = (down, pos) {
            raw.events.push(egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: ctx.input(|i| i.modifiers),
            });
        }
        raw.events.push(egui::Event::PointerGone);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(j) = &self.job {
            j.shared.request_cancel();
        }
        self.eject_all();
        // Files copied out of an archive stay pasteable after the app closes; the scratch
        // folder is then removed by a later run's sweep of stale temp folders.
        let tmp = shell::temp_dir();
        let on_clipboard = dnd::clipboard_files()
            .is_some_and(|(files, _)| files.iter().any(|f| f.starts_with(&tmp)));
        if !on_clipboard {
            let _ = std::fs::remove_dir_all(tmp);
        }
    }
}

pub fn auto_updates() -> bool {
    shell::load_setting("updates").as_deref() != Some("off")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// At most one automatic check a day.
fn update_due() -> bool {
    let last = shell::load_setting("update_checked")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    unix_now().saturating_sub(last) >= 24 * 3600
}

fn mark_update_checked() {
    shell::save_setting("update_checked", &unix_now().to_string());
}
