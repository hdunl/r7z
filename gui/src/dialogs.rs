//! Modal dialogs. Each frame `show` draws the open dialog and applies its result.

use std::path::{Path, PathBuf};

use eframe::egui::{
    self, vec2, Align, CornerRadius, Id, Key, Layout, Margin, RichText, Stroke, Ui,
};
use r7z::ops::extract::{Overwrite, OverwriteAnswer};
use r7z::ops::inspect::Level as Severity;

use crate::app::{stem_of, App, Opening};
use crate::icons::{self, Icon};
use crate::jobs::{self, BatchDest, CreateRequest};
use crate::shell;
use crate::theme::{self, Palette};
use crate::ui::button;

#[derive(Clone)]
pub struct ExtractForm {
    pub dest: String,
    pub selected_only: bool,
    pub full_paths: bool,
    pub overwrite: Overwrite,
    pub password: String,
    pub open_after: bool,
    pub error: Option<String>,
}

impl ExtractForm {
    pub fn new(app: &App) -> ExtractForm {
        let dest = app
            .stack
            .first()
            .map(|l| {
                l.disk
                    .parent()
                    .map(|p| p.join(stem_of(&l.disk)))
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        ExtractForm {
            dest: dest.display().to_string(),
            selected_only: !app.selection.is_empty(),
            full_paths: true,
            overwrite: Overwrite::Ask,
            password: String::new(),
            open_after: true,
            error: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fmt {
    SevenZ,
    Zip,
    Tar,
    TarGz,
    TarXz,
    TarBz2,
}

impl Fmt {
    pub const ALL: [Fmt; 6] = [
        Fmt::SevenZ,
        Fmt::Zip,
        Fmt::Tar,
        Fmt::TarGz,
        Fmt::TarXz,
        Fmt::TarBz2,
    ];
    pub fn ext(self) -> &'static str {
        match self {
            Fmt::SevenZ => "7z",
            Fmt::Zip => "zip",
            Fmt::Tar => "tar",
            Fmt::TarGz => "tar.gz",
            Fmt::TarXz => "tar.xz",
            Fmt::TarBz2 => "tar.bz2",
        }
    }
    fn note(self) -> &'static str {
        match self {
            Fmt::SevenZ => "Smallest files. Opens in r7z, 7-Zip and most archivers.",
            Fmt::Zip => "Opens everywhere, including Windows and macOS without extra tools.",
            Fmt::Tar => "No compression. Keeps files together for Unix systems.",
            Fmt::TarGz => "The common format on Linux. Fast.",
            Fmt::TarXz => "Smaller than tar.gz; slower to create.",
            Fmt::TarBz2 => "Older Unix format, between gzip and xz.",
        }
    }
    fn password(self) -> bool {
        matches!(self, Fmt::SevenZ | Fmt::Zip)
    }
    fn compresses(self) -> bool {
        self != Fmt::Tar
    }
}

pub struct PackForm {
    pub paths: Vec<PathBuf>,
    pub archive: String,
    pub format: Fmt,
    pub level: u32,
    pub password: String,
    pub confirm: String,
    pub encrypt_names: bool,
    pub solid: bool,
    pub error: Option<String>,
}

impl PackForm {
    pub fn add(&mut self, paths: Vec<PathBuf>) {
        for p in paths {
            if !self.paths.contains(&p) {
                self.paths.push(p);
            }
        }
        if self.archive.is_empty() {
            self.archive = default_archive_path(&self.paths, self.format);
        }
    }
}

pub struct BatchForm {
    pub archives: Vec<PathBuf>,
    pub smart: bool,
    pub dest: String,
    pub overwrite: Overwrite,
    pub password: String,
}

pub struct ConvertForm {
    pub format: Fmt,
    pub level: u32,
    pub archive: String,
    pub error: Option<String>,
}

pub enum PwFor {
    Open(Opening),
    Extract(ExtractForm),
    Test,
    Launch(usize),
    Preview,
    Copy,
    /// A drag can't wait for a dialog; the password is kept for the next try.
    Drag,
    /// Open as folder.
    Mount,
}

pub enum Dialog {
    Message {
        title: String,
        body: String,
        error: bool,
    },
    Password {
        purpose: PwFor,
        input: String,
        error: Option<String>,
    },
    Extract(ExtractForm),
    Pack(PackForm),
    Batch(BatchForm),
    Convert(ConvertForm),
    Settings,
    Safety,
    /// The outcome list of a recovery.
    Recovered(crate::recover::RecoverView),
}

impl Dialog {
    pub fn pack(paths: Vec<PathBuf>) -> Dialog {
        let mut f = PackForm {
            paths: Vec::new(),
            archive: String::new(),
            format: Fmt::SevenZ,
            level: 5,
            password: String::new(),
            confirm: String::new(),
            encrypt_names: true,
            solid: true,
            error: None,
        };
        f.add(paths);
        Dialog::Pack(f)
    }

    pub fn batch(archives: Vec<PathBuf>) -> Dialog {
        let dest = archives
            .first()
            .and_then(|p| p.parent())
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        Dialog::Batch(BatchForm {
            archives,
            smart: true,
            dest,
            overwrite: Overwrite::Ask,
            password: String::new(),
        })
    }

    pub fn password(purpose: PwFor, error: Option<String>) -> Dialog {
        Dialog::Password {
            purpose,
            input: String::new(),
            error,
        }
    }
}

pub fn default_archive_path(paths: &[PathBuf], fmt: Fmt) -> String {
    let Some(first) = paths.first() else {
        return String::new();
    };
    let parent = first.parent().map(Path::to_path_buf).unwrap_or_default();
    let base = r7z::util::archive_base_name(paths);
    let mut candidate = parent.join(format!("{base}.{}", fmt.ext()));
    let mut n = 2;
    while candidate.exists() {
        candidate = parent.join(format!("{base} ({n}).{}", fmt.ext()));
        n += 1;
    }
    candidate.display().to_string()
}

fn replace_ext(path: &str, from: Fmt, to: Fmt) -> String {
    let suffix = format!(".{}", from.ext());
    if path.to_ascii_lowercase().ends_with(&suffix) {
        format!("{}.{}", &path[..path.len() - suffix.len()], to.ext())
    } else if path.is_empty() {
        String::new()
    } else {
        format!("{path}.{}", to.ext())
    }
}

pub fn pick_and_open(app: &mut App, ctx: &egui::Context) {
    let exts: Vec<&str> = r7z::format::FORMATS
        .iter()
        .flat_map(|f| f.extensions.iter().copied())
        .collect();
    let d = rfd::FileDialog::new()
        .set_title("Open archive")
        .add_filter("Archives", &exts)
        .add_filter("All files", &["*"])
        .set_directory(app.disk_dir());
    if let Some(p) = d.pick_file() {
        app.open_disk_archive(ctx, p, None);
    }
}

// ------------------------------------------------------------------ pieces

fn title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(theme::semibold(18.0)));
    ui.add_space(4.0);
}

fn label(ui: &mut Ui, p: &Palette, text: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(text).size(12.0).color(p.dim));
}

fn field(
    ui: &mut Ui,
    p: &Palette,
    value: &mut String,
    hint: &str,
    password: bool,
    width: f32,
) -> egui::Response {
    egui::Frame::new()
        .fill(p.input)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(value)
                    .frame(egui::Frame::NONE)
                    .align(egui::Align2::LEFT_CENTER)
                    .password(password)
                    .hint_text(RichText::new(hint).color(p.faint))
                    .desired_width(width - 16.0)
                    .margin(Margin::symmetric(0, 5)),
            )
        })
        .inner
}

fn segmented<T: PartialEq + Copy>(
    ui: &mut Ui,
    p: &Palette,
    options: &[(T, &str)],
    value: &mut T,
) -> bool {
    let mut changed = false;
    egui::Frame::new()
        .fill(p.raised)
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (v, l) in options {
                    let on = *value == *v;
                    let text = if on {
                        RichText::new(*l).color(p.text).font(theme::semibold(13.0))
                    } else {
                        RichText::new(*l).color(p.dim).size(13.0)
                    };
                    let mut b = egui::Button::new(text)
                        .min_size(vec2(56.0, 26.0))
                        .corner_radius(CornerRadius::same(7));
                    b = b
                        .fill(if on {
                            p.surface
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .stroke(if on {
                            Stroke::new(1.0, p.line)
                        } else {
                            Stroke::NONE
                        });
                    if ui.add(b).clicked() && !on {
                        *value = *v;
                        changed = true;
                    }
                }
            });
        });
    changed
}

fn level_picker(ui: &mut Ui, p: &Palette, level: &mut u32) {
    let levels = [
        (0u32, "Store"),
        (1, "Fastest"),
        (3, "Fast"),
        (5, "Normal"),
        (7, "Max"),
        (9, "Ultra"),
    ];
    segmented(ui, p, &levels, level);
    let note = match *level {
        0 => "No compression; just packs the files together.",
        1 => "Quickest, larger file.",
        3 => "Fast with a good ratio.",
        5 => "Balanced. The default.",
        7 => "Smaller, slower. Uses more memory.",
        _ => "Smallest possible, slowest. Uses a lot of memory.",
    };
    ui.label(RichText::new(note).size(11.5).color(p.faint));
}

fn overwrite_picker(ui: &mut Ui, p: &Palette, value: &mut Overwrite) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("If a file exists").size(12.5).color(p.dim));
        let mut v = match *value {
            Overwrite::RenameExisting => Overwrite::RenameNew,
            other => other,
        };
        if segmented(
            ui,
            p,
            &[
                (Overwrite::Ask, "Ask"),
                (Overwrite::All, "Replace"),
                (Overwrite::Skip, "Skip"),
                (Overwrite::RenameNew, "Keep both"),
            ],
            &mut v,
        ) {
            *value = v;
        }
    });
}

fn footer(ui: &mut Ui, primary: &str, enabled: bool) -> (bool, bool) {
    ui.add_space(14.0);
    let mut go = false;
    let mut cancel = false;
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        if button(ui, None, primary, true, enabled).clicked() && enabled {
            go = true;
        }
        if button(ui, None, "Cancel", false, true).clicked() {
            cancel = true;
        }
    });
    let enter = ui.input(|i| i.key_pressed(Key::Enter)) && enabled;
    (go || enter, cancel)
}

fn modal<R>(
    ctx: &egui::Context,
    id: &str,
    width: f32,
    add: impl FnOnce(&mut Ui) -> R,
) -> (R, bool) {
    let r = egui::Modal::new(Id::unique(id)).show(ctx, |ui| {
        ui.set_width(width);
        add(ui)
    });
    let close = r.should_close();
    (r.inner, close)
}

// ------------------------------------------------------------------ show

pub fn show(app: &mut App, ctx: &egui::Context) {
    let p = theme::current(ctx);
    overwrite_prompt(app, ctx, &p);
    let Some(dialog) = app.dialog.take() else {
        return;
    };
    let next = match dialog {
        Dialog::Message {
            title: t,
            body,
            error,
        } => {
            let (ok, close) = modal(ctx, "message", 460.0, |ui| {
                ui.horizontal(|ui| {
                    icons::icon(
                        ui,
                        18.0,
                        if error { Icon::Alert } else { Icon::Check },
                        if error { p.danger } else { p.ok },
                    );
                    title(ui, &t);
                });
                egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&body).size(13.0).color(p.dim))
                                .wrap()
                                .selectable(true),
                        );
                    });
                ui.add_space(12.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    button(ui, None, "OK", true, true).clicked()
                })
                .inner
            });
            let keys = ctx.input(|i| i.key_pressed(Key::Enter) || i.key_pressed(Key::Escape));
            if ok || close || keys {
                if app.exit_when_done
                    && app.job.is_none()
                    && app.queue.is_empty()
                    && app.opening.is_none()
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                None
            } else {
                Some(Dialog::Message {
                    title: t,
                    body,
                    error,
                })
            }
        }
        other => show_rest(app, ctx, &p, other),
    };
    if app.dialog.is_none() {
        app.dialog = next;
    }
}

fn show_rest(app: &mut App, ctx: &egui::Context, p: &Palette, dialog: Dialog) -> Option<Dialog> {
    match dialog {
        Dialog::Password {
            purpose,
            mut input,
            error,
        } => {
            let mut submit = false;
            let ((), close) = modal(ctx, "password", 380.0, |ui| {
                ui.horizontal(|ui| {
                    icons::icon(ui, 18.0, Icon::Lock, p.dim);
                    title(ui, "Password");
                });
                let what = match &purpose {
                    PwFor::Open(Opening::Disk(path)) => {
                        format!("{} is encrypted.", jobs::file_name(path))
                    }
                    PwFor::Open(Opening::Nested { name, .. }) => format!("{name} is encrypted."),
                    _ => "These files are encrypted.".into(),
                };
                ui.label(RichText::new(what).size(12.5).color(p.dim));
                ui.add_space(6.0);
                let r = field(ui, p, &mut input, "Password", true, ui.available_width());
                r.request_focus();
                if let Some(e) = &error {
                    ui.label(RichText::new(e).size(12.0).color(p.danger));
                }
                let (go, cancel) = footer(ui, "Unlock", !input.is_empty());
                submit = go;
                if cancel {
                    input.clear();
                    submit = false;
                    ui.memory_mut(|m| m.data.insert_temp(Id::unique("pw-cancel"), true));
                }
            });
            let cancelled = ctx.memory_mut(|m| {
                m.data
                    .remove_temp::<bool>(Id::unique("pw-cancel"))
                    .unwrap_or(false)
            });
            if submit {
                let pw = input.clone();
                match purpose {
                    PwFor::Open(Opening::Disk(path)) => app.open_disk_archive(ctx, path, Some(pw)),
                    PwFor::Open(Opening::Nested { node, .. }) => {
                        app.open_nested(ctx, node, Some(pw))
                    }
                    PwFor::Extract(mut form) => {
                        form.password = pw;
                        app.start_extract(ctx, form);
                    }
                    PwFor::Test => {
                        if let Some(l) = app.stack.last_mut() {
                            l.password = Some(pw);
                        }
                        app.start_test(ctx);
                    }
                    PwFor::Launch(n) => {
                        if let Some(l) = app.stack.last_mut() {
                            l.password = Some(pw);
                        }
                        app.launch(ctx, n);
                    }
                    PwFor::Preview => {
                        if let Some(l) = app.stack.last_mut() {
                            l.password = Some(pw);
                        }
                        app.preview.clear();
                    }
                    PwFor::Copy => {
                        if let Some(l) = app.stack.last_mut() {
                            l.password = Some(pw);
                        }
                        app.copy_selection(ctx);
                    }
                    PwFor::Mount => {
                        if let Some(l) = app.stack.last_mut() {
                            l.password = Some(pw);
                        }
                        app.open_as_folder(ctx);
                    }
                    PwFor::Drag => {
                        if let Some(l) = app.stack.last_mut() {
                            l.password = Some(pw);
                        }
                        app.toast("Unlocked; drag the files again".into(), true, None);
                    }
                }
                None
            } else if close || cancelled {
                app.exit_when_done = false;
                None
            } else {
                Some(Dialog::Password {
                    purpose,
                    input,
                    error,
                })
            }
        }
        Dialog::Extract(mut form) => {
            let n_sel = app.selection.len();
            let needs_pw = app
                .level()
                .is_some_and(|l| l.encrypted() && l.password.is_none());
            let findings: Vec<String> = app
                .level()
                .map(|l| {
                    l.findings
                        .iter()
                        .filter(|f| f.level >= Severity::Caution)
                        .map(|f| f.title.clone())
                        .collect()
                })
                .unwrap_or_default();
            let (go, cancel, close);
            {
                let ((g, c), cl) = modal(ctx, "extract", 520.0, |ui| {
                    title(ui, "Extract");
                    label(ui, p, "Destination");
                    ui.horizontal(|ui| {
                        let w = ui.available_width() - 92.0;
                        field(ui, p, &mut form.dest, "Folder", false, w);
                        if button(ui, None, "Browse…", false, true).clicked() {
                            if let Some(d) =
                                rfd::FileDialog::new().set_title("Extract to").pick_folder()
                            {
                                form.dest = d.display().to_string();
                            }
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        let disk = app.disk_dir();
                        let stem = app
                            .stack
                            .first()
                            .map(|l| stem_of(&l.disk))
                            .unwrap_or_default();
                        let mut chips: Vec<(String, PathBuf)> = vec![
                            (format!("{stem}\\"), disk.join(&stem)),
                            ("Same folder".into(), disk.clone()),
                        ];
                        for k in [shell::Known::Desktop, shell::Known::Downloads] {
                            if let Some(d) = shell::known_folder(k) {
                                chips.push((format!("{k:?}"), d.join(&stem)));
                            }
                        }
                        for (l, path) in chips {
                            if ui
                                .add(
                                    egui::Button::new(RichText::new(l).size(12.0))
                                        .corner_radius(CornerRadius::same(12))
                                        .min_size(vec2(0.0, 24.0)),
                                )
                                .clicked()
                            {
                                form.dest = path.display().to_string();
                            }
                        }
                    });
                    ui.add_space(6.0);
                    if n_sel > 0 {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("What").size(12.5).color(p.dim));
                            segmented(
                                ui,
                                p,
                                &[
                                    (true, &*format!("Selected ({n_sel})")),
                                    (false, "Everything"),
                                ],
                                &mut form.selected_only,
                            );
                        });
                    }
                    ui.checkbox(&mut form.full_paths, "Keep folder structure");
                    overwrite_picker(ui, p, &mut form.overwrite);
                    if needs_pw {
                        label(ui, p, "Password");
                        field(
                            ui,
                            p,
                            &mut form.password,
                            "Password",
                            true,
                            ui.available_width(),
                        );
                    }
                    ui.checkbox(&mut form.open_after, "Open the folder when done");
                    if !findings.is_empty() {
                        ui.add_space(6.0);
                        egui::Frame::new()
                            .fill(p.caution.gamma_multiply(0.12))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::same(10))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                for f in findings.iter().take(3) {
                                    ui.horizontal(|ui| {
                                        icons::icon(ui, 13.0, Icon::Alert, p.caution);
                                        ui.label(RichText::new(f).size(12.0));
                                    });
                                }
                            });
                    }
                    if let Some(e) = &form.error {
                        ui.label(RichText::new(e).size(12.0).color(p.danger));
                    }
                    footer(ui, "Extract", true)
                });
                go = g;
                cancel = c;
                close = cl;
            }
            if go {
                form.error = None;
                app.start_extract(ctx, form);
                None
            } else if cancel || close {
                app.exit_when_done = false;
                None
            } else {
                Some(Dialog::Extract(form))
            }
        }
        Dialog::Pack(mut form) => {
            let ((go, cancel), close) = modal(ctx, "pack", 580.0, |ui| {
                title(ui, "New archive");
                label(ui, p, &format!("Files ({})", form.paths.len()));
                egui::Frame::new()
                    .fill(p.input)
                    .stroke(Stroke::new(1.0, p.line))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::same(6))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::ScrollArea::vertical()
                            .max_height(120.0)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                if form.paths.is_empty() {
                                    ui.label(
                                        RichText::new("Drop files here, or add them below")
                                            .size(12.5)
                                            .color(p.faint),
                                    );
                                }
                                let mut remove = None;
                                for (i, path) in form.paths.iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        let (r, _) = ui.allocate_exact_size(
                                            vec2(16.0, 16.0),
                                            egui::Sense::hover(),
                                        );
                                        if path.is_dir() {
                                            icons::folder(ui.painter(), r);
                                        } else {
                                            icons::file(
                                                ui.painter(),
                                                r,
                                                &path.to_string_lossy(),
                                                p.dark,
                                            );
                                        }
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(path.display().to_string())
                                                    .size(12.5),
                                            )
                                            .truncate(),
                                        );
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                let (r, resp) = ui.allocate_exact_size(
                                                    vec2(18.0, 18.0),
                                                    egui::Sense::click(),
                                                );
                                                icons::draw(
                                                    ui.painter(),
                                                    r.shrink(4.0),
                                                    Icon::Close,
                                                    if resp.hovered() { p.text } else { p.faint },
                                                );
                                                if resp.clicked() {
                                                    remove = Some(i);
                                                }
                                            },
                                        );
                                    });
                                }
                                if let Some(i) = remove {
                                    form.paths.remove(i);
                                }
                            });
                    });
                ui.horizontal(|ui| {
                    if button(ui, None, "Add files…", false, true).clicked() {
                        if let Some(fs) = rfd::FileDialog::new().pick_files() {
                            form.add(fs);
                        }
                    }
                    if button(ui, None, "Add folder…", false, true).clicked() {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            form.add(vec![d]);
                        }
                    }
                });
                label(ui, p, "Format");
                let before = form.format;
                let opts: Vec<(Fmt, &str)> = Fmt::ALL.iter().map(|f| (*f, f.ext())).collect();
                if segmented(ui, p, &opts, &mut form.format) {
                    form.archive = replace_ext(&form.archive, before, form.format);
                }
                ui.label(RichText::new(form.format.note()).size(11.5).color(p.faint));
                label(ui, p, "Save as");
                ui.horizontal(|ui| {
                    let w = ui.available_width() - 92.0;
                    field(ui, p, &mut form.archive, "Archive file", false, w);
                    if button(ui, None, "Browse…", false, true).clicked() {
                        let cur = PathBuf::from(&form.archive);
                        let mut d = rfd::FileDialog::new().set_title("Save archive as");
                        if let Some(dir) = cur.parent().filter(|d| d.is_dir()) {
                            d = d.set_directory(dir);
                        }
                        if let Some(n) = cur.file_name() {
                            d = d.set_file_name(n.to_string_lossy());
                        }
                        if let Some(f) = d.save_file() {
                            form.archive = f.display().to_string();
                        }
                    }
                });
                if form.format.compresses() {
                    label(ui, p, "Compression");
                    level_picker(ui, p, &mut form.level);
                    if form.format == Fmt::SevenZ {
                        ui.checkbox(
                            &mut form.solid,
                            "Solid (compress files together for a smaller archive)",
                        );
                    }
                }
                if form.format.password() {
                    label(ui, p, "Password (optional, AES-256)");
                    ui.horizontal(|ui| {
                        let w = (ui.available_width() - 8.0) / 2.0;
                        field(ui, p, &mut form.password, "Password", true, w);
                        field(ui, p, &mut form.confirm, "Repeat it", true, w);
                    });
                    if form.format == Fmt::SevenZ && !form.password.is_empty() {
                        ui.checkbox(&mut form.encrypt_names, "Hide file names too");
                    }
                }
                if Path::new(form.archive.trim()).exists() {
                    ui.label(
                        RichText::new("A file with this name exists and will be replaced.")
                            .size(12.0)
                            .color(p.caution),
                    );
                }
                if let Some(e) = &form.error {
                    ui.label(RichText::new(e).size(12.0).color(p.danger));
                }
                footer(ui, "Create", true)
            });
            if go {
                form.error = if form.paths.is_empty() {
                    Some("Add at least one file or folder.".into())
                } else if form.archive.trim().is_empty() {
                    Some("Choose where to save the archive.".into())
                } else if form.format.password() && form.password != form.confirm {
                    Some("The two passwords don't match.".into())
                } else {
                    None
                };
                if form.error.is_some() {
                    return Some(Dialog::Pack(form));
                }
                let req = CreateRequest {
                    paths: form.paths.clone(),
                    archive: PathBuf::from(form.archive.trim()),
                    level: if form.format.compresses() {
                        form.level
                    } else {
                        0
                    },
                    password: (form.format.password() && !form.password.is_empty())
                        .then(|| form.password.clone()),
                    encrypt_names: form.encrypt_names,
                    solid: form.solid,
                };
                app.enqueue(ctx, move |ctx| jobs::create(ctx, req));
                None
            } else if cancel || close {
                app.exit_when_done = false;
                None
            } else {
                Some(Dialog::Pack(form))
            }
        }
        Dialog::Batch(mut form) => {
            let ((go, cancel), close) = modal(ctx, "batch", 520.0, |ui| {
                title(
                    ui,
                    if form.archives.len() == 1 {
                        "Extract archive"
                    } else {
                        "Extract archives"
                    },
                );
                egui::Frame::new()
                    .fill(p.input)
                    .stroke(Stroke::new(1.0, p.line))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::same(8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::ScrollArea::vertical()
                            .max_height(120.0)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                for a in &form.archives {
                                    ui.horizontal(|ui| {
                                        let (r, _) = ui.allocate_exact_size(
                                            vec2(16.0, 16.0),
                                            egui::Sense::hover(),
                                        );
                                        icons::file(ui.painter(), r, &a.to_string_lossy(), p.dark);
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(jobs::file_name(a)).size(12.5),
                                            )
                                            .truncate(),
                                        );
                                    });
                                }
                            });
                    });
                label(ui, p, "Where");
                segmented(
                    ui,
                    p,
                    &[(true, "Next to each archive"), (false, "Into a folder")],
                    &mut form.smart,
                );
                if form.smart {
                    ui.label(RichText::new("A folder is created only when an archive holds several top-level items.").size(11.5).color(p.faint));
                } else {
                    ui.horizontal(|ui| {
                        let w = ui.available_width() - 92.0;
                        field(ui, p, &mut form.dest, "Folder", false, w);
                        if button(ui, None, "Browse…", false, true).clicked() {
                            if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                form.dest = d.display().to_string();
                            }
                        }
                    });
                    ui.label(
                        RichText::new("Each archive gets its own subfolder.")
                            .size(11.5)
                            .color(p.faint),
                    );
                }
                ui.add_space(4.0);
                overwrite_picker(ui, p, &mut form.overwrite);
                label(ui, p, "Password (if any are encrypted)");
                field(
                    ui,
                    p,
                    &mut form.password,
                    "Optional",
                    true,
                    ui.available_width(),
                );
                footer(ui, "Extract", true)
            });
            if go {
                let dest = if form.smart {
                    BatchDest::Smart
                } else {
                    BatchDest::Into(PathBuf::from(form.dest.trim()))
                };
                let pw = (!form.password.is_empty()).then(|| form.password.clone());
                let (archives, ow) = (form.archives, form.overwrite);
                app.enqueue(ctx, move |ctx| {
                    jobs::batch_extract(ctx, archives, dest, ow, pw)
                });
                None
            } else if cancel || close {
                None
            } else {
                Some(Dialog::Batch(form))
            }
        }
        Dialog::Convert(mut form) => {
            let ((go, cancel), close) = modal(ctx, "convert", 520.0, |ui| {
                title(ui, "Convert archive");
                ui.label(
                    RichText::new(
                        "Repack the contents into another format. The original stays as it is.",
                    )
                    .size(12.5)
                    .color(p.dim),
                );
                label(ui, p, "Format");
                let before = form.format;
                let opts: Vec<(Fmt, &str)> = Fmt::ALL.iter().map(|f| (*f, f.ext())).collect();
                if segmented(ui, p, &opts, &mut form.format) {
                    form.archive = replace_ext(&form.archive, before, form.format);
                }
                ui.label(RichText::new(form.format.note()).size(11.5).color(p.faint));
                if form.format.compresses() {
                    label(ui, p, "Compression");
                    level_picker(ui, p, &mut form.level);
                }
                label(ui, p, "Save as");
                let w = ui.available_width();
                field(ui, p, &mut form.archive, "Archive file", false, w);
                if let Some(e) = &form.error {
                    ui.label(RichText::new(e).size(12.0).color(p.danger));
                }
                footer(ui, "Convert", true)
            });
            if go {
                let level = app.stack.last()?;
                if level.encrypted() && level.password.is_none() {
                    form.error = Some(
                        "Unlock the archive first (Test or Extract asks for the password).".into(),
                    );
                    return Some(Dialog::Convert(form));
                }
                let req = CreateRequest {
                    paths: Vec::new(),
                    archive: PathBuf::from(form.archive.trim()),
                    level: if form.format.compresses() {
                        form.level
                    } else {
                        0
                    },
                    password: None,
                    encrypt_names: false,
                    solid: true,
                };
                let (a, pw) = (level.archive(), level.password.clone());
                let scratch = shell::temp_dir().join("convert");
                app.enqueue(ctx, move |ctx| jobs::convert(ctx, a, pw, req, scratch));
                None
            } else if cancel || close {
                app.exit_when_done = false;
                None
            } else {
                Some(Dialog::Convert(form))
            }
        }
        Dialog::Safety => {
            let findings = app.level().map(|l| l.findings.clone()).unwrap_or_default();
            let names: Vec<Vec<String>> = app
                .level()
                .map(|l| {
                    let e = l.opened.archive().entries();
                    findings
                        .iter()
                        .map(|f| {
                            f.entries
                                .iter()
                                .take(6)
                                .map(|&i| e[i].name.clone())
                                .collect()
                        })
                        .collect()
                })
                .unwrap_or_default();
            let (done, close) = modal(ctx, "safety", 540.0, |ui| {
                ui.horizontal(|ui| {
                    icons::icon(ui, 18.0, Icon::Shield, p.dim);
                    title(ui, "Safety check");
                });
                if findings.is_empty() {
                    ui.label(RichText::new("Nothing unusual: no paths that escape the destination, no disguised programs, no decompression bombs.").size(12.5).color(p.dim));
                }
                egui::ScrollArea::vertical()
                    .max_height(380.0)
                    .show(ui, |ui| {
                        for (f, examples) in findings.iter().zip(names.iter()) {
                            let color = match f.level {
                                Severity::Danger => p.danger,
                                Severity::Caution => p.caution,
                                Severity::Note => p.dim,
                            };
                            egui::Frame::new()
                                .fill(p.raised)
                                .corner_radius(CornerRadius::same(10))
                                .inner_margin(Margin::same(12))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        icons::icon(ui, 15.0, Icon::Alert, color);
                                        ui.label(
                                            RichText::new(&f.title)
                                                .font(theme::semibold(13.5))
                                                .color(color),
                                        );
                                    });
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&f.detail).size(12.5).color(p.dim),
                                        )
                                        .wrap(),
                                    );
                                    for n in examples {
                                        ui.label(
                                            RichText::new(n).monospace().size(11.5).color(p.text),
                                        );
                                    }
                                });
                            ui.add_space(6.0);
                        }
                    });
                ui.add_space(8.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    button(ui, None, "Done", true, true).clicked()
                })
                .inner
            });
            if done || close {
                None
            } else {
                Some(Dialog::Safety)
            }
        }
        Dialog::Settings => {
            let (done, close) = modal(ctx, "settings", 480.0, |ui| {
                title(ui, "Settings");
                label(ui, p, "Appearance");
                let mut pref = app.theme_pref;
                if segmented(
                    ui,
                    p,
                    &[
                        (egui::ThemePreference::System, "System"),
                        (egui::ThemePreference::Light, "Light"),
                        (egui::ThemePreference::Dark, "Dark"),
                    ],
                    &mut pref,
                ) {
                    app.set_theme(ctx, pref);
                }
                label(ui, p, "Files");
                let mut hidden = app.show_hidden;
                if ui.checkbox(&mut hidden, "Show hidden files").changed() {
                    app.toggle_hidden();
                }
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    let mut prot = app.show_protected;
                    if ui
                        .add_enabled(
                            app.show_hidden,
                            egui::Checkbox::new(&mut prot, "Also show protected system items"),
                        )
                        .on_hover_text("Folders like FOUND.000 and System Volume Information, which Explorer always hides")
                        .changed()
                    {
                        app.toggle_protected();
                    }
                });
                label(ui, p, "Updates");
                let mut auto = crate::app::auto_updates();
                if ui
                    .checkbox(&mut auto, "Check for updates automatically")
                    .on_hover_text("Once a day, r7z asks GitHub for the latest release. Updates are signed and checked before anything is installed.")
                    .changed()
                {
                    shell::save_setting("updates", if auto { "on" } else { "off" });
                }
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    let mut silent =
                        shell::load_setting("update_install").as_deref() == Some("auto");
                    if ui
                        .add_enabled(
                            auto,
                            egui::Checkbox::new(&mut silent, "Install them without asking"),
                        )
                        .changed()
                    {
                        shell::save_setting("update_install", if silent { "auto" } else { "ask" });
                    }
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let busy = app.update_check.is_some() || app.update_install.is_some();
                    if app.update_ready.is_some() {
                        if button(ui, None, "Restart now", true, true).clicked() {
                            app.restart(ctx);
                        }
                    } else if let Some(version) =
                        app.update_offer.as_ref().map(|m| m.version.clone())
                    {
                        if button(ui, None, &format!("Update to {version}"), true, !busy).clicked()
                        {
                            app.install_update(ctx);
                        }
                    } else if button(ui, None, "Check now", false, !busy).clicked() {
                        app.check_for_updates(ctx, true);
                    }
                    if let Some(note) = &app.update_note {
                        ui.label(RichText::new(note).size(12.0).color(p.dim));
                    }
                });
                label(ui, p, "Explorer menu");
                if app.modern_menu.is_none() {
                    app.modern_menu_job(ctx, shell::modern_menu_status);
                }
                let installed = app.explorer.unwrap_or(false);
                let modern = app.modern_menu.clone();
                let text = match (installed, &modern) {
                    (true, Some(shell::ModernMenu::Installed)) => {
                        "r7z is in the right-click menu for files and folders, in Windows 11's main menu and under \"Show more options\".".to_string()
                    }
                    (true, Some(shell::ModernMenu::Unavailable(why))) => {
                        format!("r7z is in the right-click menu for files and folders. {why}")
                    }
                    (true, Some(shell::ModernMenu::Missing)) => {
                        "r7z is in the right-click menu for files and folders, under \"Show more options\" on Windows 11. To be in the main menu as well, it needs two files from its release.".to_string()
                    }
                    (true, _) => "r7z is in the right-click menu for files and folders.".to_string(),
                    (false, _) => "Adds \"Open with r7z\", \"Extract here\", \"Extract to folder\" and \"Add to archive\" to the right-click menu. Only your user account is changed; no administrator rights are needed.".to_string(),
                };
                ui.add(egui::Label::new(RichText::new(text).size(12.5).color(p.dim)).wrap());
                ui.add_space(4.0);
                let busy = app.modern_task.is_some();
                ui.horizontal(|ui| {
                    if installed {
                        if button(ui, None, "Remove from menu", false, !busy).clicked() {
                            shell::uninstall_explorer();
                            app.explorer = Some(shell::explorer_installed());
                            if modern == Some(shell::ModernMenu::Installed) {
                                app.modern_menu_job(ctx, shell::uninstall_modern_menu);
                            }
                        }
                        if modern == Some(shell::ModernMenu::Available)
                            && button(ui, None, "Add to the Windows 11 menu", false, !busy)
                                .clicked()
                        {
                            app.modern_menu_job(ctx, shell::install_modern_menu);
                        }
                        if modern == Some(shell::ModernMenu::Missing)
                            && button(ui, None, "Get the Windows 11 menu", false, !busy).clicked()
                        {
                            app.modern_menu_job(ctx, shell::get_modern_menu);
                        }
                    } else if button(ui, None, "Add to menu", false, !busy).clicked() {
                        if !shell::install_explorer() {
                            app.toast("Couldn't add the menu entries".into(), false, None);
                        }
                        app.explorer = Some(shell::explorer_installed());
                        match modern {
                            Some(shell::ModernMenu::Available) => {
                                app.modern_menu_job(ctx, shell::install_modern_menu)
                            }
                            Some(shell::ModernMenu::Missing) => {
                                app.modern_menu_job(ctx, shell::get_modern_menu)
                            }
                            _ => {}
                        }
                    }
                    if busy {
                        ui.label(
                            RichText::new("Updating the Windows 11 menu…")
                                .size(12.0)
                                .color(p.dim),
                        );
                    }
                });
                ui.add_space(14.0);
                ui.separator();
                ui.label(
                    RichText::new(format!(
                        "r7z {} · opens {} archive formats",
                        env!("CARGO_PKG_VERSION"),
                        r7z::format::FORMATS.len()
                    ))
                    .size(11.5)
                    .color(p.faint),
                );
                ui.add_space(6.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let done = button(ui, None, "Done", true, true).clicked();
                    let tour = button(ui, None, "Welcome tour", false, true).clicked();
                    if tour {
                        crate::tour::open(app);
                    }
                    done || tour
                })
                .inner
            });
            if done || close {
                None
            } else {
                Some(Dialog::Settings)
            }
        }
        Dialog::Recovered(view) => {
            let ((done, show), close) = modal(ctx, "recovered", 560.0, |ui| {
                crate::recover::body(ui, p, &view);
                ui.add_space(12.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let done = button(ui, None, "Done", true, true).clicked();
                    let show = button(ui, None, "Show files", false, true).clicked();
                    (done, show)
                })
                .inner
            });
            if show {
                app.go(crate::app::Loc::Disk(view.dest.clone()));
            }
            if done || show || close {
                None
            } else {
                Some(Dialog::Recovered(view))
            }
        }
        Dialog::Message { .. } => None,
    }
}

fn overwrite_prompt(app: &mut App, ctx: &egui::Context, p: &Palette) {
    let Some(job) = &app.job else { return };
    let s = job.shared.clone();
    let Some(path) = s.prompt.lock().ok().and_then(|g| g.clone()) else {
        return;
    };
    egui::Modal::new(Id::unique("overwrite")).show(ctx, |ui| {
        ui.set_width(460.0);
        title(ui, "Replace the existing file?");
        ui.add(
            egui::Label::new(
                RichText::new(path.display().to_string())
                    .size(12.5)
                    .color(p.dim),
            )
            .wrap(),
        );
        if let Ok(m) = std::fs::metadata(&path) {
            let when = m.modified().ok().map(r7z::util::time::to_filetime);
            ui.label(
                RichText::new(format!(
                    "Existing: {} · {}",
                    r7z::util::fmt::human_size(m.len()),
                    crate::ui::fmt_time(when)
                ))
                .size(12.0)
                .color(p.faint),
            );
        }
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            if button(ui, None, "Replace", true, true).clicked() {
                s.answer(OverwriteAnswer::Yes);
            }
            if button(ui, None, "Skip", false, true).clicked() {
                s.answer(OverwriteAnswer::No);
            }
            if button(ui, None, "Keep both", false, true).clicked() {
                s.answer(OverwriteAnswer::Rename);
            }
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if button(ui, None, "Replace all", false, true).clicked() {
                s.answer(OverwriteAnswer::YesAll);
            }
            if button(ui, None, "Skip all", false, true).clicked() {
                s.answer(OverwriteAnswer::NoAll);
            }
            if button(ui, None, "Stop", false, true).clicked() {
                s.answer(OverwriteAnswer::Quit);
            }
        });
    });
}
