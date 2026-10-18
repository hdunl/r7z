//! Search everywhere (Ctrl+Shift+F): actions, places, drives, recent archives and the
//! files in the current listing, in one list.

use std::path::PathBuf;

use eframe::egui::{
    self, pos2, vec2, Align2, CornerRadius, FontId, Id, Key, Margin, Rect, RichText, Sense, Stroke,
};

use crate::app::{App, Loc, View};
use crate::dialogs::{Dialog, ExtractForm};
use crate::icons::{self, Icon};
use crate::model::Target;
use crate::theme;

#[derive(Default)]
pub struct FinderState {
    pub query: String,
    pub sel: usize,
}

#[derive(Clone)]
enum Cmd {
    Open,
    New,
    Extract,
    ExtractHere,
    Test,
    OpenAsFolder,
    Eject(usize),
    Convert,
    Safety,
    TogglePreview,
    Map,
    List,
    Up,
    Refresh,
    Hidden,
    Settings,
    Tour,
    Theme(egui::ThemePreference),
    Go(PathBuf),
    Recent(PathBuf),
    Row(Target),
    Undo(String),
}

struct Item {
    label: String,
    hint: String,
    icon: Option<Icon>,
    file: Option<(String, bool)>,
    cmd: Cmd,
}

fn items(app: &App) -> Vec<Item> {
    let mut v = Vec::new();
    let mut act = |label: &str, hint: &str, icon: Icon, cmd: Cmd| {
        v.push(Item {
            label: label.into(),
            hint: hint.into(),
            icon: Some(icon),
            file: None,
            cmd,
        });
    };
    act("Open archive…", "Ctrl+O", Icon::Open, Cmd::Open);
    act("New archive…", "Ctrl+N", Icon::Pack, Cmd::New);
    if app.in_archive() {
        act("Extract…", "Ctrl+E", Icon::Extract, Cmd::Extract);
        act(
            "Extract here",
            "next to the archive",
            Icon::Extract,
            Cmd::ExtractHere,
        );
        act("Test archive", "verify checksums", Icon::Test, Cmd::Test);
        act(
            "Open as folder",
            "browse in Explorer without extracting",
            Icon::External,
            Cmd::OpenAsFolder,
        );
        act("Convert to another format…", "", Icon::Layers, Cmd::Convert);
        act("Safety check", "", Icon::Shield, Cmd::Safety);
        act("Space map", "", Icon::Map, Cmd::Map);
        act("List view", "", Icon::List, Cmd::List);
    }
    if let Some((id, title)) = &app.last_undo {
        act(
            "Undo last extract",
            title,
            Icon::Back,
            Cmd::Undo(id.clone()),
        );
    }
    for (i, m) in app.mounts.active.iter().enumerate() {
        act(
            &format!("Eject {}", m.name),
            "close the folder in Explorer",
            Icon::Eject,
            Cmd::Eject(i),
        );
    }
    act(
        "Toggle preview pane",
        "Space",
        Icon::Preview,
        Cmd::TogglePreview,
    );
    act("Up one level", "Backspace", Icon::Up, Cmd::Up);
    act("Refresh", "F5", Icon::Refresh, Cmd::Refresh);
    act(
        if app.show_hidden {
            "Hide hidden files"
        } else {
            "Show hidden files"
        },
        "",
        Icon::Settings,
        Cmd::Hidden,
    );
    act(
        "Light theme",
        "",
        Icon::Settings,
        Cmd::Theme(egui::ThemePreference::Light),
    );
    act(
        "Dark theme",
        "",
        Icon::Settings,
        Cmd::Theme(egui::ThemePreference::Dark),
    );
    act(
        "System theme",
        "",
        Icon::Settings,
        Cmd::Theme(egui::ThemePreference::System),
    );
    act("Settings", "", Icon::Settings, Cmd::Settings);
    act("Welcome tour", "what r7z can do", Icon::Layers, Cmd::Tour);
    for (k, path) in &app.places {
        v.push(Item {
            label: format!("Go to {k:?}"),
            hint: path.display().to_string(),
            icon: Some(Icon::ChevronRight),
            file: None,
            cmd: Cmd::Go(path.clone()),
        });
    }
    for d in &app.drives {
        v.push(Item {
            label: format!("Go to {}", d.root.display()),
            hint: d.label.clone(),
            icon: Some(Icon::Drive),
            file: None,
            cmd: Cmd::Go(d.root.clone()),
        });
    }
    for r in app.recent.iter().take(10) {
        let name = r
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        v.push(Item {
            label: name.clone(),
            hint: "recent archive".into(),
            icon: None,
            file: Some((name, false)),
            cmd: Cmd::Recent(r.clone()),
        });
    }
    for row in app.rows.iter().take(5000) {
        v.push(Item {
            label: row.name.clone(),
            hint: row.detail.clone().unwrap_or_else(|| {
                if row.is_dir {
                    "folder".into()
                } else {
                    String::new()
                }
            }),
            icon: None,
            file: Some((row.name.clone(), row.is_dir)),
            cmd: Cmd::Row(row.target.clone()),
        });
    }
    v
}

/// Subsequence match: consecutive hits and word starts score higher. `None` = no match.
fn score(query: &str, text: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let mut s = 0i32;
    let mut ti = 0usize;
    let mut prev: Option<usize> = None;
    for qc in query.to_lowercase().chars() {
        let mut found = None;
        while ti < t.len() {
            if t[ti] == qc {
                found = Some(ti);
                break;
            }
            ti += 1;
        }
        let i = found?;
        s += 10;
        if prev.is_some_and(|p| p + 1 == i) {
            s += 15;
        }
        if i == 0 || matches!(t.get(i.wrapping_sub(1)), Some(' ' | '-' | '_' | '.' | '/')) {
            s += 12;
        }
        prev = Some(i);
        ti = i + 1;
    }
    Some(s - t.len() as i32 / 8)
}

pub fn show(app: &mut App, ctx: &egui::Context) {
    let Some(mut state) = app.finder.take() else {
        return;
    };
    let p = theme::current(ctx);
    let all = items(app);
    let mut ranked: Vec<(i32, usize)> = all
        .iter()
        .enumerate()
        .filter_map(|(i, it)| score(&state.query, &it.label).map(|s| (s, i)))
        .collect();
    if !state.query.is_empty() {
        ranked.sort_by_key(|r| std::cmp::Reverse(r.0));
    }
    ranked.truncate(60);
    let (down, up, enter, esc) = ctx.input(|i| {
        (
            i.key_pressed(Key::ArrowDown),
            i.key_pressed(Key::ArrowUp),
            i.key_pressed(Key::Enter),
            i.key_pressed(Key::Escape),
        )
    });
    if down {
        state.sel = (state.sel + 1).min(ranked.len().saturating_sub(1));
    }
    if up {
        state.sel = state.sel.saturating_sub(1);
    }
    state.sel = state.sel.min(ranked.len().saturating_sub(1));
    let mut chosen: Option<Cmd> = None;
    let area =
        egui::Modal::default_area(Id::unique("finder")).anchor(Align2::CENTER_TOP, vec2(0.0, 90.0));
    let frame = egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(14))
        .shadow(ctx.global_style().visuals.window_shadow)
        .inner_margin(Margin::same(8));
    let resp = egui::Modal::new(Id::unique("finder"))
        .area(area)
        .frame(frame)
        .show(ctx, |ui| {
            ui.set_width(560.0);
            ui.horizontal(|ui| {
                ui.add_space(6.0);
                icons::icon(ui, 16.0, Icon::Search, p.dim);
                let r = ui.add(
                    egui::TextEdit::singleline(&mut state.query)
                        .frame(egui::Frame::NONE)
                        .align(egui::Align2::LEFT_CENTER)
                        .hint_text(
                            RichText::new("Search files, folders, places and actions")
                                .color(p.faint),
                        )
                        .font(FontId::proportional(15.0))
                        .desired_width(500.0)
                        .margin(Margin::symmetric(4, 8)),
                );
                r.request_focus();
                if r.changed() {
                    state.sel = 0;
                }
            });
            ui.painter().hline(
                ui.max_rect().x_range(),
                ui.cursor().top(),
                Stroke::new(1.0, p.line),
            );
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .max_height(380.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if ranked.is_empty() {
                        ui.label(RichText::new("No matches").color(p.faint));
                    }
                    for (k, (_, i)) in ranked.iter().enumerate() {
                        let it = &all[*i];
                        let (rect, r) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 34.0), Sense::click());
                        let active = k == state.sel;
                        if active || r.hovered() {
                            ui.painter().rect_filled(
                                rect,
                                CornerRadius::same(8),
                                if active { p.accent_soft } else { p.hover },
                            );
                        }
                        if active && (down || up) {
                            ui.scroll_to_rect(rect, None);
                        }
                        let ir = Rect::from_min_size(
                            pos2(rect.left() + 10.0, rect.center().y - 9.0),
                            vec2(18.0, 18.0),
                        );
                        match (&it.icon, &it.file) {
                            (Some(icon), _) => icons::draw(
                                ui.painter(),
                                ir.shrink(1.0),
                                *icon,
                                if active { p.accent } else { p.dim },
                            ),
                            (None, Some((_, true))) => icons::folder(ui.painter(), ir),
                            (None, Some((name, false))) => {
                                icons::file(ui.painter(), ir, name, p.dark)
                            }
                            _ => {}
                        }
                        let painter = ui.painter_at(rect.shrink2(vec2(4.0, 0.0)));
                        painter.text(
                            pos2(rect.left() + 38.0, rect.center().y),
                            Align2::LEFT_CENTER,
                            &it.label,
                            FontId::proportional(13.5),
                            p.text,
                        );
                        if !it.hint.is_empty() {
                            painter.text(
                                pos2(rect.right() - 12.0, rect.center().y),
                                Align2::RIGHT_CENTER,
                                &it.hint,
                                FontId::proportional(11.5),
                                p.faint,
                            );
                        }
                        if r.clicked() {
                            chosen = Some(it.cmd.clone());
                        }
                    }
                });
        });
    if enter {
        if let Some((_, i)) = ranked.get(state.sel) {
            chosen = Some(all[*i].cmd.clone());
        }
    }
    if let Some(cmd) = chosen {
        run(app, ctx, cmd);
        return;
    }
    if esc || resp.should_close() {
        return;
    }
    app.finder = Some(state);
}

fn run(app: &mut App, ctx: &egui::Context, cmd: Cmd) {
    match cmd {
        Cmd::Open => crate::dialogs::pick_and_open(app, ctx),
        Cmd::New => app.dialog = Some(Dialog::pack(Vec::new())),
        Cmd::Extract => app.dialog = Some(Dialog::Extract(ExtractForm::new(app))),
        Cmd::ExtractHere => app.smart_extract_here(ctx),
        Cmd::Test => app.start_test(ctx),
        Cmd::OpenAsFolder => app.open_as_folder(ctx),
        Cmd::Eject(i) => app.eject(i),
        Cmd::Convert => app.open_convert(),
        Cmd::Safety => app.dialog = Some(Dialog::Safety),
        Cmd::TogglePreview => app.toggle_preview(),
        Cmd::Map => app.view = View::Map,
        Cmd::List => app.view = View::List,
        Cmd::Up => app.go_up(),
        Cmd::Refresh => app.rows_dirty = true,
        Cmd::Hidden => app.toggle_hidden(),
        Cmd::Settings => {
            app.explorer = Some(crate::shell::explorer_installed());
            app.dialog = Some(Dialog::Settings);
        }
        Cmd::Tour => crate::tour::open(app),
        Cmd::Theme(t) => app.set_theme(ctx, t),
        Cmd::Go(p) => app.go(Loc::Disk(p)),
        Cmd::Recent(p) => app.open_disk_archive(ctx, p, None),
        Cmd::Undo(id) => app.start_undo(ctx, id),
        Cmd::Row(t) => {
            app.selection.clear();
            app.selection.insert(t.clone());
            app.anchor = Some(t.clone());
            app.scroll_to = app.rows.iter().position(|r| r.target == t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::score;

    #[test]
    fn fuzzy() {
        assert!(score("ext", "Extract here").is_some());
        assert!(score("xh", "Extract here").is_some());
        assert!(score("zz", "Extract here").is_none());
        assert!(score("ex", "Extract here") > score("ex", "Toggle the preview pane next"));
    }
}
