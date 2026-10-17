//! Drawing the main window: sidebar, header, list or map, preview pane, status bar, the
//! activity card and toasts. Interaction results are applied to `App` after drawing.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, CornerRadius, FontId, Id, Key, Layout, Margin, Rect,
    RichText, Sense, Stroke, StrokeKind, Ui,
};
use egui_extras::{Column, TableBuilder};
use r7z::format::CodePage;
use r7z::ops::inspect::Level as Severity;
use r7z::util::fmt::human_size;
use r7z::util::time::format_filetime;

use crate::app::{App, Loc, ToastAct, View};
use crate::dialogs::{Dialog, ExtractForm};
use crate::icons::{self, FileClass, Icon};
use crate::model::{SortCol, Target, ROOT};
use crate::preview::Body;
use crate::shell::{self, Known};
use crate::spacemap;
use crate::theme::{self, Palette};

pub fn summary(files: u64, dirs: u64, bytes: u64) -> String {
    let mut s = format!(
        "{} {}",
        group(files),
        if files == 1 { "file" } else { "files" }
    );
    if dirs > 0 {
        s.push_str(&format!(
            ", {} {}",
            group(dirs),
            if dirs == 1 { "folder" } else { "folders" }
        ));
    }
    s.push_str(&format!(" ({})", human_size(bytes)));
    s
}

pub fn secs(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 1.0 {
        format!("{:.0} ms", s * 1000.0)
    } else if s < 90.0 {
        format!("{s:.1} s")
    } else {
        format!("{}m {:02}s", s as u64 / 60, s as u64 % 60)
    }
}

pub fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn count(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", group(n as u64), if n == 1 { one } else { many })
}

pub fn fmt_time(ft: Option<u64>) -> String {
    ft.map(|t| format_filetime(t).chars().take(16).collect())
        .unwrap_or_default()
}

// ------------------------------------------------------------------ small widgets

pub fn icon_button(
    ui: &mut Ui,
    icon: Icon,
    tip: &str,
    active: bool,
    enabled: bool,
) -> egui::Response {
    let p = theme::current(ui.ctx());
    let (rect, resp) = ui.allocate_exact_size(
        vec2(32.0, 32.0),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let bg = if active {
        p.accent_soft
    } else if enabled && resp.hovered() {
        p.raised
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, CornerRadius::same(8), bg);
    let color = if !enabled {
        p.faint
    } else if active {
        p.accent
    } else {
        p.dim
    };
    icons::draw(
        ui.painter(),
        Rect::from_center_size(rect.center(), vec2(16.0, 16.0)),
        icon,
        color,
    );
    if enabled && resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp.on_hover_text(tip)
}

/// A button with an optional leading icon. `primary` uses the accent fill.
pub fn button(
    ui: &mut Ui,
    icon: Option<Icon>,
    label: &str,
    primary: bool,
    enabled: bool,
) -> egui::Response {
    let p = theme::current(ui.ctx());
    let font = theme::semibold(13.5);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font, Color32::PLACEHOLDER);
    let icon_w = if icon.is_some() { 22.0 } else { 0.0 };
    let size = vec2(galley.size().x + icon_w + 26.0, 32.0);
    let (rect, resp) = ui.allocate_exact_size(
        size,
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let hovered = enabled && resp.hovered();
    let (fill, text, stroke) = if !enabled {
        (p.raised, p.faint, Stroke::NONE)
    } else if primary {
        (
            if hovered {
                p.accent.gamma_multiply(0.9)
            } else {
                p.accent
            },
            p.on_accent,
            Stroke::NONE,
        )
    } else {
        (
            if hovered { p.line } else { p.raised },
            p.text,
            Stroke::new(1.0, p.line),
        )
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(9),
        fill,
        stroke,
        StrokeKind::Inside,
    );
    let mut x = rect.left() + 13.0;
    if let Some(i) = icon {
        icons::draw(
            ui.painter(),
            Rect::from_min_size(pos2(x, rect.center().y - 8.0), vec2(16.0, 16.0)),
            i,
            text,
        );
        x += icon_w;
    }
    ui.painter().galley(
        pos2(x, rect.center().y - galley.size().y / 2.0),
        galley,
        text,
    );
    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn section(ui: &mut Ui, p: &Palette, label: &str) {
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.label(
            RichText::new(label.to_uppercase())
                .font(theme::semibold(10.5))
                .color(p.faint),
        );
    });
    ui.add_space(2.0);
}

/// A sidebar row: icon, label and optional right-hand detail.
fn nav_item(
    ui: &mut Ui,
    p: &Palette,
    draw_icon: impl FnOnce(&egui::Painter, Rect, Color32),
    label: &str,
    detail: &str,
    active: bool,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 30.0), Sense::click());
    let bg = if active {
        p.accent_soft
    } else if resp.hovered() {
        p.hover
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, CornerRadius::same(8), bg);
    let icon_color = if active { p.accent } else { p.dim };
    draw_icon(
        ui.painter(),
        Rect::from_min_size(
            pos2(rect.left() + 9.0, rect.center().y - 8.0),
            vec2(16.0, 16.0),
        ),
        icon_color,
    );
    let text_color = if active {
        p.text
    } else {
        p.text.gamma_multiply(0.92)
    };
    let painter = ui.painter_at(rect.shrink2(vec2(4.0, 0.0)));
    let mut right = rect.right() - 10.0;
    if !detail.is_empty() {
        let g = painter.layout_no_wrap(detail.to_string(), FontId::proportional(11.5), p.faint);
        right -= g.size().x;
        painter.galley(pos2(right, rect.center().y - g.size().y / 2.0), g, p.faint);
        right -= 8.0;
    }
    let clip = painter.with_clip_rect(Rect::from_min_max(rect.min, pos2(right, rect.max.y)));
    clip.text(
        pos2(rect.left() + 34.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(13.5),
        text_color,
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn ring(ui: &mut Ui, p: &Palette, size: f32, fraction: f32, label: &str) {
    let (rect, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    let c = rect.center();
    let r = size / 2.0 - 4.0;
    ui.painter().circle_stroke(c, r, Stroke::new(5.0, p.line));
    let f = fraction.clamp(0.0, 1.0);
    if f > 0.001 {
        let n = (64.0 * f).ceil().max(2.0) as usize;
        let start = -std::f32::consts::FRAC_PI_2;
        let pts: Vec<egui::Pos2> = (0..=n)
            .map(|i| {
                let a = start + std::f32::consts::TAU * f * i as f32 / n as f32;
                pos2(c.x + r * a.cos(), c.y + r * a.sin())
            })
            .collect();
        ui.painter()
            .add(egui::Shape::line(pts, Stroke::new(5.0, p.accent)));
    }
    ui.painter().text(
        c,
        Align2::CENTER_CENTER,
        label,
        theme::semibold(12.0),
        p.text,
    );
}

fn composition_bar(ui: &mut Ui, p: &Palette, parts: &[(FileClass, u64, u64)], width: f32) {
    let total: u64 = parts.iter().map(|x| x.1).sum::<u64>().max(1);
    let (rect, _) = ui.allocate_exact_size(vec2(width, 6.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::same(3), p.line);
    let mut x = rect.left();
    for (c, size, _) in parts {
        let w = rect.width() * (*size as f32 / total as f32);
        if w < 0.5 {
            continue;
        }
        let seg = Rect::from_min_max(
            pos2(x, rect.top()),
            pos2((x + w).min(rect.right()), rect.bottom()),
        );
        ui.painter().rect_filled(seg, CornerRadius::ZERO, c.color());
        x += w;
    }
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(3),
        Stroke::new(1.0, p.side),
        StrokeKind::Outside,
    );
}

// ------------------------------------------------------------------ sidebar

fn place_icon(k: Known) -> Icon {
    match k {
        Known::Home => Icon::Home,
        Known::Desktop => Icon::Desktop,
        Known::Downloads => Icon::Downloads,
        Known::Documents => Icon::Documents,
        Known::Pictures => Icon::Pictures,
    }
}

fn place_label(k: Known) -> &'static str {
    match k {
        Known::Home => "Home",
        Known::Desktop => "Desktop",
        Known::Downloads => "Downloads",
        Known::Documents => "Documents",
        Known::Pictures => "Pictures",
    }
}

fn sidebar(app: &mut App, root: &mut Ui, ctx: &egui::Context, p: &Palette) {
    egui::Panel::left("side")
        .exact_size(240.0)
        .resizable(false)
        .show_separator_line(false)
        .frame(egui::Frame::new().fill(p.side).inner_margin(Margin {
            left: 12,
            right: 12,
            top: 16,
            bottom: 10,
        }))
        .show(root, |ui| {
            let full = ui.max_rect();
            ui.painter().vline(
                full.right() + 12.0,
                ctx.content_rect().y_range(),
                Stroke::new(1.0, p.line),
            );
            ui.horizontal(|ui| {
                ui.add_space(6.0);
                let (r, _) = ui.allocate_exact_size(vec2(26.0, 26.0), Sense::hover());
                icons::mark(ui.painter(), r);
                ui.add_space(2.0);
                ui.label(
                    RichText::new("r7z")
                        .font(theme::semibold(18.0))
                        .color(p.text),
                );
            });
            ui.add_space(4.0);
            let settings_h = 40.0;
            let scroll_h = (ui.available_height() - settings_h).max(80.0);
            egui::ScrollArea::vertical()
                .max_height(scroll_h)
                .auto_shrink([false, false])
                .show(ui, |ui| sidebar_body(app, ui, ctx, p));
            ui.add_space(4.0);
            let r = nav_item(
                ui,
                p,
                |pt, r, c| icons::draw(pt, r, Icon::Settings, c),
                "Settings",
                "",
                false,
            );
            if r.clicked() {
                app.explorer = Some(shell::explorer_installed());
                app.dialog = Some(Dialog::Settings);
            }
        });
}

fn sidebar_body(app: &mut App, ui: &mut Ui, ctx: &egui::Context, p: &Palette) {
    let current_disk = match &app.loc {
        Loc::Disk(d) => Some(d.clone()),
        _ => None,
    };
    section(ui, p, "Places");
    let mut go: Option<PathBuf> = None;
    for (k, path) in app.places.clone() {
        let active = current_disk.as_deref() == Some(path.as_path());
        if nav_item(
            ui,
            p,
            |pt, r, c| icons::draw(pt, r, place_icon(k), c),
            place_label(k),
            "",
            active,
        )
        .clicked()
        {
            go = Some(path);
        }
    }
    section(ui, p, "Drives");
    for d in &app.drives {
        let letter = d
            .root
            .display()
            .to_string()
            .trim_end_matches('\\')
            .to_string();
        let label = if d.label.is_empty() {
            format!("Drive ({letter})")
        } else {
            format!("{} ({letter})", d.label)
        };
        let active = current_disk.as_deref() == Some(d.root.as_path());
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 42.0), Sense::click());
        let bg = if active {
            p.accent_soft
        } else if resp.hovered() {
            p.hover
        } else {
            Color32::TRANSPARENT
        };
        ui.painter().rect_filled(rect, CornerRadius::same(8), bg);
        icons::draw(
            ui.painter(),
            Rect::from_min_size(pos2(rect.left() + 9.0, rect.top() + 6.0), vec2(16.0, 16.0)),
            Icon::Drive,
            if active { p.accent } else { p.dim },
        );
        let painter = ui.painter_at(rect.shrink2(vec2(4.0, 0.0)));
        painter.text(
            pos2(rect.left() + 34.0, rect.top() + 14.0),
            Align2::LEFT_CENTER,
            &label,
            FontId::proportional(13.5),
            p.text,
        );
        if d.total > 0 {
            let used = 1.0 - d.free as f32 / d.total as f32;
            let bar = Rect::from_min_max(
                pos2(rect.left() + 34.0, rect.top() + 28.0),
                pos2(rect.left() + 104.0, rect.top() + 32.0),
            );
            painter.rect_filled(bar, CornerRadius::same(2), p.line);
            let fill = Rect::from_min_max(
                bar.min,
                pos2(bar.left() + bar.width() * used.clamp(0.0, 1.0), bar.max.y),
            );
            painter.rect_filled(
                fill,
                CornerRadius::same(2),
                if used > 0.9 { p.danger } else { p.dim },
            );
            painter.text(
                pos2(bar.right() + 8.0, bar.center().y),
                Align2::LEFT_CENTER,
                format!("{} free", human_size(d.free)),
                FontId::proportional(11.0),
                p.faint,
            );
        }
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            go = Some(d.root.clone());
        }
    }
    mounts_section(app, ui, p);
    if app.level().is_some() {
        section(ui, p, "Archive");
        archive_card(app, ui, ctx, p);
    }
    let recent: Vec<PathBuf> = app
        .recent
        .iter()
        .filter(|r| r.exists())
        .take(6)
        .cloned()
        .collect();
    if !recent.is_empty() {
        section(ui, p, "Recent");
        for path in recent {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let n2 = name.clone();
            let resp = nav_item(
                ui,
                p,
                move |pt, r, _| icons::file(pt, r, &n2, p.dark),
                &name,
                "",
                false,
            );
            let resp = resp.on_hover_text(path.display().to_string());
            if resp.clicked() {
                app.open_disk_archive(ctx, path, None);
            }
        }
    }
    if let Some(dir) = go {
        app.go(Loc::Disk(dir));
    }
}

/// Archives open as folders in Explorer: click to show the folder, the button ejects.
fn mounts_section(app: &mut App, ui: &mut Ui, p: &Palette) {
    if app.mounts.active.is_empty() && app.mounts.pending.is_none() {
        return;
    }
    section(ui, p, "Open as folders");
    let mut eject = None;
    for (i, m) in app.mounts.active.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            let w = ui.available_width() - 34.0;
            let resp = ui
                .allocate_ui(vec2(w, 30.0), |ui| {
                    nav_item(
                        ui,
                        p,
                        |pt, r, c| icons::draw(pt, r, Icon::External, c),
                        &m.name,
                        "",
                        false,
                    )
                })
                .inner;
            let mut tip = format!(
                "{}\n{}",
                m.root.display(),
                count(m.files as usize, "file", "files")
            );
            let served = m.served();
            if served > 0 {
                tip.push_str(&format!(", {} read so far", human_size(served)));
            }
            if resp.on_hover_text(tip).clicked() {
                shell::open_path(&m.root);
            }
            if icon_button(ui, Icon::Eject, "Eject", false, true).clicked() {
                eject = Some(i);
            }
        });
    }
    if let Some((_, _, name)) = &app.mounts.pending {
        ui.horizontal(|ui| {
            ui.add_space(34.0);
            ui.label(
                RichText::new(format!("Opening {name}…"))
                    .size(12.0)
                    .color(p.faint),
            );
        });
    }
    if let Some(i) = eject {
        app.eject(i);
    }
}

fn archive_card(app: &mut App, ui: &mut Ui, ctx: &egui::Context, p: &Palette) {
    let Some(level) = app.level() else { return };
    let coding = level.opened.archive().name_coding();
    let mut pick_code_page: Option<Option<CodePage>> = None;
    let root = &level.tree.nodes[ROOT];
    let packed = if level.physical > 0 {
        level.physical
    } else {
        root.packed
    };
    let ratio = if root.size > 0 {
        packed as f32 / root.size as f32
    } else {
        1.0
    };
    let chain = level
        .opened
        .levels
        .iter()
        .map(|l| l.archive.format().name)
        .collect::<Vec<_>>()
        .join(" › ");
    let parts = level.tree.class_sizes(ROOT);
    let findings = level.findings.clone();
    let (files, dirs, size) = (root.files, level.tree.dir_count(), root.size);
    let (method, solid, enc, name) = (
        level.method.clone(),
        level.solid,
        level.encrypted(),
        level.name.clone(),
    );
    let mut set_filter: Option<Option<FileClass>> = None;
    let mut open_safety = false;
    // Recovery reopens the file on disk, so it is offered for the outermost archive.
    let damaged = (level.damaged && app.stack.len() == 1).then(|| level.disk.clone());
    let mut recover = false;
    let mut as_folder = false;
    let mounted = app.level_is_mounted();
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let label = format!("{:.0}%", ratio.min(1.0) * 100.0);
                ring(ui, p, 46.0, ratio.min(1.0), &label);
                ui.vertical(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(&name).font(theme::semibold(13.5)))
                            .truncate(),
                    );
                    ui.label(
                        RichText::new(format!("{} → {}", human_size(size), human_size(packed)))
                            .size(12.0)
                            .color(p.dim),
                    );
                    ui.label(RichText::new(chain).size(11.5).color(p.faint));
                });
            });
            ui.add_space(8.0);
            let worst = findings.iter().map(|f| f.level).max();
            let (icon, color, text) = match worst {
                None => (Icon::Check, p.ok, "No safety concerns".to_string()),
                Some(Severity::Note) => {
                    (Icon::Shield, p.dim, count(findings.len(), "note", "notes"))
                }
                Some(Severity::Caution) => (
                    Icon::Alert,
                    p.caution,
                    count(findings.len(), "thing to check", "things to check"),
                ),
                Some(Severity::Danger) => (
                    Icon::Alert,
                    p.danger,
                    count(findings.len(), "warning", "warnings"),
                ),
            };
            let (rect, resp) =
                ui.allocate_exact_size(vec2(ui.available_width(), 26.0), Sense::click());
            ui.painter().rect_filled(
                rect,
                CornerRadius::same(7),
                if resp.hovered() { p.hover } else { p.raised },
            );
            icons::draw(
                ui.painter(),
                Rect::from_min_size(
                    pos2(rect.left() + 7.0, rect.center().y - 7.0),
                    vec2(14.0, 14.0),
                ),
                icon,
                color,
            );
            ui.painter().text(
                pos2(rect.left() + 28.0, rect.center().y),
                Align2::LEFT_CENTER,
                text,
                FontId::proportional(12.0),
                p.text,
            );
            if resp.clicked() {
                open_safety = true;
            }
            if damaged.is_some() {
                ui.add_space(6.0);
                recover = button(ui, Some(Icon::Alert), "Recover files…", false, true)
                    .on_hover_text("Extract everything that is still readable")
                    .clicked();
            }
            ui.add_space(6.0);
            as_folder = button(
                ui,
                Some(Icon::External),
                if mounted {
                    "Show folder"
                } else {
                    "Open as folder"
                },
                false,
                true,
            )
            .on_hover_text("Browse it in Explorer like a normal folder, without extracting")
            .clicked();
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!(
                    "{} files · {} folders",
                    group(files),
                    group(dirs as u64)
                ))
                .size(12.0)
                .color(p.dim),
            );
            let mut tags: Vec<String> = Vec::new();
            if let Some(m) = method {
                tags.push(m);
            }
            if solid {
                tags.push("solid".into());
            }
            if enc {
                tags.push("encrypted".into());
            }
            if !tags.is_empty() {
                ui.add(
                    egui::Label::new(RichText::new(tags.join(" · ")).size(11.5).color(p.faint))
                        .wrap(),
                );
            }
            // Names stored without a Unicode flag: show the code page used, and let the
            // user pick another when the names look wrong.
            if let Some(c) = coding {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let how = if c.detected {
                        "Names (detected)"
                    } else {
                        "Names"
                    };
                    ui.label(RichText::new(how).size(11.5).color(p.dim));
                    egui::ComboBox::from_id_salt("name_code_page")
                        .selected_text(RichText::new(c.page.to_string()).size(11.5))
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            if ui
                                .selectable_label(c.detected, "Detect automatically")
                                .clicked()
                                && !c.detected
                            {
                                pick_code_page = Some(None);
                            }
                            for cp in CodePage::all() {
                                let on = !c.detected && cp == c.page;
                                if ui.selectable_label(on, cp.to_string()).clicked() && !on {
                                    pick_code_page = Some(Some(cp));
                                }
                            }
                        })
                        .response
                        .on_hover_text("Code page of the file names");
                });
            }
            if !parts.is_empty() {
                ui.add_space(8.0);
                composition_bar(ui, p, &parts, ui.available_width());
                ui.add_space(4.0);
                let total: u64 = parts.iter().map(|x| x.1).sum::<u64>().max(1);
                for (c, s, n) in parts.iter().take(3) {
                    let active = app.class_filter == Some(*c);
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 20.0), Sense::click());
                    if resp.hovered() || active {
                        ui.painter().rect_filled(
                            rect,
                            CornerRadius::same(5),
                            if active { p.accent_soft } else { p.hover },
                        );
                    }
                    ui.painter().circle_filled(
                        pos2(rect.left() + 7.0, rect.center().y),
                        3.5,
                        c.color(),
                    );
                    ui.painter().text(
                        pos2(rect.left() + 16.0, rect.center().y),
                        Align2::LEFT_CENTER,
                        c.label(),
                        FontId::proportional(12.0),
                        p.text,
                    );
                    ui.painter().text(
                        pos2(rect.right() - 4.0, rect.center().y),
                        Align2::RIGHT_CENTER,
                        format!("{} · {:.0}%", n, *s as f64 * 100.0 / total as f64),
                        FontId::proportional(11.5),
                        p.faint,
                    );
                    if resp.clicked() {
                        set_filter = Some(if active { None } else { Some(*c) });
                    }
                    resp.on_hover_text("Show only these");
                }
            }
        });
    if let Some(f) = set_filter {
        app.class_filter = f;
        app.rows_dirty = true;
    }
    if open_safety {
        app.dialog = Some(Dialog::Safety);
    }
    if as_folder {
        app.open_as_folder(ctx);
    }
    if let (true, Some(path)) = (recover, damaged) {
        app.start_recover(ctx, path);
    }
    if let Some(cp) = pick_code_page {
        app.relist_with_code_page(ctx, cp);
    }
}

// ------------------------------------------------------------------ header

struct Crumb {
    label: String,
    loc: Loc,
    archive: bool,
}

fn crumbs(app: &App) -> Vec<Crumb> {
    let mut v = Vec::new();
    match &app.loc {
        Loc::Disk(d) => {
            let mut parts: Vec<&Path> = d.ancestors().collect();
            parts.reverse();
            for a in parts {
                let label = a
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| a.display().to_string().trim_end_matches('\\').to_string());
                v.push(Crumb {
                    label,
                    loc: Loc::Disk(a.to_path_buf()),
                    archive: false,
                });
            }
        }
        Loc::Archive { depth, node } => {
            if let Some(parent) = app.stack[0].disk.parent() {
                let label = parent
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| parent.display().to_string());
                v.push(Crumb {
                    label,
                    loc: Loc::Disk(parent.to_path_buf()),
                    archive: false,
                });
            }
            for k in 0..=*depth {
                let level = &app.stack[k];
                v.push(Crumb {
                    label: level.name.clone(),
                    loc: Loc::Archive {
                        depth: k,
                        node: ROOT,
                    },
                    archive: true,
                });
                let inner = if k == *depth {
                    *node
                } else {
                    app.stack[k + 1].parent_node
                };
                for n in level.tree.ancestry(inner).into_iter().skip(1) {
                    v.push(Crumb {
                        label: level.tree.nodes[n].name.clone(),
                        loc: Loc::Archive { depth: k, node: n },
                        archive: false,
                    });
                }
            }
        }
    }
    v
}

fn header(app: &mut App, root: &mut Ui, ctx: &egui::Context, p: &Palette) {
    egui::Panel::top("header")
        .show_separator_line(false)
        .frame(egui::Frame::new().fill(p.base).inner_margin(Margin {
            left: 16,
            right: 16,
            top: 12,
            bottom: 6,
        }))
        .show(root, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                if icon_button(
                    ui,
                    Icon::Back,
                    "Back (Alt+Left)",
                    false,
                    !app.back.is_empty(),
                )
                .clicked()
                {
                    app.go_back();
                }
                if icon_button(
                    ui,
                    Icon::Forward,
                    "Forward (Alt+Right)",
                    false,
                    !app.forward.is_empty(),
                )
                .clicked()
                {
                    app.go_forward();
                }
                if icon_button(
                    ui,
                    Icon::Up,
                    "Up one level (Backspace)",
                    false,
                    app.parent_loc().is_some(),
                )
                .clicked()
                {
                    app.go_up();
                }
                ui.add_space(8.0);
                ui.spacing_mut().item_spacing.x = 6.0;
                let right_w = if app.in_archive() { 112.0 } else { 40.0 };
                let avail = (ui.available_width() - right_w).max(120.0);
                ui.allocate_ui_with_layout(
                    vec2(avail, 32.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.set_clip_rect(ui.max_rect());
                        breadcrumb(app, ui, p, avail);
                    },
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    if icon_button(
                        ui,
                        Icon::Preview,
                        "Preview pane (Space)",
                        app.show_preview,
                        true,
                    )
                    .clicked()
                    {
                        app.toggle_preview();
                    }
                    if app.in_archive() {
                        if icon_button(ui, Icon::Map, "Space map", app.view == View::Map, true)
                            .clicked()
                        {
                            app.view = View::Map;
                        }
                        if icon_button(ui, Icon::List, "List", app.view == View::List, true)
                            .clicked()
                        {
                            app.view = View::List;
                        }
                    }
                });
            });
            ui.add_space(8.0);
            action_bar(app, ui, ctx, p);
        });
}

fn breadcrumb(app: &mut App, ui: &mut Ui, p: &Palette, width: f32) {
    let all = crumbs(app);
    let mut go: Option<Loc> = None;
    // Keep as many trailing crumbs as fit; the current folder always shows.
    let widths: Vec<f32> = all
        .iter()
        .map(|c| {
            let g = ui
                .painter()
                .layout_no_wrap(c.label.clone(), theme::semibold(14.5), p.text);
            g.size().x + 22.0 + if c.archive { 20.0 } else { 0.0 }
        })
        .collect();
    let mut used = 30.0;
    let mut skip = all.len();
    while skip > 0 && used + widths[skip - 1] <= width {
        used += widths[skip - 1];
        skip -= 1;
    }
    if skip == all.len() && skip > 0 {
        skip -= 1;
    }
    if skip > 0 {
        let target = all[skip - 1].loc.clone();
        if ui
            .add(egui::Button::new(RichText::new("…").color(p.dim)).frame(false))
            .on_hover_text("Show earlier folders")
            .clicked()
        {
            go = Some(target);
        }
        icons::icon(ui, 12.0, Icon::ChevronRight, p.faint);
    }
    let last = all.len().saturating_sub(1);
    for (i, c) in all.iter().enumerate().skip(skip) {
        if i > skip {
            icons::icon(ui, 12.0, Icon::ChevronRight, p.faint);
        }
        if c.archive {
            let (r, _) = ui.allocate_exact_size(vec2(16.0, 16.0), Sense::hover());
            icons::file(ui.painter(), r, &c.label, p.dark);
        }
        let text = if i == last {
            RichText::new(&c.label)
                .font(theme::semibold(14.5))
                .color(p.text)
        } else {
            RichText::new(&c.label).size(14.0).color(p.dim)
        };
        let resp = ui.add(egui::Button::new(text).frame(false).truncate());
        if resp.hovered() && i != last {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() && i != last {
            go = Some(c.loc.clone());
        }
    }
    if let Some(l) = go {
        app.go(l);
    }
}

fn search_box(app: &mut App, ui: &mut Ui, p: &Palette) {
    let width = 250.0;
    egui::Frame::new()
        .fill(p.input)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin {
            left: 9,
            right: 6,
            top: 3,
            bottom: 3,
        })
        .show(ui, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                icons::icon(ui, 14.0, Icon::Search, p.faint);
                let hint = if app.in_archive() {
                    "Search this archive"
                } else {
                    "Filter this folder"
                };
                let r = ui.add(
                    egui::TextEdit::singleline(&mut app.search)
                        .frame(egui::Frame::NONE)
                        .align(egui::Align2::LEFT_CENTER)
                        .hint_text(RichText::new(hint).color(p.faint))
                        .desired_width(width - 60.0)
                        .margin(Margin::symmetric(2, 4)),
                );
                if app.focus_search {
                    r.request_focus();
                    app.focus_search = false;
                }
                if r.changed() {
                    app.rows_dirty = true;
                }
                if app.search.is_empty() {
                    ui.label(RichText::new("Ctrl F").size(10.5).color(p.faint));
                } else if ui
                    .add(egui::Button::new(RichText::new("×").size(14.0).color(p.dim)).frame(false))
                    .clicked()
                {
                    app.search.clear();
                    app.rows_dirty = true;
                }
            });
        });
}

fn action_bar(app: &mut App, ui: &mut Ui, ctx: &egui::Context, p: &Palette) {
    ui.horizontal(|ui| {
        ui.set_min_height(34.0);
        search_box(app, ui, p);
        ui.add_space(6.0);
        if let Some(c) = app.class_filter {
            let (rect, resp) = ui.allocate_exact_size(vec2(160.0, 26.0), Sense::click());
            ui.painter()
                .rect_filled(rect, CornerRadius::same(13), p.accent_soft);
            ui.painter()
                .circle_filled(pos2(rect.left() + 13.0, rect.center().y), 4.0, c.color());
            ui.painter().text(
                pos2(rect.left() + 24.0, rect.center().y),
                Align2::LEFT_CENTER,
                format!("Only {}", c.label().to_lowercase()),
                FontId::proportional(12.5),
                p.text,
            );
            icons::draw(
                ui.painter(),
                Rect::from_center_size(
                    pos2(rect.right() - 14.0, rect.center().y),
                    vec2(11.0, 11.0),
                ),
                Icon::Close,
                p.dim,
            );
            if resp.on_hover_text("Show everything").clicked() {
                app.class_filter = None;
                app.rows_dirty = true;
            }
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            if app.in_archive() {
                let label = if app.selection.is_empty() {
                    "Extract"
                } else {
                    "Extract selected"
                };
                if button(ui, Some(Icon::Extract), label, true, true)
                    .on_hover_text("Choose where to extract (Ctrl+E)")
                    .clicked()
                {
                    app.dialog = Some(Dialog::Extract(ExtractForm::new(app)));
                }
                if button(ui, None, "Extract here", false, true)
                    .on_hover_text("Next to the archive; a folder is created only when needed")
                    .clicked()
                {
                    app.smart_extract_here(ctx);
                }
                ui.add_space(4.0);
                if icon_button(ui, Icon::Layers, "Convert to another format", false, true).clicked()
                {
                    app.open_convert();
                }
                if icon_button(
                    ui,
                    Icon::Test,
                    "Test: check every file against its checksum",
                    false,
                    true,
                )
                .clicked()
                {
                    app.start_test(ctx);
                }
            } else {
                let sel = app.selected_rows();
                let archives: Vec<PathBuf> = sel
                    .iter()
                    .filter(|r| r.is_archive())
                    .filter_map(|r| match &r.target {
                        Target::Disk(p) => Some(p.clone()),
                        _ => None,
                    })
                    .collect();
                let paths: Vec<PathBuf> = sel
                    .iter()
                    .filter_map(|r| match &r.target {
                        Target::Disk(p) => Some(p.clone()),
                        _ => None,
                    })
                    .collect();
                let primary = archives.is_empty();
                if !archives.is_empty() {
                    let label = if archives.len() == 1 {
                        "Extract".to_string()
                    } else {
                        format!("Extract {}", archives.len())
                    };
                    if button(ui, Some(Icon::Extract), &label, true, true).clicked() {
                        app.dialog = Some(Dialog::batch(archives));
                    }
                }
                let label = if paths.is_empty() {
                    "New archive"
                } else {
                    "Compress"
                };
                if button(ui, Some(Icon::Pack), label, primary, true)
                    .on_hover_text("Pack files into an archive (Ctrl+N)")
                    .clicked()
                {
                    app.dialog = Some(Dialog::pack(paths));
                }
            }
        });
    });
}

// ------------------------------------------------------------------ list

enum RowAct {
    Click(Target, egui::Modifiers),
    Activate(Target),
    Menu(Target, MenuAct),
    Drag(Target),
}

#[derive(Clone, Copy)]
enum MenuAct {
    Open,
    ExtractTo,
    ExtractHere,
    OpenAsArchive,
    OpenAsFolder,
    Reveal,
    Compress,
    Copy,
    Paste,
    CopyName,
    CopyPath,
}

fn list(app: &mut App, ui: &mut Ui, ctx: &egui::Context, p: &Palette) {
    let in_archive = app.in_archive();
    let mut acts: Vec<RowAct> = Vec::new();
    let mut sort_click: Option<SortCol> = None;
    let searching = !app.search.trim().is_empty();
    let scroll_to = app.scroll_to.take();
    let mut drag_spent = app.drag_spent;
    let can_paste = app.can_paste();
    {
        let rows = &app.rows;
        let selection = &app.selection;
        let sort = app.sort;
        if rows.is_empty() {
            let msg = if let Some(e) = &app.list_error {
                format!("This folder can't be opened\n{e}")
            } else if searching || app.class_filter.is_some() {
                "Nothing matches".to_string()
            } else {
                "This folder is empty".to_string()
            };
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new(msg).color(p.dim));
            });
            return;
        }
        let header_cell =
            |ui: &mut Ui, label: &str, col: SortCol, right: bool, click: &mut Option<SortCol>| {
                let layout = if right {
                    Layout::right_to_left(Align::Center)
                } else {
                    Layout::left_to_right(Align::Center)
                };
                ui.with_layout(layout, |ui| {
                    ui.spacing_mut().item_spacing.x = 3.0;
                    if right {
                        ui.add_space(10.0);
                    }
                    let active = sort.0 == col;
                    let color = if active { p.text } else { p.faint };
                    if right && active {
                        icons::icon(
                            ui,
                            10.0,
                            if sort.1 { Icon::Up } else { Icon::ChevronDown },
                            p.dim,
                        );
                    }
                    let r = ui.add(
                        egui::Label::new(
                            RichText::new(label)
                                .font(theme::semibold(11.5))
                                .color(color),
                        )
                        .sense(Sense::click()),
                    );
                    if !right && active {
                        icons::icon(
                            ui,
                            10.0,
                            if sort.1 { Icon::Up } else { Icon::ChevronDown },
                            p.dim,
                        );
                    }
                    if r.clicked() {
                        *click = Some(col);
                    }
                });
            };
        let mut tb = TableBuilder::new(ui)
            .id_salt(("list", in_archive))
            .auto_shrink([false, false])
            .striped(false)
            .resizable(false)
            .sense(Sense::click_and_drag())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::remainder().at_least(150.0).clip(true))
            .column(Column::initial(124.0).at_least(70.0).clip(true))
            .column(Column::initial(104.0).at_least(56.0).clip(true))
            .column(Column::initial(76.0).at_least(52.0).clip(true));
        if in_archive {
            tb = tb.column(Column::initial(76.0).at_least(52.0).clip(true));
        }
        if let Some(i) = scroll_to {
            tb = tb.scroll_to_row(i, None);
        }
        tb.header(30.0, |mut h| {
            h.col(|ui| header_cell(ui, "Name", SortCol::Name, false, &mut sort_click));
            h.col(|ui| header_cell(ui, "Modified", SortCol::Modified, false, &mut sort_click));
            h.col(|ui| header_cell(ui, "Type", SortCol::Kind, false, &mut sort_click));
            h.col(|ui| header_cell(ui, "Size", SortCol::Size, true, &mut sort_click));
            if in_archive {
                h.col(|ui| header_cell(ui, "Packed", SortCol::Packed, true, &mut sort_click));
            }
        })
        .body(|body| {
            body.rows(32.0, rows.len(), |mut row| {
                let r = &rows[row.index()];
                row.set_selected(selection.contains(&r.target));
                row.col(|ui| {
                    ui.add_space(4.0);
                    let (ir, _) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::hover());
                    if r.is_dir {
                        icons::folder(ui.painter(), ir);
                    } else {
                        icons::file(ui.painter(), ir, &r.name, p.dark);
                    }
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(RichText::new(&r.name).size(13.5).color(if r.hidden {
                            p.dim
                        } else {
                            p.text
                        }))
                        .truncate()
                        .selectable(false),
                    );
                    if r.encrypted && !r.is_dir {
                        icons::icon(ui, 12.0, Icon::Lock, p.faint);
                    }
                    if let Some(d) = &r.detail {
                        let parent = d.rsplit_once('/').map(|(a, _)| a).unwrap_or("");
                        if !parent.is_empty() {
                            ui.add(
                                egui::Label::new(RichText::new(parent).size(12.0).color(p.faint))
                                    .truncate()
                                    .selectable(false),
                            );
                        }
                    }
                });
                row.col(|ui| {
                    ui.label(RichText::new(fmt_time(r.mtime)).size(12.5).color(p.dim));
                });
                row.col(|ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(icons::kind_label(&r.name, r.is_dir))
                                .size(12.5)
                                .color(p.dim),
                        )
                        .truncate(),
                    );
                });
                let num = |ui: &mut Ui, v: Option<u64>| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(v.map(human_size).unwrap_or_default())
                                .size(12.5)
                                .color(p.dim),
                        );
                    });
                };
                row.col(|ui| {
                    num(
                        ui,
                        if r.is_dir && !in_archive {
                            None
                        } else {
                            r.size
                        },
                    )
                });
                if in_archive {
                    row.col(|ui| num(ui, r.packed));
                }
                let resp = row.response();
                // A drag out of the window starts once the pointer has moved a few pixels
                // with the button held, so clicks and selection work as before.
                if resp.dragged() && !drag_spent {
                    let moved = resp.ctx.input(|i| {
                        match (i.pointer.press_origin(), i.pointer.latest_pos()) {
                            (Some(a), Some(b)) => a.distance(b) > 5.0,
                            _ => false,
                        }
                    });
                    if moved {
                        drag_spent = true;
                        acts.push(RowAct::Drag(r.target.clone()));
                    }
                }
                if resp.double_clicked() {
                    acts.push(RowAct::Activate(r.target.clone()));
                } else if resp.clicked() {
                    acts.push(RowAct::Click(
                        r.target.clone(),
                        resp.ctx.input(|i| i.modifiers),
                    ));
                } else if resp.secondary_clicked() && !selection.contains(&r.target) {
                    acts.push(RowAct::Click(r.target.clone(), egui::Modifiers::NONE));
                }
                resp.context_menu(|ui| {
                    ui.set_min_width(200.0);
                    let t = r.target.clone();
                    let mut item = |ui: &mut Ui, label: &str, act: MenuAct| {
                        if ui.button(label).clicked() {
                            acts.push(RowAct::Menu(t.clone(), act));
                            ui.close();
                        }
                    };
                    item(ui, "Open", MenuAct::Open);
                    match &r.target {
                        Target::Node(_) => {
                            item(ui, "Extract to…", MenuAct::ExtractTo);
                            item(ui, "Extract next to the archive", MenuAct::ExtractHere);
                            if r.is_archive() {
                                item(ui, "Browse inside", MenuAct::OpenAsArchive);
                            }
                        }
                        Target::Disk(_) => {
                            if r.is_archive() {
                                item(ui, "Extract here", MenuAct::ExtractHere);
                                item(ui, "Extract to folder…", MenuAct::ExtractTo);
                                item(ui, "Open as folder", MenuAct::OpenAsFolder);
                            }
                            item(ui, "Compress…", MenuAct::Compress);
                            item(ui, "Show in Explorer", MenuAct::Reveal);
                        }
                    }
                    ui.separator();
                    item(ui, "Copy", MenuAct::Copy);
                    if can_paste {
                        item(ui, "Paste", MenuAct::Paste);
                    }
                    item(ui, "Copy name", MenuAct::CopyName);
                    item(ui, "Copy path", MenuAct::CopyPath);
                });
            });
        });
    }
    if let Some(col) = sort_click {
        app.sort = if app.sort.0 == col {
            (col, !app.sort.1)
        } else {
            (col, matches!(col, SortCol::Name | SortCol::Kind))
        };
        app.rows_dirty = true;
    }
    app.drag_spent = drag_spent;
    for a in acts {
        match a {
            RowAct::Click(t, m) => click(app, t, m),
            RowAct::Activate(t) => app.activate(ctx, &t),
            RowAct::Menu(t, act) => menu_action(app, ctx, t, act),
            RowAct::Drag(t) => {
                if !app.selection.contains(&t) {
                    app.selection.clear();
                    app.selection.insert(t.clone());
                    app.anchor = Some(t);
                }
                app.start_drag(ctx);
            }
        }
    }
}

fn click(app: &mut App, t: Target, m: egui::Modifiers) {
    if m.shift {
        if let Some(a) = app.anchor.clone() {
            let ia = app.rows.iter().position(|r| r.target == a);
            let ib = app.rows.iter().position(|r| r.target == t);
            if let (Some(ia), Some(ib)) = (ia, ib) {
                let (lo, hi) = (ia.min(ib), ia.max(ib));
                if !m.command {
                    app.selection.clear();
                }
                for r in &app.rows[lo..=hi] {
                    app.selection.insert(r.target.clone());
                }
                return;
            }
        }
    }
    if m.command {
        if !app.selection.remove(&t) {
            app.selection.insert(t.clone());
        }
    } else {
        app.selection.clear();
        app.selection.insert(t.clone());
    }
    app.anchor = Some(t);
}

fn menu_action(app: &mut App, ctx: &egui::Context, t: Target, act: MenuAct) {
    if !app.selection.contains(&t) {
        app.selection.clear();
        app.selection.insert(t.clone());
    }
    let name = app
        .rows
        .iter()
        .find(|r| r.target == t)
        .map(|r| r.name.clone())
        .unwrap_or_default();
    match (act, &t) {
        (MenuAct::Open, _) => app.activate(ctx, &t),
        (MenuAct::OpenAsArchive, Target::Node(n)) => app.open_nested(ctx, *n, None),
        (MenuAct::ExtractTo, Target::Node(_)) => {
            let mut f = ExtractForm::new(app);
            f.selected_only = true;
            app.dialog = Some(Dialog::Extract(f));
        }
        (MenuAct::ExtractHere, Target::Node(_)) => {
            let mut f = ExtractForm::new(app);
            f.selected_only = true;
            f.open_after = false;
            f.dest = app.disk_dir().display().to_string();
            app.start_extract(ctx, f);
        }
        (MenuAct::ExtractHere, Target::Disk(p)) => {
            let archives = vec![p.clone()];
            let make = move |ctx: &egui::Context| {
                crate::jobs::batch_extract(
                    ctx,
                    archives,
                    crate::jobs::BatchDest::Smart,
                    r7z::ops::extract::Overwrite::Ask,
                    None,
                )
            };
            app.enqueue(ctx, make);
        }
        (MenuAct::ExtractTo, Target::Disk(p)) => app.dialog = Some(Dialog::batch(vec![p.clone()])),
        (MenuAct::Compress, Target::Disk(_)) => {
            let paths = app
                .selected_rows()
                .iter()
                .filter_map(|r| match &r.target {
                    Target::Disk(p) => Some(p.clone()),
                    _ => None,
                })
                .collect();
            app.dialog = Some(Dialog::pack(paths));
        }
        (MenuAct::OpenAsFolder, Target::Disk(p)) => app.open_as_folder_from_disk(ctx, p.clone()),
        (MenuAct::Reveal, Target::Disk(p)) => shell::reveal(p),
        (MenuAct::Copy, _) => app.copy_selection(ctx),
        (MenuAct::Paste, _) => app.paste(ctx),
        (MenuAct::CopyName, _) => ctx.copy_text(name),
        (MenuAct::CopyPath, Target::Disk(p)) => ctx.copy_text(p.display().to_string()),
        (MenuAct::CopyPath, Target::Node(n)) => {
            if let Loc::Archive { depth, .. } = app.loc {
                ctx.copy_text(app.stack[depth].tree.nodes[*n].path.clone());
            }
        }
        _ => {}
    }
}

fn central(app: &mut App, root: &mut Ui, ctx: &egui::Context, p: &Palette) {
    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(p.base).inner_margin(Margin {
            left: 16,
            right: 16,
            top: 2,
            bottom: 10,
        }))
        .show(root, |ui| {
            egui::Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.line))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin {
                    left: 6,
                    right: 6,
                    top: 4,
                    bottom: 4,
                })
                .show(ui, |ui| {
                    ui.set_min_size(ui.available_size());
                    if app.opening.is_some() {
                        ui.centered_and_justified(|ui| {
                            ui.add(egui::Spinner::new().size(28.0).color(p.accent));
                        });
                        return;
                    }
                    match (app.view, &app.loc) {
                        (View::Map, Loc::Archive { depth, node }) => {
                            let (depth, node) = (*depth, *node);
                            let selected = app.single_selected().and_then(|r| match r.target {
                                Target::Node(n) => Some(n),
                                _ => None,
                            });
                            let act = spacemap::show(ui, &app.stack[depth].tree, node, selected, p);
                            match act {
                                Some(spacemap::MapAction::Enter(n)) => {
                                    app.go(Loc::Archive { depth, node: n })
                                }
                                Some(spacemap::MapAction::Select(n)) => {
                                    app.selection.clear();
                                    app.selection.insert(Target::Node(n));
                                }
                                None => {}
                            }
                        }
                        _ => list(app, ui, ctx, p),
                    }
                });
        });
}

// ------------------------------------------------------------------ preview pane

/// The field for a pasted hash, and whether the file matches it.
fn hash_check(app: &mut App, ui: &mut Ui, ctx: &egui::Context, p: &Palette, name: &str) {
    let width = ui.available_width();
    let edited = egui::Frame::new()
        .fill(p.input)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("expected-hash")
                .max_height(64.0)
                .show(ui, |ui| {
                    // A fixed id: the rows above change while hashing, which would
                    // otherwise give the field a new id and take its focus away.
                    ui.add(
                        egui::TextEdit::multiline(&mut app.preview.expected)
                            .id_salt("expected-hash-text")
                            .frame(egui::Frame::NONE)
                            .align(egui::Align2::LEFT_CENTER)
                            .desired_rows(1)
                            .font(FontId::monospace(11.5))
                            .hint_text(
                                RichText::new("Paste a hash to check this file")
                                    .font(FontId::proportional(12.0))
                                    .color(p.faint),
                            )
                            .desired_width(width - 16.0)
                            .margin(Margin::symmetric(0, 4)),
                    )
                    .changed()
                })
                .inner
        })
        .inner;
    if edited {
        app.preview.expected_edit = Some(Instant::now());
    }
    // Hashing starts once typing pauses, so a hash typed by hand isn't checked as a
    // CRC32 at its eighth digit. `None` means the text was not edited for this file.
    const SETTLE: Duration = Duration::from_millis(350);
    let settled = match app.preview.expected_edit {
        Some(t) if t.elapsed() >= SETTLE => Some(true),
        Some(t) => {
            ctx.request_repaint_after(SETTLE - t.elapsed());
            Some(false)
        }
        None => None,
    };
    let Some(parsed) = crate::preview::parse_expected(&app.preview.expected, name) else {
        return;
    };
    let exp = match parsed {
        Ok(e) => e,
        Err(msg) => {
            ui.add(egui::Label::new(RichText::new(msg).size(12.0).color(p.caution)).wrap());
            return;
        }
    };
    let actual = match &app.preview.digest {
        Some(Ok(d)) => d.get(exp.algo).map(str::to_string),
        _ => None,
    };
    match actual {
        Some(actual) if exp.matches(&actual) => {
            ui.horizontal(|ui| {
                icons::icon(ui, 14.0, Icon::Check, p.ok);
                ui.label(
                    RichText::new(format!("{} matches", exp.algo.name()))
                        .font(theme::semibold(12.5))
                        .color(p.ok),
                );
            });
        }
        Some(actual) => {
            ui.horizontal(|ui| {
                icons::icon(ui, 14.0, Icon::Alert, p.danger);
                ui.label(
                    RichText::new(format!("{} doesn't match", exp.algo.name()))
                        .font(theme::semibold(12.5))
                        .color(p.danger),
                );
            });
            ui.add(
                egui::Label::new(
                    RichText::new(format!("This file: {actual}"))
                        .monospace()
                        .size(11.0)
                        .color(p.dim),
                )
                .wrap()
                .selectable(true),
            );
        }
        None if app.preview.hashing() => {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(14.0));
                ui.label(
                    RichText::new(format!("Computing {}…", exp.algo.name()))
                        .size(12.0)
                        .color(p.dim),
                );
            });
            // A different kind of hash pasted while another is computed.
            if settled == Some(true) {
                app.preview.expected_edit = None;
                app.preview.ensure_hash(ctx, exp.algo);
            }
        }
        None => match settled {
            Some(true) => {
                app.preview.expected_edit = None;
                app.preview.ensure_hash(ctx, exp.algo);
            }
            Some(false) => {}
            None => {
                let label = format!("Check {}", exp.algo.name());
                if button(ui, None, &label, false, true).clicked() {
                    app.preview.ensure_hash(ctx, exp.algo);
                }
            }
        },
    }
    if let Some(other) = exp.name.as_deref().filter(|_| !exp.is_for(name)) {
        ui.add(
            egui::Label::new(
                RichText::new(format!("The pasted hash is for {other}."))
                    .size(12.0)
                    .color(p.caution),
            )
            .wrap(),
        );
    }
}

fn prop(ui: &mut Ui, p: &Palette, k: &str, v: &str) {
    if v.is_empty() {
        return;
    }
    ui.horizontal(|ui| {
        ui.add_sized(
            vec2(78.0, 18.0),
            egui::Label::new(RichText::new(k).size(12.0).color(p.faint)),
        );
        ui.add(
            egui::Label::new(RichText::new(v).size(12.5).color(p.text))
                .wrap()
                .selectable(true),
        );
    });
}

fn preview_panel(app: &mut App, root: &mut Ui, ctx: &egui::Context, p: &Palette) {
    egui::Panel::right("preview")
        .resizable(true)
        .default_size(330.0)
        .size_range(270.0..=620.0)
        .show_separator_line(false)
        .frame(egui::Frame::new().fill(p.side).inner_margin(Margin {
            left: 16,
            right: 16,
            top: 16,
            bottom: 12,
        }))
        .show(root, |ui| {
            let r = ui.max_rect();
            ui.painter().vline(
                r.left() - 16.0,
                ctx.content_rect().y_range(),
                Stroke::new(1.0, p.line),
            );
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| preview_body(app, ui, ctx, p));
        });
}

fn preview_body(app: &mut App, ui: &mut Ui, ctx: &egui::Context, p: &Palette) {
    let selected: Vec<_> = app.selected_rows().into_iter().cloned().collect();
    if selected.len() > 1 {
        let size: u64 = selected.iter().filter_map(|r| r.size).sum();
        ui.label(
            RichText::new(format!("{} items selected", selected.len())).font(theme::semibold(16.0)),
        );
        ui.label(RichText::new(human_size(size)).color(p.dim));
        return;
    }
    let Some(row) = selected.into_iter().next() else {
        folder_summary(app, ui, p);
        return;
    };
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(vec2(48.0, 48.0), Sense::hover());
        if row.is_dir {
            icons::folder(ui.painter(), r);
        } else {
            icons::file(ui.painter(), r, &row.name, p.dark);
        }
        ui.vertical(|ui| {
            ui.add(egui::Label::new(RichText::new(&row.name).font(theme::semibold(15.0))).wrap());
            ui.label(
                RichText::new(icons::kind_label(&row.name, row.is_dir))
                    .size(12.0)
                    .color(p.dim),
            );
        });
    });
    ui.add_space(12.0);
    if !row.is_dir {
        preview_content(app, ui, ctx, p);
        ui.add_space(12.0);
    }
    let mut size = row.size.map(human_size).unwrap_or_default();
    if let (Some(s), Some(pk)) = (row.size, row.packed) {
        if s > 0 {
            size = format!(
                "{size}  ·  packed {} ({:.0}%)",
                human_size(pk),
                pk as f64 * 100.0 / s as f64
            );
        }
    }
    prop(ui, p, "Size", &size);
    prop(ui, p, "Modified", &fmt_time(row.mtime));
    match &row.target {
        Target::Disk(path) => prop(
            ui,
            p,
            "Location",
            &path
                .parent()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
        ),
        Target::Node(n) => {
            if let Loc::Archive { depth, .. } = app.loc {
                let level = &app.stack[depth];
                let node = &level.tree.nodes[*n];
                prop(ui, p, "Path", &node.path);
                if let Some(e) = node.entry.map(|i| &level.opened.archive().entries()[i]) {
                    prop(ui, p, "Method", e.method.as_deref().unwrap_or(""));
                    prop(
                        ui,
                        p,
                        "CRC32",
                        &e.crc.map(|c| format!("{c:08X}")).unwrap_or_default(),
                    );
                    if e.encrypted {
                        prop(ui, p, "Encrypted", "yes");
                    }
                    if let Some(c) = &e.comment {
                        prop(ui, p, "Comment", c);
                    }
                }
            }
        }
    }
    if !row.is_dir {
        ui.add_space(10.0);
        match &app.preview.digest {
            Some(Ok(d)) => {
                let (sha, crc) = (d.sha256.clone(), d.crc32.clone());
                ui.horizontal(|ui| {
                    ui.add_sized(
                        vec2(78.0, 18.0),
                        egui::Label::new(RichText::new("SHA-256").size(12.0).color(p.faint)),
                    );
                    ui.add(
                        egui::Label::new(RichText::new(&sha).monospace().size(11.0))
                            .wrap()
                            .selectable(true),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add_space(82.0);
                    if ui.small_button("Copy SHA-256").clicked() {
                        ctx.copy_text(sha.clone());
                    }
                    if ui.small_button("Copy CRC32").clicked() {
                        ctx.copy_text(crc.clone());
                    }
                });
            }
            Some(Err(e)) => {
                ui.label(
                    RichText::new(format!("Couldn't hash: {e}"))
                        .size(12.0)
                        .color(p.danger),
                );
            }
            None if app.preview.hashing() => {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label(RichText::new("Hashing…").size(12.0).color(p.dim));
                });
            }
            None => {
                if button(ui, None, "Compute SHA-256", false, true).clicked() {
                    app.preview.start_hash(ctx);
                }
            }
        }
        ui.add_space(8.0);
        hash_check(app, ui, ctx, p, &row.name);
    }
    ui.add_space(12.0);
    ui.horizontal_wrapped(|ui| {
        let target = row.target.clone();
        let label = if row.is_dir {
            "Open"
        } else if row.is_archive() {
            "Browse"
        } else {
            "Open"
        };
        if button(ui, Some(Icon::External), label, true, true).clicked() {
            app.activate(ctx, &target);
        }
        if let Target::Disk(path) = &target {
            if button(ui, None, "Show in Explorer", false, true).clicked() {
                shell::reveal(path);
            }
        } else if button(ui, Some(Icon::Extract), "Extract", false, true).clicked() {
            let mut f = ExtractForm::new(app);
            f.selected_only = true;
            app.dialog = Some(Dialog::Extract(f));
        }
    });
}

fn checkerboard(ui: &Ui, r: Rect, p: &Palette) {
    let (a, b) = if p.dark {
        (Color32::from_gray(40), Color32::from_gray(52))
    } else {
        (Color32::from_gray(236), Color32::from_gray(250))
    };
    ui.painter().rect_filled(r, CornerRadius::same(8), a);
    let s = 10.0;
    let painter = ui.painter().with_clip_rect(r);
    let mut y = r.top();
    let mut row = 0;
    while y < r.bottom() {
        let mut x = r.left() + if row % 2 == 0 { 0.0 } else { s };
        while x < r.right() {
            painter.rect_filled(
                Rect::from_min_size(pos2(x, y), vec2(s, s)),
                CornerRadius::ZERO,
                b,
            );
            x += 2.0 * s;
        }
        y += s;
        row += 1;
    }
}

fn preview_content(app: &mut App, ui: &mut Ui, ctx: &egui::Context, p: &Palette) {
    let width = ui.available_width();
    if app.preview.waiting_for_user {
        egui::Frame::new()
            .fill(p.surface)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(width - 28.0);
                ui.label(
                    RichText::new("Large file; not previewed automatically.")
                        .size(12.5)
                        .color(p.dim),
                );
                if button(ui, None, "Preview anyway", false, true).clicked() {
                    app.preview.start(ctx);
                }
            });
        return;
    }
    if app.preview.loading() {
        egui::Frame::new()
            .fill(p.surface)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(width - 28.0);
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                    ui.label(RichText::new("Loading preview…").size(12.5).color(p.dim));
                });
            });
        return;
    }
    let mut unlock = false;
    match &app.preview.body {
        Some(Ok(Body::Image { orig, .. })) => {
            if let Some(tex) = &app.preview.texture {
                let ts = tex.size_vec2();
                let scale = (width / ts.x).min(320.0 / ts.y).min(1.0);
                let size = ts * scale;
                let (r, _) = ui.allocate_exact_size(vec2(width, size.y), Sense::hover());
                let img_rect = Rect::from_center_size(r.center(), size);
                checkerboard(ui, img_rect, p);
                ui.painter().image(
                    tex.id(),
                    img_rect,
                    Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                    Color32::WHITE,
                );
                ui.label(
                    RichText::new(format!("{} × {} px", orig.0, orig.1))
                        .size(11.5)
                        .color(p.faint),
                );
            }
        }
        Some(Ok(Body::Text {
            text,
            lines,
            truncated,
        })) => {
            code_box(ui, p, text, *lines, *truncated, width, true);
        }
        Some(Ok(Body::Hex { text, truncated })) => {
            code_box(ui, p, text, 0, *truncated, width, false);
        }
        Some(Ok(Body::Archive(s))) => {
            egui::Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.line))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::same(12))
                .show(ui, |ui| {
                    ui.set_width(width - 26.0);
                    ui.label(
                        RichText::new(format!("{} archive", s.chain)).font(theme::semibold(13.0)),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} files · {} folders · {} → {}",
                            group(s.files),
                            group(s.dirs as u64),
                            human_size(s.unpacked),
                            human_size(s.packed)
                        ))
                        .size(12.0)
                        .color(p.dim),
                    );
                    if s.encrypted {
                        ui.label(RichText::new("Encrypted").size(12.0).color(p.caution));
                    }
                    ui.add_space(6.0);
                    for (name, dir) in &s.top {
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(vec2(14.0, 14.0), Sense::hover());
                            if *dir {
                                icons::folder(ui.painter(), r);
                            } else {
                                icons::file(ui.painter(), r, name, p.dark);
                            }
                            ui.add(egui::Label::new(RichText::new(name).size(12.5)).truncate());
                        });
                    }
                    if s.more > 0 {
                        ui.label(
                            RichText::new(format!("and {} more", s.more))
                                .size(12.0)
                                .color(p.faint),
                        );
                    }
                    for f in s.findings.iter().take(4) {
                        let color = match f.level {
                            Severity::Danger => p.danger,
                            Severity::Caution => p.caution,
                            Severity::Note => p.dim,
                        };
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            icons::icon(ui, 13.0, Icon::Alert, color);
                            ui.add(
                                egui::Label::new(RichText::new(&f.title).size(12.0).color(color))
                                    .wrap(),
                            );
                        });
                    }
                });
        }
        Some(Ok(Body::Locked)) => {
            egui::Frame::new()
                .fill(p.surface)
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.set_width(width - 28.0);
                    ui.horizontal(|ui| {
                        icons::icon(ui, 16.0, Icon::Lock, p.dim);
                        ui.label(
                            RichText::new("Encrypted. Unlock to preview.")
                                .size(12.5)
                                .color(p.dim),
                        );
                    });
                    if button(ui, None, "Enter password", false, true).clicked() {
                        unlock = true;
                    }
                });
        }
        Some(Ok(Body::Empty)) => {
            ui.label(RichText::new("Empty file").size(12.5).color(p.dim));
        }
        Some(Err(e)) => {
            ui.label(
                RichText::new(format!("No preview: {e}"))
                    .size(12.5)
                    .color(p.dim),
            );
        }
        None => {}
    }
    if unlock {
        app.dialog = Some(Dialog::password(crate::dialogs::PwFor::Preview, None));
    }
}

fn code_box(
    ui: &mut Ui,
    p: &Palette,
    text: &str,
    lines: usize,
    truncated: bool,
    width: f32,
    numbered: bool,
) {
    egui::Frame::new()
        .fill(p.input)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(width - 22.0);
            egui::ScrollArea::both()
                .id_salt("code")
                .max_height(340.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    let shown: String = text.lines().take(3000).collect::<Vec<_>>().join("\n");
                    if numbered {
                        let count = shown.lines().count().max(1);
                        let nums: String = (1..=count)
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join("\n");
                        ui.horizontal_top(|ui| {
                            ui.label(RichText::new(nums).monospace().size(11.5).color(p.faint));
                            ui.add_space(6.0);
                            ui.label(RichText::new(shown).monospace().size(11.5).color(p.text));
                        });
                    } else {
                        ui.label(RichText::new(shown).monospace().size(11.0).color(p.text));
                    }
                });
        });
    if truncated || lines > 3000 {
        ui.label(
            RichText::new("Showing the beginning of the file")
                .size(11.5)
                .color(p.faint),
        );
    }
}

fn folder_summary(app: &mut App, ui: &mut Ui, p: &Palette) {
    match &app.loc {
        Loc::Disk(d) => {
            let name = d
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| d.display().to_string());
            ui.label(RichText::new(name).font(theme::semibold(16.0)));
            let files = app.rows.iter().filter(|r| !r.is_dir).count();
            let dirs = app.rows.len() - files;
            let archives = app.rows.iter().filter(|r| r.is_archive()).count();
            let size: u64 = app.rows.iter().filter_map(|r| r.size).sum();
            ui.label(
                RichText::new(format!(
                    "{} folders · {} files · {}",
                    group(dirs as u64),
                    group(files as u64),
                    human_size(size)
                ))
                .size(12.5)
                .color(p.dim),
            );
            if archives > 0 {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "{archives} archives here. Double-click one to look inside."
                    ))
                    .size(12.5)
                    .color(p.dim),
                );
            }
            ui.add_space(14.0);
            ui.label(
                RichText::new(
                    "Select a file to preview it. Drop files on the window to compress them.",
                )
                .size(12.0)
                .color(p.faint),
            );
        }
        Loc::Archive { depth, node } => {
            let t = &app.stack[*depth].tree;
            let n = &t.nodes[*node];
            ui.label(RichText::new(&n.name).font(theme::semibold(16.0)));
            ui.label(
                RichText::new(format!("{} files · {}", group(n.files), human_size(n.size)))
                    .size(12.5)
                    .color(p.dim),
            );
            let parts = t.class_sizes(*node);
            if !parts.is_empty() {
                ui.add_space(10.0);
                composition_bar(ui, p, &parts, ui.available_width());
                ui.add_space(6.0);
                let total: u64 = parts.iter().map(|x| x.1).sum::<u64>().max(1);
                for (c, s, cnt) in &parts {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(vec2(10.0, 16.0), Sense::hover());
                        ui.painter().circle_filled(r.center(), 3.5, c.color());
                        ui.label(RichText::new(c.label()).size(12.5));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{}  ·  {}  ·  {:.0}%",
                                    cnt,
                                    human_size(*s),
                                    *s as f64 * 100.0 / total as f64
                                ))
                                .size(12.0)
                                .color(p.dim),
                            );
                        });
                    });
                }
            }
        }
    }
}

// ------------------------------------------------------------------ bottom

fn status(app: &mut App, root: &mut Ui, p: &Palette) {
    egui::Panel::bottom("status")
        .show_separator_line(false)
        .exact_size(26.0)
        .frame(egui::Frame::new().fill(p.base).inner_margin(Margin {
            left: 18,
            right: 18,
            top: 0,
            bottom: 4,
        }))
        .show(root, |ui| {
            ui.horizontal_centered(|ui| {
                let sel = app.selected_rows();
                let count = app.rows.len() as u64;
                let total: u64 = app.rows.iter().filter_map(|r| r.size).sum();
                let mut text = if app.search.trim().is_empty() {
                    format!("{} items · {}", group(count), human_size(total))
                } else {
                    format!("{} matches", group(count))
                };
                if !sel.is_empty() {
                    let size: u64 = sel.iter().filter_map(|r| r.size).sum();
                    text.push_str(&format!(
                        "   ·   {} selected · {}",
                        sel.len(),
                        human_size(size)
                    ));
                } else if let Loc::Disk(d) = &app.loc {
                    if let Some(dr) = app.drives.iter().find(|dr| d.starts_with(&dr.root)) {
                        text.push_str(&format!("   ·   {} free", human_size(dr.free)));
                    }
                }
                ui.label(RichText::new(text).size(11.5).color(p.faint));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !app.queue.is_empty() {
                        ui.label(
                            RichText::new(format!("{} queued", app.queue.len()))
                                .size(11.5)
                                .color(p.faint),
                        );
                    } else {
                        ui.label(
                            RichText::new("Ctrl+Shift+F  search everywhere")
                                .size(11.5)
                                .color(p.faint),
                        );
                    }
                });
            });
        });
}

fn activity(app: &mut App, ctx: &egui::Context, p: &Palette) {
    let Some(job) = &app.job else { return };
    let s = job.shared.clone();
    let title = job.title.clone();
    egui::Area::new(Id::unique("activity"))
        .anchor(Align2::RIGHT_BOTTOM, vec2(-18.0, -38.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.line))
                .corner_radius(CornerRadius::same(14))
                .shadow(ui.visuals().popup_shadow)
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.set_width(340.0);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&title).font(theme::semibold(13.5)))
                                .truncate(),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let cancelling = s.cancel.load(Ordering::Relaxed);
                            let (r, resp) =
                                ui.allocate_exact_size(vec2(22.0, 22.0), Sense::click());
                            if resp.hovered() {
                                ui.painter().rect_filled(r, CornerRadius::same(6), p.raised);
                            }
                            icons::draw(
                                ui.painter(),
                                r.shrink(5.0),
                                Icon::Close,
                                if cancelling { p.faint } else { p.dim },
                            );
                            if resp.on_hover_text("Stop").clicked() {
                                s.request_cancel();
                            }
                        });
                    });
                    let phase = s.phase.lock().map(|g| g.clone()).unwrap_or_default();
                    let current = s.current.lock().map(|g| g.clone()).unwrap_or_default();
                    let sub = if !phase.is_empty() { phase } else { current };
                    if !sub.is_empty() {
                        ui.add(
                            egui::Label::new(RichText::new(sub).size(11.5).color(p.faint))
                                .truncate(),
                        );
                    }
                    ui.add_space(6.0);
                    let total = s.total.load(Ordering::Relaxed);
                    let done = s.done.load(Ordering::Relaxed);
                    let (bar, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 6.0), Sense::hover());
                    ui.painter().rect_filled(bar, CornerRadius::same(3), p.line);
                    if total > 0 {
                        let f = s.fraction();
                        let fill = Rect::from_min_max(
                            bar.min,
                            pos2(bar.left() + bar.width() * f, bar.max.y),
                        );
                        ui.painter()
                            .rect_filled(fill, CornerRadius::same(3), p.accent);
                    } else {
                        let t = ui.input(|i| i.time) as f32;
                        let x = bar.left() + (t * 0.8).fract() * bar.width();
                        let seg = Rect::from_min_max(
                            pos2(x - 40.0, bar.top()),
                            pos2(x + 40.0, bar.bottom()),
                        )
                        .intersect(bar);
                        ui.painter()
                            .rect_filled(seg, CornerRadius::same(3), p.accent);
                    }
                    ui.add_space(4.0);
                    let elapsed = s.started.elapsed().as_secs_f64().max(0.001);
                    let rate = done as f64 / elapsed;
                    let mut line = if total > 0 {
                        format!("{} of {}", human_size(done), human_size(total))
                    } else {
                        "Preparing…".into()
                    };
                    if elapsed > 0.5 && rate > 0.0 {
                        line.push_str(&format!(" · {}/s", human_size(rate as u64)));
                        if total > done && done * 10 >= total {
                            line.push_str(&format!(
                                " · {} left",
                                secs(Duration::from_secs_f64((total - done) as f64 / rate))
                            ));
                        }
                    }
                    ui.label(RichText::new(line).size(11.5).color(p.dim));
                });
        });
}

fn toasts(app: &mut App, ctx: &egui::Context, p: &Palette) {
    let now = Instant::now();
    app.toasts.retain(|t| t.until > now);
    if app.toasts.is_empty() {
        return;
    }
    let offset = if app.job.is_some() { -150.0 } else { -38.0 };
    let mut act: Option<(usize, usize)> = None;
    let mut dismiss: Option<usize> = None;
    egui::Area::new(Id::unique("toasts"))
        .anchor(Align2::RIGHT_BOTTOM, vec2(-18.0, offset))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            for (i, t) in app.toasts.iter().enumerate() {
                egui::Frame::new()
                    .fill(p.surface)
                    .stroke(Stroke::new(1.0, p.line))
                    .corner_radius(CornerRadius::same(12))
                    .shadow(ui.visuals().popup_shadow)
                    .inner_margin(Margin::symmetric(14, 10))
                    .show(ui, |ui| {
                        ui.set_max_width(400.0);
                        ui.horizontal(|ui| {
                            icons::icon(
                                ui,
                                15.0,
                                if t.ok { Icon::Check } else { Icon::Alert },
                                if t.ok { p.ok } else { p.caution },
                            );
                            ui.add(egui::Label::new(RichText::new(&t.text).size(12.5)).wrap());
                            for (k, (label, _)) in t.actions.iter().enumerate() {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new(label)
                                                .color(p.accent)
                                                .font(theme::semibold(12.5)),
                                        )
                                        .frame(false),
                                    )
                                    .clicked()
                                {
                                    act = Some((i, k));
                                }
                            }
                            let (r, resp) =
                                ui.allocate_exact_size(vec2(18.0, 18.0), Sense::click());
                            icons::draw(ui.painter(), r.shrink(4.0), Icon::Close, p.faint);
                            if resp.clicked() {
                                dismiss = Some(i);
                            }
                        });
                    });
                ui.add_space(8.0);
            }
        });
    if let Some((i, k)) = act {
        let mut t = app.toasts.remove(i);
        match t.actions.swap_remove(k).1 {
            ToastAct::OpenArchive(p) => app.open_disk_archive(ctx, p, None),
            ToastAct::Go(p) => app.go(Loc::Disk(p)),
            ToastAct::Recover(p) => app.start_recover(ctx, p),
            ToastAct::Undo(id) => app.start_undo(ctx, id),
            ToastAct::Update => app.install_update(ctx),
            ToastAct::Restart => app.restart(ctx),
            ToastAct::Link(url) => shell::open_path(std::path::Path::new(&url)),
        }
    } else if let Some(i) = dismiss {
        app.toasts.remove(i);
    }
}

fn drop_overlay(app: &App, ctx: &egui::Context, p: &Palette) {
    let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
    if !hovering || app.drag.is_some() {
        return;
    }
    let rect = ctx.content_rect();
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        Id::unique("drop"),
    ));
    painter.rect_filled(
        rect,
        CornerRadius::ZERO,
        Color32::from_black_alpha(if p.dark { 150 } else { 90 }),
    );
    let card = Rect::from_center_size(rect.center(), vec2(420.0, 150.0));
    painter.rect(
        card,
        CornerRadius::same(18),
        p.surface,
        Stroke::new(1.5, p.accent),
        StrokeKind::Inside,
    );
    icons::draw(
        &painter,
        Rect::from_center_size(pos2(card.center().x, card.top() + 44.0), vec2(28.0, 28.0)),
        Icon::Pack,
        p.accent,
    );
    let text = if matches!(app.dialog, Some(Dialog::Pack(_))) {
        "Add to the new archive"
    } else {
        "Drop archives to open or extract them,\nother files to compress them"
    };
    painter.text(
        pos2(card.center().x, card.top() + 100.0),
        Align2::CENTER_CENTER,
        text,
        theme::semibold(14.0),
        p.text,
    );
}

pub fn frame(app: &mut App, root: &mut Ui) {
    let ctx = &root.ctx().clone();
    let p = theme::current(ctx);
    sidebar(app, root, ctx, &p);
    // In narrow windows the list matters more than the preview.
    if app.show_preview && ctx.content_rect().width() >= 980.0 {
        preview_panel(app, root, ctx, &p);
    }
    header(app, root, ctx, &p);
    status(app, root, &p);
    central(app, root, ctx, &p);
    activity(app, ctx, &p);
    toasts(app, ctx, &p);
    drop_overlay(app, ctx, &p);
}

// ------------------------------------------------------------------ keyboard

pub fn shortcuts(app: &mut App, ctx: &egui::Context) {
    // Tracked every frame so a press is seen once, whatever has the focus.
    let paste = crate::dnd::paste_pressed(&mut app.paste_down) && ctx.input(|i| i.focused);
    if app.dialog.is_some() || app.finder.is_some() {
        return;
    }
    let typing = ctx.egui_wants_keyboard_input();
    let (cmd, alt, shift) =
        ctx.input(|i| (i.modifiers.command, i.modifiers.alt, i.modifiers.shift));
    let pressed = |k: Key| ctx.input(|i| i.key_pressed(k));
    if cmd && shift && pressed(Key::F) {
        app.finder = Some(crate::finder::FinderState::default());
        return;
    }
    if cmd && pressed(Key::F) {
        app.focus_search = true;
    }
    if cmd && pressed(Key::O) {
        crate::dialogs::pick_and_open(app, ctx);
    }
    if cmd && pressed(Key::N) {
        let paths = app
            .selected_rows()
            .iter()
            .filter_map(|r| match &r.target {
                Target::Disk(p) => Some(p.clone()),
                _ => None,
            })
            .collect();
        app.dialog = Some(Dialog::pack(paths));
    }
    if cmd && pressed(Key::E) && app.in_archive() {
        app.dialog = Some(Dialog::Extract(ExtractForm::new(app)));
    }
    if pressed(Key::F5) {
        app.rows_dirty = true;
    }
    if alt && pressed(Key::ArrowLeft) {
        app.go_back();
    }
    if alt && pressed(Key::ArrowRight) {
        app.go_forward();
    }
    if typing {
        if pressed(Key::Escape) {
            app.search.clear();
            app.rows_dirty = true;
        }
        return;
    }
    if pressed(Key::Backspace) {
        app.go_up();
    }
    if pressed(Key::Space) {
        app.toggle_preview();
    }
    if cmd && pressed(Key::A) {
        app.selection = app.rows.iter().map(|r| r.target.clone()).collect();
    }
    if ctx.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Copy))) {
        app.copy_selection(ctx);
    }
    if paste {
        app.paste(ctx);
    }
    // Esc during a drag cancels the drag, not the selection.
    if pressed(Key::Escape) && app.drag.is_none() && !app.drag_spent {
        app.selection.clear();
    }
    if pressed(Key::Enter) {
        if let Some(r) = app.single_selected().map(|r| r.target.clone()) {
            app.activate(ctx, &r);
        }
    }
    let down = pressed(Key::ArrowDown);
    let up = pressed(Key::ArrowUp) && !alt;
    if (down || up) && !app.rows.is_empty() {
        let cur = app
            .anchor
            .as_ref()
            .and_then(|a| app.rows.iter().position(|r| &r.target == a));
        let next = match (cur, down) {
            (None, _) => 0,
            (Some(i), true) => (i + 1).min(app.rows.len() - 1),
            (Some(i), false) => i.saturating_sub(1),
        };
        let t = app.rows[next].target.clone();
        if !shift {
            app.selection.clear();
        }
        app.selection.insert(t.clone());
        app.anchor = Some(t);
        app.scroll_to = Some(next);
    }
}
