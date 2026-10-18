//! The welcome tour: a few pages that show what r7z can do, each with a screenshot taken
//! from the app. It opens by itself once, on the first normal launch (not when r7z was
//! started from the Explorer menu to do a job), and again from Settings or search
//! everywhere.

use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, CornerRadius, Id, Key, Layout, Margin, Rect,
    RichText, Sense, Stroke, StrokeKind, TextureHandle, TextureOptions,
};

use crate::app::App;
use crate::icons;
use crate::shell;
use crate::theme;
use crate::ui::button;

struct Page {
    title: &'static str,
    body: &'static str,
    /// A screenshot (WebP); the first page shows the logo instead.
    image: Option<&'static [u8]>,
}

const PAGES: &[Page] = &[
    Page {
        title: "Welcome to r7z",
        body: "A fast archiver that opens what 7-Zip opens and extracts several times faster. Here's a quick look at what it can do. It takes a minute, and you can skip it anytime.",
        image: None,
    },
    Page {
        title: "Look inside without extracting",
        body: "Select a file to preview pictures, text and code straight from the archive. Paste the hash a website publishes for a download, and r7z tells you whether the file matches.",
        image: Some(include_bytes!("../res/tour/preview.webp")),
    },
    Page {
        title: "See what takes up space",
        body: "The space map shows an archive by size, down to single files, colored by type. Point at a block for details, and double-click a folder to go in.",
        image: Some(include_bytes!("../res/tour/map.webp")),
    },
    Page {
        title: "Know what you're opening",
        body: "Every archive is checked as it opens. Files that would land outside the folder, programs dressed up as documents and zip bombs are flagged before you extract anything.",
        image: Some(include_bytes!("../res/tour/safety.webp")),
    },
    Page {
        title: "Extract, and change your mind",
        body: "Extract here makes a folder only when the archive needs one, so files never spill everywhere. Every extraction can be undone, and anything it replaced comes back.",
        image: Some(include_bytes!("../res/tour/undo.webp")),
    },
    Page {
        title: "Find anything",
        body: "Press Ctrl+Shift+F to reach files, folders, places and actions from one box. Ctrl+F filters the folder you're in.",
        image: Some(include_bytes!("../res/tour/search.webp")),
    },
    Page {
        title: "Right from Explorer",
        body: "Add r7z to the right-click menu to open, extract and compress files without starting the app first. r7z keeps itself up to date with signed updates.",
        image: Some(include_bytes!("../res/tour/menu.webp")),
    },
];

pub struct Tour {
    page: usize,
    textures: Vec<Option<TextureHandle>>,
    /// When the current page appeared, for the fade-in.
    shown_at: f64,
}

impl Tour {
    pub fn new() -> Tour {
        Tour {
            page: 0,
            textures: vec![None; PAGES.len()],
            shown_at: f64::NEG_INFINITY,
        }
    }

    /// Decodes a page's screenshot the first time it is shown.
    fn texture(&mut self, ctx: &egui::Context, i: usize) -> Option<TextureHandle> {
        if self.textures[i].is_none() {
            let decoded = image::load_from_memory(PAGES[i].image?).ok()?.to_rgba8();
            let size = [decoded.width() as usize, decoded.height() as usize];
            let pixels = egui::ColorImage::from_rgba_unmultiplied(size, decoded.as_raw());
            self.textures[i] =
                Some(ctx.load_texture(format!("tour-{i}"), pixels, TextureOptions::LINEAR));
        }
        self.textures[i].clone()
    }
}

/// Whether the tour should open by itself: it has not been finished or skipped yet.
pub fn first_run() -> bool {
    shell::load_setting("tour").as_deref() != Some("seen")
}

pub fn open(app: &mut App) {
    app.tour = Some(Tour::new());
}

pub fn show(app: &mut App, ctx: &egui::Context) {
    let Some(mut tour) = app.tour.take() else {
        return;
    };
    let p = theme::current(ctx);
    let last = PAGES.len() - 1;
    let now = ctx.input(|i| i.time);
    if tour.shown_at == f64::NEG_INFINITY {
        tour.shown_at = now;
    }
    let (left, right, enter, esc) = ctx.input(|i| {
        (
            i.key_pressed(Key::ArrowLeft),
            i.key_pressed(Key::ArrowRight),
            i.key_pressed(Key::Enter),
            i.key_pressed(Key::Escape),
        )
    });
    let mut go: Option<usize> = None;
    let mut done = esc;
    if right || enter {
        if tour.page == last {
            done = true;
        } else {
            go = Some(tour.page + 1);
        }
    }
    if left && tour.page > 0 {
        go = Some(tour.page - 1);
    }

    // Each page fades and rises in over a fifth of a second.
    let t = ((now - tour.shown_at) / 0.2).clamp(0.0, 1.0) as f32;
    let fade = 1.0 - (1.0 - t) * (1.0 - t);
    if t < 1.0 {
        ctx.request_repaint();
    }
    let page = tour.page;
    let texture = tour.texture(ctx, page);
    let screen = ctx.content_rect();
    let width = (screen.width() - 96.0).clamp(480.0, 720.0);
    let stage_h = (screen.height() - 330.0).clamp(150.0, 360.0);

    let area =
        egui::Modal::default_area(Id::unique("tour")).anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0));
    let frame = egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(18))
        .shadow(ctx.global_style().visuals.window_shadow)
        .inner_margin(Margin::same(24));
    egui::Modal::new(Id::unique("tour"))
        .area(area)
        .frame(frame)
        .backdrop_color(Color32::from_black_alpha(if p.dark { 170 } else { 110 }))
        .show(ctx, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} of {}", page + 1, PAGES.len()))
                        .size(12.0)
                        .color(p.faint),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if page < last && text_button(ui, "Skip tour", &p).clicked() {
                        done = true;
                    }
                });
            });
            ui.add_space(10.0);

            let (stage, _) = ui.allocate_exact_size(vec2(width, stage_h), Sense::hover());
            let painter = ui.painter_at(stage);
            painter.rect_filled(stage, CornerRadius::same(14), p.base);
            glow(&painter, stage, p.accent, if p.dark { 0.16 } else { 0.10 });
            let lift = vec2(0.0, (1.0 - fade) * 10.0);
            match &texture {
                Some(tex) => {
                    let size = tex.size_vec2();
                    let scale = ((stage.width() - 56.0) / size.x)
                        .min((stage.height() - 44.0) / size.y)
                        .min(1.0);
                    let rect = Rect::from_center_size(stage.center() + lift, size * scale);
                    painter.rect_filled(
                        rect.translate(vec2(0.0, 8.0)).expand(4.0),
                        CornerRadius::same(14),
                        Color32::from_black_alpha((70.0 * fade) as u8),
                    );
                    egui::Image::from_texture(egui::load::SizedTexture::from_handle(tex))
                        .corner_radius(CornerRadius::same(10))
                        .tint(Color32::WHITE.gamma_multiply(fade))
                        .paint_at(ui, rect);
                    painter.rect_stroke(
                        rect,
                        CornerRadius::same(10),
                        Stroke::new(1.0, p.line.gamma_multiply(fade)),
                        StrokeKind::Outside,
                    );
                }
                None => {
                    let logo = Rect::from_center_size(
                        stage.center() - vec2(0.0, 22.0) + lift,
                        vec2(92.0, 92.0),
                    );
                    icons::mark(&painter, logo);
                    painter.text(
                        pos2(stage.center().x, logo.bottom() + 30.0),
                        Align2::CENTER_CENTER,
                        "r7z",
                        theme::semibold(26.0),
                        p.text.gamma_multiply(fade),
                    );
                }
            }

            ui.add_space(20.0);
            ui.label(
                RichText::new(PAGES[page].title)
                    .font(theme::semibold(22.0))
                    .color(p.text.gamma_multiply(fade)),
            );
            ui.add_space(6.0);
            // Room for two lines on every page, so the buttons below stay put.
            ui.vertical(|ui| {
                ui.set_min_height(42.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(PAGES[page].body)
                            .size(14.0)
                            .color(p.dim.gamma_multiply(fade)),
                    )
                    .wrap(),
                );
            });
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                for i in 0..PAGES.len() {
                    let w = if i == page { 22.0 } else { 8.0 };
                    let (r, resp) = ui.allocate_exact_size(vec2(w, 8.0), Sense::click());
                    let col = if i == page {
                        p.accent
                    } else if resp.hovered() {
                        p.faint
                    } else {
                        p.line
                    };
                    ui.painter().rect_filled(r, CornerRadius::same(4), col);
                    if resp.clicked() && i != page {
                        go = Some(i);
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let next = if page == last { "Get started" } else { "Next" };
                    if button(ui, None, next, true, true).clicked() {
                        if page == last {
                            done = true;
                        } else {
                            go = Some(page + 1);
                        }
                    }
                    if page > 0 && button(ui, None, "Back", false, true).clicked() {
                        go = Some(page - 1);
                    }
                    let installed = *app.explorer.get_or_insert_with(shell::explorer_installed);
                    if page == last
                        && !installed
                        && button(ui, None, "Add to right-click menu", false, true).clicked()
                    {
                        if shell::install_explorer() {
                            app.toast("r7z is in the right-click menu".into(), true, None);
                        } else {
                            app.toast("Couldn't add the menu entries".into(), false, None);
                        }
                        app.explorer = Some(shell::explorer_installed());
                    }
                });
            });
        });

    if done {
        shell::save_setting("tour", "seen");
        return;
    }
    if let Some(next) = go {
        tour.page = next;
        tour.shown_at = now;
    }
    app.tour = Some(tour);
}

/// A quiet text-only button, for "Skip tour".
fn text_button(ui: &mut egui::Ui, label: &str, p: &theme::Palette) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        theme::semibold(12.5),
        Color32::PLACEHOLDER,
    );
    let (rect, resp) = ui.allocate_exact_size(galley.size() + vec2(8.0, 6.0), Sense::click());
    let col = if resp.hovered() { p.text } else { p.dim };
    ui.painter().galley(rect.min + vec2(4.0, 3.0), galley, col);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// A soft accent glow in the stage: a radial gradient that fades out from the middle.
fn glow(painter: &egui::Painter, stage: Rect, accent: Color32, strength: f32) {
    use egui::epaint::Mesh;
    let center = pos2(stage.center().x, stage.top() + stage.height() * 0.45);
    let radius = stage.width().max(stage.height()) * 0.5;
    let rings = [
        (0.0, strength),
        (0.35, strength * 0.6),
        (0.7, strength * 0.2),
        (1.0, 0.0),
    ];
    let segments = 72;
    let mut mesh = Mesh::default();
    for &(r, a) in &rings {
        for i in 0..segments {
            let angle = i as f32 / segments as f32 * std::f32::consts::TAU;
            let at = center + vec2(angle.cos(), angle.sin()) * radius * r;
            mesh.colored_vertex(at, accent.gamma_multiply(a));
        }
    }
    let seg = segments as u32;
    for ring in 0..rings.len() as u32 - 1 {
        for i in 0..seg {
            let (a, b) = (ring * seg + i, ring * seg + (i + 1) % seg);
            let (c, d) = (a + seg, b + seg);
            mesh.add_triangle(a, b, c);
            mesh.add_triangle(b, d, c);
        }
    }
    painter.add(egui::Shape::mesh(mesh));
}

#[cfg(test)]
mod tests {
    use super::PAGES;

    #[test]
    fn every_screenshot_decodes() {
        for page in PAGES {
            if let Some(bytes) = page.image {
                let img = image::load_from_memory(bytes).expect(page.title);
                assert!(img.width() > 100 && img.height() > 50, "{}", page.title);
            }
        }
    }
}
