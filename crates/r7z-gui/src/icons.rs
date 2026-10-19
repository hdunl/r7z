//! Interface icons in one stroke style on a 16-unit grid, plus file-type glyphs and the
//! mark. Everything is drawn with the painter, so it stays sharp at any scale.

use std::f32::consts::PI;

use eframe::egui::{
    self, pos2, vec2, Align2, Color32, CornerRadius, FontId, Painter, Pos2, Rect, Sense, Shape,
    Stroke, StrokeKind, Ui,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Back,
    Forward,
    Up,
    Search,
    Open,
    Extract,
    Pack,
    Test,
    Settings,
    Preview,
    List,
    Map,
    Home,
    Desktop,
    Downloads,
    Documents,
    Pictures,
    Drive,
    Close,
    Check,
    Alert,
    Shield,
    Lock,
    External,
    ChevronDown,
    ChevronRight,
    Refresh,
    Layers,
    Eject,
}

struct Grid {
    r: Rect,
    stroke: Stroke,
}

impl Grid {
    fn p(&self, x: f32, y: f32) -> Pos2 {
        pos2(
            self.r.min.x + x * self.r.width() / 16.0,
            self.r.min.y + y * self.r.height() / 16.0,
        )
    }
    fn u(&self, v: f32) -> f32 {
        v * self.r.width() / 16.0
    }
    fn line(&self, p: &Painter, pts: &[(f32, f32)]) {
        let v: Vec<Pos2> = pts.iter().map(|&(x, y)| self.p(x, y)).collect();
        p.add(Shape::line(v, self.stroke));
    }
    fn closed(&self, p: &Painter, pts: &[(f32, f32)]) {
        let v: Vec<Pos2> = pts.iter().map(|&(x, y)| self.p(x, y)).collect();
        p.add(Shape::closed_line(v, self.stroke));
    }
    fn rect(&self, p: &Painter, x0: f32, y0: f32, x1: f32, y1: f32, rad: f32) {
        let r = Rect::from_min_max(self.p(x0, y0), self.p(x1, y1));
        p.rect_stroke(
            r,
            CornerRadius::same(self.u(rad).round() as u8),
            self.stroke,
            StrokeKind::Middle,
        );
    }
    fn circle(&self, p: &Painter, x: f32, y: f32, rad: f32) {
        p.circle_stroke(self.p(x, y), self.u(rad), self.stroke);
    }
    fn dot(&self, p: &Painter, x: f32, y: f32, rad: f32) {
        p.circle_filled(self.p(x, y), self.u(rad), self.stroke.color);
    }
    fn arc(&self, p: &Painter, x: f32, y: f32, rad: f32, a0: f32, a1: f32) {
        let n = 18;
        let v: Vec<Pos2> = (0..=n)
            .map(|i| {
                let a = a0 + (a1 - a0) * i as f32 / n as f32;
                self.p(x + rad * a.cos(), y + rad * a.sin())
            })
            .collect();
        p.add(Shape::line(v, self.stroke));
    }
}

pub fn draw(p: &Painter, rect: Rect, icon: Icon, color: Color32) {
    let w = (rect.width() / 16.0 * 1.45).clamp(1.15, 2.4);
    let g = Grid {
        r: rect,
        stroke: Stroke::new(w, color),
    };
    match icon {
        Icon::Back => g.line(p, &[(10.0, 3.0), (5.0, 8.0), (10.0, 13.0)]),
        Icon::Forward => g.line(p, &[(6.0, 3.0), (11.0, 8.0), (6.0, 13.0)]),
        Icon::Up => {
            g.line(p, &[(8.0, 13.5), (8.0, 3.0)]);
            g.line(p, &[(3.5, 7.5), (8.0, 3.0), (12.5, 7.5)]);
        }
        Icon::Search => {
            g.circle(p, 7.0, 7.0, 4.6);
            g.line(p, &[(10.5, 10.5), (14.0, 14.0)]);
        }
        Icon::Open => {
            g.line(
                p,
                &[
                    (1.8, 12.8),
                    (1.8, 3.2),
                    (6.0, 3.2),
                    (7.6, 4.9),
                    (12.6, 4.9),
                    (12.6, 7.3),
                ],
            );
            g.closed(p, &[(1.8, 12.8), (4.0, 7.3), (15.0, 7.3), (12.8, 12.8)]);
        }
        Icon::Extract => {
            g.line(p, &[(8.0, 1.8), (8.0, 9.8)]);
            g.line(p, &[(4.6, 6.4), (8.0, 9.8), (11.4, 6.4)]);
            g.line(p, &[(2.0, 9.8), (2.0, 13.8), (14.0, 13.8), (14.0, 9.8)]);
        }
        Icon::Pack => {
            g.closed(p, &[(1.6, 2.6), (14.4, 2.6), (14.4, 5.6), (1.6, 5.6)]);
            g.line(p, &[(2.6, 5.6), (2.6, 13.6), (13.4, 13.6), (13.4, 5.6)]);
            g.line(p, &[(6.4, 8.6), (9.6, 8.6)]);
        }
        Icon::Test | Icon::Shield => {
            g.closed(
                p,
                &[
                    (8.0, 1.6),
                    (13.6, 3.6),
                    (13.3, 8.6),
                    (8.0, 14.4),
                    (2.7, 8.6),
                    (2.4, 3.6),
                ],
            );
            if icon == Icon::Test {
                g.line(p, &[(5.5, 8.0), (7.3, 9.8), (10.7, 6.2)]);
            }
        }
        Icon::Settings => {
            g.line(p, &[(1.8, 4.5), (3.5, 4.5)]);
            g.line(p, &[(7.5, 4.5), (14.2, 4.5)]);
            g.circle(p, 5.5, 4.5, 2.0);
            g.line(p, &[(1.8, 11.5), (8.5, 11.5)]);
            g.line(p, &[(12.5, 11.5), (14.2, 11.5)]);
            g.circle(p, 10.5, 11.5, 2.0);
        }
        Icon::Preview => {
            g.rect(p, 1.8, 2.8, 14.2, 13.2, 1.8);
            g.line(p, &[(9.6, 2.8), (9.6, 13.2)]);
        }
        Icon::List => {
            for y in [4.0, 8.0, 12.0] {
                g.dot(p, 2.6, y, 0.95);
                g.line(p, &[(5.6, y), (14.0, y)]);
            }
        }
        Icon::Map => {
            g.rect(p, 1.8, 2.4, 14.2, 13.6, 1.6);
            g.line(p, &[(8.6, 2.4), (8.6, 13.6)]);
            g.line(p, &[(8.6, 8.2), (14.2, 8.2)]);
            g.line(p, &[(1.8, 10.0), (8.6, 10.0)]);
        }
        Icon::Home => {
            g.line(p, &[(1.8, 7.6), (8.0, 2.4), (14.2, 7.6)]);
            g.line(p, &[(3.6, 6.2), (3.6, 13.6), (12.4, 13.6), (12.4, 6.2)]);
            g.line(p, &[(6.6, 13.6), (6.6, 10.0), (9.4, 10.0), (9.4, 13.6)]);
        }
        Icon::Desktop => {
            g.rect(p, 1.6, 2.4, 14.4, 11.0, 1.4);
            g.line(p, &[(8.0, 11.0), (8.0, 13.6)]);
            g.line(p, &[(5.0, 13.6), (11.0, 13.6)]);
        }
        Icon::Downloads => {
            g.line(p, &[(8.0, 1.8), (8.0, 10.6)]);
            g.line(p, &[(4.2, 6.8), (8.0, 10.6), (11.8, 6.8)]);
            g.line(p, &[(3.0, 14.0), (13.0, 14.0)]);
        }
        Icon::Documents => {
            g.closed(
                p,
                &[
                    (3.4, 1.8),
                    (9.6, 1.8),
                    (12.6, 4.8),
                    (12.6, 14.2),
                    (3.4, 14.2),
                ],
            );
            g.line(p, &[(9.6, 1.8), (9.6, 4.8), (12.6, 4.8)]);
            g.line(p, &[(5.8, 8.2), (10.2, 8.2)]);
            g.line(p, &[(5.8, 11.0), (10.2, 11.0)]);
        }
        Icon::Pictures => {
            g.rect(p, 1.6, 2.4, 14.4, 13.6, 1.8);
            g.circle(p, 5.4, 6.0, 1.3);
            g.line(
                p,
                &[
                    (1.8, 12.2),
                    (6.2, 8.4),
                    (9.2, 11.0),
                    (11.0, 9.4),
                    (14.2, 12.2),
                ],
            );
        }
        Icon::Drive => {
            g.rect(p, 1.6, 4.4, 14.4, 11.6, 2.0);
            g.line(p, &[(4.2, 8.0), (8.4, 8.0)]);
            g.dot(p, 11.6, 8.0, 0.95);
        }
        Icon::Eject => {
            g.closed(p, &[(8.0, 3.0), (13.4, 9.0), (2.6, 9.0)]);
            g.line(p, &[(2.6, 12.6), (13.4, 12.6)]);
        }
        Icon::Close => {
            g.line(p, &[(4.2, 4.2), (11.8, 11.8)]);
            g.line(p, &[(11.8, 4.2), (4.2, 11.8)]);
        }
        Icon::Check => g.line(p, &[(3.4, 8.4), (6.6, 11.6), (12.6, 4.6)]),
        Icon::Alert => {
            g.closed(p, &[(8.0, 2.0), (14.6, 13.6), (1.4, 13.6)]);
            g.line(p, &[(8.0, 6.2), (8.0, 9.6)]);
            g.dot(p, 8.0, 11.6, 0.85);
        }
        Icon::Lock => {
            g.rect(p, 3.4, 7.2, 12.6, 14.0, 1.6);
            g.arc(p, 8.0, 7.2, 3.0, PI, 2.0 * PI);
        }
        Icon::External => {
            g.line(
                p,
                &[
                    (12.6, 9.2),
                    (12.6, 13.6),
                    (2.4, 13.6),
                    (2.4, 3.4),
                    (6.8, 3.4),
                ],
            );
            g.line(p, &[(9.4, 2.4), (13.6, 2.4), (13.6, 6.6)]);
            g.line(p, &[(13.6, 2.4), (7.6, 8.4)]);
        }
        Icon::ChevronDown => g.line(p, &[(4.0, 6.0), (8.0, 10.0), (12.0, 6.0)]),
        Icon::ChevronRight => g.line(p, &[(6.0, 4.0), (10.0, 8.0), (6.0, 12.0)]),
        Icon::Refresh => {
            g.arc(p, 8.0, 8.0, 5.6, -0.35 * PI, 1.35 * PI);
            let end = (
                8.0 + 5.6 * (-0.35 * PI).cos(),
                8.0 + 5.6 * (-0.35 * PI).sin(),
            );
            g.line(
                p,
                &[(end.0 - 3.2, end.1 - 0.4), end, (end.0 + 0.2, end.1 + 3.0)],
            );
        }
        Icon::Layers => {
            g.closed(p, &[(8.0, 2.0), (14.4, 5.4), (8.0, 8.8), (1.6, 5.4)]);
            g.line(p, &[(1.6, 8.4), (8.0, 11.8), (14.4, 8.4)]);
            g.line(p, &[(1.6, 11.2), (8.0, 14.6), (14.4, 11.2)]);
        }
    }
}

/// Allocates a square and draws an interface icon in it.
pub fn icon(ui: &mut Ui, size: f32, icon: Icon, color: Color32) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    draw(ui.painter(), rect, icon, color);
    resp
}

// ------------------------------------------------------------------ file types

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum FileClass {
    Image,
    Document,
    Code,
    Media,
    Archive,
    Program,
    Other,
}

impl FileClass {
    pub fn label(self) -> &'static str {
        match self {
            FileClass::Image => "Images",
            FileClass::Document => "Documents",
            FileClass::Code => "Code",
            FileClass::Media => "Audio & video",
            FileClass::Archive => "Archives",
            FileClass::Program => "Programs",
            FileClass::Other => "Other",
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            FileClass::Image => Color32::from_rgb(0x3E, 0xC4, 0x8B),
            FileClass::Document => Color32::from_rgb(0x4C, 0x9A, 0xF5),
            FileClass::Code => Color32::from_rgb(0xA0, 0x7C, 0xF6),
            FileClass::Media => Color32::from_rgb(0xEC, 0x5F, 0x9A),
            FileClass::Archive => Color32::from_rgb(0xFF, 0x8A, 0x3D),
            FileClass::Program => Color32::from_rgb(0xF0, 0x55, 0x55),
            FileClass::Other => Color32::from_rgb(0x8E, 0x92, 0x9E),
        }
    }
}

pub fn extension(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.rsplit_once('.')
        .map(|(s, e)| {
            if s.is_empty() {
                String::new()
            } else {
                e.to_ascii_lowercase()
            }
        })
        .unwrap_or_default()
}

pub fn classify(name: &str) -> FileClass {
    match extension(name).as_str() {
        "7z" | "zip" | "rar" | "tar" | "gz" | "tgz" | "bz2" | "tbz2" | "xz" | "txz" | "zst"
        | "lz4" | "cab" | "iso" | "wim" | "jar" | "apk" | "deb" | "rpm" | "dmg" | "lzma" | "z"
        | "arj" | "lzh" | "cpio" | "xar" | "pkg" | "001" | "zipx" | "esd" | "vhd" | "vhdx"
        | "img" => FileClass::Archive,
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" | "ico" | "tif" | "tiff"
        | "heic" | "avif" | "psd" | "raw" | "cr2" | "nef" => FileClass::Image,
        "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" | "opus" | "mp4" | "mkv" | "mov" | "avi"
        | "webm" | "wmv" | "m4v" => FileClass::Media,
        "rs" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs" | "js" | "mjs" | "cjs" | "ts" | "tsx"
        | "jsx" | "py" | "go" | "java" | "kt" | "rb" | "php" | "sh" | "ps1" | "json" | "toml"
        | "yaml" | "yml" | "xml" | "html" | "htm" | "css" | "scss" | "lua" | "sql" | "swift"
        | "vue" | "ini" | "cfg" | "conf" | "lock" | "gradle" | "cmake" | "mk" | "map" | "d" => {
            FileClass::Code
        }
        "txt" | "md" | "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods"
        | "odp" | "rtf" | "csv" | "log" | "epub" | "tex" | "rst" | "chm" => FileClass::Document,
        "exe" | "dll" | "sys" | "msi" | "so" | "dylib" | "com" | "bat" | "cmd" | "node" | "scr"
        | "efi" | "elf" | "appx" | "msix" | "bin" | "o" | "obj" | "lib" | "a" | "pdb" => {
            FileClass::Program
        }
        _ => FileClass::Other,
    }
}

/// A short description for the Type column, e.g. "PNG image", "Folder".
pub fn kind_label(name: &str, is_dir: bool) -> String {
    if is_dir {
        return "Folder".into();
    }
    let ext = extension(name);
    let noun = match classify(name) {
        FileClass::Image => "image",
        FileClass::Document => "document",
        FileClass::Code => "source",
        FileClass::Media => "media",
        FileClass::Archive => "archive",
        FileClass::Program => "program",
        FileClass::Other => "file",
    };
    if ext.is_empty() {
        "File".into()
    } else {
        format!("{} {noun}", ext.to_ascii_uppercase())
    }
}

pub fn folder(p: &Painter, r: Rect) {
    let w = r.width();
    let h = r.height();
    let back = Color32::from_rgb(0xD9, 0x8E, 0x2B);
    let front = Color32::from_rgb(0xF2, 0xB2, 0x4E);
    let rad = CornerRadius::same((w * 0.1).clamp(1.0, 8.0) as u8);
    let tab = Rect::from_min_max(
        pos2(r.left() + w * 0.06, r.top() + h * 0.17),
        pos2(r.left() + w * 0.44, r.top() + h * 0.38),
    );
    let body = Rect::from_min_max(
        pos2(r.left() + w * 0.06, r.top() + h * 0.26),
        pos2(r.right() - w * 0.06, r.bottom() - h * 0.14),
    );
    let lid = Rect::from_min_max(
        pos2(r.left() + w * 0.06, r.top() + h * 0.37),
        pos2(r.right() - w * 0.06, r.bottom() - h * 0.14),
    );
    p.rect_filled(tab, rad, back);
    p.rect_filled(body, rad, back);
    p.rect_filled(lid, rad, front);
}

/// A page with a folded corner and a colored band; large sizes also print the extension.
pub fn file(p: &Painter, r: Rect, name: &str, dark: bool) {
    let class = classify(name);
    let w = r.width();
    let h = r.height();
    let page = Rect::from_min_max(
        pos2(r.left() + w * 0.17, r.top() + h * 0.05),
        pos2(r.right() - w * 0.17, r.bottom() - h * 0.05),
    );
    let fold = page.width() * 0.32;
    let paper = if dark {
        Color32::from_rgb(0x2C, 0x2E, 0x35)
    } else {
        Color32::WHITE
    };
    let edge = if dark {
        Color32::from_rgb(0x43, 0x45, 0x4F)
    } else {
        Color32::from_rgb(0xCF, 0xD1, 0xD8)
    };
    let pts = vec![
        page.left_top(),
        pos2(page.right() - fold, page.top()),
        pos2(page.right(), page.top() + fold),
        page.right_bottom(),
        page.left_bottom(),
    ];
    p.add(Shape::convex_polygon(pts, paper, Stroke::new(1.0, edge)));
    p.add(Shape::convex_polygon(
        vec![
            pos2(page.right() - fold, page.top()),
            pos2(page.right() - fold, page.top() + fold),
            pos2(page.right(), page.top() + fold),
        ],
        edge,
        Stroke::NONE,
    ));
    let color = class.color();
    if w >= 36.0 {
        let label: String = extension(name)
            .to_ascii_uppercase()
            .chars()
            .take(4)
            .collect();
        let band = Rect::from_min_max(
            pos2(page.left() - w * 0.08, page.bottom() - h * 0.38),
            pos2(page.right() - w * 0.08, page.bottom() - h * 0.14),
        );
        p.rect_filled(band, CornerRadius::same((w * 0.05) as u8), color);
        if !label.is_empty() {
            p.text(
                band.center(),
                Align2::CENTER_CENTER,
                label,
                FontId::new(h * 0.15, egui::FontFamily::Name("semibold".into())),
                Color32::from_rgb(0x12, 0x12, 0x14),
            );
        }
    } else {
        let band = Rect::from_min_max(
            pos2(page.left() + 1.0, page.bottom() - page.height() * 0.28),
            pos2(page.right() - 1.0, page.bottom() - 1.0),
        );
        p.rect_filled(band, CornerRadius::same(1), color);
        if class == FileClass::Archive {
            let x = page.center().x;
            let mut y = page.top() + page.height() * 0.14;
            while y < band.top() - 2.0 {
                p.line_segment(
                    [pos2(x - 1.6, y), pos2(x + 1.6, y)],
                    Stroke::new(1.2, color),
                );
                y += 3.0;
            }
        }
    }
}

/// Draws the r7z mark (graphite tile, orange zipper) into `r`.
pub fn mark(p: &Painter, r: Rect) {
    let s = r.width();
    let [tr, tg, tb] = crate::logo::TILE;
    let [ar, ag, ab] = crate::logo::ACCENT;
    p.rect_filled(
        r,
        CornerRadius::same((s * 0.23) as u8),
        Color32::from_rgb(tr, tg, tb),
    );
    for b in crate::logo::mark_shapes() {
        let rect = Rect::from_min_max(
            pos2(r.left() + b[0] * s, r.top() + b[1] * s),
            pos2(r.left() + b[2] * s, r.top() + b[3] * s),
        );
        p.rect_filled(
            rect,
            CornerRadius::same((s * 0.02).max(1.0) as u8),
            Color32::from_rgb(ar, ag, ab),
        );
    }
}
