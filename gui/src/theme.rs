//! Colors, type and spacing. Graphite neutrals with a single vermilion accent; dark text
//! sits on the accent in both themes. Fonts come from Windows, so nothing large ships.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow,
    Stroke, TextStyle, Theme, Visuals,
};

#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub base: Color32,
    pub side: Color32,
    pub surface: Color32,
    pub raised: Color32,
    pub hover: Color32,
    pub line: Color32,
    pub text: Color32,
    pub dim: Color32,
    pub faint: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub accent_soft: Color32,
    pub danger: Color32,
    pub caution: Color32,
    pub ok: Color32,
    pub input: Color32,
}

const fn rgb(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

pub fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            dark,
            base: rgb(0x0F1012),
            side: rgb(0x131417),
            surface: rgb(0x17181C),
            raised: rgb(0x222328),
            hover: Color32::from_rgba_unmultiplied(255, 255, 255, 11),
            line: rgb(0x26272D),
            text: rgb(0xECECEF),
            dim: rgb(0x9A9CA5),
            faint: rgb(0x5F616A),
            accent: rgb(0xFF6B2C),
            on_accent: rgb(0x170B05),
            accent_soft: Color32::from_rgba_unmultiplied(255, 107, 44, 40),
            danger: rgb(0xFF5F5F),
            caution: rgb(0xF2B13C),
            ok: rgb(0x3CCF8A),
            input: rgb(0x0C0D0F),
        }
    } else {
        Palette {
            dark,
            base: rgb(0xF3F3F4),
            side: rgb(0xEBEBED),
            surface: rgb(0xFFFFFF),
            raised: rgb(0xEDEDEF),
            hover: Color32::from_rgba_unmultiplied(20, 20, 30, 10),
            line: rgb(0xE0E0E4),
            text: rgb(0x17181B),
            dim: rgb(0x5E606A),
            faint: rgb(0xA2A4AC),
            accent: rgb(0xF25A1C),
            on_accent: rgb(0x180A03),
            accent_soft: Color32::from_rgba_unmultiplied(242, 90, 28, 30),
            danger: rgb(0xD63A3A),
            caution: rgb(0xB57713),
            ok: rgb(0x1C9A61),
            input: rgb(0xFFFFFF),
        }
    }
}

pub fn current(ctx: &egui::Context) -> Palette {
    palette(ctx.global_style().visuals.dark_mode)
}

fn visuals(dark: bool) -> Visuals {
    let p = palette(dark);
    let mut v = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.panel_fill = p.base;
    v.window_fill = p.surface;
    v.extreme_bg_color = p.input;
    v.faint_bg_color = p.raised;
    v.code_bg_color = p.raised;
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.window_corner_radius = CornerRadius::same(14);
    v.menu_corner_radius = CornerRadius::same(10);
    v.window_stroke = Stroke::new(1.0, p.line);
    let shadow = if dark {
        Color32::from_black_alpha(140)
    } else {
        Color32::from_black_alpha(40)
    };
    v.window_shadow = Shadow {
        offset: [0, 16],
        blur: 40,
        spread: 0,
        color: shadow,
    };
    v.popup_shadow = Shadow {
        offset: [0, 8],
        blur: 22,
        spread: 0,
        color: shadow,
    };
    v.striped = false;
    v.slider_trailing_fill = true;
    v.handle_shape = egui::style::HandleShape::Circle;
    let w = &mut v.widgets;
    for s in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        s.corner_radius = CornerRadius::same(8);
        s.fg_stroke = Stroke::new(1.0, p.text);
        s.expansion = 0.0;
    }
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.line);
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.inactive.bg_fill = p.raised;
    w.inactive.weak_bg_fill = p.raised;
    w.inactive.bg_stroke = Stroke::new(1.0, p.line);
    w.hovered.bg_fill = p.line;
    w.hovered.weak_bg_fill = p.line;
    w.hovered.bg_stroke = Stroke::new(1.0, p.faint);
    w.active.bg_fill = p.accent_soft;
    w.active.weak_bg_fill = p.accent_soft;
    w.active.bg_stroke = Stroke::new(1.0, p.accent);
    w.open.weak_bg_fill = p.raised;
    w.open.bg_stroke = Stroke::new(1.0, p.line);
    v.text_cursor.stroke = Stroke::new(1.5, p.accent);
    v
}

pub fn apply(ctx: &egui::Context, pref: egui::ThemePreference) {
    ctx.set_theme(pref);
    ctx.set_visuals_of(Theme::Dark, visuals(true));
    ctx.set_visuals_of(Theme::Light, visuals(false));
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(12.0, 5.0);
        s.spacing.interact_size.y = 30.0;
        s.spacing.window_margin = Margin::same(20);
        s.spacing.menu_margin = Margin::same(6);
        s.spacing.scroll = egui::style::ScrollStyle::floating();
        s.text_styles = [
            (TextStyle::Small, FontId::proportional(11.5)),
            (TextStyle::Body, FontId::proportional(13.5)),
            (TextStyle::Button, FontId::proportional(13.5)),
            (TextStyle::Heading, semibold(18.0)),
            (TextStyle::Monospace, FontId::monospace(12.5)),
        ]
        .into();
        s.interaction.selectable_labels = false;
        s.animation_time = 0.12;
    });
}

fn read_font(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var_os("WINDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "C:\\Windows".into());
    std::fs::read(dir.join("Fonts").join(name)).ok()
}

/// Segoe UI and Cascadia Mono when present. The CJK fallback is large and only loaded when
/// a listing needs it.
pub fn install_fonts(ctx: &egui::Context, cjk: bool) {
    let mut fonts = FontDefinitions::default();
    let mut add = |key: &str, files: &[&str]| -> bool {
        for f in files {
            if let Some(bytes) = read_font(f) {
                fonts
                    .font_data
                    .insert(key.into(), Arc::new(FontData::from_owned(bytes)));
                return true;
            }
        }
        false
    };
    let regular = add("ui", &["segoeui.ttf"]);
    let semibold = add("ui-semibold", &["seguisb.ttf"]);
    let symbols = add("ui-symbols", &["seguisym.ttf"]);
    let mono = add("mono", &["CascadiaMono.ttf", "consola.ttf"]);
    let cjk = cjk && add("cjk", &["msyh.ttc", "YuGothR.ttc", "malgun.ttf"]);

    let prop = fonts.families.entry(FontFamily::Proportional).or_default();
    let mut front = Vec::new();
    if regular {
        front.push("ui".to_string());
    }
    if cjk {
        front.push("cjk".to_string());
    }
    for (i, f) in front.into_iter().enumerate() {
        prop.insert(i, f);
    }
    if symbols {
        prop.push("ui-symbols".into());
    }
    let fallback = prop.clone();
    let mut sb = Vec::new();
    if semibold {
        sb.push("ui-semibold".to_string());
    }
    sb.extend(fallback.iter().cloned());
    fonts
        .families
        .insert(FontFamily::Name("semibold".into()), sb);
    let monos = fonts.families.entry(FontFamily::Monospace).or_default();
    if mono {
        monos.insert(0, "mono".into());
    }
    if cjk {
        monos.push("cjk".into());
    }
    ctx.set_fonts(fonts);
}

pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("semibold".into()))
}
