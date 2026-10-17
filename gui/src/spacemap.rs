//! The space map: a squarified treemap of what takes room inside the current folder.

use eframe::egui::{
    self, pos2, vec2, Align2, Color32, CornerRadius, FontId, Rect, Sense, Stroke, StrokeKind, Ui,
};

use crate::icons::classify;
use crate::model::Tree;
use crate::theme::Palette;
use r7z::util::fmt::human_size;

/// Lays out `values` (sorted descending, all positive) into `rect`, keeping cells close to
/// square (Bruls, Huizing and van Wijk). Returns one rectangle per value, in order.
pub fn squarify(values: &[f64], rect: Rect) -> Vec<Rect> {
    let total: f64 = values.iter().sum();
    if values.is_empty() || total <= 0.0 || rect.area() <= 0.0 {
        return vec![Rect::NOTHING; values.len()];
    }
    let scale = rect.area() as f64 / total;
    let areas: Vec<f64> = values.iter().map(|v| v * scale).collect();
    let worst = |row: &[f64], side: f64| -> f64 {
        let s: f64 = row.iter().sum();
        let (mx, mn) = row
            .iter()
            .fold((0f64, f64::MAX), |(a, b), &v| (a.max(v), b.min(v)));
        let s2 = s * s;
        let w2 = side * side;
        (w2 * mx / s2).max(s2 / (w2 * mn))
    };
    let mut out = Vec::with_capacity(values.len());
    let mut r = rect;
    let mut i = 0;
    while i < areas.len() {
        let side = r.width().min(r.height()) as f64;
        let mut j = i + 1;
        while j < areas.len() && worst(&areas[i..=j], side) <= worst(&areas[i..j], side) {
            j += 1;
        }
        let row = &areas[i..j];
        let sum: f64 = row.iter().sum();
        if r.width() >= r.height() {
            let w = (sum / r.height() as f64) as f32;
            let mut y = r.top();
            for &a in row {
                let h = (a / w as f64) as f32;
                out.push(Rect::from_min_size(pos2(r.left(), y), vec2(w, h)));
                y += h;
            }
            r.min.x += w;
        } else {
            let h = (sum / r.width() as f64) as f32;
            let mut x = r.left();
            for &a in row {
                let w = (a / h as f64) as f32;
                out.push(Rect::from_min_size(pos2(x, r.top()), vec2(w, h)));
                x += w;
            }
            r.min.y += h;
        }
        i = j;
    }
    out
}

pub enum MapAction {
    Select(usize),
    Enter(usize),
}

fn cell_color(tree: &Tree, n: usize, p: &Palette) -> Color32 {
    let nd = &tree.nodes[n];
    if nd.is_dir {
        if p.dark {
            Color32::from_rgb(0x2A, 0x2C, 0x33)
        } else {
            Color32::from_rgb(0xDD, 0xDF, 0xE5)
        }
    } else {
        classify(&nd.name).color()
    }
}

fn layout_children(tree: &Tree, node: usize, rect: Rect, limit: usize) -> Vec<(usize, Rect)> {
    let mut kids: Vec<usize> = tree.nodes[node]
        .children
        .iter()
        .copied()
        .filter(|&c| tree.nodes[c].size > 0)
        .collect();
    kids.sort_by(|&a, &b| tree.nodes[b].size.cmp(&tree.nodes[a].size));
    kids.truncate(limit);
    let values: Vec<f64> = kids.iter().map(|&k| tree.nodes[k].size as f64).collect();
    kids.into_iter().zip(squarify(&values, rect)).collect()
}

/// Fills `rect` with the contents of folder `node`, descending into subfolders so files
/// show in their type colors. `budget` caps the number of cells drawn per frame; the
/// deepest cell under the pointer is reported for the tooltip.
#[allow(clippy::too_many_arguments)]
fn draw_nested(
    painter: &egui::Painter,
    tree: &Tree,
    node: usize,
    rect: Rect,
    depth: usize,
    budget: &mut usize,
    p: &Palette,
    pointer: Option<egui::Pos2>,
    hovered: &mut Option<(usize, Rect)>,
) {
    for (c, cr) in layout_children(tree, node, rect, 200) {
        if *budget == 0 {
            return;
        }
        let cr = cr.shrink(0.75);
        if cr.width() < 1.0 || cr.height() < 1.0 {
            continue;
        }
        *budget -= 1;
        let nd = &tree.nodes[c];
        if nd.is_dir {
            let shade = if p.dark {
                Color32::from_white_alpha(10)
            } else {
                Color32::from_black_alpha(14)
            };
            painter.rect_filled(cr, CornerRadius::same(3), shade);
            if depth < 6 && cr.width() > 6.0 && cr.height() > 6.0 {
                draw_nested(
                    painter,
                    tree,
                    c,
                    cr.shrink(1.5),
                    depth + 1,
                    budget,
                    p,
                    pointer,
                    hovered,
                );
            }
        } else {
            let col = classify(&nd.name).color();
            painter.rect_filled(
                cr,
                CornerRadius::same(2),
                col.gamma_multiply(if p.dark { 0.62 } else { 0.8 }),
            );
            if pointer.is_some_and(|pos| cr.contains(pos)) {
                *hovered = Some((c, cr));
            }
        }
    }
}

/// Draws the map for `node` and returns what the user clicked.
pub fn show(
    ui: &mut Ui,
    tree: &Tree,
    node: usize,
    selected: Option<usize>,
    p: &Palette,
) -> Option<MapAction> {
    let (rect, _) = ui.allocate_exact_size(ui.available_size(), Sense::hover());
    let painter = ui.painter_at(rect);
    let mut action = None;
    let cells = layout_children(tree, node, rect.shrink(1.0), 400);
    if cells.is_empty() {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "Nothing here takes up space",
            FontId::proportional(13.5),
            p.dim,
        );
        return None;
    }
    let pointer = ui.ctx().pointer_hover_pos();
    let mut hovered: Option<(usize, Rect)> = None;
    for (i, &(n, r)) in cells.iter().enumerate() {
        let r = r.shrink(1.5);
        if r.width() < 1.0 || r.height() < 1.0 {
            continue;
        }
        let nd = &tree.nodes[n];
        let base = cell_color(tree, n, p);
        let fill = if nd.is_dir {
            base
        } else {
            base.gamma_multiply(if p.dark { 0.55 } else { 0.75 })
        };
        painter.rect_filled(r, CornerRadius::same(6), fill);
        if nd.is_dir && r.width() > 40.0 && r.height() > 40.0 {
            let inner = Rect::from_min_max(
                pos2(r.left() + 4.0, r.top() + 20.0),
                pos2(r.right() - 4.0, r.bottom() - 4.0),
            );
            let mut budget = 3000usize;
            draw_nested(
                &painter,
                tree,
                n,
                inner,
                1,
                &mut budget,
                p,
                pointer,
                &mut hovered,
            );
        }
        if r.width() > 56.0 && r.height() > 30.0 {
            let text_color = if nd.is_dir {
                p.text
            } else if p.dark {
                Color32::from_rgb(0xF4, 0xF4, 0xF6)
            } else {
                Color32::from_rgb(0x10, 0x10, 0x12)
            };
            let galley =
                painter.layout_no_wrap(nd.name.clone(), crate::theme::semibold(12.0), text_color);
            let clip = painter.with_clip_rect(r.shrink(4.0));
            clip.galley(pos2(r.left() + 7.0, r.top() + 5.0), galley, text_color);
            if r.height() > 46.0 && !nd.is_dir {
                clip.text(
                    pos2(r.left() + 7.0, r.top() + 21.0),
                    Align2::LEFT_TOP,
                    human_size(nd.size),
                    FontId::proportional(11.0),
                    text_color.gamma_multiply(0.75),
                );
            }
        }
        if Some(n) == selected {
            painter.rect_stroke(
                r,
                CornerRadius::same(6),
                Stroke::new(2.0, p.accent),
                StrokeKind::Inside,
            );
        }
        if hovered.is_none() && pointer.is_some_and(|pos| r.contains(pos)) {
            hovered = Some((n, r));
        }
        let id = ui.scope_id().with(("cell", i));
        let resp = ui.interact(r, id, Sense::click());
        if resp.hovered() {
            let nd = &tree.nodes[hovered.map_or(n, |h| h.0)];
            let total = tree.nodes[node].size.max(1);
            let pct = nd.size as f64 * 100.0 / total as f64;
            let kind = if nd.is_dir {
                format!("{} files", nd.files)
            } else {
                crate::icons::kind_label(&nd.name, false)
            };
            let (name, size) = (nd.name.clone(), human_size(nd.size));
            resp.clone().on_hover_ui(|ui| {
                ui.label(egui::RichText::new(name).font(crate::theme::semibold(13.0)));
                ui.label(
                    egui::RichText::new(format!("{size} · {pct:.1}% · {kind}"))
                        .size(12.0)
                        .color(p.dim),
                );
            });
        }
        if resp.double_clicked() && nd.is_dir {
            action = Some(MapAction::Enter(n));
        } else if resp.clicked() {
            action = Some(MapAction::Select(n));
        }
    }
    if let Some((_, r)) = hovered {
        painter.rect_stroke(
            r,
            CornerRadius::same(6),
            Stroke::new(1.5, p.text.gamma_multiply(0.6)),
            StrokeKind::Inside,
        );
    }
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_fill_the_area() {
        let r = Rect::from_min_size(pos2(0.0, 0.0), vec2(600.0, 400.0));
        let vals = [500.0, 300.0, 120.0, 50.0, 20.0, 10.0];
        let cells = squarify(&vals, r);
        assert_eq!(cells.len(), vals.len());
        let area: f32 = cells.iter().map(|c| c.area()).sum();
        assert!((area - r.area()).abs() < 1.0);
        for c in &cells {
            assert!(r.expand(0.01).contains_rect(*c));
        }
    }
}
