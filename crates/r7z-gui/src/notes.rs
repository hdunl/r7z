//! Shows release notes: the small part of Markdown they use. Paragraphs, `-` lists (also
//! nested), `**bold**`, `` `code` ``, links (shown as their text), `##` headings and tables.
//! Anything else is shown as the text it is.

use eframe::egui::{self, text::LayoutJob, FontFamily, FontId, TextFormat, Ui};

use crate::theme::{self, Palette};

const SIZE: f32 = 13.0;

pub fn show(ui: &mut Ui, p: &Palette, text: &str) {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            ui.add_space(6.0);
            i += 1;
        } else if let Some(h) = trimmed.strip_prefix("### ").or(trimmed.strip_prefix("## ")) {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(h)
                    .font(theme::semibold(14.0))
                    .color(p.text),
            );
            i += 1;
        } else if trimmed.starts_with('|') {
            let start = i;
            while i < lines.len() && lines[i].trim_start().starts_with('|') {
                i += 1;
            }
            table(ui, p, &lines[start..i]);
        } else if let Some((indent, item)) = bullet(line) {
            // A list item continues on more-indented lines that start no new item.
            let mut text = item.to_string();
            i += 1;
            while i < lines.len() && continues(lines[i], indent) {
                text.push(' ');
                text.push_str(lines[i].trim());
                i += 1;
            }
            ui.horizontal_top(|ui| {
                ui.add_space(indent as f32 * 7.0);
                ui.label(egui::RichText::new("•").size(SIZE).color(p.dim));
                ui.add(egui::Label::new(inline(p, &text)).wrap());
            });
        } else {
            let mut text = trimmed.to_string();
            i += 1;
            while i < lines.len() && plain(lines[i]) {
                text.push(' ');
                text.push_str(lines[i].trim());
                i += 1;
            }
            ui.add(egui::Label::new(inline(p, &text)).wrap());
        }
    }
}

/// `(indent, text)` of a `- ` or `* ` list item.
fn bullet(line: &str) -> Option<(usize, &str)> {
    let indent = line.len() - line.trim_start().len();
    let t = line.trim_start();
    t.strip_prefix("- ")
        .or_else(|| t.strip_prefix("* "))
        .map(|rest| (indent, rest))
}

fn continues(line: &str, indent: usize) -> bool {
    let own = line.len() - line.trim_start().len();
    !line.trim().is_empty() && own > indent && bullet(line).is_none()
}

fn plain(line: &str) -> bool {
    let t = line.trim_start();
    !t.is_empty() && bullet(line).is_none() && !t.starts_with('|') && !t.starts_with('#')
}

fn table(ui: &mut Ui, p: &Palette, rows: &[&str]) {
    let cells = |row: &str| -> Vec<String> {
        let row = row.trim().trim_start_matches('|').trim_end_matches('|');
        row.split('|').map(|c| c.trim().to_string()).collect()
    };
    let rule = |c: &[String]| {
        c.iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| matches!(ch, '-' | ':')))
    };
    let rows: Vec<Vec<String>> = rows.iter().map(|r| cells(r)).collect();
    ui.add_space(4.0);
    egui::Grid::new(ui.next_auto_id())
        .striped(true)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            for (n, row) in rows.iter().filter(|r| !rule(r)).enumerate() {
                for cell in row {
                    let text = if n == 0 && !cell.is_empty() {
                        format!("**{}**", cell.trim_matches('*'))
                    } else {
                        cell.clone()
                    };
                    ui.add(egui::Label::new(inline(p, &text)).wrap());
                }
                ui.end_row();
            }
        });
    ui.add_space(4.0);
}

/// One line of text with `**bold**`, `` `code` `` and `[text](link)` resolved.
fn inline(p: &Palette, text: &str) -> LayoutJob {
    let normal = TextFormat::simple(FontId::proportional(SIZE), p.text);
    let bold = TextFormat::simple(theme::semibold(SIZE), p.text);
    let code = TextFormat::simple(FontId::new(SIZE - 1.0, FontFamily::Monospace), p.text);
    let mut job = LayoutJob::default();
    let mut is_bold = false;
    let mut rest = text;
    let mut run = String::new();
    let flush = |job: &mut LayoutJob, run: &mut String, bold_now: bool| {
        if !run.is_empty() {
            job.append(
                run,
                0.0,
                if bold_now {
                    bold.clone()
                } else {
                    normal.clone()
                },
            );
            run.clear();
        }
    };
    while let Some(c) = rest.chars().next() {
        if let Some(after) = rest.strip_prefix("**") {
            flush(&mut job, &mut run, is_bold);
            is_bold = !is_bold;
            rest = after;
        } else if let Some(end) = rest.strip_prefix('`').and_then(|a| a.find('`')) {
            flush(&mut job, &mut run, is_bold);
            job.append(&rest[1..1 + end], 0.0, code.clone());
            rest = &rest[end + 2..];
        } else if let Some((label, after)) = link(rest) {
            run.push_str(label);
            rest = after;
        } else {
            run.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    flush(&mut job, &mut run, is_bold);
    job
}

/// `[label](target)` at the start of `s`: the label and the text after the link.
fn link(s: &str) -> Option<(&str, &str)> {
    let s = s.strip_prefix('[')?;
    let close = s.find("](")?;
    let after = &s[close + 2..];
    let end = after.find(')')?;
    Some((&s[..close], &after[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(job: &LayoutJob) -> &str {
        &job.text
    }

    #[test]
    fn inline_markup_becomes_plain_text_with_formats() {
        let p = theme::palette(true);
        let job = inline(&p, "**Faster** `r7z x` see [the page](https://x.y/z) now");
        assert_eq!(text(&job), "Faster r7z x see the page now");
        assert_eq!(job.sections.len(), 4);
        // Unbalanced markup is shown as written, without panicking, also after
        // characters that take more than one byte.
        assert_eq!(text(&inline(&p, "a ` b [c](d e **f")), "a ` b [c](d e f");
        assert_eq!(text(&inline(&p, "· → `x` ·")), "· → x ·");
    }

    #[test]
    fn list_items_join_their_continuation_lines() {
        assert_eq!(bullet("  - item"), Some((2, "item")));
        assert!(continues("    more text", 2));
        assert!(!continues("    - next", 2));
        assert!(!continues("plain", 2));
    }
}
