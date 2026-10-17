//! "Recover files…": salvaging a damaged archive. The work runs as a job (`jobs::recover`);
//! this holds where the files go and the outcome list shown when it finishes.

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText, Ui};
use r7z::ops::recover::{Outcome, RecoverReport};
use r7z::util::fmt::human_size;

use crate::icons::{self, Icon};
use crate::theme::{self, Palette};

/// What a finished recovery shows.
pub struct RecoverView {
    pub name: String,
    pub dest: PathBuf,
    pub report: RecoverReport,
}

/// A new folder next to the archive, `name (recovered)`, never an existing one.
pub fn destination(archive: &Path) -> PathBuf {
    let parent = archive.parent().map(Path::to_path_buf).unwrap_or_default();
    let stem = crate::app::stem_of(archive);
    let mut dest = parent.join(format!("{stem} (recovered)"));
    let mut n = 2;
    while dest.exists() {
        dest = parent.join(format!("{stem} (recovered {n})"));
        n += 1;
    }
    dest
}

/// One line for the toast after a recovery.
pub fn headline(r: &RecoverReport) -> String {
    let mut s = format!("Recovered {} of {} files", r.recovered(), r.entries.len());
    if r.partial() > 0 {
        s.push_str(&format!(" · {} partial", r.partial()));
    }
    if r.lost() > 0 {
        s.push_str(&format!(" · {} lost", r.lost()));
    }
    s
}

/// The dialog body: totals, what had to be worked around, then every file that did not
/// come out whole.
pub fn body(ui: &mut Ui, p: &Palette, v: &RecoverView) {
    let r = &v.report;
    let clean = r.partial() == 0 && r.lost() == 0;
    ui.horizontal(|ui| {
        icons::icon(
            ui,
            18.0,
            if clean { Icon::Check } else { Icon::Alert },
            if clean { p.ok } else { p.caution },
        );
        ui.label(RichText::new(headline(r)).font(theme::semibold(18.0)));
    });
    ui.label(
        RichText::new(format!("{} · {} written", v.name, human_size(r.bytes)))
            .size(12.5)
            .color(p.dim),
    );
    ui.add_space(8.0);
    for n in &r.notes {
        ui.add(egui::Label::new(RichText::new(n).size(12.5).color(p.dim)).wrap());
    }
    let damaged: Vec<_> = r
        .entries
        .iter()
        .filter(|e| !matches!(e.outcome, Outcome::Recovered { .. }))
        .collect();
    if damaged.is_empty() {
        return;
    }
    ui.add_space(8.0);
    egui::ScrollArea::vertical()
        .max_height(300.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for e in damaged {
                let (tag, color, why) = match &e.outcome {
                    Outcome::Partial {
                        bytes,
                        kept,
                        reason,
                    } => (
                        if *kept { "Partial" } else { "Partial, removed" },
                        p.caution,
                        format!("{} readable · {reason}", human_size(*bytes)),
                    ),
                    Outcome::Lost { reason } => ("Lost", p.danger, reason.clone()),
                    Outcome::Recovered { .. } => continue,
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(tag).font(theme::semibold(12.0)).color(color));
                    ui.add(egui::Label::new(RichText::new(&e.name).size(12.5)).truncate());
                });
                ui.add(egui::Label::new(RichText::new(why).size(11.5).color(p.faint)).wrap());
                ui.add_space(4.0);
            }
        });
}
