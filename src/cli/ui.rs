//! Terminal output: progress bars, prompts and styling. Everything interactive goes to
//! stderr so stdout stays clean for `-so` and scripting.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use console::style;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use r7z::ops::create::Progress;
use r7z::ops::extract::{Callbacks, OverwriteAnswer};
use r7z::util::fmt::human_size;

pub fn stderr_tty() -> bool {
    std::io::stderr().is_terminal()
}

pub fn bar(total: u64, enabled: bool, verb: &str) -> ProgressBar {
    if !enabled || !stderr_tty() || total == 0 {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr_with_hz(10));
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.cyan.bold} [{bar:32.cyan/blue}] {percent:>3}%  {binary_bytes}/{binary_total_bytes}  {binary_bytes_per_sec}  ETA {eta}",
        )
        .unwrap()
        .progress_chars("━╸ "),
    );
    pb.set_prefix(verb.to_string());
    pb.enable_steady_tick(Duration::from_millis(200));
    pb
}

pub struct BarProgress {
    pub pb: ProgressBar,
}

impl Progress for BarProgress {
    fn add(&self, bytes: u64) {
        self.pb.inc(bytes);
    }
    fn warn(&self, msg: &str) {
        self.pb.suspend(|| warn(msg));
    }
}

pub struct ExtractUi {
    pub pb: ProgressBar,
    pub assume_yes: bool,
}

impl Callbacks for ExtractUi {
    fn add(&self, bytes: u64) {
        self.pb.inc(bytes);
    }
    fn confirm_overwrite(&self, path: &Path) -> OverwriteAnswer {
        if self.assume_yes {
            return OverwriteAnswer::Yes;
        }
        if !std::io::stdin().is_terminal() {
            return OverwriteAnswer::No;
        }
        self.pb.suspend(|| loop {
            eprint!(
                "{} {} already exists. Overwrite? [{}]es / [{}]o / [{}]lways / [{}]kip all / [{}]ename / [{}]uit: ",
                style("?").yellow().bold(),
                style(path.display()).bold(),
                style("y").bold(),
                style("n").bold(),
                style("a").bold(),
                style("s").bold(),
                style("r").bold(),
                style("q").bold()
            );
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() || line.is_empty() {
                return OverwriteAnswer::Quit;
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return OverwriteAnswer::Yes,
                "n" | "no" => return OverwriteAnswer::No,
                "a" | "always" => return OverwriteAnswer::YesAll,
                "s" | "skip" => return OverwriteAnswer::NoAll,
                "r" | "rename" => return OverwriteAnswer::Rename,
                "q" | "quit" => return OverwriteAnswer::Quit,
                _ => {}
            }
        })
    }
}

pub fn warn(msg: &str) {
    eprintln!("{} {msg}", style("warning:").yellow().bold());
}

pub fn error(msg: &str) {
    eprintln!("{} {msg}", style("error:").red().bold());
}

pub fn ok(msg: &str) {
    eprintln!("{} {msg}", style("✓").green().bold());
}

pub fn rate(bytes: u64, d: Duration) -> String {
    let s = d.as_secs_f64();
    if s <= 0.0005 {
        return "-".into();
    }
    format!("{}/s", human_size((bytes as f64 / s) as u64))
}

pub fn secs(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 1.0 {
        format!("{:.0} ms", s * 1000.0)
    } else {
        format!("{s:.2} s")
    }
}

/// Prompts for a password on the terminal. `confirm` asks twice (for new archives).
pub fn prompt_password(confirm: bool) -> Option<String> {
    if !stderr_tty() {
        return None;
    }
    let p = rpassword::prompt_password("Enter password: ").ok()?;
    if confirm {
        let q = rpassword::prompt_password("Verify password: ").ok()?;
        if p != q {
            error("passwords do not match");
            return None;
        }
    }
    Some(p)
}

/// Thousands separators for counts and byte columns.
pub fn grouped(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}
