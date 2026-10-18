#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! r7z desktop app: a file browser that treats archives like folders.
//!
//! `r7z-gui [archive or folder]` opens it. Explorer menu verbs use
//! `--extract-here <archives...>`, `--extract-to <archives...>`, `--test <archive>`,
//! `--convert <archive>`, `--add <paths...>`, and `--add-7z` / `--add-zip <paths...>`
//! to compress right away with the default settings.

mod app;
mod dialogs;
mod dnd;
mod finder;
mod icons;
mod jobs;
mod logo;
mod model;
#[cfg(windows)]
mod mount;
#[cfg(not(windows))]
#[path = "mount_stub.rs"]
mod mount;
mod open_folder;
mod preview;
#[cfg(windows)]
mod projfs;
mod recover;
mod shell;
mod spacemap;
mod theme;
mod tour;
mod ui;
mod undo;
mod update;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;

fn parse_args() -> app::Startup {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = |i: usize| args.get(i).map(PathBuf::from);
    match args.first().map(String::as_str) {
        None => app::Startup::None,
        Some("--extract-here") => match &args[1..] {
            [] => app::Startup::None,
            [_] => app::Startup::ExtractHere(path(1).unwrap_or_default()),
            many => app::Startup::ExtractHereAll(many.iter().map(PathBuf::from).collect()),
        },
        Some("--extract-to") => match &args[1..] {
            [] => app::Startup::None,
            [_] => app::Startup::ExtractTo(path(1).unwrap_or_default()),
            many => app::Startup::ExtractToAll(many.iter().map(PathBuf::from).collect()),
        },
        Some("--add") => app::Startup::Add(args[1..].iter().map(PathBuf::from).collect()),
        Some(flag @ ("--add-7z" | "--add-zip")) => match &args[1..] {
            [] => app::Startup::None,
            paths => app::Startup::Compress(
                paths.iter().map(PathBuf::from).collect(),
                if flag == "--add-7z" {
                    dialogs::Fmt::SevenZ
                } else {
                    dialogs::Fmt::Zip
                },
            ),
        },
        Some("--test") => match path(1) {
            Some(p) => app::Startup::Test(p),
            None => app::Startup::None,
        },
        Some("--convert") => match path(1) {
            Some(p) => app::Startup::Convert(p),
            None => app::Startup::None,
        },
        Some(p) => app::Startup::Open(PathBuf::from(p)),
    }
}

/// Panics on the UI thread end the app: record what happened and tell the user where.
/// Panics in background work are caught by the job runner and shown as errors instead.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current()
            .name()
            .unwrap_or("worker")
            .to_string();
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let backtrace = std::backtrace::Backtrace::force_capture();
        let report = format!(
            "r7z {} crash report\nthread: {thread}\nat: {location}\nmessage: {payload}\n\n{backtrace}\n",
            env!("CARGO_PKG_VERSION")
        );
        let mut saved = None;
        if let Some(path) = shell::crash_log_path() {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = f.write_all(report.as_bytes());
                saved = Some(path);
            }
        }
        if thread == "main" {
            let where_ = saved
                .map(|p| format!("\n\nDetails were saved to {}", p.display()))
                .unwrap_or_default();
            shell::fatal_box(
                "r7z stopped unexpectedly",
                &format!("{payload}\n({location}){where_}"),
            );
        }
        default(info);
    }));
}

fn main() -> eframe::Result {
    install_panic_hook();
    let startup = parse_args();
    let icon = egui::IconData {
        rgba: logo::logo_rgba(64),
        width: 64,
        height: 64,
    };
    let compact = matches!(
        startup,
        app::Startup::ExtractHere(_) | app::Startup::ExtractTo(_) | app::Startup::Compress(..)
    );
    let size = if compact {
        [720.0, 420.0]
    } else {
        [1240.0, 780.0]
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("r7z")
            .with_inner_size(size)
            .with_min_inner_size([760.0, 440.0])
            .with_icon(Arc::new(icon))
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "r7z",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, startup)))),
    )
}
