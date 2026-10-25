//! Temporary archives that do not outlive an interrupted run.
//!
//! An archive is written to a temporary file next to its target and renamed into place
//! once complete. When the console ends r7z with Ctrl-C, Ctrl-Break or by closing, the
//! process exits without unwinding, so a handler removes the temporary files still being
//! written. Rust opens files with delete sharing, so a file another thread still writes is
//! removed once the process has exited.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Temporary files being written.
static WATCHED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// A temporary file that is removed if the console ends the process. Dropping it stops
/// watching; renaming or removing the file stays with the caller.
pub struct TempFile(PathBuf);

impl TempFile {
    pub fn new(path: PathBuf) -> TempFile {
        install();
        if let Ok(mut w) = WATCHED.lock() {
            w.push(path.clone());
        }
        TempFile(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Ok(mut w) = WATCHED.lock() {
            if let Some(i) = w.iter().position(|p| *p == self.0) {
                w.swap_remove(i);
            }
        }
    }
}

impl Deref for TempFile {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempFile {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// Removes every watched file.
fn remove_watched() {
    if let Ok(w) = WATCHED.lock() {
        remove_all(&w);
    }
}

fn remove_all(paths: &[PathBuf]) {
    for p in paths {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(test)]
fn is_watched(p: &Path) -> bool {
    WATCHED.lock().is_ok_and(|w| w.iter().any(|q| q == p))
}

#[cfg(windows)]
fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    /// Runs on a thread of its own for any console event; returning 0 lets the default
    /// handler end the process.
    unsafe extern "system" fn on_console_event(_event: u32) -> i32 {
        remove_watched();
        0
    }
    ONCE.call_once(|| {
        // SAFETY: the handler is a plain function that stays valid for the process.
        unsafe {
            SetConsoleCtrlHandler(Some(on_console_event), 1);
        }
    });
}

#[cfg(not(windows))]
fn install() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watched_files_are_removed_until_dropped() {
        let dir = std::env::temp_dir().join(format!("r7z-tempfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.tmp");
        let b = dir.join("b.tmp");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let ta = TempFile::new(a.clone());
        {
            let _tb = TempFile::new(b.clone());
            assert!(is_watched(&b));
        }
        assert!(is_watched(&a), "a guard watches its file");
        assert!(!is_watched(&b), "a dropped guard stops watching");
        // Other tests' files are watched too, so only this one is removed here. An open
        // writer does not keep it: deletion is shared.
        let open = std::fs::OpenOptions::new().append(true).open(&*ta).unwrap();
        remove_all(std::slice::from_ref(&a));
        drop(open);
        assert!(!a.exists(), "a watched file is removed");
        drop(ta);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
