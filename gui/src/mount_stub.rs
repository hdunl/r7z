//! "Open as folder" needs Windows Projected File System; elsewhere it reports that.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use r7z::format::Archive;

pub const ENABLE_HELP: &str = "Open as folder needs Windows 10 1809 or later.";

pub fn available() -> Result<(), String> {
    Err(ENABLE_HELP.into())
}

pub fn sweep_stale() {}

pub struct Source {
    pub archive: Arc<dyn Archive>,
    pub name: String,
    pub key: String,
    pub password: Option<String>,
    pub time: u64,
}

pub struct Mount {
    pub name: String,
    pub root: PathBuf,
    pub key: String,
    pub files: u64,
}

impl Mount {
    pub fn start(_src: Source, _cache_dir: PathBuf) -> Result<Mount, String> {
        Err(ENABLE_HELP.into())
    }

    pub fn served(&self) -> u64 {
        0
    }

    pub fn eject(self, _patience: Duration) {}
}
