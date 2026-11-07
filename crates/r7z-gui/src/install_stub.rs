//! The Microsoft Store installs and removes r7z, so its build has none of `install.rs`:
//! no registry entries, no copying itself, no deleting its own folder. The app still reads
//! the state, which here is always that r7z didn't install itself.

use std::path::PathBuf;

#[derive(Clone, PartialEq)]
pub enum State {
    NotInstalled,
    // The interface that shows this is compiled, but never runs in this build.
    #[allow(dead_code)]
    Installed {
        dir: PathBuf,
        here: bool,
    },
}

pub fn target_dir() -> Option<PathBuf> {
    None
}

pub fn state() -> State {
    State::NotInstalled
}

pub fn install() -> Result<PathBuf, String> {
    Err("the Microsoft Store installs r7z".into())
}

pub fn uninstall() -> Result<(), String> {
    Err("the Microsoft Store removes r7z".into())
}

pub fn refresh() {}
