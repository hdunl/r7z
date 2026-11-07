//! The Microsoft Store keeps r7z up to date, so its build has none of `update.rs`, which
//! is also the only code in the app that reaches the network. Nothing here runs: the app
//! never asks for an update in this build.

use std::sync::atomic::AtomicBool;

use r7z::error::{Error, Result};

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct Manifest {
    pub version: String,
}

impl Manifest {
    pub fn release_url(&self) -> String {
        release_page(&self.version)
    }
}

pub fn release_page(version: &str) -> String {
    format!("https://github.com/hdunl/r7z/releases/tag/v{version}")
}

pub enum Check {
    UpToDate,
    // The interface that shows this is compiled, but never runs in this build.
    #[allow(dead_code)]
    Available(Manifest, Option<String>),
}

pub fn check(_cancel: &AtomicBool) -> Result<Check> {
    Ok(Check::UpToDate)
}

pub fn download_and_install(_m: &Manifest, _cancel: &AtomicBool) -> Result<String> {
    Err(Error::Other("the Microsoft Store updates r7z".into()))
}

pub fn relaunch() -> Result<()> {
    Err(Error::Other("the Microsoft Store updates r7z".into()))
}

pub fn cleanup() {}
