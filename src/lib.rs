//! r7z: a fast, lightweight 7z archiver.
//!
//! Layers, innermost first: `sevenz` (container model, reader, writer), `codec` (coder
//! pipelines), `format` (the format-neutral archive interface and every format handler),
//! `ops` (create/extract/hash/bench workflows). The CLI lives in `main.rs`.

pub mod codec;
pub mod error;
pub mod format;
pub mod ops;
pub mod sevenz;
pub mod util;

pub use error::{Error, Result};
