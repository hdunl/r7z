//! Self-extracting archives: a 7z, zip, rar or cab appended to an executable stub, as 7-Zip
//! and WinRAR build them.
//!
//! The archive starts after the PE image, so the signatures of the archive formats are
//! searched for in the overlay. Each candidate is opened as that format, and the first that
//! opens (or needs a password) is the payload. Opening then gives that format's own archive:
//! its entries and type are those of the archive inside.

use super::data::{Input, Slice};
use super::pe::Image;
use super::{Archive, Format, OpenOptions, Signature};
use crate::error::{Error, Result};

/// A payload format: no signature and no extension. [`carries_payload`] recognizes it in a
/// PE file, and `payload_format` in `format/mod.rs` calls that.
pub const FORMAT: Format = Format {
    name: "Sfx",
    aliases: &[],
    extensions: &[],
    signatures: &[],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

/// Formats an SFX stub can carry.
const PAYLOADS: [&Format; 4] = [
    &super::sevenz::FORMAT,
    &super::zip::FORMAT,
    &super::rar::FORMAT,
    &super::cab::FORMAT,
];

/// The payload formats' signatures, worked out at compile time, so code that only looks for
/// them (the Explorer menu) does not link the parsers through the formats' `open`.
const PAYLOAD_SIGNATURES: [&[Signature]; 4] = {
    let mut out: [&[Signature]; 4] = [&[]; 4];
    let mut i = 0;
    while i < PAYLOADS.len() {
        out[i] = PAYLOADS[i].signatures;
        i += 1;
    }
    out
};

/// Signature hits tried per format. Stubs carry few copies of a signature in their overlay,
/// and each try opens the archive's headers.
const MAX_TRIES: usize = 4;

/// Candidate payload offsets in the overlay of a PE file, earliest first.
fn candidates(file: &Slice) -> Vec<(usize, &'static Format)> {
    let Ok(image) = Image::parse(file) else {
        return Vec::new();
    };
    let tail = &file[image.overlay..];
    let mut out = Vec::new();
    for f in PAYLOADS {
        for sig in f.signatures.iter().filter(|s| s.offset == 0) {
            let hits = tail
                .windows(sig.bytes.len())
                .enumerate()
                .filter(|(_, w)| *w == sig.bytes)
                .take(MAX_TRIES);
            out.extend(hits.map(|(i, _)| (image.overlay + i, f)));
        }
    }
    out.sort_by_key(|c| c.0);
    out
}

/// Whether a payload format's signature appears after the PE image. Opens nothing, so it
/// can claim a payload that turns out not to open; [`carries_payload`] decides.
pub(crate) fn overlay_has_signature(file: &[u8]) -> bool {
    let Ok(image) = Image::parse(file) else {
        return false;
    };
    let tail = &file[image.overlay..];
    PAYLOAD_SIGNATURES
        .iter()
        .flat_map(|sigs| sigs.iter())
        .filter(|s| s.offset == 0 && !s.bytes.is_empty())
        .any(|s| tail.windows(s.bytes.len()).any(|w| w == s.bytes))
}

/// Whether the PE file carries an archive r7z can open, or one that needs a password.
pub fn carries_payload(file: &Slice) -> bool {
    match open_payload(file, None) {
        Ok(_) => true,
        Err(Error::PasswordRequired | Error::WrongPassword) => true,
        Err(_) => false,
    }
}

/// Opens the first candidate payload that opens, with `password`.
fn open_payload(file: &Slice, password: Option<&str>) -> Result<Box<dyn Archive>> {
    let mut needs_password = None;
    for (at, fmt) in candidates(file) {
        let opts = OpenOptions {
            password: password.map(str::to_string),
            ..Default::default()
        };
        let sub = file.sub(at as u64..file.len() as u64)?;
        match (fmt.open)(Input::Mem(sub), &opts) {
            Ok(archive) => return Ok(archive),
            Err(e @ (Error::PasswordRequired | Error::WrongPassword)) => {
                needs_password.get_or_insert(e);
            }
            Err(_) => {}
        }
    }
    Err(needs_password.unwrap_or(Error::NotArchive))
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let file = input.into_mem()?;
    open_payload(&file, opts.password.as_deref())
}
