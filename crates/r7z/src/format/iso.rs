//! ISO 9660 images (`.iso`), with Joliet, Rock Ridge and El Torito boot entries.

use std::sync::Arc;

use super::{Archive, Format, Input, OpenOptions, ReadAt, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "Iso",
    aliases: &[],
    extensions: &["iso", "img"],
    signatures: &[Signature::at(32769, b"CD001")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let _volume: Arc<dyn ReadAt> = input.volume()?;
    Err(Error::unsupported(
        "ISO 9660 reading is not implemented yet",
    ))
}
