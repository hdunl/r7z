//! HFS+ and HFSX volumes (a disk partition or a raw volume image).

use super::{Archive, Format, Input, OpenOptions, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "HFS",
    aliases: &["hfsplus", "hfsx"],
    extensions: &["hfs"],
    signatures: &[Signature::at(1024, b"H+"), Signature::at(1024, b"HX")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let _volume = input.volume()?;
    Err(Error::unsupported("HFS+ reading is not implemented yet"))
}
