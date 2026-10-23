//! UDF images (OSTA UDF 1.02 to 2.60, including the metadata partition used by Blu-ray).

use std::sync::Arc;

use super::{Archive, Format, Input, OpenOptions, ReadAt, Signature};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "Udf",
    aliases: &[],
    extensions: &["udf"],
    signatures: &[Signature::at(32769, b"BEA01")],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    open_udf(input.volume()?, opts)
}

/// Whether `src` carries a UDF volume recognition sequence and anchor. Used by the ISO
/// handler to prefer UDF on hybrid images.
pub fn is_udf(_src: &dyn ReadAt) -> bool {
    false
}

/// Opens the UDF file system on `src`.
pub fn open_udf(_src: Arc<dyn ReadAt>, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    Err(Error::unsupported("UDF reading is not implemented yet"))
}
