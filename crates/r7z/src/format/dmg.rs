//! Apple disk images (UDIF, `.dmg`): the koly trailer, the plist of `blkx` chunks, and the
//! partitions they decode to. Each partition is an entry that opens as a volume.

use super::{Archive, Format, Input, OpenOptions, ReadAt};
use crate::error::{Error, Result};

pub const FORMAT: Format = Format {
    name: "Dmg",
    aliases: &["udif"],
    extensions: &["dmg"],
    signatures: &[],
    detect: None,
    write: false,
    stream: false,
    sequential: true,
    open,
};

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let _volume = input.volume()?;
    Err(Error::unsupported(
        "disk image reading is not implemented yet",
    ))
}

/// Whether `src` ends with a UDIF trailer (`koly`).
pub fn is_udif(_src: &dyn ReadAt) -> bool {
    false
}
