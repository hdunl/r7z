//! The 7z container format: signature header, (encoded) header, streams and file metadata.

pub mod bytes;
pub mod model;
pub mod read;
pub mod salvage;
pub mod write;

pub use model::*;

pub const SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];
pub const VERSION_MAJOR: u8 = 0;
pub const VERSION_MINOR: u8 = 4;
pub const SIGNATURE_HEADER_SIZE: u64 = 32;

/// Property IDs from 7zFormat.txt.
pub mod id {
    pub const END: u64 = 0x00;
    pub const HEADER: u64 = 0x01;
    pub const ARCHIVE_PROPERTIES: u64 = 0x02;
    pub const ADDITIONAL_STREAMS_INFO: u64 = 0x03;
    pub const MAIN_STREAMS_INFO: u64 = 0x04;
    pub const FILES_INFO: u64 = 0x05;
    pub const PACK_INFO: u64 = 0x06;
    pub const UNPACK_INFO: u64 = 0x07;
    pub const SUBSTREAMS_INFO: u64 = 0x08;
    pub const SIZE: u64 = 0x09;
    pub const CRC: u64 = 0x0A;
    pub const FOLDER: u64 = 0x0B;
    pub const CODERS_UNPACK_SIZE: u64 = 0x0C;
    pub const NUM_UNPACK_STREAM: u64 = 0x0D;
    pub const EMPTY_STREAM: u64 = 0x0E;
    pub const EMPTY_FILE: u64 = 0x0F;
    pub const ANTI: u64 = 0x10;
    pub const NAME: u64 = 0x11;
    pub const CTIME: u64 = 0x12;
    pub const ATIME: u64 = 0x13;
    pub const MTIME: u64 = 0x14;
    pub const WIN_ATTRIBUTES: u64 = 0x15;
    pub const COMMENT: u64 = 0x16;
    pub const ENCODED_HEADER: u64 = 0x17;
    pub const START_POS: u64 = 0x18;
    pub const DUMMY: u64 = 0x19;
}

/// Windows attribute bits used in 7z `kWinAttributes`.
pub mod attr {
    pub const READONLY: u32 = 0x01;
    pub const HIDDEN: u32 = 0x02;
    pub const SYSTEM: u32 = 0x04;
    pub const DIRECTORY: u32 = 0x10;
    pub const ARCHIVE: u32 = 0x20;
    /// p7zip/7-Zip extension: the high 16 bits hold a Unix `st_mode`.
    pub const UNIX_EXTENSION: u32 = 0x8000;
}
