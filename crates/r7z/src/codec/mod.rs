//! Codec registry and coder pipelines.

pub mod aes;
pub mod bzip2par;
pub mod bzip2scan;
pub mod decode;
pub mod encode;
pub mod huffman;
pub mod lzh;
pub mod lzma2par;
pub mod lzma2scan;
pub mod lzms;
pub mod lzw;
pub mod lzx;
pub mod lzx_wim;
pub mod mszip;
pub mod pcompress;
pub mod pkware;
pub mod quantum;
pub mod xpress;
pub mod xzscan;
pub mod xzwrite;
pub mod zipcrypt;
pub mod zstdwrite;

use crate::sevenz::Coder;
use crate::util::fmt::dict_label;

/// 7z method IDs (same values 7-Zip registers; see the REA report codec table).
pub mod method {
    pub const COPY: u64 = 0x00;
    pub const DELTA: u64 = 0x03;
    pub const BCJ_X86: u64 = 0x0303_0103;
    pub const BCJ2: u64 = 0x0303_011B;
    pub const PPC: u64 = 0x0303_0205;
    pub const IA64: u64 = 0x0303_0401;
    pub const ARM: u64 = 0x0303_0501;
    pub const ARMT: u64 = 0x0303_0701;
    pub const SPARC: u64 = 0x0303_0805;
    pub const ARM64: u64 = 0x0A;
    pub const RISCV: u64 = 0x0B;
    pub const SWAP2: u64 = 0x0002_0302;
    pub const SWAP4: u64 = 0x0002_0304;
    pub const LZMA2: u64 = 0x21;
    pub const LZMA: u64 = 0x0003_0101;
    pub const PPMD: u64 = 0x0003_0401;
    pub const DEFLATE: u64 = 0x0004_0108;
    pub const DEFLATE64: u64 = 0x0004_0109;
    pub const BZIP2: u64 = 0x0004_0202;
    pub const AES: u64 = 0x06F1_0701;
}

pub fn method_name(id: u64) -> &'static str {
    use method::*;
    match id {
        COPY => "Copy",
        DELTA => "Delta",
        BCJ_X86 => "BCJ",
        BCJ2 => "BCJ2",
        PPC => "PPC",
        IA64 => "IA64",
        ARM => "ARM",
        ARMT => "ARMT",
        SPARC => "SPARC",
        ARM64 => "ARM64",
        RISCV => "RISCV",
        SWAP2 => "Swap2",
        SWAP4 => "Swap4",
        LZMA2 => "LZMA2",
        LZMA => "LZMA",
        PPMD => "PPMD",
        DEFLATE => "Deflate",
        DEFLATE64 => "Deflate64",
        BZIP2 => "BZip2",
        AES => "7zAES",
        _ => "?",
    }
}

/// Whether r7z can decode this method.
pub fn can_decode(id: u64) -> bool {
    use method::*;
    matches!(
        id,
        COPY | DELTA
            | BCJ_X86
            | BCJ2
            | PPC
            | IA64
            | ARM
            | ARMT
            | SPARC
            | ARM64
            | RISCV
            | LZMA2
            | LZMA
            | PPMD
            | BZIP2
            | DEFLATE
            | DEFLATE64
            | AES
    )
}

/// Whether r7z can encode this method.
pub fn can_encode(id: u64) -> bool {
    use method::*;
    matches!(id, COPY | DELTA | BCJ_X86 | LZMA2 | LZMA | AES)
}

/// LZMA2 dictionary size encoded in its one-byte property.
pub fn lzma2_dict_from_prop(p: u8) -> Option<u32> {
    match p {
        0..=39 => Some((2 | (p as u32 & 1)) << (p / 2 + 11)),
        40 => Some(u32::MAX),
        _ => None,
    }
}

/// Smallest LZMA2 dictionary property whose size is at least `dict`.
pub fn lzma2_prop_for_dict(dict: u32) -> u8 {
    (0..40u8)
        .find(|&p| lzma2_dict_from_prop(p).unwrap() >= dict)
        .unwrap_or(40)
}

/// 7-Zip style coder description, e.g. `LZMA2:24`, `BCJ`, `7zAES:19`.
pub fn describe_coder(c: &Coder) -> String {
    let name = method_name(c.method);
    let name = if name == "?" {
        format!("{:X}", c.method)
    } else {
        name.to_string()
    };
    match c.method {
        method::LZMA2 if c.props.len() == 1 => match lzma2_dict_from_prop(c.props[0]) {
            Some(d) => format!("{name}:{}", dict_label(d as u64)),
            None => name,
        },
        method::LZMA if c.props.len() == 5 => {
            let d = u32::from_le_bytes(c.props[1..5].try_into().unwrap());
            let (lc, lp, pb) = (c.props[0] % 9, (c.props[0] / 9) % 5, c.props[0] / 45);
            let mut s = format!("{name}:{}", dict_label(d as u64));
            if lc != 3 {
                s.push_str(&format!(":lc{lc}"));
            }
            if lp != 0 {
                s.push_str(&format!(":lp{lp}"));
            }
            if pb != 2 {
                s.push_str(&format!(":pb{pb}"));
            }
            s
        }
        method::DELTA if c.props.len() == 1 => format!("{name}:{}", c.props[0] as u32 + 1),
        method::PPMD if c.props.len() == 5 => {
            let mem = u32::from_le_bytes(c.props[1..5].try_into().unwrap());
            format!("{name}:o{}:mem{}", c.props[0], dict_label(mem as u64))
        }
        method::AES if !c.props.is_empty() => format!("{name}:{}", c.props[0] & 0x3F),
        _ => name,
    }
}

/// Method string for a folder as 7-Zip's `l -slt` prints it (coders in reverse order).
pub fn describe_folder(f: &crate::sevenz::Folder) -> String {
    f.coders
        .iter()
        .rev()
        .map(describe_coder)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lzma2_props() {
        assert_eq!(lzma2_dict_from_prop(0), Some(4096));
        assert_eq!(lzma2_dict_from_prop(1), Some(6144));
        assert_eq!(lzma2_dict_from_prop(24), Some(16 << 20));
        assert_eq!(lzma2_prop_for_dict(16 << 20), 24);
        assert_eq!(lzma2_prop_for_dict(1), 0);
        assert_eq!(lzma2_prop_for_dict((16 << 20) + 1), 25);
    }
}
