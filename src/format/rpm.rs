//! RPM packages: a 96-byte lead, a signature header, the main header (tag index plus data
//! store) and a compressed cpio payload. Like 7-Zip, the package lists as one entry, the
//! payload (`name-version-release.arch.cpio.gz`); as a stream format, the archive inside
//! it opens too.

use std::sync::Arc;

use super::data::BoxRead;
use super::Unit;
use super::{Archive, Ctx, Entry, EntryFn, Format, Input, OpenOptions, Opener, Signature, Slice};
use crate::error::{Error, Result};
use crate::util::time::format_filetime;
use crate::util::time::unix_to_filetime;

pub static FORMAT: Format = Format {
    name: "Rpm",
    aliases: &[],
    extensions: &["rpm"],
    signatures: &[Signature::at(0, &[0xED, 0xAB, 0xEE, 0xDB])],
    detect: None,
    write: false,
    stream: true,
    sequential: false,
    open,
};

const LEAD: usize = 96;
const HEADER_MAGIC: [u8; 4] = [0x8E, 0xAD, 0xE8, 0x01];
/// Signature types: none, or a header structure like the main header.
const SIG_NONE: u16 = 0;
const SIG_HEADER: u16 = 5;

const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_SUMMARY: u32 = 1004;
const TAG_BUILDTIME: u32 = 1006;
const TAG_OS: u32 = 1021;
const TAG_ARCH: u32 = 1022;
const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
/// Signature tags holding the size of the main header plus payload.
const SIGTAG_SIZE: u32 = 1000;
const SIGTAG_LONGSIZE: u32 = 270;

const TYPE_INT32: u32 = 4;
const TYPE_INT64: u32 = 5;
const TYPE_STRING: u32 = 6;
const TYPE_I18NSTRING: u32 = 9;

/// Lead architecture numbers, as 7-Zip names them (used when the header has no ARCH tag).
const CPUS: &[&str] = &[
    "noarch",
    "i386",
    "alpha",
    "sparc",
    "mips",
    "ppc",
    "m68k",
    "sgi",
    "rs6000",
    "ia64",
    "sparc64",
    "mips64",
    "arm",
    "m68kmint",
    "s390",
    "s390x",
    "ppc64",
    "sh",
    "xtensa",
    "aarch64",
    "mipsr6",
    "mips64r6",
    "riscv64",
    "loongarch64",
];

/// Lead operating system numbers.
const OSES: &[&str] = &[
    "0",
    "Linux",
    "Irix",
    "solaris",
    "SunOS",
    "AmigaOS",
    "AIX",
    "HP-UX",
    "osf",
    "FreeBSD",
    "SCO_SV",
    "Irix64",
    "NextStep",
    "bsdi",
    "machten",
    "cygwin32-NT",
    "cygwin32-95",
    "MP_RAS",
    "MiNT",
    "OS/390",
    "VM/ESA",
    "Linux/390",
    "darwin",
];

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

/// A parsed header structure: index entries over a data store.
struct Header<'a> {
    index: &'a [u8],
    store: &'a [u8],
}

impl<'a> Header<'a> {
    /// Parses the header at `pos`, returning it and the offset just past it.
    fn parse(data: &'a [u8], pos: usize) -> Result<(Self, usize)> {
        let bad = || Error::corrupt("bad rpm header");
        let h = data.get(pos..pos + 16).ok_or_else(bad)?;
        if h[..4] != HEADER_MAGIC {
            return Err(bad());
        }
        let n = be32(h, 8) as usize;
        let store_len = be32(h, 12) as usize;
        let index_end = n
            .checked_mul(16)
            .and_then(|l| l.checked_add(pos + 16))
            .ok_or_else(bad)?;
        let end = index_end.checked_add(store_len).ok_or_else(bad)?;
        if end > data.len() {
            return Err(Error::corrupt("rpm header is truncated"));
        }
        Ok((
            Header {
                index: &data[pos + 16..index_end],
                store: &data[index_end..end],
            },
            end,
        ))
    }

    /// The type, data-store offset and count of `tag`.
    fn find(&self, tag: u32) -> Option<(u32, usize, usize)> {
        self.index.as_chunks::<16>().0.iter().find_map(|e| {
            (be32(e, 0) == tag).then(|| (be32(e, 4), be32(e, 8) as usize, be32(e, 12) as usize))
        })
    }

    fn string(&self, tag: u32) -> Option<String> {
        let (ty, off, _) = self.find(tag)?;
        if ty != TYPE_STRING && ty != TYPE_I18NSTRING {
            return None;
        }
        let rest = self.store.get(off..)?;
        let len = rest.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&rest[..len]).into_owned())
    }

    fn int32(&self, tag: u32) -> Option<u32> {
        match self.find(tag)? {
            (TYPE_INT32, off, 1..) => Some(be32(self.store.get(off..off + 4)?, 0)),
            _ => None,
        }
    }

    fn int(&self, tag: u32) -> Option<u64> {
        let (ty, off, count) = self.find(tag)?;
        if count == 0 {
            return None;
        }
        match ty {
            TYPE_INT32 => Some(be32(self.store.get(off..off + 4)?, 0).into()),
            TYPE_INT64 => Some(u64::from_be_bytes(
                self.store.get(off..off + 8)?.try_into().ok()?,
            )),
            _ => None,
        }
    }
}

pub struct Rpm {
    payload: Slice,
    entries: Vec<Entry>,
    units: Vec<Unit>,
    properties: Vec<(&'static str, String)>,
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let data = input.into_mem()?;
    if data.len() < LEAD || data[..4] != [0xED, 0xAB, 0xEE, 0xDB] {
        return Err(Error::NotArchive);
    }
    let lead_type = be16(&data, 6);
    let lead_arch = be16(&data, 8);
    let lead_name_len = data[10..76].iter().position(|&b| b == 0).unwrap_or(66);
    let lead_name = String::from_utf8_lossy(&data[10..10 + lead_name_len]).into_owned();
    let lead_os = be16(&data, 76);
    let sig_type = be16(&data, 78);

    let (payload_size, main_pos) = match sig_type {
        SIG_NONE => (None, LEAD),
        SIG_HEADER => {
            let (sig, end) = Header::parse(&data, LEAD)?;
            let size = sig.int(SIGTAG_LONGSIZE).or_else(|| sig.int(SIGTAG_SIZE));
            (size, end.next_multiple_of(8))
        }
        t => return Err(Error::unsupported(format!("rpm signature type {t}"))),
    };
    let (main, headers_end) = Header::parse(&data, main_pos)?;
    let len = data.len() as u64;
    // The signature records the main header plus payload size; trust it when plausible.
    let end = payload_size
        .and_then(|s| s.checked_add(main_pos as u64))
        .filter(|&e| e >= headers_end as u64)
        .unwrap_or(len);
    let payload = data.sub_clamped(headers_end as u64..end);
    let payload_len = end - headers_end as u64;

    let name = main.string(TAG_NAME).unwrap_or_default();
    let version = main.string(TAG_VERSION).unwrap_or_default();
    let release = main.string(TAG_RELEASE).unwrap_or_default();
    let cpu = main.string(TAG_ARCH).unwrap_or_else(|| match lead_type {
        0 => CPUS
            .get(lead_arch as usize)
            .map_or_else(|| lead_arch.to_string(), |s| s.to_string()),
        _ => String::new(),
    });
    let os = main
        .string(TAG_OS)
        .or_else(|| OSES.get(lead_os as usize).map(|s| s.to_string()));
    let build_time = main
        .int32(TAG_BUILDTIME)
        .filter(|&t| t != 0)
        .map(|t| unix_to_filetime(t as i64));

    let mut base = if name.is_empty() {
        lead_name
    } else {
        [name.as_str(), version.as_str(), release.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("-")
    };
    base.push('.');
    base.push_str(if lead_type == 1 { "src" } else { &cpu });
    let payload_format = main
        .string(TAG_PAYLOADFORMAT)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cpio".into());
    let compressor = match main.string(TAG_PAYLOADCOMPRESSOR).filter(|s| !s.is_empty()) {
        Some(c) if c == "gzip" => "gz".to_string(),
        Some(c) if c == "bzip2" => "bz2".to_string(),
        Some(c) => c,
        None => match &payload[..payload.len().min(6)] {
            [0x1F, 0x8B, ..] => "gz",
            [0xFD, b'7', b'z', b'X', b'Z', 0] => "xz",
            [b'B', b'Z', b'h', c, ..] if (b'1'..=b'9').contains(c) => "bz2",
            _ => "lzma",
        }
        .to_string(),
    };

    let mut properties = vec![
        ("Physical Size", end.max(headers_end as u64).to_string()),
        ("Headers Size", headers_end.to_string()),
    ];
    if !cpu.is_empty() {
        properties.push(("CPU", cpu));
    }
    if let Some(os) = os {
        properties.push(("Host OS", os));
    }
    if let Some(t) = build_time {
        properties.push(("Created", format_filetime(t)));
    }
    for (key, tag) in [
        ("Name", TAG_NAME),
        ("Version", TAG_VERSION),
        ("Release", TAG_RELEASE),
        ("Summary", TAG_SUMMARY),
    ] {
        if let Some(v) = main.string(tag).filter(|s| !s.is_empty()) {
            properties.push((key, v));
        }
    }

    let entry = Entry {
        name: format!("{base}.{payload_format}.{compressor}"),
        size: Some(payload_len),
        packed_size: Some(payload_len),
        mtime: build_time,
        ctime: build_time,
        ..Default::default()
    };
    Ok(Box::new(Rpm {
        payload,
        entries: vec![entry],
        units: vec![Unit {
            entries: vec![0],
            encrypted: false,
        }],
        properties,
    }))
}

impl Archive for Rpm {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, _unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        // A payload shorter than the signature says reads short; the extractor reports it.
        f(0, &mut self.payload.reader())?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.properties.clone()
    }

    fn stream(&self, i: usize) -> Option<Opener> {
        if i != 0 {
            return None;
        }
        let payload = self.payload.clone();
        Some(Arc::new(move || Ok(Box::new(payload.reader()) as BoxRead)))
    }
}
