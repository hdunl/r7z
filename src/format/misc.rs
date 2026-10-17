//! Small container formats: split volumes (`.001`), Base64 text and Intel HEX.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use super::data::{materialize, Input, Slice};
use super::{stream_entry_name, Archive, Ctx, Entry, EntryFn, Format, OpenOptions, Unit};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------------------
// Split volumes

pub static SPLIT: Format = Format {
    name: "Split",
    aliases: &["001"],
    extensions: &["001"],
    signatures: &[],
    detect: Some(|_| true),
    write: false,
    stream: true,
    sequential: false,
    open: open_split,
};

/// `x.7z.001` → (`x.7z`, digits).
fn split_base(name: &str) -> Option<(&str, usize)> {
    let (base, ext) = name.rsplit_once('.')?;
    (ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit()) && ext.parse::<u32>().ok()? == 1)
        .then_some((base, ext.len()))
}

fn open_split(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let first = input.into_mem()?;
    let (base, digits) = split_base(&opts.name).ok_or(Error::NotArchive)?;
    let dir = opts
        .path
        .as_ref()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default();
    let mut volumes: Vec<PathBuf> = Vec::new();
    for n in 2u32.. {
        let p = dir.join(format!("{base}.{n:0digits$}"));
        if !p.is_file() {
            break;
        }
        volumes.push(p);
    }
    let data = if volumes.is_empty() {
        first
    } else {
        let mut sizes = first.len() as u64;
        for v in &volumes {
            sizes += std::fs::metadata(v)?.len();
        }
        let mut chain: Box<dyn Read> = Box::new(first.reader());
        for v in &volumes {
            let f = File::open(v)
                .map_err(|e| Error::Other(format!("cannot open {}: {e}", v.display())))?;
            chain = Box::new(chain.chain(f));
        }
        materialize(&mut chain, Some(sizes))?
    };
    let props = vec![
        ("Volumes", (volumes.len() + 1).to_string()),
        ("Total Physical Size", data.len().to_string()),
    ];
    Ok(super::stream::plain(&SPLIT, data, base.to_string(), props))
}

// ---------------------------------------------------------------------------------------
// Base64

pub static BASE64: Format = Format {
    name: "Base64",
    aliases: &["b64"],
    extensions: &["b64"],
    signatures: &[],
    detect: Some(looks_base64),
    write: false,
    stream: true,
    sequential: false,
    open: open_base64,
};

fn b64_value(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    })
}

fn looks_base64(h: &[u8]) -> bool {
    let body: Vec<u8> = strip_pem(h).filter(|c| !c.is_ascii_whitespace()).collect();
    body.len() >= 4 && body.iter().all(|&c| c == b'=' || b64_value(c).is_some())
}

/// The bytes outside `-----BEGIN/END ...-----` lines.
fn strip_pem(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    data.split(|&c| c == b'\n')
        .filter(|l| !l.starts_with(b"-----"))
        .flat_map(|l| l.iter().copied().chain(std::iter::once(b'\n')))
}

fn decode_base64(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    let mut done = false;
    for c in strip_pem(data) {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            done = true;
            continue;
        }
        if done {
            return Err(Error::corrupt("Base64: data after padding"));
        }
        let v = b64_value(c)
            .ok_or_else(|| Error::corrupt(format!("Base64: invalid character {c:#04x}")))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

fn open_base64(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let raw = input.into_mem()?;
    if !looks_base64(&raw[..raw.len().min(1 << 16)]) {
        return Err(Error::NotArchive);
    }
    let decoded = decode_base64(&raw)?;
    let name = stream_entry_name(&opts.name, &["b64"], &[]);
    let props = vec![("Physical Size", raw.len().to_string())];
    Ok(super::stream::plain(
        &BASE64,
        Slice::from_vec(decoded),
        name,
        props,
    ))
}

// ---------------------------------------------------------------------------------------
// Intel HEX

pub static IHEX: Format = Format {
    name: "IHex",
    aliases: &["hex"],
    extensions: &["ihex", "hex"],
    signatures: &[],
    detect: Some(|h| {
        let mut lines = h
            .split(|&c| c == b'\n')
            .map(|l| l.trim_ascii())
            .filter(|l| !l.is_empty());
        lines.next().is_some_and(|l| parse_record(l).is_ok())
    }),
    write: false,
    stream: false,
    sequential: false,
    open: open_ihex,
};

struct Record {
    typ: u8,
    addr: u16,
    data: Vec<u8>,
}

fn parse_record(line: &[u8]) -> Result<Record> {
    let bad = || Error::corrupt("Intel HEX: malformed record");
    let hex = line.strip_prefix(b":").ok_or_else(bad)?;
    if hex.len() < 10 || hex.len() % 2 != 0 {
        return Err(bad());
    }
    let bytes: Vec<u8> = hex
        .chunks_exact(2)
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect::<Option<_>>()
        .ok_or_else(bad)?;
    let len = bytes[0] as usize;
    if bytes.len() != len + 5 {
        return Err(bad());
    }
    if bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return Err(Error::corrupt("Intel HEX: record checksum mismatch"));
    }
    if bytes[3] > 5 {
        return Err(bad());
    }
    Ok(Record {
        typ: bytes[3],
        addr: u16::from_be_bytes([bytes[1], bytes[2]]),
        data: bytes[4..4 + len].to_vec(),
    })
}

struct IHex {
    entries: Vec<Entry>,
    units: Vec<Unit>,
    blocks: Vec<Vec<u8>>,
    size: u64,
}

fn open_ihex(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let raw = input.into_mem()?;
    let mut base = 0u32;
    let mut blocks: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut ended = false;
    for line in raw
        .split(|&c| c == b'\n')
        .map(|l| l.trim_ascii())
        .filter(|l| !l.is_empty())
    {
        if ended {
            break;
        }
        let r = parse_record(line).map_err(|e| {
            if blocks.is_empty() {
                Error::NotArchive
            } else {
                e
            }
        })?;
        match r.typ {
            0 => {
                let addr = base.wrapping_add(r.addr as u32);
                match blocks.last_mut() {
                    Some((start, b)) if start.wrapping_add(b.len() as u32) == addr => {
                        b.extend_from_slice(&r.data)
                    }
                    _ => blocks.push((addr, r.data)),
                }
            }
            1 => ended = true,
            2 if r.data.len() == 2 => {
                base = (u16::from_be_bytes([r.data[0], r.data[1]]) as u32) << 4
            }
            4 if r.data.len() == 2 => {
                base = (u16::from_be_bytes([r.data[0], r.data[1]]) as u32) << 16
            }
            3 | 5 => {}
            _ => return Err(Error::corrupt("Intel HEX: malformed address record")),
        }
    }
    if blocks.is_empty() && !ended {
        return Err(Error::NotArchive);
    }
    let single = blocks.len() == 1;
    let entries = blocks
        .iter()
        .enumerate()
        .map(|(i, (addr, b))| Entry {
            name: if single {
                stream_entry_name(&opts.name, &["ihex", "hex"], &[])
            } else {
                i.to_string()
            },
            size: Some(b.len() as u64),
            comment: Some(format!("Virtual Address = {addr:#x}")),
            ..Default::default()
        })
        .collect();
    let units = (0..blocks.len())
        .map(|i| Unit {
            entries: vec![i],
            encrypted: false,
        })
        .collect();
    Ok(Box::new(IHex {
        entries,
        units,
        blocks: blocks.into_iter().map(|(_, b)| b).collect(),
        size: raw.len() as u64,
    }))
}

impl Archive for IHex {
    fn format(&self) -> &'static Format {
        &IHEX
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn units(&self) -> &[Unit] {
        &self.units
    }
    fn extract_unit(&self, unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let mut r: &[u8] = &self.blocks[unit];
        f(unit, &mut r)?;
        Ok(())
    }
    fn properties(&self) -> Vec<(&'static str, String)> {
        vec![("Physical Size", self.size.to_string())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_with_pem_and_whitespace() {
        let t = b"-----BEGIN X-----\naGVs\r\nbG8=\n-----END X-----\n";
        assert_eq!(decode_base64(t).unwrap(), b"hello");
    }

    #[test]
    fn split_names() {
        assert_eq!(split_base("a.7z.001"), Some(("a.7z", 3)));
        assert_eq!(split_base("a.7z.002"), None);
        assert_eq!(split_base("a.zip"), None);
    }
}
