//! RAR 1.5-4.x block headers. Every block starts with a 7-byte common header (CRC16, type,
//! flags, size) and carries its data area after the header when it has one. With header
//! encryption (main-header flag 0x80) each block after the main header is an 8-byte salt
//! followed by AES-128-CBC ciphertext of the header.

use crc32fast::Hasher;

use super::crypt::{rar3_key, Cbc};
use super::{Crypt, Member, Scan};
use crate::error::{Error, Result};
use crate::format::data::Slice;
use crate::util::time::dos_datetime_to_filetime;

pub const MARK: &[u8] = b"Rar!\x1A\x07\x00";

/// Whether the first volume is part of a multi-volume set (from the main header).
pub fn peek_volume(d: &[u8]) -> bool {
    if d.len() < 13 || d[9] != MAIN {
        return false;
    }
    u16::from_le_bytes([d[10], d[11]]) & MHD_VOLUME != 0
}

const MAIN: u8 = 0x73;
const OLD_AV: u8 = 0x76;
const OLD_SERVICE: u8 = 0x77;
const OLD_SIGN: u8 = 0x79;
const FILE: u8 = 0x74;
const END: u8 = 0x7B;
const NEW_SUB: u8 = 0x7A;

const MHD_VOLUME: u16 = 0x01;
const MHD_COMMENT: u16 = 0x02;
const MHD_ENCRYPT_VER: u16 = 0x200;
const MHD_PASSWORD: u16 = 0x80;
const MHD_SOLID: u16 = 0x08;
const MHD_FIRST_VOLUME: u16 = 0x100;
const LONG_BLOCK: u16 = 0x8000;
const LHD_SPLIT_BEFORE: u16 = 0x01;
const LHD_SPLIT_AFTER: u16 = 0x02;
const LHD_PASSWORD: u16 = 0x04;
const LHD_COMMENT: u16 = 0x08;
const LHD_LARGE: u16 = 0x100;
const LHD_UNICODE: u16 = 0x200;
const LHD_SALT: u16 = 0x400;
const LHD_SOLID: u16 = 0x10;
const END_NEXT_VOLUME: u16 = 0x01;

/// One block: its raw header bytes and where its data area lies in the volume.
struct Block {
    kind: u8,
    flags: u16,
    head: Vec<u8>,
    data: std::ops::Range<usize>,
}

fn u16_at(b: &[u8], p: usize) -> Result<u16> {
    b.get(p..p + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(truncated)
}

fn u32_at(b: &[u8], p: usize) -> Result<u32> {
    b.get(p..p + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(truncated)
}

fn truncated() -> Error {
    Error::corrupt("RAR header is truncated")
}

/// The RAR 4 header checksum: the low 16 bits of CRC32 over everything after the CRC.
fn header_crc(head: &[u8]) -> u16 {
    let mut h = Hasher::new();
    h.update(&head[2..]);
    h.finalize() as u16
}

/// Reads the block at `pos`. `keys` holds the password-derived cipher for encrypted
/// headers, one per salt; `password` derives it when a new salt appears.
fn read_block(
    d: &[u8],
    pos: usize,
    encrypted: bool,
    password: Option<&str>,
    cache: &mut Option<([u8; 8], [u8; 16], [u8; 16])>,
) -> Result<(Block, usize)> {
    let (head, after) = if encrypted {
        let salt: [u8; 8] = d
            .get(pos..pos + 8)
            .ok_or_else(truncated)?
            .try_into()
            .unwrap();
        let pw = password.ok_or(Error::PasswordRequired)?;
        let (key, iv) = match *cache {
            Some((s, k, v)) if s == salt => (k, v),
            _ => {
                let (k, v) = rar3_key(pw, &salt);
                *cache = Some((salt, k, v));
                (k, v)
            }
        };
        let start = pos + 8;
        let first = d.get(start..start + 16).ok_or_else(truncated)?;
        let mut buf = [0u8; 16];
        buf.copy_from_slice(first);
        Cbc::aes128(&key, iv).decrypt(&mut buf);
        let size = u16::from_le_bytes([buf[5], buf[6]]) as usize;
        if size < 7 {
            return Err(Error::WrongPassword);
        }
        let total = size.div_ceil(16) * 16;
        let body = d.get(start..start + total).ok_or_else(truncated)?;
        let mut plain = body.to_vec();
        Cbc::aes128(&key, iv).decrypt(&mut plain);
        plain.truncate(size);
        (plain, start + total)
    } else {
        let size_at = pos + 5;
        let size = u16_at(d, size_at)? as usize;
        if size < 7 {
            return Err(Error::corrupt("RAR header size"));
        }
        let head = d.get(pos..pos + size).ok_or_else(truncated)?.to_vec();
        (head, pos + size)
    };
    if head.len() < 7 {
        return Err(Error::corrupt("RAR header size"));
    }
    let stored = u16::from_le_bytes([head[0], head[1]]);
    let flags = u16::from_le_bytes([head[3], head[4]]);
    let covered: &[u8] = match head[2] {
        // RAR 1.5 and 2.0 keep comments inside main and file headers; the CRC stops
        // before them: after the fixed main fields, or after the file name.
        MAIN if flags & MHD_COMMENT != 0 => {
            let fixed = if flags & MHD_ENCRYPT_VER != 0 { 14 } else { 13 };
            &head[..fixed.min(head.len())]
        }
        FILE if flags & LHD_COMMENT != 0 && !encrypted => {
            let name_at = if flags & LHD_LARGE != 0 { 40 } else { 32 };
            let name_len = usize::from(u16_at(&head, 26)?);
            &head[..(name_at + name_len).min(head.len())]
        }
        // An old service block's CRC also covers the data after its header.
        OLD_SERVICE if !encrypted => {
            let data = if flags & LONG_BLOCK != 0 {
                u32_at(&head, 7)? as usize
            } else {
                0
            };
            d.get(pos..pos + head.len() + data).ok_or_else(truncated)?
        }
        _ => &head[..],
    };
    // Old authenticity-verification and signature blocks never had a valid CRC. They carry
    // no data, unlike file headers, so a damaged file header cannot pass for one.
    let unchecked = matches!(head[2], OLD_AV | OLD_SIGN) && flags & LONG_BLOCK == 0;
    if !unchecked && stored != header_crc(covered) {
        return Err(if encrypted {
            Error::WrongPassword
        } else {
            Error::corrupt("RAR header CRC mismatch")
        });
    }
    let kind = head[2];
    let flags = u16::from_le_bytes([head[3], head[4]]);
    // Data area: a file's packed size, or ADD_SIZE for blocks with the long-block flag.
    let data_len = match kind {
        FILE | NEW_SUB => {
            let mut n = u64::from(u32_at(&head, 7)?);
            if flags & LHD_LARGE != 0 {
                n |= u64::from(u32_at(&head, 32)?) << 32;
            }
            n
        }
        _ if flags & LONG_BLOCK != 0 => u64::from(u32_at(&head, 7)?),
        _ => 0,
    };
    let data_start = after;
    let data_end = data_start
        .checked_add(usize::try_from(data_len).map_err(|_| truncated())?)
        .ok_or_else(truncated)?;
    if data_end > d.len() {
        return Err(Error::corrupt(
            "RAR data area runs past the end of the volume",
        ));
    }
    Ok((
        Block {
            kind,
            flags,
            head,
            data: data_start..data_end,
        },
        data_end,
    ))
}

/// Parses a file header's fields into a member (possibly one part of a split file).
fn file_member(b: &Block) -> Result<FileRec> {
    let h = &b.head;
    let unp = u64::from(u32_at(h, 11)?);
    let host = *h.get(15).ok_or_else(truncated)?;
    let crc = u32_at(h, 16)?;
    let ftime = u32_at(h, 20)?;
    let ver = *h.get(24).ok_or_else(truncated)?;
    let method = *h.get(25).ok_or_else(truncated)?;
    let name_len = u16_at(h, 26)? as usize;
    let attr = u32_at(h, 28)?;
    let flags = b.flags;
    let (unp, name_at) = if flags & LHD_LARGE != 0 {
        (unp | (u64::from(u32_at(h, 36)?) << 32), 40)
    } else {
        (unp, 32)
    };
    let raw_name = h.get(name_at..name_at + name_len).ok_or_else(truncated)?;
    let name = decode_name(raw_name, flags & LHD_UNICODE != 0);
    let after_name = name_at + name_len;
    let salt = if flags & LHD_SALT != 0 {
        let s: [u8; 8] = h
            .get(after_name..after_name + 8)
            .ok_or_else(truncated)?
            .try_into()
            .unwrap();
        Some(s)
    } else {
        None
    };
    let encrypted = flags & LHD_PASSWORD != 0;
    let is_dir = flags & 0xE0 == 0xE0;
    let attrib = if host == 3 {
        Some((attr << 16) | 0x8000)
    } else {
        Some(attr)
    };
    let name = name.replace('\\', "/");
    Ok(FileRec {
        split_before: flags & LHD_SPLIT_BEFORE != 0,
        split_after: flags & LHD_SPLIT_AFTER != 0,
        member: Member {
            name,
            is_dir,
            size: unp,
            packed: Vec::new(),
            mtime: dos_datetime_to_filetime(ftime),
            attrib,
            crc: Some(crc),
            blake2: None,
            method: method.saturating_sub(0x30),
            version: ver,
            solid: flags & LHD_SOLID != 0,
            dict: 0x1_0000u64 << ((flags >> 5) & 7),
            crypt: match (encrypted, salt) {
                (true, Some(s)) => Some(Crypt::Rar3 { salt: s }),
                (true, None) => Some(Crypt::Legacy),
                (false, _) => None,
            },
            incomplete: false,
        },
    })
}

/// A file header's member, plus whether its data continues in another part.
pub struct FileRec {
    pub member: Member,
    pub split_before: bool,
    pub split_after: bool,
}

/// Decodes a RAR 4 file name. With the Unicode flag the name is an ASCII part, a zero
/// byte, and a compressed UTF-16 form of the name against that ASCII part.
fn decode_name(raw: &[u8], unicode: bool) -> String {
    if !unicode {
        return String::from_utf8_lossy(raw).into_owned();
    }
    let Some(zero) = raw.iter().position(|&b| b == 0) else {
        return String::from_utf8_lossy(raw).into_owned();
    };
    let ascii = &raw[..zero];
    let enc = &raw[zero + 1..];
    let mut out: Vec<u16> = Vec::new();
    if let Some((&high, rest)) = enc.split_first() {
        let mut pos = 0;
        let mut flags = 0u8;
        let mut bits = 0;
        while pos < rest.len() {
            if bits == 0 {
                flags = rest[pos];
                pos += 1;
                bits = 8;
            }
            match flags >> 6 {
                0 => {
                    let Some(&b) = rest.get(pos) else { break };
                    out.push(u16::from(b));
                    pos += 1;
                }
                1 => {
                    let Some(&b) = rest.get(pos) else { break };
                    out.push(u16::from(b) | (u16::from(high) << 8));
                    pos += 1;
                }
                2 => {
                    let (Some(&lo), Some(&hi)) = (rest.get(pos), rest.get(pos + 1)) else {
                        break;
                    };
                    out.push(u16::from(lo) | (u16::from(hi) << 8));
                    pos += 2;
                }
                _ => {
                    let Some(&len) = rest.get(pos) else { break };
                    pos += 1;
                    if len & 0x80 != 0 {
                        let Some(&corr) = rest.get(pos) else { break };
                        pos += 1;
                        for _ in 0..(len & 0x7F) + 2 {
                            let Some(&a) = ascii.get(out.len()) else {
                                break;
                            };
                            out.push(u16::from(a.wrapping_add(corr)) | (u16::from(high) << 8));
                        }
                    } else {
                        for _ in 0..len + 2 {
                            let Some(&a) = ascii.get(out.len()) else {
                                break;
                            };
                            out.push(u16::from(a));
                        }
                    }
                }
            }
            flags <<= 2;
            bits -= 2;
        }
        return String::from_utf16_lossy(&out);
    }
    String::from_utf8_lossy(ascii).into_owned()
}

/// Scans the headers of every volume in order.
pub fn scan(volumes: &[Slice], password: Option<&str>) -> Result<Scan> {
    let mut members: Vec<Member> = Vec::new();
    let mut info = Scan::default();
    let mut key_cache: Option<([u8; 8], [u8; 16], [u8; 16])> = None;
    let mut continuing = false;
    for (vi, vol) in volumes.iter().enumerate() {
        let d: &[u8] = vol;
        if !d.starts_with(MARK) {
            return Err(Error::corrupt(format!(
                "RAR volume {} has no signature",
                vi + 1
            )));
        }
        let mut pos = MARK.len();
        let mut encrypted_headers = false;
        let mut more = false;
        let mut saw_end = false;
        loop {
            if pos >= d.len() {
                break;
            }
            let (b, next) = read_block(d, pos, encrypted_headers, password, &mut key_cache)?;
            match b.kind {
                MAIN => {
                    info.volume = b.flags & MHD_VOLUME != 0;
                    info.first_volume = b.flags & MHD_FIRST_VOLUME != 0;
                    info.solid = b.flags & MHD_SOLID != 0;
                    encrypted_headers = b.flags & MHD_PASSWORD != 0;
                    if encrypted_headers && password.is_none() {
                        return Err(Error::PasswordRequired);
                    }
                }
                FILE => {
                    let rec = file_member(&b)?;
                    let part = d_slice(volumes, vi, &b.data)?;
                    match members.last_mut() {
                        Some(last) if rec.split_before && continuing => {
                            // The final part's CRC covers the whole file.
                            last.packed.push(part);
                            last.crc = rec.member.crc;
                            last.incomplete = rec.split_after;
                        }
                        _ => {
                            let mut m = rec.member;
                            m.packed.push(part);
                            m.incomplete = rec.split_after;
                            members.push(m);
                        }
                    }
                    continuing = rec.split_after;
                }
                END => {
                    saw_end = true;
                    more = b.flags & END_NEXT_VOLUME != 0;
                    pos = next;
                    break;
                }
                _ => {}
            }
            pos = next;
        }
        if !saw_end {
            // RAR 2.x volumes have no end block: a file split into the next volume is
            // what says there is one.
            more = info.volume && continuing;
        }
        if !more && vi + 1 < volumes.len() {
            return Err(Error::corrupt("RAR volume chain ended early"));
        }
        if more && vi + 1 == volumes.len() {
            info.missing_volume = true;
        }
    }
    info.members = members;
    Ok(info)
}

/// A slice of volume `vi` for a block's data area.
fn d_slice(volumes: &[Slice], vi: usize, r: &std::ops::Range<usize>) -> Result<Slice> {
    let v = &volumes[vi];
    v.sub(r.start as u64..r.end as u64)
}
