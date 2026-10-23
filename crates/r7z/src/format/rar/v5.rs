//! RAR 5 block headers. After the 8-byte signature every block is a CRC32, a vint header
//! size and the header (type, flags, optional extra and data area sizes, type fields, and
//! the extra area at its end), followed by its data area. With header encryption (an
//! archive encryption block right after the signature) each later header is a 16-byte IV
//! followed by its AES-256-CBC ciphertext, padded to whole cipher blocks.
//!
//! A file's packed data is its own stream: it may be split across volumes at any byte, and
//! when encrypted it is one CBC stream over all its parts.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::ops::Range;

use sha2::{Digest, Sha256};

use super::crypt::{self, Cbc, Rar5Keys};
use super::{drain, Checked, Crypt, Member, Scan};
use crate::codec::rar5::Lz5;
use crate::error::{Error, Result};
use crate::format::data::Slice;
use crate::format::{Ctx, EntryFn, Flow};
use crate::util::time::unix_to_filetime;

pub const MARK: &[u8] = b"Rar!\x1A\x07\x01\x00";

const HEAD_MAIN: u64 = 1;
const HEAD_FILE: u64 = 2;
const HEAD_CRYPT: u64 = 4;
const HEAD_END: u64 = 5;

const HFL_EXTRA: u64 = 0x01;
const HFL_DATA: u64 = 0x02;
const HFL_SPLIT_BEFORE: u64 = 0x08;
const HFL_SPLIT_AFTER: u64 = 0x10;

const MHFL_VOLUME: u64 = 0x01;
const MHFL_VOLNUMBER: u64 = 0x02;
const MHFL_SOLID: u64 = 0x04;

const FHFL_DIRECTORY: u64 = 0x01;
const FHFL_UTIME: u64 = 0x02;
const FHFL_CRC32: u64 = 0x04;

const EHFL_NEXTVOLUME: u64 = 0x01;

const FHEXTRA_CRYPT: u64 = 0x01;
const FHEXTRA_HASH: u64 = 0x02;
const FHEXTRA_HTIME: u64 = 0x03;

const CHFL_PSWCHECK: u64 = 0x01;
const CHFL_HASHMAC: u64 = 0x02;

const HOST_UNIX: u64 = 1;

/// Headers larger than this are treated as damage.
const MAX_HEADER: u64 = 0x20_0000;

/// Smallest window when a unit does not fit its dictionary: room for the longest filter
/// block while its start is held back.
const MIN_WINDOW: u64 = 1 << 23;

fn truncated() -> Error {
    Error::corrupt("RAR 5 header is truncated")
}

/// Reads the little-endian fields of a header.
struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, p: 0 }
    }

    fn left(&self) -> usize {
        self.b.len() - self.p
    }

    /// A vint: 7 bits per byte, low groups first, high bit set on all but the last byte.
    fn vint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let c = *self.b.get(self.p).ok_or_else(truncated)?;
            self.p += 1;
            let bits = u64::from(c & 0x7F);
            if i == 9 && bits > 1 {
                return Err(Error::corrupt("RAR 5 number out of range"));
            }
            v |= bits << (7 * i);
            if c & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::corrupt("RAR 5 number out of range"))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .b
            .get(self.p..self.p.checked_add(n).ok_or_else(truncated)?);
        let s = s.ok_or_else(truncated)?;
        self.p += n;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().unwrap())
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

/// One block: its header bytes (from the type field on) and where its data area lies.
struct Block {
    kind: u64,
    flags: u64,
    head: Vec<u8>,
    /// Type-specific fields, and the extra area, as ranges of `head`.
    body: Range<usize>,
    extra: Range<usize>,
    data: Range<usize>,
}

/// Reads the block at `pos`, decrypting its header with `key` when headers are encrypted.
fn read_block(d: &[u8], pos: usize, key: Option<&[u8; 32]>) -> Result<(Block, usize)> {
    let (raw, after) = match key {
        None => {
            let mut r = Rd::new(d.get(pos..).ok_or_else(truncated)?);
            r.u32()?;
            let size = r.vint()?;
            if size == 0 || size > MAX_HEADER {
                return Err(Error::corrupt("RAR 5 header size"));
            }
            let total = r.p + size as usize;
            let raw = d.get(pos..pos + total).ok_or_else(truncated)?.to_vec();
            (raw, pos + total)
        }
        Some(key) => {
            let iv: [u8; 16] = d
                .get(pos..pos + 16)
                .ok_or_else(truncated)?
                .try_into()
                .unwrap();
            let start = pos + 16;
            let mut first = [0u8; 16];
            first.copy_from_slice(d.get(start..start + 16).ok_or_else(truncated)?);
            Cbc::aes256(key, iv).decrypt(&mut first);
            // A wrong key shows as a nonsensical size here, or as a CRC mismatch below.
            let mut r = Rd::new(&first);
            r.u32()?;
            let size = r.vint().map_err(|_| Error::WrongPassword)?;
            if size == 0 || size > MAX_HEADER {
                return Err(Error::WrongPassword);
            }
            let total = r.p + size as usize;
            let padded = total.div_ceil(16) * 16;
            let mut raw = d.get(start..start + padded).ok_or_else(truncated)?.to_vec();
            Cbc::aes256(key, iv).decrypt(&mut raw);
            raw.truncate(total);
            (raw, start + padded)
        }
    };
    let stored = u32::from_le_bytes(raw[..4].try_into().unwrap());
    if crc32fast::hash(&raw[4..]) != stored {
        return Err(if key.is_some() {
            Error::WrongPassword
        } else {
            Error::corrupt("RAR 5 header CRC mismatch")
        });
    }
    // Skip the CRC and the size field.
    let mut r = Rd::new(&raw[4..]);
    r.vint()?;
    let head = raw[4 + r.p..].to_vec();
    let mut r = Rd::new(&head);
    let kind = r.vint()?;
    let flags = r.vint()?;
    let extra_len = if flags & HFL_EXTRA != 0 { r.vint()? } else { 0 };
    let data_len = if flags & HFL_DATA != 0 { r.vint()? } else { 0 };
    let extra_len = usize::try_from(extra_len)
        .ok()
        .filter(|&n| n <= r.left())
        .ok_or_else(|| Error::corrupt("RAR 5 extra area size"))?;
    let body = r.p..head.len() - extra_len;
    let extra = head.len() - extra_len..head.len();
    let data_end = usize::try_from(data_len)
        .ok()
        .and_then(|n| after.checked_add(n))
        .filter(|&e| e <= d.len())
        .ok_or_else(|| Error::corrupt("RAR 5 data area runs past the end of the volume"))?;
    Ok((
        Block {
            kind,
            flags,
            head,
            body,
            extra,
            data: after..data_end,
        },
        data_end,
    ))
}

/// Whether the first volume is part of a multi-volume set. With encrypted headers the
/// main header cannot be read yet, so the set is assumed to be one; the scan then uses
/// the other volumes only if the main header says so.
pub fn peek_volume(d: &[u8]) -> Result<bool> {
    if !d.starts_with(MARK) {
        return Err(Error::corrupt("RAR 5 signature"));
    }
    let (b, _) = read_block(d, MARK.len(), None)?;
    match b.kind {
        HEAD_CRYPT => Ok(true),
        HEAD_MAIN => Ok(Rd::new(&b.head[b.body.clone()]).vint()? & MHFL_VOLUME != 0),
        _ => Err(Error::corrupt("RAR 5 archive without a main header")),
    }
}

/// Keys derived for a password, one per salt and round count.
#[derive(Default)]
struct Keys {
    done: Vec<([u8; 16], u8, Rar5Keys)>,
}

impl Keys {
    fn get(&mut self, password: &str, salt: &[u8; 16], lg2: u8) -> Result<&Rar5Keys> {
        let i = match self
            .done
            .iter()
            .position(|(s, l, _)| s == salt && *l == lg2)
        {
            Some(i) => i,
            None => {
                self.done
                    .push((*salt, lg2, crypt::rar5_keys(password, salt, lg2)?));
                self.done.len() - 1
            }
        };
        Ok(&self.done[i].2)
    }
}

/// The password check of a crypt record: 8 bytes, kept only when the 4-byte SHA-256
/// checksum after them matches.
fn password_check(r: &mut Rd) -> Result<Option<[u8; 8]>> {
    let check: [u8; 8] = r.array()?;
    let sum: [u8; 4] = r.array()?;
    Ok((Sha256::digest(check)[..4] == sum).then_some(check))
}

/// A file header's member, plus whether its data continues in another part.
struct FileRec {
    member: Member,
    split_before: bool,
    split_after: bool,
}

fn file_member(b: &Block) -> Result<FileRec> {
    let mut r = Rd::new(&b.head[b.body.clone()]);
    let fflags = r.vint()?;
    let size = r.vint()?;
    let attr = r.vint()?;
    let mut mtime = if fflags & FHFL_UTIME != 0 {
        Some(unix_to_filetime(i64::from(r.u32()?)))
    } else {
        None
    };
    let crc = if fflags & FHFL_CRC32 != 0 {
        Some(r.u32()?)
    } else {
        None
    };
    let info = r.vint()?;
    let host = r.vint()?;
    let name_len = usize::try_from(r.vint()?).map_err(|_| truncated())?;
    let name = String::from_utf8_lossy(r.bytes(name_len)?).into_owned();
    // `/` separates names on every host; a backslash is part of a Unix name.
    let name = if host == HOST_UNIX {
        name
    } else {
        name.replace('\\', "/")
    };
    let mut blake2 = None;
    let mut crypt = None;
    let mut ex = Rd::new(&b.head[b.extra.clone()]);
    while ex.left() > 0 {
        let len = usize::try_from(ex.vint()?).map_err(|_| truncated())?;
        let mut rec = Rd::new(ex.bytes(len)?);
        match rec.vint()? {
            FHEXTRA_CRYPT => {
                let version = rec.vint()?;
                if version != 0 {
                    return Err(Error::unsupported(format!(
                        "RAR 5 encryption version {version}"
                    )));
                }
                let flags = rec.vint()?;
                let lg2 = rec.array::<1>()?[0];
                let salt = rec.array()?;
                let iv = rec.array()?;
                let check = if flags & CHFL_PSWCHECK != 0 {
                    password_check(&mut rec)?
                } else {
                    None
                };
                crypt = Some(Crypt::Rar5 {
                    salt,
                    iv,
                    lg2,
                    check,
                    mac: flags & CHFL_HASHMAC != 0,
                });
            }
            FHEXTRA_HASH => {
                if rec.vint()? == 0 {
                    blake2 = Some(rec.array()?);
                }
            }
            FHEXTRA_HTIME => {
                let flags = rec.vint()?;
                let unix = flags & 0x01 != 0;
                // Modification, creation and access times, in that order when present.
                let mut times = [None; 3];
                for (k, t) in times.iter_mut().enumerate() {
                    if flags & (0x02 << k) != 0 {
                        *t = Some(if unix {
                            unix_to_filetime(i64::from(rec.u32()?))
                        } else {
                            rec.u64()?
                        });
                    }
                }
                if unix && flags & 0x10 != 0 {
                    for t in times.iter_mut().flatten() {
                        *t += u64::from(rec.u32()? & 0x3FFF_FFFF) / 100;
                    }
                }
                if times[0].is_some() {
                    mtime = times[0];
                }
            }
            // Version, link, owner and other records do not change the data.
            _ => {}
        }
    }
    let is_dir = fflags & FHFL_DIRECTORY != 0;
    let attr = attr as u32;
    let attrib = if host == HOST_UNIX {
        (attr << 16) | 0x8000
    } else {
        attr
    };
    Ok(FileRec {
        split_before: b.flags & HFL_SPLIT_BEFORE != 0,
        split_after: b.flags & HFL_SPLIT_AFTER != 0,
        member: Member {
            name,
            is_dir,
            size,
            packed: Vec::new(),
            mtime,
            attrib: Some(attrib),
            crc,
            blake2,
            method: ((info >> 7) & 7) as u8,
            version: (info & 0x3F) as u8,
            solid: info & 0x40 != 0,
            dict: 0x2_0000u64 << ((info >> 10) & 0x1F),
            crypt,
            incomplete: false,
        },
    })
}

/// Scans the headers of every volume in order.
pub fn scan(volumes: &[Slice], password: Option<&str>) -> Result<Scan> {
    let mut members: Vec<Member> = Vec::new();
    let mut info = Scan::default();
    let mut keys = Keys::default();
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
        let mut header_key: Option<[u8; 32]> = None;
        let mut more = false;
        while pos < d.len() {
            let (b, next) = read_block(d, pos, header_key.as_ref())?;
            let mut r = Rd::new(&b.head[b.body.clone()]);
            match b.kind {
                HEAD_CRYPT => {
                    if r.vint()? != 0 {
                        return Err(Error::unsupported("RAR 5 header encryption version"));
                    }
                    let flags = r.vint()?;
                    let lg2 = r.array::<1>()?[0];
                    let salt: [u8; 16] = r.array()?;
                    let check = if flags & CHFL_PSWCHECK != 0 {
                        password_check(&mut r)?
                    } else {
                        None
                    };
                    let pw = password.ok_or(Error::PasswordRequired)?;
                    let k = keys.get(pw, &salt, lg2)?;
                    if check.is_some_and(|c| c != k.check) {
                        return Err(Error::WrongPassword);
                    }
                    header_key = Some(k.key);
                }
                HEAD_MAIN => {
                    let flags = r.vint()?;
                    let number = if flags & MHFL_VOLNUMBER != 0 {
                        r.vint()?
                    } else {
                        0
                    };
                    if vi == 0 {
                        info.volume = flags & MHFL_VOLUME != 0;
                        info.first_volume = number == 0;
                        info.solid = flags & MHFL_SOLID != 0;
                    }
                }
                HEAD_FILE => {
                    let rec = file_member(&b)?;
                    let part = vol.sub(b.data.start as u64..b.data.end as u64)?;
                    match members.last_mut() {
                        Some(last) if rec.split_before && continuing => {
                            // The last part's checksums cover the whole file.
                            last.packed.push(part);
                            last.crc = rec.member.crc;
                            last.blake2 = rec.member.blake2;
                            if let (
                                Some(Crypt::Rar5 { mac, .. }),
                                Some(Crypt::Rar5 { mac: part_mac, .. }),
                            ) = (last.crypt.as_mut(), rec.member.crypt.as_ref())
                            {
                                *mac = *part_mac;
                            }
                            last.incomplete = rec.split_after;
                        }
                        _ => {
                            let mut m = rec.member;
                            m.packed.push(part);
                            // A continuation without its start cannot be decoded.
                            m.incomplete = rec.split_after || rec.split_before;
                            members.push(m);
                        }
                    }
                    continuing = rec.split_after;
                }
                HEAD_END => {
                    more = r.vint()? & EHFL_NEXTVOLUME != 0;
                    break;
                }
                // Service headers (quick open, comments, streams) and unknown blocks.
                _ => {}
            }
            pos = next;
        }
        if !info.volume {
            // Not a volume set: other files that look like volumes are not part of it.
            if more {
                info.missing_volume = true;
            }
            break;
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

/// A member's packed data: its parts in order, decrypted as one CBC stream when the
/// member is encrypted (parts may end in the middle of a cipher block).
struct Packed {
    parts: VecDeque<Slice>,
    pos: usize,
    cbc: Option<Cbc>,
    /// Decrypted bytes of a block not yet handed out.
    spare: [u8; 16],
    spare_at: usize,
}

impl Packed {
    fn new(m: &Member, cbc: Option<Cbc>) -> Result<Packed> {
        if cbc.is_some() && m.packed.iter().map(|s| s.len() as u64).sum::<u64>() % 16 != 0 {
            return Err(Error::corrupt("encrypted RAR data is not block aligned"));
        }
        Ok(Packed {
            parts: m.packed.iter().cloned().collect(),
            pos: 0,
            cbc,
            spare: [0; 16],
            spare_at: 16,
        })
    }

    /// Copies raw bytes into `out` until it is full or the parts are used up.
    fn raw(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            let Some(part) = self.parts.front() else {
                break;
            };
            let k = (part.len() - self.pos).min(out.len() - n);
            out[n..n + k].copy_from_slice(&part[self.pos..self.pos + k]);
            n += k;
            self.pos += k;
            if self.pos == part.len() {
                self.parts.pop_front();
                self.pos = 0;
            }
        }
        n
    }
}

impl Read for Packed {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.cbc.is_none() {
            return Ok(self.raw(out));
        }
        if self.spare_at < 16 {
            let k = (16 - self.spare_at).min(out.len());
            out[..k].copy_from_slice(&self.spare[self.spare_at..self.spare_at + k]);
            self.spare_at += k;
            return Ok(k);
        }
        if out.len() >= 16 {
            let want = out.len() & !15;
            let n = self.raw(&mut out[..want]);
            // The total is a whole number of blocks, so a short read is the end.
            let n = n & !15;
            self.cbc.as_mut().unwrap().decrypt(&mut out[..n]);
            return Ok(n);
        }
        let mut block = [0u8; 16];
        if self.raw(&mut block) < 16 {
            return Ok(0);
        }
        self.cbc.as_mut().unwrap().decrypt(&mut block);
        self.spare = block;
        let k = out.len();
        out.copy_from_slice(&block[..k]);
        self.spare_at = k;
        Ok(k)
    }
}

/// Adapts the LZ decoder to `Read`.
struct Lz5Read<'a>(&'a mut Lz5);

impl Read for Lz5Read<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(Error::into_io)
    }
}

/// Extracts one unit of a RAR 5 archive: `entries` are the archive indexes of `members`.
pub(super) fn extract_unit(
    entries: &[usize],
    members: &[&Member],
    ctx: &Ctx,
    f: &mut EntryFn<'_>,
) -> Result<()> {
    // The window holds the whole unit when it fits within the dictionary; otherwise it is
    // the dictionary, but at least large enough for a held-back filter block.
    let total: u64 = members.iter().map(|m| m.size).sum();
    let dict = members.iter().map(|m| m.dict).max().unwrap_or(0x2_0000);
    let win = if total <= dict {
        (total + 1024).max(1 << 16).next_power_of_two()
    } else {
        dict.max(MIN_WINDOW).next_power_of_two()
    };
    let win = usize::try_from(win)
        .map_err(|_| Error::unsupported("RAR 5 dictionary larger than the address space"))?;
    let mut keys = Keys::default();
    let mut lz: Option<Lz5> = None;
    for (&i, &m) in entries.iter().zip(members) {
        let (cbc, mac) = match &m.crypt {
            None => (None, None),
            Some(Crypt::Rar5 {
                salt,
                iv,
                lg2,
                check,
                mac,
            }) => {
                let pw = ctx.password.as_deref().ok_or(Error::PasswordRequired)?;
                let k = keys.get(pw, salt, *lg2)?;
                if check.is_some_and(|c| c != k.check) {
                    return Err(Error::WrongPassword);
                }
                (Some(Cbc::aes256(&k.key, *iv)), mac.then_some(k.hash_key))
            }
            Some(Crypt::Rar3 { .. }) => {
                return Err(Error::corrupt("RAR 3 encryption in a RAR 5 archive"))
            }
        };
        let mut src = Packed::new(m, cbc)?;
        let flow = if m.method == 0 {
            let mut r = Checked::new(&mut src, m).with_mac(mac);
            let flow = f(i, &mut r)?;
            drain(&mut r)?;
            flow
        } else {
            if m.version != 0 {
                return Err(Error::unsupported(format!(
                    "RAR 5 compression algorithm version {}",
                    m.version
                )));
            }
            let lz = lz.get_or_insert_with(|| Lz5::new(win));
            lz.begin(Box::new(src), m.size)?;
            let mut inner = Lz5Read(lz);
            let mut r = Checked::new(&mut inner, m).with_mac(mac);
            let flow = f(i, &mut r)?;
            drain(&mut r)?;
            flow
        };
        if flow == Flow::Stop {
            break;
        }
    }
    Ok(())
}
