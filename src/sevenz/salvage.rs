//! Finding a 7z header when the normal route to it is broken: the signature header is
//! damaged or zeroed (an interrupted write leaves it so), its CRCs no longer match, or the
//! start header points nowhere useful.

use super::read::{parse, parse_header_block};
use super::{id, Archive, SIGNATURE, SIGNATURE_HEADER_SIZE};
use crate::error::{Error, Result};

/// Decoded headers larger than this are not believed while scanning.
const SCAN_HEADER_LIMIT: u64 = 256 << 20;

/// Parses `data` as well as damage allows. Returns the metadata plus notes on what was
/// worked around; fails when no usable header exists.
pub fn parse_damaged(data: &[u8], password: Option<&str>) -> Result<(Archive, Vec<String>)> {
    let first = match parse(data, password) {
        Ok(a) => return Ok((a, Vec::new())),
        Err(e @ (Error::PasswordRequired | Error::WrongPassword | Error::Unsupported(_))) => {
            return Err(e)
        }
        Err(e) => e,
    };
    let why = match &first {
        Error::Corrupt(m) => m.clone(),
        Error::NotArchive => "the signature is damaged".into(),
        e => e.to_string(),
    };
    // The start header's pointer, believed without its CRC.
    if data.len() as u64 >= SIGNATURE_HEADER_SIZE {
        let off = u64::from_le_bytes(data[12..20].try_into().unwrap());
        let size = u64::from_le_bytes(data[20..28].try_into().unwrap());
        let start = SIGNATURE_HEADER_SIZE.saturating_add(off);
        let end = start.saturating_add(size);
        if size > 0 && end <= data.len() as u64 {
            let raw = &data[start as usize..end as usize];
            if let Ok(a) = parse_header_block(data, raw, password, end, SCAN_HEADER_LIMIT) {
                return Ok((
                    a,
                    vec![format!("{why}; the header was read without that check")],
                ));
            }
        }
    }
    match scan(data, password) {
        Some(Ok((a, at))) => Ok((
            a,
            vec![format!(
                "{why}; found the archive header by scanning, at offset {at}"
            )],
        )),
        Some(Err(e)) => Err(e),
        None => Err(Error::corrupt(format!(
            "{why}, and no archive header was found anywhere in the file"
        ))),
    }
}

/// Looks for a header block from the end of the file backwards. A candidate counts only if
/// it parses and every pack stream it describes lies before it.
fn scan(data: &[u8], password: Option<&str>) -> Option<Result<(Archive, usize)>> {
    let lo = SIGNATURE_HEADER_SIZE as usize;
    if data.len() < lo + 2 {
        return None;
    }
    let mut wrong_password = None;
    for p in (lo..data.len() - 1).rev() {
        let (a, b) = (data[p] as u64, data[p + 1] as u64);
        let candidate = (a == id::ENCODED_HEADER && b == id::PACK_INFO)
            || (a == id::HEADER
                && matches!(
                    b,
                    id::MAIN_STREAMS_INFO | id::FILES_INFO | id::ARCHIVE_PROPERTIES
                ));
        if !candidate {
            continue;
        }
        match parse_header_block(
            data,
            &data[p..],
            password,
            p as u64,
            SCAN_HEADER_LIMIT.min(data.len() as u64 * 64 + (1 << 20)),
        ) {
            Ok(arc) if arc.physical_size <= p as u64 && !arc.entries.is_empty() => {
                let mut arc = arc;
                arc.physical_size = data.len() as u64;
                return Some(Ok((arc, p)));
            }
            Err(e @ (Error::PasswordRequired | Error::WrongPassword)) => {
                wrong_password.get_or_insert(e);
            }
            _ => {}
        }
    }
    wrong_password.map(Err)
}

/// Whether `data` still starts with the 7z signature.
pub fn has_signature(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6] == SIGNATURE
}
