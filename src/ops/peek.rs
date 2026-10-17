//! Reading a single entry: previews, hashing, opening a file or a nested archive.

use crate::error::{Error, Result};
use crate::format::{Archive, Ctx, Flow};

/// The first bytes of an entry, or all of it.
pub struct Peeked {
    pub data: Vec<u8>,
    /// The entry is longer than `data`.
    pub truncated: bool,
}

/// Streams entry `index` to `sink` in blocks and returns its length. A complete read is
/// checked against the entry's CRC when the format does not verify data itself. Entries in
/// solid blocks are reached by decoding the block from its start, so this costs as much as
/// the data before the entry. `sink` may stop early by returning `Error::Cancelled`.
pub fn stream_entry(
    a: &dyn Archive,
    index: usize,
    password: Option<&str>,
    cancelled: &dyn Fn() -> bool,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let entry = a
        .entries()
        .get(index)
        .ok_or_else(|| Error::Other("no such entry".into()))?;
    if entry.is_dir {
        return Ok(0);
    }
    let unit_index = a
        .units()
        .iter()
        .position(|u| u.entries.contains(&index))
        .ok_or_else(|| Error::Other(format!("{} has no data", entry.name)))?;
    let encrypted = a.units()[unit_index].encrypted;
    let ctx = Ctx {
        password: password.map(str::to_string),
        threads: crate::util::default_threads(),
    };
    let mut total: Option<u64> = None;
    let mut crc = crc32fast::Hasher::new();
    let mut stopped_early = false;
    let result = a.extract_unit(unit_index, &ctx, &mut |i, reader| {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if i != index {
            return Ok(Flow::Continue);
        }
        let mut chunk = vec![0u8; 256 << 10];
        let mut n_total = 0u64;
        loop {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            let n = reader.read(&mut chunk).map_err(Error::from_codec)?;
            if n == 0 {
                break;
            }
            crc.update(&chunk[..n]);
            n_total += n as u64;
            match sink(&chunk[..n]) {
                Ok(()) => {}
                Err(Error::Cancelled) => {
                    stopped_early = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        total = Some(n_total);
        Ok(Flow::Stop)
    });
    if let Err(e) = result {
        return Err(
            if encrypted && matches!(e, Error::Corrupt(_) | Error::Checksum(_)) {
                Error::WrongPassword
            } else {
                e
            },
        );
    }
    let total =
        total.ok_or_else(|| Error::Other(format!("{} was not found in its block", entry.name)))?;
    if !stopped_early && !a.verifies_data() {
        if let Some(expected) = entry.crc {
            if crc.finalize() != expected {
                return Err(if encrypted {
                    Error::WrongPassword
                } else {
                    Error::Checksum(entry.name.clone())
                });
            }
        }
    }
    Ok(total)
}

/// Reads up to `limit` bytes of entry `index` into memory.
pub fn read_entry(
    a: &dyn Archive,
    index: usize,
    password: Option<&str>,
    limit: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<Peeked> {
    let expected = a
        .entries()
        .get(index)
        .and_then(|e| e.size)
        .map(|s| s.min(limit as u64) as usize)
        .unwrap_or(0);
    let mut data = Vec::with_capacity(expected.min(64 << 20));
    let mut truncated = false;
    stream_entry(a, index, password, cancelled, &mut |b| {
        let room = limit - data.len();
        if b.len() > room {
            data.extend_from_slice(&b[..room]);
            truncated = true;
            return Err(Error::Cancelled);
        }
        data.extend_from_slice(b);
        Ok(())
    })?;
    Ok(Peeked { data, truncated })
}
