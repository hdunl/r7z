//! Walks LZMA2 chunk headers without decoding, to find how many independently decodable
//! blocks (dictionary resets) a stream has. Parallel decoding is only worth it with 2+.

/// Counts dictionary-reset blocks, stopping once `stop_at` is reached.
/// Returns `None` if the chunk structure is malformed (the decoder will report the error).
pub fn count_blocks(data: &[u8], stop_at: usize) -> Option<usize> {
    let mut pos = 0usize;
    let mut blocks = 0usize;
    loop {
        let c = *data.get(pos)?;
        pos += 1;
        match c {
            0x00 => return Some(blocks),
            0x01 | 0x02 => {
                if c == 0x01 {
                    blocks += 1;
                }
                let size = u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize + 1;
                pos += 2 + size;
            }
            0x80..=0xFF => {
                let mode = (c >> 5) & 3;
                if mode == 3 {
                    blocks += 1;
                }
                let packed =
                    u16::from_be_bytes([*data.get(pos + 2)?, *data.get(pos + 3)?]) as usize + 1;
                pos += 4 + if mode >= 2 { 1 } else { 0 } + packed;
            }
            _ => return None,
        }
        if blocks >= stop_at {
            return Some(blocks);
        }
    }
}

/// Dictionary resets after the first chunk, as (packed offset, unpacked offset) pairs: the
/// points where decoding can start over without the data before them. The walk stops at a
/// malformed chunk header, since later offsets cannot be known past it.
pub fn restart_points(data: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut unpacked = 0u64;
    while let Some(&c) = data.get(pos) {
        let (head, packed, size) = match c {
            0x00 => break,
            0x01 | 0x02 => {
                let Some(b) = data.get(pos + 1..pos + 3) else {
                    break;
                };
                let n = u16::from_be_bytes([b[0], b[1]]) as usize + 1;
                (3, n, n as u64)
            }
            0x80..=0xFF => {
                let Some(b) = data.get(pos + 1..pos + 5) else {
                    break;
                };
                let size =
                    (((c & 0x1F) as u64) << 16) + u16::from_be_bytes([b[0], b[1]]) as u64 + 1;
                let packed = u16::from_be_bytes([b[2], b[3]]) as usize + 1;
                (if (c >> 5) & 3 >= 2 { 6 } else { 5 }, packed, size)
            }
            _ => break,
        };
        if pos > 0 && (c == 0x01 || c >= 0xE0) {
            out.push((pos as u64, unpacked));
        }
        pos += head + packed;
        unpacked += size;
    }
    out
}

/// Length of the LZMA2 stream at the start of `data`, through its end marker; `None` when
/// the chunk chain is malformed or runs past the end of `data`.
pub fn stream_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    loop {
        let c = *data.get(pos)?;
        pos += match c {
            0x00 => return Some(pos + 1),
            0x01 | 0x02 => {
                3 + u16::from_be_bytes([*data.get(pos + 1)?, *data.get(pos + 2)?]) as usize + 1
            }
            0x80..=0xFF => {
                let packed =
                    u16::from_be_bytes([*data.get(pos + 3)?, *data.get(pos + 4)?]) as usize + 1;
                (if (c >> 5) & 3 >= 2 { 6 } else { 5 }) + packed
            }
            _ => return None,
        };
        if pos > data.len() {
            return None;
        }
    }
}
