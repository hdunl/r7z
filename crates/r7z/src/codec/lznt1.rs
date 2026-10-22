//! LZNT1, the compression NTFS applies to files and folders with the compressed attribute.
//! The stream is a sequence of 4 KiB chunks, each either stored as it is or holding LZ77
//! tokens. In a token the split between length and distance moves with the position in the
//! chunk, so short distances near the start of a chunk use few bits.

use crate::error::{Error, Result};

/// Uncompressed bytes in one chunk.
pub const CHUNK: usize = 4096;

/// Decompresses `input` and appends at most `limit` bytes to `out`. Decoding stops at the end
/// of the input or at a zero chunk header; a chunk that does not decode is an error.
pub fn decompress(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let mut pos = 0usize;
    while pos + 2 <= input.len() && out.len() < limit {
        let header = u16::from_le_bytes([input[pos], input[pos + 1]]);
        if header == 0 {
            break;
        }
        let size = usize::from(header & 0x0FFF) + 3;
        let start = pos + 2;
        let end = (start + size).min(input.len());
        let chunk = &input[start..end];
        let out_start = out.len();
        if header & 0x8000 == 0 {
            // Stored: the chunk is the 4 KiB of data as it is.
            let n = chunk.len().min(CHUNK).min(limit - out.len());
            out.extend_from_slice(&chunk[..n]);
        } else {
            decode_tokens(chunk, out, out_start, limit)?;
        }
        pos = end;
    }
    Ok(())
}

/// Decodes one compressed chunk: a flag byte, then eight literals or tokens, repeated.
fn decode_tokens(chunk: &[u8], out: &mut Vec<u8>, start: usize, limit: usize) -> Result<()> {
    let mut i = 0usize;
    while i < chunk.len() && out.len() < limit && out.len() - start < CHUNK {
        let flags = chunk[i];
        i += 1;
        for bit in 0..8 {
            if i >= chunk.len() || out.len() >= limit || out.len() - start >= CHUNK {
                break;
            }
            if flags & (1 << bit) == 0 {
                out.push(chunk[i]);
                i += 1;
                continue;
            }
            if i + 2 > chunk.len() {
                return Err(Error::corrupt("LZNT1 token is truncated"));
            }
            let token = usize::from(u16::from_le_bytes([chunk[i], chunk[i + 1]]));
            i += 2;
            let pos = out.len() - start;
            // Displacement bits: 4 for the first 16 bytes of a chunk, one more per doubling,
            // up to 12 (the whole 4 KiB).
            let mut disp_bits = 4u32;
            while disp_bits < 12 && (1usize << disp_bits) < pos {
                disp_bits += 1;
            }
            let len_bits = 16 - disp_bits;
            let len = (token & ((1 << len_bits) - 1)) + 3;
            let disp = (token >> len_bits) + 1;
            if disp > pos {
                return Err(Error::corrupt("LZNT1 distance reaches before the chunk"));
            }
            for _ in 0..len {
                if out.len() >= limit || out.len() - start >= CHUNK {
                    break;
                }
                let b = out[out.len() - disp];
                out.push(b);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_an_overlapping_match() {
        // Chunk: flags 0b00001000 (three literals, then a token), "ABC", then a token with
        // length 6 and distance 3 at position 3, which copies "ABCABC".
        let chunk = [0x08, b'A', b'B', b'C', 0x03, 0x20];
        let header = 0x8000u16 | (chunk.len() as u16 - 3);
        let mut input = header.to_le_bytes().to_vec();
        input.extend_from_slice(&chunk);
        let mut out = Vec::new();
        decompress(&input, &mut out, usize::MAX).unwrap();
        assert_eq!(out, b"ABCABCABC");
    }

    #[test]
    fn stored_chunk_is_copied() {
        let data = vec![7u8; CHUNK];
        let header = (CHUNK - 3) as u16; // size field 0xFFD, no compression bit
        let mut input = header.to_le_bytes().to_vec();
        input.extend_from_slice(&data);
        let mut out = Vec::new();
        decompress(&input, &mut out, usize::MAX).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn distance_before_the_chunk_is_rejected() {
        // A token at position 0 with any distance reaches before the chunk.
        let chunk = [0x01, 0x00, 0x00];
        let header = 0x8000u16 | (chunk.len() as u16 - 3);
        let mut input = header.to_le_bytes().to_vec();
        input.extend_from_slice(&chunk);
        assert!(decompress(&input, &mut Vec::new(), usize::MAX).is_err());
    }
}
