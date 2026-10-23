//! Apple Data Compression (ADC), the chunk codec of `UDCO` disk images.
//!
//! A stream is a sequence of opcodes, told apart by the top bits of the first byte:
//!
//! * `1LLLLLLL`: a plain run. The next `L + 1` bytes are literals.
//! * `00SSSSDD DDDDDDDD`: a short copy of `S + 3` bytes (3 to 18) from `D + 1` bytes back.
//! * `01SSSSSS DDDDDDDD DDDDDDDD`: a long copy of `S + 4` bytes (4 to 67) from `D + 1` bytes
//!   back, with a big-endian 16-bit distance.
//!
//! A copy may overlap the bytes it produces, so it runs byte by byte.

use crate::error::{Error, Result};

fn truncated() -> Error {
    Error::corrupt("ADC stream is truncated")
}

/// Decodes one ADC stream into `out`, which is the exact decoded size. Input after the
/// output is full is not read.
pub fn decode(src: &[u8], out: &mut [u8]) -> Result<()> {
    let (mut i, mut o) = (0usize, 0usize);
    while o < out.len() {
        let op = *src.get(i).ok_or_else(truncated)?;
        i += 1;
        if op & 0x80 != 0 {
            let n = usize::from(op & 0x7F) + 1;
            let lit = src.get(i..i + n).ok_or_else(truncated)?;
            let dst = out
                .get_mut(o..o + n)
                .ok_or_else(|| Error::corrupt("ADC literal run overruns its output"))?;
            dst.copy_from_slice(lit);
            i += n;
            o += n;
            continue;
        }
        let (n, dist) = if op & 0x40 == 0 {
            let b = *src.get(i).ok_or_else(truncated)?;
            i += 1;
            (
                usize::from((op >> 2) & 0x0F) + 3,
                (usize::from(op & 0x03) << 8) | usize::from(b),
            )
        } else {
            let b: [u8; 2] = src
                .get(i..i + 2)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(truncated)?;
            i += 2;
            (
                usize::from(op & 0x3F) + 4,
                usize::from(u16::from_be_bytes(b)),
            )
        };
        // The distance counts back from the newest output byte, so `dist + 1` bytes of
        // output must already exist.
        if dist >= o {
            return Err(Error::corrupt(
                "ADC copy reaches before the start of its chunk",
            ));
        }
        if n > out.len() - o {
            return Err(Error::corrupt("ADC copy overruns its output"));
        }
        let from = o - dist - 1;
        for k in 0..n {
            let b = out[from + k];
            out[o + k] = b;
        }
        o += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_every_opcode() {
        // Plain run of 4, a short copy of 3 at distance 1, a long copy of 4 at distance 7.
        let src = [0x83, 0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x40, 0x00, 0x06];
        let want = [
            0xfe, 0xed, 0xfa, 0xce, 0xce, 0xce, 0xce, 0xfe, 0xed, 0xfa, 0xce,
        ];
        let mut out = [0u8; 11];
        decode(&src, &mut out).unwrap();
        assert_eq!(out, want);
    }

    #[test]
    fn long_copy_distance_is_big_endian() {
        // 257 literals, then a copy of 4 from distance 257 (offset 0x0100, big-endian).
        let data: Vec<u8> = (0..257u32).map(|b| (b * 7 + 3) as u8).collect();
        let mut src = vec![0xFF];
        src.extend(&data[..128]);
        src.push(0xFF);
        src.extend(&data[128..256]);
        src.push(0x80);
        src.push(data[256]);
        src.extend([0x40, 0x01, 0x00]);
        let mut want = data.clone();
        want.extend(&data[..4]);
        let mut out = vec![0u8; want.len()];
        decode(&src, &mut out).unwrap();
        assert_eq!(out, want);
    }

    #[test]
    fn rejects_copy_before_start() {
        let mut out = [0u8; 3];
        assert!(decode(&[0x00, 0x00], &mut out).is_err());
    }

    #[test]
    fn rejects_truncated_input() {
        let mut out = [0u8; 5];
        assert!(decode(&[0x83, 0xfe], &mut out).is_err());
        assert!(decode(&[], &mut out).is_err());
    }

    #[test]
    fn rejects_run_past_output() {
        let mut out = [0u8; 3];
        assert!(decode(&[0x83, 1, 2, 3, 4], &mut out).is_err());
    }
}
