//! MSZIP (CAB method 1): each data block is `CK` followed by raw deflate data that may refer
//! back into the previous blocks' last 32 KiB. The inflater is reset per block and primed
//! with that history as a stored deflate block.

use flate2::{Decompress, FlushDecompress, Status};

use crate::error::{Error, Result};

const HISTORY: usize = 1 << 15;

pub struct MsZip {
    inflate: Decompress,
    /// The last (up to) 32 KiB of decoded output.
    history: Vec<u8>,
    /// Scratch for the priming block (header + history) and its discarded output.
    prime: Vec<u8>,
    sink: Vec<u8>,
}

impl Default for MsZip {
    fn default() -> Self {
        Self::new()
    }
}

impl MsZip {
    pub fn new() -> Self {
        MsZip {
            inflate: Decompress::new(false),
            history: Vec::with_capacity(HISTORY),
            prime: Vec::with_capacity(HISTORY + 5),
            sink: vec![0; HISTORY],
        }
    }

    /// Decodes one block into `out`, which must come out exactly `size` bytes long.
    pub fn decode_block(&mut self, data: &[u8], size: usize, out: &mut Vec<u8>) -> Result<()> {
        let body = match data {
            [b'C', b'K', rest @ ..] => rest,
            _ => return Err(Error::corrupt("MSZIP block has no CK signature")),
        };
        self.inflate.reset(false);
        if !self.history.is_empty() {
            let n = self.history.len() as u16;
            self.prime.clear();
            self.prime.push(0); // BFINAL=0, BTYPE=stored
            self.prime.extend_from_slice(&n.to_le_bytes());
            self.prime.extend_from_slice(&(!n).to_le_bytes());
            self.prime.extend_from_slice(&self.history);
            let t0 = self.inflate.total_out();
            let st = self
                .inflate
                .decompress(&self.prime, &mut self.sink, FlushDecompress::None);
            if !matches!(st, Ok(Status::Ok | Status::BufError))
                || self.inflate.total_out() - t0 != n as u64
            {
                return Err(Error::corrupt("MSZIP history priming failed"));
            }
        }
        out.clear();
        out.resize(size, 0);
        let before = self.inflate.total_out();
        let mut filled = 0usize;
        let mut consumed = 0usize;
        // A block decodes in one call; the loop only guards against short internal writes.
        loop {
            let in_before = self.inflate.total_in();
            let out_before = self.inflate.total_out();
            let st = self
                .inflate
                .decompress(
                    &body[consumed..],
                    &mut out[filled..],
                    FlushDecompress::Finish,
                )
                .map_err(|e| Error::corrupt(format!("MSZIP data error: {e}")))?;
            consumed += (self.inflate.total_in() - in_before) as usize;
            filled = (self.inflate.total_out() - before) as usize;
            let progressed =
                self.inflate.total_out() != out_before || self.inflate.total_in() != in_before;
            if st == Status::StreamEnd || filled == size || !progressed {
                break;
            }
        }
        if filled != size {
            return Err(Error::corrupt(format!(
                "MSZIP block decoded to {filled} bytes, expected {size}"
            )));
        }
        if size >= HISTORY {
            self.history.clear();
            self.history.extend_from_slice(&out[size - HISTORY..]);
        } else {
            let excess = (self.history.len() + size).saturating_sub(HISTORY);
            self.history.drain(..excess);
            self.history.extend_from_slice(out);
        }
        Ok(())
    }
}
