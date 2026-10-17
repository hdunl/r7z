//! 7zAES: AES-256-CBC with a SHA-256 iterated key derivation.
//!
//! Key = SHA-256 over 2^NumCyclesPower repetitions of `salt || UTF-16LE(password) || u64le(i)`.
//! 7-Zip 25.01's encoder uses NumCyclesPower = 19, no salt and a random 16-byte IV
//! (observed in the REA report, `FUN_10116150`). AES runs through the `aes` crate, which
//! selects AES-NI at runtime; SHA-256 uses SHA-NI when available.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Mutex, OnceLock};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};

use super::encode::Sink;
use crate::error::{Error, Result};
use crate::util::read_full;

pub const DEFAULT_CYCLES_POWER: u8 = 19;
const MAX_CYCLES_POWER: u8 = 24;

type Block = GenericArray<u8, aes::cipher::consts::U16>;

#[derive(Debug, Clone)]
pub struct AesProps {
    pub cycles_power: u8,
    pub salt: Vec<u8>,
    pub iv: [u8; 16],
}

impl AesProps {
    pub fn parse(p: &[u8]) -> Result<Self> {
        let b0 = *p
            .first()
            .ok_or_else(|| Error::corrupt("7zAES properties missing"))?;
        let cycles_power = b0 & 0x3F;
        let mut iv = [0u8; 16];
        if b0 & 0xC0 == 0 {
            if p.len() != 1 {
                return Err(Error::corrupt("7zAES properties have a bad size"));
            }
            return Ok(AesProps {
                cycles_power,
                salt: Vec::new(),
                iv,
            });
        }
        let b1 = *p
            .get(1)
            .ok_or_else(|| Error::corrupt("7zAES properties truncated"))?;
        let salt_size = ((b0 >> 7) & 1) as usize + (b1 >> 4) as usize;
        let iv_size = ((b0 >> 6) & 1) as usize + (b1 & 0x0F) as usize;
        if p.len() != 2 + salt_size + iv_size {
            return Err(Error::corrupt("7zAES properties have a bad size"));
        }
        let salt = p[2..2 + salt_size].to_vec();
        iv[..iv_size].copy_from_slice(&p[2 + salt_size..]);
        Ok(AesProps {
            cycles_power,
            salt,
            iv,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let salt_n = self.salt.len();
        let iv_n = 16;
        let mut out = vec![
            self.cycles_power | if salt_n == 0 { 0 } else { 0x80 } | 0x40,
            (((salt_n.saturating_sub(1)) as u8) << 4) | (iv_n - 1) as u8,
        ];
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.iv);
        out
    }
}

type CacheKey = (u8, Vec<u8>, String);

fn key_cache() -> &'static Mutex<HashMap<CacheKey, [u8; 32]>> {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, [u8; 32]>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Derives (and memoizes) the AES key. Archives usually share one salt and password across
/// every folder, so the 2^19-round KDF runs once per process instead of once per folder.
pub fn derive_key(password: &str, salt: &[u8], cycles_power: u8) -> Result<[u8; 32]> {
    if cycles_power > MAX_CYCLES_POWER && cycles_power != 0x3F {
        return Err(Error::unsupported(format!(
            "7zAES NumCyclesPower {cycles_power} (maximum is {MAX_CYCLES_POWER})"
        )));
    }
    let ck = (cycles_power, salt.to_vec(), password.to_string());
    if let Some(k) = key_cache().lock().unwrap().get(&ck) {
        return Ok(*k);
    }
    let pw: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let mut key = [0u8; 32];
    if cycles_power == 0x3F {
        let raw: Vec<u8> = salt.iter().chain(pw.iter()).copied().take(32).collect();
        key[..raw.len()].copy_from_slice(&raw);
    } else {
        let unit = salt.len() + pw.len() + 8;
        let rounds = 1u64 << cycles_power;
        // Hash many rounds per update call; the digest only sees the concatenated stream.
        let per_batch = (64 * 1024 / unit).max(1) as u64;
        let mut batch = Vec::with_capacity(unit * per_batch as usize);
        let mut h = Sha256::new();
        let mut i = 0u64;
        while i < rounds {
            batch.clear();
            let end = (i + per_batch).min(rounds);
            for c in i..end {
                batch.extend_from_slice(salt);
                batch.extend_from_slice(&pw);
                batch.extend_from_slice(&c.to_le_bytes());
            }
            h.update(&batch);
            i = end;
        }
        key.copy_from_slice(&h.finalize());
    }
    key_cache().lock().unwrap().insert(ck, key);
    Ok(key)
}

fn as_blocks(buf: &mut [u8]) -> &mut [Block] {
    debug_assert!(buf.len() % 16 == 0);
    // SAFETY: GenericArray<u8, U16> is a transparent wrapper over [u8; 16] with alignment 1.
    unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut Block, buf.len() / 16) }
}

/// CBC decryption reader. Whole buffers are decrypted at once so AES-NI can pipeline
/// independent blocks; CBC decryption only needs the previous ciphertext for the XOR.
pub struct AesReader<R> {
    inner: R,
    cipher: Aes256,
    iv: [u8; 16],
    buf: Vec<u8>,
    scratch: Vec<u8>,
    start: usize,
    end: usize,
    done: bool,
}

const AES_BUF: usize = 256 * 1024;

impl<R: Read> AesReader<R> {
    pub fn new(inner: R, props: &[u8], password: Option<&str>) -> Result<Self> {
        let p = AesProps::parse(props)?;
        let password = password.ok_or(Error::PasswordRequired)?;
        let key = derive_key(password, &p.salt, p.cycles_power)?;
        Ok(AesReader {
            inner,
            cipher: Aes256::new(GenericArray::from_slice(&key)),
            iv: p.iv,
            buf: vec![0u8; AES_BUF],
            scratch: vec![0u8; AES_BUF],
            start: 0,
            end: 0,
            done: false,
        })
    }

    fn refill(&mut self) -> io::Result<()> {
        let n = read_full(&mut self.inner, &mut self.buf)?;
        if n < self.buf.len() {
            self.done = true;
        }
        let n = n - n % 16;
        if n == 0 {
            self.start = 0;
            self.end = 0;
            return Ok(());
        }
        let data = &mut self.buf[..n];
        self.scratch[..n].copy_from_slice(data);
        self.cipher.decrypt_blocks(as_blocks(data));
        for (i, chunk) in data.chunks_exact_mut(16).enumerate() {
            let prev: &[u8] = if i == 0 {
                &self.iv
            } else {
                &self.scratch[(i - 1) * 16..i * 16]
            };
            for (a, b) in chunk.iter_mut().zip(prev) {
                *a ^= b;
            }
        }
        self.iv.copy_from_slice(&self.scratch[n - 16..n]);
        self.start = 0;
        self.end = n;
        Ok(())
    }
}

impl<R: Read> Read for AesReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.start == self.end {
            if self.done {
                return Ok(0);
            }
            self.refill()?;
            if self.start == self.end {
                return Ok(0);
            }
        }
        let n = out.len().min(self.end - self.start);
        out[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

/// CBC encryption sink. The tail is zero-padded to a whole block, as 7-Zip does.
pub struct AesWriter<'a> {
    inner: Box<dyn Sink + 'a>,
    cipher: Aes256,
    prev: [u8; 16],
    pending: Vec<u8>,
}

impl<'a> AesWriter<'a> {
    pub fn new(inner: Box<dyn Sink + 'a>, key: &[u8; 32], iv: [u8; 16]) -> Self {
        AesWriter {
            inner,
            cipher: Aes256::new(GenericArray::from_slice(key)),
            prev: iv,
            pending: Vec::with_capacity(AES_BUF + 16),
        }
    }

    fn encrypt_whole_blocks(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_exact_mut(16) {
            for (a, b) in chunk.iter_mut().zip(&self.prev) {
                *a ^= b;
            }
            let blk = GenericArray::from_mut_slice(chunk);
            self.cipher.encrypt_block(blk);
            self.prev.copy_from_slice(chunk);
        }
    }

    fn drain(&mut self, all: bool) -> io::Result<()> {
        let mut n = self.pending.len() - self.pending.len() % 16;
        if all && self.pending.len() % 16 != 0 {
            let pad = 16 - self.pending.len() % 16;
            self.pending.extend(std::iter::repeat_n(0u8, pad));
            n = self.pending.len();
        }
        if n == 0 {
            return Ok(());
        }
        let mut buf = std::mem::take(&mut self.pending);
        self.encrypt_whole_blocks(&mut buf[..n]);
        self.inner.write_all(&buf[..n])?;
        buf.drain(..n);
        self.pending = buf;
        Ok(())
    }
}

impl Write for AesWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(data);
        if self.pending.len() >= AES_BUF {
            self.drain(false)?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink for AesWriter<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.drain(true)?;
        self.inner.finish()
    }
}

pub fn random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("OS random source unavailable");
    iv
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn props_roundtrip() {
        let p = AesProps {
            cycles_power: 19,
            salt: vec![],
            iv: [7u8; 16],
        };
        let s = p.serialize();
        assert_eq!(s[0], 0x53);
        assert_eq!(s.len(), 18);
        let q = AesProps::parse(&s).unwrap();
        assert_eq!(q.cycles_power, 19);
        assert_eq!(q.iv, [7u8; 16]);
        assert!(q.salt.is_empty());
    }
}
