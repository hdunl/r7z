//! Zip encryption: traditional PKWARE "ZipCrypto" (decrypt only) and WinZip AES (AE-1/AE-2:
//! PBKDF2-HMAC-SHA1 with 1000 iterations, AES-CTR with a little-endian counter starting at
//! 1, and a 10-byte HMAC-SHA1 tag over the ciphertext).

use std::io::{self, Read};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{Error, Result};

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC: [u32; 256] = crc_table();

fn crc_byte(crc: u32, b: u8) -> u32 {
    (crc >> 8) ^ CRC[((crc ^ b as u32) & 0xFF) as usize]
}

/// The three ZipCrypto keys.
#[derive(Clone)]
pub struct ZipCrypto {
    k: [u32; 3],
}

impl ZipCrypto {
    pub fn new(password: &[u8]) -> Self {
        let mut z = ZipCrypto {
            k: [0x1234_5678, 0x2345_6789, 0x3456_7890],
        };
        for &b in password {
            z.update(b);
        }
        z
    }

    fn update(&mut self, b: u8) {
        self.k[0] = crc_byte(self.k[0], b);
        self.k[1] = self.k[1]
            .wrapping_add(self.k[0] & 0xFF)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.k[2] = crc_byte(self.k[2], (self.k[1] >> 24) as u8);
    }

    fn stream_byte(&self) -> u8 {
        let t = (self.k[2] | 2) as u16;
        (t.wrapping_mul(t ^ 1) >> 8) as u8
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for b in buf {
            let c = *b ^ self.stream_byte();
            self.update(c);
            *b = c;
        }
    }
}

/// Decrypts ZipCrypto data after its 12-byte header.
pub struct ZipCryptoReader<R: Read> {
    inner: R,
    keys: ZipCrypto,
}

impl<R: Read> ZipCryptoReader<R> {
    /// Reads the header and checks its last byte against `check` (the CRC's or the DOS
    /// time's high byte).
    pub fn new(mut inner: R, password: &[u8], check: u8) -> Result<Self> {
        let mut keys = ZipCrypto::new(password);
        let mut h = [0u8; 12];
        inner
            .read_exact(&mut h)
            .map_err(|_| Error::corrupt("encryption header truncated"))?;
        keys.decrypt(&mut h);
        if h[11] != check {
            return Err(Error::WrongPassword);
        }
        Ok(ZipCryptoReader { inner, keys })
    }
}

impl<R: Read> Read for ZipCryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.keys.decrypt(&mut buf[..n]);
        Ok(n)
    }
}

enum Cipher {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

/// AES-CTR keystream plus the HMAC over the ciphertext.
pub struct WzAes {
    cipher: Cipher,
    counter: u128,
    ks: [u8; 16],
    pos: usize,
    mac: Hmac<Sha1>,
}

/// Salt length for AES strength 1/2/3 (128/192/256-bit keys).
pub fn salt_len(strength: u8) -> Option<usize> {
    match strength {
        1 => Some(8),
        2 => Some(12),
        3 => Some(16),
        _ => None,
    }
}

impl WzAes {
    /// Derives keys; returns the cipher state and the 2-byte password verifier.
    pub fn new(password: &[u8], salt: &[u8], strength: u8) -> Result<(Self, [u8; 2])> {
        let key_len = match strength {
            1 => 16,
            2 => 24,
            3 => 32,
            _ => return Err(Error::unsupported(format!("AES strength {strength}"))),
        };
        let mut dk = vec![0u8; key_len * 2 + 2];
        pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut dk);
        let key = &dk[..key_len];
        let cipher = match key_len {
            16 => Cipher::A128(aes::Aes128::new_from_slice(key).unwrap()),
            24 => Cipher::A192(aes::Aes192::new_from_slice(key).unwrap()),
            _ => Cipher::A256(aes::Aes256::new_from_slice(key).unwrap()),
        };
        let mac = <Hmac<Sha1> as Mac>::new_from_slice(&dk[key_len..key_len * 2]).unwrap();
        let pv = [dk[key_len * 2], dk[key_len * 2 + 1]];
        Ok((
            WzAes {
                cipher,
                counter: 0,
                ks: [0; 16],
                pos: 16,
                mac,
            },
            pv,
        ))
    }

    fn xor(&mut self, buf: &mut [u8]) {
        for b in buf {
            if self.pos == 16 {
                self.counter = self.counter.wrapping_add(1);
                let mut block = GenericArray::from(self.counter.to_le_bytes());
                match &self.cipher {
                    Cipher::A128(c) => c.encrypt_block(&mut block),
                    Cipher::A192(c) => c.encrypt_block(&mut block),
                    Cipher::A256(c) => c.encrypt_block(&mut block),
                }
                self.ks.copy_from_slice(&block);
                self.pos = 0;
            }
            *b ^= self.ks[self.pos];
            self.pos += 1;
        }
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) {
        self.xor(buf);
        self.mac.update(buf);
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.mac.update(buf);
        self.xor(buf);
    }

    /// The 10-byte authentication code over everything processed so far.
    pub fn tag(self) -> [u8; 10] {
        let full = self.mac.finalize().into_bytes();
        full[..10].try_into().unwrap()
    }
}

/// Decrypts WinZip AES data (`salt || verifier || data || tag`) given as one slice and
/// checks the tag once the data has been read.
pub struct WzAesReader<'a> {
    data: &'a [u8],
    tag: &'a [u8],
    aes: Option<WzAes>,
}

impl<'a> WzAesReader<'a> {
    pub fn new(raw: &'a [u8], password: &[u8], strength: u8) -> Result<Self> {
        let sl = salt_len(strength)
            .ok_or_else(|| Error::unsupported(format!("AES strength {strength}")))?;
        if raw.len() < sl + 2 + 10 {
            return Err(Error::corrupt("AES-encrypted data truncated"));
        }
        let (aes, pv) = WzAes::new(password, &raw[..sl], strength)?;
        if pv != raw[sl..sl + 2] {
            return Err(Error::WrongPassword);
        }
        Ok(WzAesReader {
            data: &raw[sl + 2..raw.len() - 10],
            tag: &raw[raw.len() - 10..],
            aes: Some(aes),
        })
    }
}

impl Read for WzAesReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.data.len().min(buf.len());
        if n == 0 {
            if let Some(aes) = self.aes.take() {
                if aes.tag()[..] != *self.tag {
                    return Err(Error::WrongPassword.into_io());
                }
            }
            return Ok(0);
        }
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        self.aes.as_mut().unwrap().decrypt(&mut buf[..n]);
        Ok(n)
    }
}

/// Encrypts `data` in place-free fashion for writing: returns `salt || pv || ct || tag`.
pub fn wz_aes_encrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| Error::Other(format!("random source failed: {e}")))?;
    let (mut aes, pv) = WzAes::new(password, &salt, 3)?;
    let mut out = Vec::with_capacity(data.len() + 28);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&pv);
    let start = out.len();
    out.extend_from_slice(data);
    aes.encrypt(&mut out[start..]);
    out.extend_from_slice(&aes.tag());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_roundtrip_and_wrong_password() {
        let data = b"some secret bytes that span more than one AES block!".repeat(3);
        let enc = wz_aes_encrypt(&data, b"pw").unwrap();
        let mut out = Vec::new();
        WzAesReader::new(&enc, b"pw", 3)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data);
        assert!(
            matches!(
                WzAesReader::new(&enc, b"nope", 3),
                Err(Error::WrongPassword)
            ) || {
                // 1 in 65536 verifier collisions: the tag check must catch it.
                let mut o = Vec::new();
                WzAesReader::new(&enc, b"nope", 3)
                    .unwrap()
                    .read_to_end(&mut o)
                    .is_err()
            }
        );
    }
}
