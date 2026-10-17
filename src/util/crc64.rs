//! CRC-64/XZ (ECMA-182 polynomial, reflected), the CRC64 used by 7-Zip and xz.
//! Slicing-by-8 table implementation.

const POLY: u64 = 0xC96C_5795_D787_0F42;

const fn make_tables() -> [[u64; 256]; 8] {
    let mut t = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

static TABLES: [[u64; 256]; 8] = make_tables();

#[derive(Clone)]
pub struct Crc64 {
    state: u64,
}

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc64 {
    pub fn new() -> Self {
        Crc64 { state: !0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        let t = &TABLES;
        let mut c = self.state;
        while data.len() >= 8 {
            let v = c ^ u64::from_le_bytes(data[..8].try_into().unwrap());
            c = t[7][(v & 0xFF) as usize]
                ^ t[6][((v >> 8) & 0xFF) as usize]
                ^ t[5][((v >> 16) & 0xFF) as usize]
                ^ t[4][((v >> 24) & 0xFF) as usize]
                ^ t[3][((v >> 32) & 0xFF) as usize]
                ^ t[2][((v >> 40) & 0xFF) as usize]
                ^ t[1][((v >> 48) & 0xFF) as usize]
                ^ t[0][(v >> 56) as usize];
            data = &data[8..];
        }
        for &b in data {
            c = t[0][((c ^ b as u64) & 0xFF) as usize] ^ (c >> 8);
        }
        self.state = c;
    }

    pub fn finalize(&self) -> u64 {
        !self.state
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_value() {
        let mut c = super::Crc64::new();
        c.update(b"123456789");
        assert_eq!(c.finalize(), 0x995D_C9BB_DF19_39FA);
    }
}
