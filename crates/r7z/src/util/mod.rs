pub mod blake2sp;
pub mod codepage;
pub mod crc64;
pub mod fmt;
pub mod mem;
pub mod text;
pub mod time;
pub mod wildcard;

/// Reads until `buf` is full or EOF, returning the number of bytes read.
pub fn read_full<R: std::io::Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Sum of sizes read from an archive. Header values are untrusted, so the total stops at
/// `u64::MAX` instead of overflowing.
pub fn saturating_sum(values: impl IntoIterator<Item = u64>) -> u64 {
    values.into_iter().fold(0, u64::saturating_add)
}

/// The name a new archive of `paths` gets, without its extension: the folder or the file
/// name without its extension for one item, the name of their folder for several.
pub fn archive_base_name(paths: &[std::path::PathBuf]) -> String {
    let base = match paths {
        [] => None,
        [one] if one.is_dir() => one.file_name(),
        [one] => one.file_stem(),
        [first, ..] => first.parent().and_then(|p| p.file_name()),
    };
    base.map(|b| b.to_string_lossy().into_owned())
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| "archive".into())
}

/// Number of worker threads to use by default.
pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// A random 64-bit value (for temporary names and salts).
pub fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    u64::from_le_bytes(b)
}
