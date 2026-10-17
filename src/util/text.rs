//! Names in the system's ANSI code page (CAB names without the UTF-8 attribute). The legacy
//! code pages of zip, LZH, ARJ and tar names are in [`super::codepage`].

/// Decodes a name in the system's ANSI code page (Windows) or as Latin-1 elsewhere.
pub fn ansi(b: &[u8]) -> String {
    if b.is_ascii() {
        return String::from_utf8_lossy(b).into_owned();
    }
    #[cfg(windows)]
    {
        if let Some(s) = windows_codepage(b, 0) {
            return s;
        }
    }
    b.iter().map(|&c| c as char).collect()
}

#[cfg(windows)]
fn windows_codepage(b: &[u8], cp: u32) -> Option<String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn MultiByteToWideChar(
            cp: u32,
            flags: u32,
            s: *const u8,
            n: i32,
            w: *mut u16,
            wn: i32,
        ) -> i32;
    }
    let n = i32::try_from(b.len()).ok()?;
    // SAFETY: lengths are passed explicitly; the first call sizes the buffer the second fills.
    unsafe {
        let len = MultiByteToWideChar(cp, 0, b.as_ptr(), n, std::ptr::null_mut(), 0);
        if len <= 0 {
            return None;
        }
        let mut w = vec![0u16; len as usize];
        let got = MultiByteToWideChar(cp, 0, b.as_ptr(), n, w.as_mut_ptr(), len);
        if got <= 0 {
            return None;
        }
        w.truncate(got as usize);
        Some(String::from_utf16_lossy(&w))
    }
}
