//! Physical memory query, used to bound encoder thread counts.

/// Total and currently available physical memory in bytes, if they can be determined.
#[cfg(windows)]
pub fn memory() -> Option<(u64, u64)> {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalMemoryStatusEx(buf: *mut MemoryStatusEx) -> i32;
    }
    // SAFETY: the struct matches MEMORYSTATUSEX and `length` is set as the API requires.
    unsafe {
        let mut m: MemoryStatusEx = std::mem::zeroed();
        m.length = std::mem::size_of::<MemoryStatusEx>() as u32;
        if GlobalMemoryStatusEx(&mut m) != 0 {
            Some((m.total_phys, m.avail_phys))
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
pub fn memory() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let field = |name: &str| -> Option<u64> {
        let line = s.lines().find(|l| l.starts_with(name))?;
        line.split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
            .map(|kb| kb * 1024)
    };
    let total = field("MemTotal:")?;
    Some((total, field("MemAvailable:").unwrap_or(total / 2)))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn memory() -> Option<(u64, u64)> {
    None
}

/// Memory r7z allows itself for encoder working sets: half of physical RAM, but no more
/// than three quarters of what is free right now (at least 256 MiB; 2 GiB if unknown).
pub fn encoder_budget() -> u64 {
    match memory() {
        Some((total, avail)) => (total / 2).min(avail / 4 * 3).max(256 << 20),
        None => 2 << 30,
    }
}
