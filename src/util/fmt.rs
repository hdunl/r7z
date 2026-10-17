/// Human-readable binary size, e.g. `12.3 MiB`.
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[u])
    } else if v >= 10.0 {
        format!("{v:.1} {}", UNITS[u])
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

/// Size as written in 7-Zip method strings: `24` for 2^24, otherwise `3m`, `768k`, `100b`.
pub fn dict_label(size: u64) -> String {
    if size.is_power_of_two() {
        return size.trailing_zeros().to_string();
    }
    if size % (1 << 20) == 0 {
        format!("{}m", size >> 20)
    } else if size % (1 << 10) == 0 {
        format!("{}k", size >> 10)
    } else {
        format!("{size}b")
    }
}

/// Parses sizes like `64m`, `1g`, `512k`, `100b`, or a plain byte count.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mul) = match s.chars().last()?.to_ascii_lowercase() {
        'b' => (&s[..s.len() - 1], 1u64),
        'k' => (&s[..s.len() - 1], 1 << 10),
        'm' => (&s[..s.len() - 1], 1 << 20),
        'g' => (&s[..s.len() - 1], 1 << 30),
        't' => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mul)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}
