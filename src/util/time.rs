//! Windows FILETIME (100 ns ticks since 1601-01-01 UTC), the timestamp unit 7z stores.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
const TICKS_PER_SEC: u64 = 10_000_000;

pub fn to_filetime(t: SystemTime) -> u64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() + EPOCH_DIFF_SECS) * TICKS_PER_SEC + (d.subsec_nanos() / 100) as u64,
        Err(e) => {
            let d = e.duration();
            let ticks = d.as_secs() * TICKS_PER_SEC + (d.subsec_nanos() / 100) as u64;
            (EPOCH_DIFF_SECS * TICKS_PER_SEC).saturating_sub(ticks)
        }
    }
}

/// Seconds since 1970 (UTC) to FILETIME.
pub fn unix_to_filetime(secs: i64) -> u64 {
    ((secs + EPOCH_DIFF_SECS as i64).max(0) as u64) * TICKS_PER_SEC
}

/// FILETIME to seconds since 1970 (UTC).
pub fn filetime_to_unix(ft: u64) -> i64 {
    (ft / TICKS_PER_SEC) as i64 - EPOCH_DIFF_SECS as i64
}

/// MS-DOS date and time (local time, 2-second resolution) to FILETIME.
pub fn dos_to_filetime(date: u16, time: u16) -> Option<u64> {
    let (y, m, d) = (
        1980 + (date >> 9) as i64,
        ((date >> 5) & 15) as u32,
        (date & 31) as u32,
    );
    let (hh, mm, ss) = (
        (time >> 11) as i64,
        ((time >> 5) & 63) as i64,
        ((time & 31) * 2) as i64,
    );
    if !(1..=12).contains(&m) || d == 0 || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    let days = days_from_civil(y, m, d);
    let local = days * 86_400 + hh * 3600 + mm * 60 + ss;
    Some(unix_to_filetime(local - local_offset_secs()))
}

/// A packed DOS date (high 16 bits) and time (low 16 bits) to FILETIME; zero and impossible
/// values have no time.
pub fn dos_datetime_to_filetime(dos: u32) -> Option<u64> {
    dos_to_filetime((dos >> 16) as u16, dos as u16)
}

/// FILETIME to MS-DOS date and time (local), clamped to the DOS range 1980-2107.
pub fn filetime_to_dos(ft: u64) -> (u16, u16) {
    let secs = filetime_to_unix(ft) + local_offset_secs();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if y < 1980 {
        return (0x21, 0);
    }
    if y > 2107 {
        return (0xFF9F, 0xBF7D);
    }
    let date = (((y - 1980) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let time =
        (((rem / 3600) as u16) << 11) | ((((rem / 60) % 60) as u16) << 5) | ((rem % 60) / 2) as u16;
    (date, time)
}

/// Howard Hinnant's civil-to-days conversion (days since 1970-01-01).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn from_filetime(ft: u64) -> SystemTime {
    let epoch_ticks = EPOCH_DIFF_SECS * TICKS_PER_SEC;
    if ft >= epoch_ticks {
        let t = ft - epoch_ticks;
        UNIX_EPOCH + Duration::new(t / TICKS_PER_SEC, ((t % TICKS_PER_SEC) * 100) as u32)
    } else {
        let t = epoch_ticks - ft;
        UNIX_EPOCH - Duration::new(t / TICKS_PER_SEC, ((t % TICKS_PER_SEC) * 100) as u32)
    }
}

/// Formats a FILETIME as local `YYYY-MM-DD HH:MM:SS`.
pub fn format_filetime(ft: u64) -> String {
    let secs = (ft / TICKS_PER_SEC) as i64 - EPOCH_DIFF_SECS as i64 + local_offset_secs();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil conversion.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(windows)]
fn local_offset_secs() -> i64 {
    #[repr(C)]
    struct TimeZoneInformation {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: [u16; 8],
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: [u16; 8],
        daylight_bias: i32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTimeZoneInformation(tzi: *mut TimeZoneInformation) -> u32;
    }
    // SAFETY: the struct matches the Win32 TIME_ZONE_INFORMATION layout and is fully written.
    unsafe {
        let mut tzi: TimeZoneInformation = std::mem::zeroed();
        let r = GetTimeZoneInformation(&mut tzi);
        let bias = match r {
            2 => tzi.bias + tzi.daylight_bias, // TIME_ZONE_ID_DAYLIGHT
            1 => tzi.bias + tzi.standard_bias, // TIME_ZONE_ID_STANDARD
            0 => tzi.bias,
            _ => 0,
        };
        -(bias as i64) * 60
    }
}

#[cfg(not(windows))]
fn local_offset_secs() -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let now = SystemTime::now();
        let ft = to_filetime(now);
        let back = from_filetime(ft);
        let diff = now.duration_since(back).unwrap_or_default();
        assert!(diff < Duration::from_micros(1));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
