//! Formatting helpers shared by the engine messages and both UIs (no egui dependency).
//! Dates are fixed-width local time: "YYYY-MM-DD HH:MM" (A-1), with the order and seconds chosen
//! in Settings > General.

use crate::settings::DateFmt;
use std::sync::atomic::{AtomicU8, Ordering};

pub fn human(n: u64) -> String {
    let mut v = n as f64;
    for u in ["B", "KB", "MB", "GB", "TB"] {
        if v < 1024.0 {
            return if u == "B" { format!("{n} B") } else { format!("{v:.1} {u}") };
        }
        v /= 1024.0;
    }
    format!("{v:.1} PB")
}

/// bit 0-1: format (0 iso, 1 dots, 2 us), bit 2: seconds.
static DATE_STYLE: AtomicU8 = AtomicU8::new(0);

pub fn set_date_style(f: DateFmt, seconds: bool) {
    let code = match f {
        DateFmt::Iso => 0,
        DateFmt::Dots => 1,
        DateFmt::Us => 2,
    };
    DATE_STYLE.store(code | if seconds { 4 } else { 0 }, Ordering::Relaxed);
}

fn style() -> (DateFmt, bool) {
    let v = DATE_STYLE.load(Ordering::Relaxed);
    let f = match v & 3 {
        1 => DateFmt::Dots,
        2 => DateFmt::Us,
        _ => DateFmt::Iso,
    };
    (f, v & 4 != 0)
}

/// True when dates include seconds (wider date column).
pub fn seconds_on() -> bool {
    style().1
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Civil {
    pub y: i64,
    pub mo: u32,
    pub d: u32,
    pub h: u32,
    pub mi: u32,
    pub s: u32,
}

/// Always the same width for a given style (zero padded, 24-hour clock).
pub fn format_civil(c: Civil, f: DateFmt, seconds: bool) -> String {
    let day = match f {
        DateFmt::Iso => format!("{:04}-{:02}-{:02}", c.y, c.mo, c.d),
        DateFmt::Dots => format!("{:04}.{:02}.{:02}", c.y, c.mo, c.d),
        DateFmt::Us => format!("{:02}/{:02}/{:04}", c.mo, c.d, c.y),
    };
    if seconds {
        format!("{day} {:02}:{:02}:{:02}", c.h, c.mi, c.s)
    } else {
        format!("{day} {:02}:{:02}", c.h, c.mi)
    }
}

/// UTC civil time from Unix seconds (Howard Hinnant's civil-from-days).
pub fn civil_utc(secs: i64) -> Civil {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dd = doy - (153 * mp + 2) / 5 + 1;
    let mm = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mm <= 2 { y + 1 } else { y };
    Civil { y, mo: mm as u32, d: dd as u32, h: (rem / 3600) as u32, mi: (rem / 60 % 60) as u32, s: (rem % 60) as u32 }
}

/// Local civil time (Windows: the time zone rules valid at that date, DST included).
fn civil_local(secs: i64) -> Civil {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
        use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
        let ft100 = (secs + 11_644_473_600) as u64 * 10_000_000;
        let ft = FILETIME { dwLowDateTime: ft100 as u32, dwHighDateTime: (ft100 >> 32) as u32 };
        let mut utc: SYSTEMTIME = core::mem::zeroed();
        let mut loc: SYSTEMTIME = core::mem::zeroed();
        if secs > -11_644_473_600
            && FileTimeToSystemTime(&ft, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTime(core::ptr::null(), &utc, &mut loc) != 0
        {
            return Civil {
                y: loc.wYear as i64,
                mo: loc.wMonth as u32,
                d: loc.wDay as u32,
                h: loc.wHour as u32,
                mi: loc.wMinute as u32,
                s: loc.wSecond as u32,
            };
        }
    }
    civil_utc(secs)
}

/// Modification time in the chosen style, local time. Empty when unknown.
pub fn date(t: Option<std::time::SystemTime>) -> String {
    let Some(t) = t else { return String::new() };
    let secs = match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let (f, s) = style();
    format_civil(civil_local(secs), f, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats() {
        assert_eq!(human(10), "10 B");
        assert_eq!(human(2048), "2.0 KB");
        let c = civil_utc(1_700_000_000);
        assert_eq!(format_civil(c, DateFmt::Iso, false), "2023-11-14 22:13");
        assert_eq!(format_civil(c, DateFmt::Iso, true), "2023-11-14 22:13:20");
        assert_eq!(format_civil(c, DateFmt::Dots, false), "2023.11.14 22:13");
        assert_eq!(format_civil(c, DateFmt::Us, false), "11/14/2023 22:13");
    }
    #[test]
    fn fixed_width() {
        for secs in [0, 86_399, 1_700_000_000, 4_102_444_799] {
            assert_eq!(format_civil(civil_utc(secs), DateFmt::Iso, false).len(), 16);
            assert_eq!(format_civil(civil_utc(secs), DateFmt::Iso, true).len(), 19);
        }
        assert_eq!(date(None), "");
        let now = date(Some(std::time::SystemTime::now()));
        assert!(now.len() == 16 || now.len() == 19, "{now}");
    }
}
