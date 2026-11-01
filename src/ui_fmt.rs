//! Formatting helpers shared by the engine messages and both UIs (no egui dependency).

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

/// Local-agnostic "YYYY-MM-DD HH:MM" (UTC) for a modification time.
pub fn date(t: Option<std::time::SystemTime>) -> String {
    let Some(t) = t else { return String::new() };
    let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) else { return String::new() };
    let s = d.as_secs() as i64;
    let (days, rem) = (s.div_euclid(86_400), s.rem_euclid(86_400));
    // civil-from-days (Howard Hinnant)
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
    format!("{y:04}-{mm:02}-{dd:02} {:02}:{:02} UTC", rem / 3600, rem / 60 % 60)
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats() {
        assert_eq!(super::human(10), "10 B");
        assert_eq!(super::human(2048), "2.0 KB");
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(super::date(Some(t)), "2023-11-14 22:13 UTC");
    }
}
