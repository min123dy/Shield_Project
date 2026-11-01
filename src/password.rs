//! Password policy: one normalization (Unicode NFC) for every operation, and a deliberately modest
//! strength estimate. The estimate is a rough guess, never a guarantee.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// UTF-8 bytes of the NFC form. Encrypt, decrypt, password change and container open all call
/// this, so a password typed with composed or decomposed Hangul (or accents) gives the same key.
/// The output buffer is reserved up front (NFC grows UTF-8 by at most 3x) so it never reallocates
/// and leaves no stale copy.
pub fn normalize(s: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(String::with_capacity(s.len() * 3 + 4));
    for c in s.nfc() {
        out.push(c);
    }
    let mut v = Zeroizing::new(Vec::with_capacity(out.len()));
    v.extend_from_slice(out.as_bytes());
    v
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Small built-in list of very common passwords and fragments (lowercase).
const COMMON: &[&str] = &[
    "password", "passw0rd", "p@ssw0rd", "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwer1234", "1q2w3e4r", "1q2w3e4r5t", "q1w2e3r4", "asdf1234", "asdfgh",
    "zxcvbn", "iloveyou", "admin", "administrator", "letmein", "welcome", "monkey", "dragon",
    "football", "baseball", "superman", "master", "sunshine", "princess", "shadow", "abc123",
    "111111", "000000", "121212", "654321", "666666", "777777", "888888", "999999", "aaaaaa",
    "qazwsx", "trustno1", "starwars", "whatever", "freedom", "secret", "login", "changeme",
    "korea", "seoul", "samsung", "naver", "kakao", "love", "saranghae", "사랑해", "비밀번호",
    "패스워드", "shield", "shieldpassword",
];

const ROWS: &[&str] = &["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"];

pub struct Assessment {
    /// Rough bits after penalties (a guess).
    pub bits: f64,
    pub label: &'static str,
    pub warnings: Vec<&'static str>,
}

fn charset_bits(s: &str) -> f64 {
    let (mut lo, mut up, mut di, mut sy, mut hangul, mut ot) = (false, false, false, false, false, false);
    for c in s.chars() {
        match c {
            'a'..='z' => lo = true,
            'A'..='Z' => up = true,
            '0'..='9' => di = true,
            c if c.is_ascii() => sy = true,
            '\u{AC00}'..='\u{D7A3}' | '\u{3131}'..='\u{318E}' => hangul = true,
            _ => ot = true,
        }
    }
    // Hangul syllables are counted like a few hundred common ones, not 11,172 (people use few).
    let pool = lo as u32 * 26 + up as u32 * 26 + di as u32 * 10 + sy as u32 * 33 + hangul as u32 * 400 + ot as u32 * 100;
    if pool == 0 {
        0.0
    } else {
        (pool as f64).log2()
    }
}

/// Number of characters that continue a run (same char) or a sequence (ab, 12, keyboard rows).
fn predictable_chars(s: &str) -> usize {
    let c: Vec<char> = s.chars().flat_map(|c| c.to_lowercase()).collect();
    let mut n = 0;
    for i in 1..c.len() {
        let (a, b) = (c[i - 1], c[i]);
        let step = b as i64 - a as i64;
        let in_row = ROWS.iter().any(|r| {
            let pair: String = [a, b].iter().collect();
            let rev: String = [b, a].iter().collect();
            r.contains(&pair) || r.contains(&rev)
        });
        if a == b || step.abs() == 1 || in_row {
            n += 1;
        }
    }
    n
}

/// Length of the shortest unit whose repetition gives the whole string ("abcabc" -> 3).
fn repeat_unit(s: &str) -> usize {
    let c: Vec<char> = s.chars().collect();
    let n = c.len();
    for u in 1..=n / 2 {
        if n.is_multiple_of(u) && (u..n).all(|i| c[i] == c[i % u]) {
            return u;
        }
    }
    n
}

pub fn assess(pw: &str) -> Assessment {
    let mut w = Vec::new();
    let n = pw.chars().count();
    if n == 0 {
        return Assessment { bits: 0.0, label: "없음", warnings: w };
    }
    let lower = Zeroizing::new(pw.to_lowercase());
    let per = charset_bits(pw);
    let unit = repeat_unit(pw);
    let mut effective = n as f64;
    if unit < n {
        w.push("같은 문자열이 반복됩니다 (예: abcabc).");
        effective = unit as f64 + 1.0;
    }
    let pred = predictable_chars(pw);
    if pred * 2 >= n && n >= 4 {
        w.push("연속되거나 반복되는 문자·숫자·키보드 배열이 많습니다 (예: 1234, aaaa, qwer).");
    }
    effective = (effective - pred as f64 * 0.75).max(1.0);
    let mut bits = effective * per;
    if COMMON.iter().any(|c| lower.as_str() == *c) {
        w.push("매우 흔한 비밀번호입니다. 공격자가 가장 먼저 시도합니다.");
        bits = bits.min(10.0);
    } else if COMMON.iter().any(|c| c.chars().count() >= 5 && lower.contains(c)) {
        w.push("흔한 비밀번호나 단어를 포함합니다.");
        bits -= 15.0;
    }
    if pw.chars().all(|c| c.is_ascii_digit()) {
        w.push("숫자만으로 이루어져 있습니다.");
    }
    let bits = bits.max(0.0);
    let label = if bits < 40.0 {
        "약함"
    } else if bits < 60.0 {
        "보통"
    } else if bits < 80.0 {
        "강함"
    } else {
        "매우 강함"
    };
    Assessment { bits, label, warnings: w }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nfc_makes_hangul_input_methods_equal() {
        let composed = "한글암호";
        let decomposed: String = composed.nfd().collect();
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        assert_eq!(&*normalize(composed), &*normalize(&decomposed));
        assert_eq!(&*normalize("abc"), b"abc");
    }
    #[test]
    fn weak_patterns_are_flagged() {
        assert_eq!(assess("password").label, "약함");
        assert_eq!(assess("12345678").label, "약함");
        assert!(!assess("abcabcabcabc").warnings.is_empty());
        assert!(!assess("aaaaaaaaaaaa").warnings.is_empty());
        assert!(!assess("qwertyuiop").warnings.is_empty());
        let good = assess("correct-Horse7-battery-staple");
        assert!(good.warnings.is_empty() && good.bits >= 80.0, "{}", good.bits);
    }
}
