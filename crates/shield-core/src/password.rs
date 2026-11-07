//! Password policy: one normalization (Unicode NFC) for every operation, one checker for every new
//! password (encryption, password / key change, key-file-only containers, settings password, the
//! console), and a deliberately modest strength estimate. The estimate is a rough guess, never a
//! guarantee. Everything here runs offline: nothing is sent anywhere.
//!
//! A new password gets two kinds of findings (3.0.0 §1):
//! * `blocks`: it can't be used at all (empty, confirmation differs, too long, and the longer
//!   minimum that compensates for a PIM below the default).
//! * `warnings`: it can be used after an explicit "use it anyway" (short, simple, common, patterns,
//!   the program or user name). The GUI lists them live under the field and asks in a dialog; the
//!   console asks on the terminal (or needs `--yes`).

use crate::i18n::{t, tf};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;
use zeroize::Zeroizing;

/// From this many characters on, length alone is not a warning ("12 characters or fewer" is).
pub const RECOMMENDED_LEN: usize = 13;
/// Longest run of a pattern (aaaa, 1234, qwer) that is still not reported.
const PATTERN_RUN: usize = 4;

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

/// Length as the user sees it: grapheme clusters, so "한글" is 2 whether typed composed or as
/// jamo, and an emoji with modifiers is 1. Every length rule and message uses this.
pub fn length(s: &str) -> usize {
    s.graphemes(true).count()
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
    "패스워드", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "football1", "princess1",
];

/// Program names that must not be the password (or part of it).
const NAMES: &[&str] = &["shield"];

const ROWS: &[&str] = &["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"];

pub struct Assessment {
    /// Rough bits after penalties (a guess).
    pub bits: f64,
    /// 0 none, 1 weak, 2 fair, 3 strong, 4 very strong.
    pub level: u8,
    pub label: &'static str,
    pub warnings: Vec<&'static str>,
}

/// Lowercased characters in a zeroizing buffer (the checks never leave plain copies behind).
fn lower_chars(s: &str) -> Zeroizing<Vec<char>> {
    let mut v = Zeroizing::new(Vec::with_capacity(s.len()));
    for c in s.chars().flat_map(char::to_lowercase) {
        v.push(c);
    }
    v
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

/// `a` then `b` are neighbours on a keyboard row or in the alphabet / digits (either direction).
fn in_row(a: char, b: char) -> bool {
    if !(a.is_ascii() && b.is_ascii()) {
        return false;
    }
    let (a, b) = (a as u8, b as u8);
    ROWS.iter().any(|r| r.as_bytes().windows(2).any(|w| (w[0] == a && w[1] == b) || (w[0] == b && w[1] == a)))
}

/// A predictable step from `a` to `b`: same character, next / previous code point, keyboard row.
fn predictable_step(a: char, b: char) -> bool {
    let step = b as i64 - a as i64;
    a == b || step.abs() == 1 || in_row(a, b)
}

/// Number of characters that continue a run (same char) or a sequence (ab, 12, keyboard rows).
fn predictable_chars(c: &[char]) -> usize {
    c.windows(2).filter(|w| predictable_step(w[0], w[1])).count()
}

/// The longest stretch of one repeated character, or of one direction of sequence / keyboard row.
fn longest_pattern(c: &[char]) -> usize {
    let (mut best, mut same, mut seq, mut dir) = (c.len().min(1), 1usize, 1usize, 0i64);
    for w in c.windows(2) {
        let (a, b) = (w[0], w[1]);
        same = if a == b { same + 1 } else { 1 };
        let step = b as i64 - a as i64;
        let d = if step.abs() == 1 {
            step
        } else if in_row(a, b) {
            // keyboard rows: direction = order on the row
            let row = ROWS.iter().find(|r| r.contains(a) && r.contains(b));
            row.map(|r| if r.find(b) > r.find(a) { 2 } else { -2 }).unwrap_or(0)
        } else {
            0
        };
        seq = if d != 0 && d == dir { seq + 1 } else if d != 0 { 2 } else { 1 };
        dir = d;
        best = best.max(same).max(seq);
    }
    best
}

/// Length of the shortest unit whose repetition gives the whole string ("abcabc" -> 3).
fn repeat_unit(c: &[char]) -> usize {
    let n = c.len();
    for u in 1..=n / 2 {
        if n.is_multiple_of(u) && (u..n).all(|i| c[i] == c[i % u]) {
            return u;
        }
    }
    n
}

/// Name of the signed-in user (from the environment; empty when unknown). Lowercase.
pub fn user_name() -> Zeroizing<String> {
    let n = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
    Zeroizing::new(n.to_lowercase())
}

/// The findings for a new password. `blocks` empty = it may be used; `warnings` non-empty = only
/// after "use it anyway".
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Check {
    pub blocks: Vec<String>,
    pub warnings: Vec<String>,
}

impl Check {
    pub fn usable(&self) -> bool {
        self.blocks.is_empty()
    }
    /// Blocks first, then warnings (the live list under the field).
    pub fn all(&self) -> impl Iterator<Item = &String> {
        self.blocks.iter().chain(&self.warnings)
    }
}

/// What a new password is checked against.
#[derive(Clone, Copy, Debug)]
pub struct Rules<'a> {
    /// A key file is used too (an empty password is then allowed, but warned about).
    pub has_keyfile: bool,
    /// Hard minimum in characters (0 = none). Only the PIM rule sets it: below the default PIM the
    /// KDF is cheaper per guess, so a longer password is required (see `engine::min_password_len`).
    pub min_len: usize,
    /// Lowercase user name to look for (empty = skip).
    pub user: &'a str,
}

/// The one checker for every new password. `confirm_ok`: the confirmation field matches (`None` =
/// there is no confirmation, e.g. `--password` on the console). `overflow`: more than the input
/// buffer holds was typed (the password is refused, never cut).
pub fn check_new(pw: &str, confirm_ok: Option<bool>, overflow: bool, r: Rules) -> Check {
    let mut c = Check::default();
    let n = length(pw);
    if overflow {
        c.blocks.push(tf("ui.pw_too_long", &[&crate::harden::SECRET_CAP]));
    }
    if n == 0 && !r.has_keyfile {
        c.blocks.push(t("pw.b_empty").into());
    }
    if r.min_len > 0 && n < r.min_len && !(n == 0 && r.has_keyfile) {
        c.blocks.push(tf("pw.b_min_len_pim", &[&r.min_len, &n]));
    }
    if confirm_ok == Some(false) {
        c.blocks.push(t("pw.b_confirm").into());
    }
    c.warnings = weak_reasons_for(pw, r.has_keyfile, r.user);
    c
}

/// Reasons a new password needs the explicit "use it anyway" confirmation (B-10). Empty = fine.
/// The confirmation dialog lists these and has Cancel as its default button.
pub fn weak_reasons(pw: &str, has_keyfile: bool) -> Vec<String> {
    weak_reasons_for(pw, has_keyfile, &user_name())
}

fn weak_reasons_for(pw: &str, has_keyfile: bool, user: &str) -> Vec<String> {
    let n = length(pw);
    let mut r = Vec::new();
    if n == 0 {
        if has_keyfile {
            r.push(t("pw.r_empty_with_kf").to_string());
        }
        return r;
    }
    let lower = Zeroizing::new(pw.to_lowercase());
    let chars = lower_chars(pw);
    if n < RECOMMENDED_LEN {
        r.push(tf("pw.r_short", &[&n]));
    }
    let digits = pw.chars().all(|c| c.is_ascii_digit());
    let lowers = pw.chars().all(|c| c.is_ascii_lowercase());
    let uppers = pw.chars().all(|c| c.is_ascii_uppercase());
    if digits {
        r.push(t("pw.r_digits_only").into());
    } else if lowers || uppers {
        r.push(t("pw.r_letters_only").into());
    }
    if COMMON.iter().any(|c| lower.as_str() == *c) {
        r.push(t("pw.r_common").into());
    } else if COMMON.iter().any(|c| c.chars().count() >= 5 && lower.contains(c)) {
        r.push(t("pw.r_contains_common").into());
    }
    if longest_pattern(&chars) >= PATTERN_RUN || (repeat_unit(&chars) < chars.len() && n >= 4) {
        r.push(t("pw.r_pattern").into());
    }
    let user_hit = user.chars().count() >= 3 && lower.contains(user);
    if NAMES.iter().any(|x| lower.contains(x)) || user_hit {
        r.push(t("pw.r_name").into());
    }
    let a = assess(pw);
    if r.is_empty() && a.level <= 2 {
        r.push(tf("pw.r_low_score", &[&(a.bits as u32)]));
    }
    r
}

pub fn assess(pw: &str) -> Assessment {
    let mut w = Vec::new();
    let n = length(pw);
    if n == 0 {
        return Assessment { bits: 0.0, level: 0, label: t("pw.none"), warnings: w };
    }
    let lower = Zeroizing::new(pw.to_lowercase());
    let chars = lower_chars(pw);
    let per = charset_bits(pw);
    let unit = repeat_unit(&chars);
    let mut effective = n as f64;
    if unit < chars.len() {
        w.push(t("pw.w_repeat"));
        effective = unit as f64 + 1.0;
    }
    let pred = predictable_chars(&chars);
    if pred * 2 >= n && n >= 4 {
        w.push(t("pw.w_sequence"));
    }
    effective = (effective - pred as f64 * 0.75).max(1.0);
    let mut bits = effective * per;
    if COMMON.iter().any(|c| lower.as_str() == *c) {
        w.push(t("pw.w_common"));
        bits = bits.min(10.0);
    } else if COMMON.iter().chain(NAMES).any(|c| c.chars().count() >= 5 && lower.contains(c)) {
        w.push(t("pw.w_contains_common"));
        bits -= 15.0;
    }
    if pw.chars().all(|c| c.is_ascii_digit()) {
        w.push(t("pw.w_digits"));
    }
    let bits = bits.max(0.0);
    let level = if bits < 40.0 {
        1
    } else if bits < 60.0 {
        2
    } else if bits < 80.0 {
        3
    } else {
        4
    };
    let label = t(["pw.none", "pw.weak", "pw.fair", "pw.strong", "pw.very_strong"][level as usize]);
    Assessment { bits, level, label, warnings: w }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{t, tf};

    const STRONG: &str = "correct-Horse7-battery-staple";

    fn rules() -> Rules<'static> {
        Rules { has_keyfile: false, min_len: 0, user: "" }
    }
    fn warns(pw: &str) -> Vec<String> {
        check_new(pw, Some(true), false, rules()).warnings
    }

    #[test]
    fn nfc_makes_hangul_input_methods_equal() {
        let composed = "한글암호";
        let decomposed: String = composed.nfd().collect();
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        assert_eq!(&*normalize(composed), &*normalize(&decomposed));
        assert_eq!(&*normalize("abc"), b"abc");
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        assert_eq!(length("한글암호"), 4);
        let decomposed: String = "한글암호".nfd().collect();
        assert_eq!(length(&decomposed), 4, "jamo typed separately are still 4 characters");
        // built from code points: the glyph audit keeps emoji out of the source
        let cps = |v: &[u32]| v.iter().filter_map(|c| char::from_u32(*c)).collect::<String>();
        assert_eq!(length(&cps(&[0x1F44D, 0x1F3FD])), 1, "emoji with a skin tone modifier");
        assert_eq!(length(&cps(&[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467])), 1, "family emoji (ZWJ sequence)");
        assert_eq!(length(&cps(&[0x65, 0x301])), 1, "combining accent");
        // a 13-character Hangul / emoji password is not "short"
        let ko = "가나다라마바사아자차카타파";
        assert_eq!(length(ko), 13);
        assert!(!warns(ko).contains(&tf("pw.r_short", &[&13usize])));
        assert!(warns("가나다라마바사아자차카타").contains(&tf("pw.r_short", &[&12usize])));
    }

    #[test]
    fn weak_patterns_are_flagged() {
        assert_eq!(assess("password").level, 1);
        assert_eq!(assess("12345678").level, 1);
        assert!(!assess("abcabcabcabc").warnings.is_empty());
        assert!(!assess("aaaaaaaaaaaa").warnings.is_empty());
        assert!(!assess("qwertyuiop").warnings.is_empty());
        let good = assess(STRONG);
        assert!(good.warnings.is_empty() && good.bits >= 80.0, "{}", good.bits);
    }

    #[test]
    fn each_reason_is_reported() {
        let has = |pw: &str, key: &'static str| warns(pw).iter().any(|w| w == t(key));
        assert!(warns("Zk#9vQ!x").contains(&tf("pw.r_short", &[&8usize])), "short");
        assert!(warns("Zk#9vQ!x2Lp$").contains(&tf("pw.r_short", &[&12usize])), "12 is still short");
        assert!(!warns("Zk#9vQ!x2Lp$7").contains(&tf("pw.r_short", &[&13usize])), "13 is not short");
        assert!(has("80417395261847", "pw.r_digits_only"));
        assert!(has("thequickbrownfoxjumps", "pw.r_letters_only"));
        assert!(has("THEQUICKBROWNFOXJUMPS", "pw.r_letters_only"));
        assert!(has("password", "pw.r_common"));
        assert!(has("My-password-Vault-77", "pw.r_contains_common"));
        for p in ["Vb7#aaaa-Kq2!", "Vb7#1234-Kq2!", "Vb7#qwer-Kq2!", "Vb7#dcba-Kq2!", "Vb7#Kq2!Vb7#Kq2!"] {
            assert!(has(p, "pw.r_pattern"), "{p}");
        }
        assert!(has("My-Shield-Vault-7x!", "pw.r_name"));
        let w = check_new("Kq2!jsmith-Vault-77", Some(true), false, Rules { user: "jsmith", ..rules() }).warnings;
        assert!(w.iter().any(|x| x == t("pw.r_name")), "user name");
        assert!(weak_reasons("", true).iter().any(|x| x == t("pw.r_empty_with_kf")));
    }

    #[test]
    fn strong_password_has_no_warning() {
        for p in [STRONG, "Zk#9vQ!x2Lp$7", "녹차-Rain7-다람쥐-Mug"] {
            assert!(warns(p).is_empty(), "{p}: {:?}", warns(p));
            assert!(check_new(p, Some(true), false, Rules { has_keyfile: true, ..rules() }).warnings.is_empty());
        }
    }

    #[test]
    fn blocks_and_warnings_are_separate() {
        // blocked: empty, confirmation differs, too long, low-PIM minimum
        let c = check_new("", Some(true), false, rules());
        assert_eq!(c.blocks, vec![t("pw.b_empty").to_string()]);
        assert!(!c.usable());
        let c = check_new(STRONG, Some(false), false, rules());
        assert_eq!(c.blocks, vec![t("pw.b_confirm").to_string()]);
        let c = check_new(STRONG, Some(true), true, rules());
        assert_eq!(c.blocks.len(), 1);
        let c = check_new(STRONG, None, false, Rules { min_len: 30, ..rules() });
        assert_eq!(c.blocks, vec![tf("pw.b_min_len_pim", &[&30usize, &length(STRONG)])]);
        // usable after a warning: short, simple, common
        for p in ["abc", "12345678", "password1"] {
            let c = check_new(p, Some(true), false, rules());
            assert!(c.usable() && !c.warnings.is_empty(), "{p}");
        }
        // key file only: allowed, warned
        let c = check_new("", Some(true), false, Rules { has_keyfile: true, ..rules() });
        assert!(c.usable() && c.warnings == vec![t("pw.r_empty_with_kf").to_string()]);
    }

    #[test]
    fn weak_password_reasons() {
        assert!(!weak_reasons("short", false).is_empty(), "12 characters or fewer");
        assert!(!weak_reasons("passwordpassword", false).is_empty(), "long but a weak pattern");
        assert!(!weak_reasons("12345678901234", false).is_empty(), "long but digits in sequence");
        assert!(!weak_reasons("", true).is_empty(), "key file with an empty password still asks");
        assert!(!weak_reasons("abc", true).is_empty(), "key file with a very weak password still asks");
        assert!(weak_reasons(STRONG, false).is_empty());
        assert!(weak_reasons(STRONG, true).is_empty());
    }
}
