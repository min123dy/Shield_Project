//! A-2 glyph audit (test only). The UI draws with Malgun Gothic first and egui's bundled
//! Ubuntu-Light as fallback; no emoji font is relied on. Every non-ASCII, non-Hangul character in
//! the code and in the string tables must be listed here and must exist in one of those fonts.
//!
//! Characters removed in 2.1 (they rendered as boxes or depended on the emoji font):
//! check mark -> "●", heavy x -> "×", warning sign -> "※", double bar -> "|" / "+",
//! em dash -> "-", arrows -> "->", folder/file/lock/key/gear/magnifier emoji -> text only.

/// Allowed special characters and where they are used.
pub const ALLOWED: &[(char, &str)] = &[
    ('\u{00B7}', "middle dot: separators in messages"),
    ('\u{00D7}', "multiplication sign: chunk count, remove button, failed check"),
    ('\u{2022}', "bullet: help lists"),
    ('\u{2026}', "ellipsis: buttons that open a dialog, truncated cells"),
    ('\u{203A}', "single angle quote: path inside a container"),
    ('\u{203B}', "reference mark: warnings"),
    ('\u{25B6}', "triangle: current stage"),
    ('\u{25CB}', "white circle: pending stage, 'no' rows"),
    ('\u{25CF}', "black circle: passed checks, done stage"),
];

/// Characters that appear only in code that inspects names (never drawn): superscript digits
/// that Windows treats as device names ("COM¹").
pub const CODE_ONLY: &[char] = &['\u{00B9}', '\u{00B2}', '\u{00B3}'];

#[cfg(test)]
mod tests {
    use super::{ALLOWED, CODE_ONLY};
    use ab_glyph::{Font, FontRef};
    use std::path::Path;

    /// Hangul syllables and compatibility jamo (both in Malgun Gothic).
    fn hangul(c: char) -> bool {
        ('\u{AC00}'..='\u{D7A3}').contains(&c) || ('\u{3131}'..='\u{318E}').contains(&c)
    }

    fn special(c: char) -> bool {
        !c.is_ascii() && !hangul(c)
    }

    fn allowed(c: char) -> bool {
        ALLOWED.iter().any(|(a, _)| *a == c)
    }

    /// Replaces `\u{..}` escapes so escaped characters are checked as well.
    fn unescape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("\\u{") {
            out.push_str(&rest[..i]);
            let tail = &rest[i + 3..];
            match tail.find('}').and_then(|j| u32::from_str_radix(&tail[..j], 16).ok().and_then(char::from_u32).map(|c| (c, j))) {
                Some((c, j)) => {
                    out.push(c);
                    rest = &tail[j + 1..];
                }
                None => {
                    out.push_str("\\u{");
                    rest = tail;
                }
            }
        }
        out.push_str(rest);
        out
    }

    fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                sources(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push((p.display().to_string(), std::fs::read_to_string(&p).unwrap()));
            }
        }
    }

    /// Code lines without comments (`//` at the start or after a space).
    fn code_part(line: &str) -> &str {
        let t = line.trim_start();
        if t.starts_with("//") {
            return "";
        }
        match line.find(" //") {
            Some(i) => &line[..i],
            None => line,
        }
    }

    fn all_strings() -> Vec<&'static str> {
        let mut v = vec![];
        for t in [crate::lang::ko_core::T, crate::lang::en_core::T, crate::lang::ko_ui::T, crate::lang::en_ui::T] {
            v.extend(t.iter().map(|(_, s)| *s));
        }
        for h in [crate::lang::help_ko::ENC_USAGE, crate::lang::help_ko::MGR_USAGE, crate::lang::help_en::ENC_USAGE, crate::lang::help_en::MGR_USAGE] {
            for (title, lines) in h {
                v.push(title);
                v.extend(lines.iter().copied());
            }
        }
        for r in [crate::lang::help_ko::ALGO_ROWS, crate::lang::help_en::ALGO_ROWS] {
            v.extend(r.iter().flat_map(|(a, b)| [*a, *b]));
        }
        v.extend(crate::lang::help_ko::ALGO_NOTES.iter().chain(crate::lang::help_en::ALGO_NOTES));
        v
    }

    #[test]
    fn source_uses_only_allowed_special_characters() {
        let mut files = vec![];
        sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        assert!(files.len() > 20);
        let mut bad = vec![];
        // this file names the removed emoji on purpose (font test below)
        for (name, text) in files.iter().filter(|(n, _)| !n.ends_with("glyphs.rs")) {
            for (n, line) in text.lines().enumerate() {
                for c in unescape(code_part(line)).chars().filter(|c| special(*c) && !allowed(*c) && !CODE_ONLY.contains(c)) {
                    bad.push(format!("{name}:{}: U+{:04X} {c}", n + 1, c as u32));
                }
            }
        }
        assert!(bad.is_empty(), "characters outside the glyph list:\n{}", bad.join("\n"));
    }

    #[test]
    fn tables_use_only_allowed_special_characters() {
        let bad: Vec<String> = all_strings().iter().flat_map(|s| s.chars()).filter(|c| special(*c) && !allowed(*c)).map(|c| format!("U+{:04X} {c}", c as u32)).collect();
        assert!(bad.is_empty(), "{bad:?}");
    }

    /// Every allowed character exists in Malgun Gothic or in egui's bundled Ubuntu-Light, and every
    /// Hangul syllable used exists in Malgun Gothic. Skipped where the Windows font is absent.
    #[test]
    fn allowed_characters_exist_in_the_fonts() {
        let defs = eframe::egui::FontDefinitions::default();
        let ubuntu = FontRef::try_from_slice(&defs.font_data["Ubuntu-Light"].font).unwrap();
        let malgun_bytes = std::fs::read(r"C:\Windows\Fonts\malgun.ttf").ok();
        let malgun = malgun_bytes.as_deref().map(|b| FontRef::try_from_slice(b).unwrap());
        let has = |f: &FontRef, c: char| f.glyph_id(c).0 != 0;
        let mut missing = vec![];
        for (c, what) in ALLOWED {
            let ok = has(&ubuntu, *c) || malgun.as_ref().is_some_and(|m| has(m, *c));
            if !ok && malgun.is_some() {
                missing.push(format!("U+{:04X} {c} ({what})", *c as u32));
            }
        }
        if let Some(m) = &malgun {
            for c in all_strings().iter().flat_map(|s| s.chars()).filter(|c| hangul(*c)) {
                if !has(m, c) {
                    missing.push(format!("Hangul U+{:04X} {c}", c as u32));
                }
            }
            // the replaced symbols really were the problem: no emoji glyphs in either font
            for c in ['\u{1F512}', '\u{1F4C1}', '\u{1F5C2}', '\u{1F9EC}', '\u{1F9FD}'] {
                assert!(!has(m, c) && !has(&ubuntu, c), "U+{:04X} unexpectedly present", c as u32);
            }
        }
        assert!(missing.is_empty(), "{missing:?}");
    }
}
