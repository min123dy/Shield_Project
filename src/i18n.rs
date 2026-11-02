//! UI language (Korean / English). Every user-visible string goes through `t("key")` or
//! `tf("key", &[..])`; the tables live in `lang/` (one module per language and area), so adding a
//! language means adding tables with the same keys. Tests check that both languages have the same
//! keys, the same number of `{}` arguments, that every key used in the source exists, and that no
//! string needs a glyph the bundled fonts lack.
//!
//! Errors that code must recognise carry a language-independent code (`[E_BAD]`); the text in front
//! of it is translated, the code is not.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    Ko,
    En,
}

static CUR: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(l: Lang) {
    CUR.store(l as u8, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    if CUR.load(Ordering::Relaxed) == Lang::En as u8 {
        Lang::En
    } else {
        Lang::Ko
    }
}

/// Windows UI language (Korean -> Ko, anything else -> En).
pub fn system_lang() -> Lang {
    #[cfg(windows)]
    {
        let id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
        if id & 0x3FF == 0x12 {
            return Lang::Ko;
        }
        Lang::En
    }
    #[cfg(not(windows))]
    {
        match std::env::var("LANG") {
            Ok(v) if v.starts_with("ko") => Lang::Ko,
            _ => Lang::En,
        }
    }
}

pub type Table = &'static [(&'static str, &'static str)];

fn tables(l: Lang) -> [Table; 2] {
    match l {
        Lang::Ko => [crate::lang::ko_core::T, crate::lang::ko_ui::T],
        Lang::En => [crate::lang::en_core::T, crate::lang::en_ui::T],
    }
}

fn map(l: Lang) -> &'static HashMap<&'static str, &'static str> {
    static KO: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    static EN: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    let cell = if l == Lang::Ko { &KO } else { &EN };
    cell.get_or_init(|| tables(l).iter().flat_map(|t| t.iter().copied()).collect())
}

/// Translated text for `key` in the current language (the key itself if missing; tests forbid that).
pub fn t(key: &'static str) -> &'static str {
    map(lang()).get(key).copied().unwrap_or(key)
}

/// `t(key)` with each `{}` replaced by the next argument.
pub fn tf(key: &'static str, args: &[&dyn Display]) -> String {
    fill(t(key), args)
}

pub fn fill(s: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    let mut it = args.iter();
    let mut rest = s;
    while let Some(i) = rest.find("{}") {
        out.push_str(&rest[..i]);
        match it.next() {
            Some(a) => out.push_str(&a.to_string()),
            None => out.push_str("{}"),
        }
        rest = &rest[i + 2..];
    }
    out.push_str(rest);
    out
}

/// Translated message followed by its stable code, e.g. "... [E_BAD]".
pub fn coded(code: &str, key: &'static str) -> String {
    format!("{} [{code}]", t(key))
}

pub fn has_code(msg: &str, code: &str) -> bool {
    msg.contains(&format!("[{code}]"))
}

#[cfg(test)]
#[path = "i18n_tests.rs"]
mod tests;
