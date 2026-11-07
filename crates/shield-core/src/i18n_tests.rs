//! E-3: both languages have the same keys and arguments, every key used in the code exists, and
//! the help texts have the same structure.

use super::*;
use crate::lang::{help_en, help_ko};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

fn keys(t: Table) -> BTreeSet<&'static str> {
    let mut seen = HashSet::new();
    for (k, _) in t {
        assert!(seen.insert(*k), "duplicate key {k}");
    }
    t.iter().map(|(k, _)| *k).collect()
}

fn args(s: &str) -> usize {
    s.matches("{}").count()
}

#[test]
fn both_languages_have_the_same_keys() {
    let (ko, en) = (tables(Lang::Ko), tables(Lang::En));
    for (i, (a, b)) in ko.iter().zip(en.iter()).enumerate() {
        let area = ["core", "ui", "v3", "cli"][i];
        let (ka, kb) = (keys(a), keys(b));
        let only_ko: Vec<_> = ka.difference(&kb).collect();
        let only_en: Vec<_> = kb.difference(&ka).collect();
        assert!(only_ko.is_empty() && only_en.is_empty(), "{area}: only ko {only_ko:?}, only en {only_en:?}");
    }
    let mut all = HashSet::new();
    for t in ko {
        for (k, _) in t {
            assert!(all.insert(*k), "key {k} in two areas");
        }
    }
}

#[test]
fn both_languages_take_the_same_arguments() {
    for (a, b) in tables(Lang::Ko).into_iter().zip(tables(Lang::En)) {
        for (k, ko) in a {
            let en = b.iter().find(|(x, _)| x == k).map(|(_, s)| *s).unwrap();
            assert_eq!(args(ko), args(en), "{k}: ko {ko:?} / en {en:?}");
        }
    }
}

#[test]
fn appended_fragments_start_with_a_separator_in_both_languages() {
    // these are added to the end of another message
    for k in ["eng.skipped", "eng.no_guarantee", "eng.wipe_cancelled", "eng.wipe_failed", "eng.zone_only", "man.streams_shredded", "man.changed_kept", "man.hardlinks_kept", "man.shred_failed", "man.dirs_kept", "ui.eta", "job.secs", "eng.some_stored"] {
        for m in [map(Lang::Ko), map(Lang::En)] {
            assert!(m[k].starts_with(' '), "{k}");
        }
    }
}

fn source_keys() -> BTreeSet<String> {
    const PREFIXES: &[&str] = &[
        "ads", "algo", "arc", "cap", "col", "comp", "cont", "crypto", "dlg", "eng", "err", "fmt", "help", "i", "job", "kf", "m", "man", "p", "pw", "set", "shell",
        "st", "stage", "stage_s", "sys", "tab", "ui", "v", "wipe", "sig", "upd", "cli", "ent", "info", "multi", "harden", "win",
    ];
    // file names that look like keys ("m.shd" in a test)
    const NOT_KEYS: &[&str] = &["shd", "rs", "txt", "lst", "key", "lck", "tmp", "ttf", "exe", "pdf", "toml"];
    let mut out = BTreeSet::new();
    // keys are used by every crate of the workspace (core, GUI, console)
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut stack: Vec<_> = ["shield-core", "shield-gui", "shield-cli"].iter().map(|c| crates.join(c).join("src")).filter(|p| p.is_dir()).collect();
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                if !p.ends_with("lang") {
                    stack.push(p);
                }
                continue;
            }
            if !p.extension().is_some_and(|x| x == "rs") || p.file_name().is_some_and(|n| n.to_string_lossy().ends_with("tests.rs")) {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            // every `"word.word"` run, independent of how the quotes pair up elsewhere in the file
            let b = text.as_bytes();
            let key_byte = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.';
            for (i, _) in text.match_indices('"') {
                let mut j = i + 1;
                while j < b.len() && key_byte(b[j]) {
                    j += 1;
                }
                if j >= b.len() || b[j] != b'"' || j == i + 1 {
                    continue;
                }
                let lit = &text[i + 1..j];
                let Some((pre, rest)) = lit.split_once('.') else { continue };
                if PREFIXES.contains(&pre) && !rest.is_empty() && !rest.contains('.') && !NOT_KEYS.contains(&rest) {
                    out.insert(lit.to_string());
                }
            }
        }
    }
    out
}

#[test]
fn every_key_used_in_the_code_exists() {
    let used = source_keys();
    assert!(used.len() > 400, "scanner found only {} keys", used.len());
    for l in [Lang::Ko, Lang::En] {
        let m = map(l);
        let missing: Vec<_> = used.iter().filter(|k| !m.contains_key(k.as_str())).collect();
        assert!(missing.is_empty(), "{l:?} is missing {missing:?}");
    }
}

#[test]
fn no_table_entry_is_unused() {
    let used = source_keys();
    let unused: Vec<_> = tables(Lang::Ko).into_iter().flat_map(keys).filter(|k| !used.contains(*k)).collect();
    assert!(unused.is_empty(), "unused keys {unused:?}");
}

#[test]
fn help_texts_have_the_same_structure() {
    for (a, b) in [(help_ko::ENC_USAGE, help_en::ENC_USAGE), (help_ko::MGR_USAGE, help_en::MGR_USAGE)] {
        assert_eq!(a.len(), b.len());
        for ((_, la), (tb, lb)) in a.iter().zip(b) {
            assert_eq!(la.len(), lb.len(), "section {tb}");
        }
    }
    assert_eq!(help_ko::ALGO_ROWS.len(), help_en::ALGO_ROWS.len());
    assert_eq!(help_ko::ALGO_NOTES.len(), help_en::ALGO_NOTES.len());
}

#[test]
fn lookup_fill_and_codes() {
    assert_eq!(map(Lang::En)["tab.encrypt"], "Encrypt");
    assert_eq!(map(Lang::Ko)["tab.encrypt"], "암호화");
    assert_eq!(fill("a {} b {}", &[&1, &"x"]), "a 1 b x");
    assert_eq!(fill("{} {}", &[&1]), "1 {}", "a missing argument stays visible");
    let m = coded("E_X", "tab.help");
    assert!(has_code(&m, "E_X") && !has_code(&m, "E_Y"));
    assert_eq!(t("no.such_key"), "no.such_key");
    // the error code is the same whatever the language
    for l in [Lang::Ko, Lang::En] {
        let s = format!("{} [E_BAD]", map(l)["err.bad"]);
        assert!(has_code(&s, "E_BAD"));
    }
}

#[test]
fn system_language_is_korean_or_english() {
    assert!(matches!(system_lang(), Lang::Ko | Lang::En));
}
