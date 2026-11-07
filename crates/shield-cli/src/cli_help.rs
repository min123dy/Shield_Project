//! Console help (3.0.0 §7), built from one source: the command and option tables of `args` plus
//! the translated texts below (ko / en in shield-core's `lang/*_cli.rs`). `shield help`,
//! `shield -h | --help | -help`, `shield help <command>` and `shield <command> -h | --help |
//! -help` all print from here. Printing help has no side effects: nothing is written, no
//! secret is asked, no network is used.
//!
//! Layout: wrapped to the terminal width (`COLUMNS`, else the console size, else 80; display
//! width aware for Hangul), headings in bold only on a terminal without `NO_COLOR` / `TERM=dumb`.

use crate::args::{spec, Opt, COMMANDS, COMMON, CRED, NEW_CRED};
use crate::i18n::{t_in, Lang};
use unicode_width::UnicodeWidthStr;

/// (command, synopsis key or "", summary key). Every command of `args::COMMANDS` is here (test).
pub const CMDS: &[(&str, &str, &str)] = &[
    ("encrypt", "cli.s_encrypt", "cli.h_encrypt"),
    ("decrypt", "cli.s_container", "cli.h_decrypt"),
    ("list", "cli.s_container", "cli.h_list"),
    ("add", "cli.s_add", "cli.h_add"),
    ("remove", "cli.s_remove", "cli.h_remove"),
    ("change-password", "cli.s_container", "cli.h_change_password"),
    ("rekey", "cli.s_container", "cli.h_rekey"),
    ("keyfile", "cli.s_keyfile", "cli.h_keyfile"),
    ("verify", "cli.s_verify", "cli.h_verify"),
    ("update", "", "cli.h_update"),
    ("entropy", "", "cli.h_entropy"),
    ("version", "", "cli.h_version"),
    ("help", "cli.s_help", "cli.h_help"),
    ("gui", "cli.s_gui", "cli.h_gui"),
];

/// (command or "" for all, option, value placeholder key or "", description key). Every option
/// of every command is here (test); a command-specific row wins over the general one.
pub const OPTS: &[(&str, &str, &str, &str)] = &[
    ("", "quiet", "", "cli.o_quiet"),
    ("", "json", "", "cli.o_json"),
    ("", "yes", "", "cli.o_yes"),
    ("", "lang", "cli.v_lang", "cli.o_lang"),
    ("", "keyfile", "cli.v_path", "cli.o_keyfile"),
    ("", "pim", "cli.v_pim", "cli.o_pim"),
    ("", "reveal", "", "cli.o_reveal"),
    ("", "password", "cli.v_pw", "cli.o_password"),
    ("", "allow-arg-secrets", "", "cli.o_allow_arg"),
    ("", "new-keyfile", "cli.v_path", "cli.o_new_keyfile"),
    ("", "new-pim", "cli.v_pim", "cli.o_new_pim"),
    ("", "new-password", "cli.v_pw", "cli.o_new_password"),
    ("encrypt", "output", "cli.v_path", "cli.o_output_enc"),
    ("decrypt", "output", "cli.v_folder", "cli.o_output_dec"),
    ("", "separate", "", "cli.o_separate"),
    ("encrypt", "shred", "", "cli.o_shred"),
    ("add", "shred", "", "cli.o_shred_add"),
    ("", "passes", "cli.v_passes", "cli.o_passes"),
    ("", "wipe-free", "", "cli.o_wipe_free"),
    ("", "strength", "cli.v_strength", "cli.o_strength"),
    ("", "include-streams", "", "cli.o_include_streams"),
    ("", "into", "cli.v_folder", "cli.o_into"),
    ("", "overwrite", "", "cli.o_overwrite"),
    ("", "size", "cli.v_kib", "cli.o_size"),
    ("", "key", "cli.v_key", "cli.o_key"),
    ("", "check", "", "cli.o_check"),
    ("", "enable", "cli.v_source", "cli.o_enable"),
    ("", "disable", "cli.v_source", "cli.o_disable"),
];

#[derive(Clone, Copy, Debug)]
pub struct Style {
    pub width: usize,
    pub color: bool,
}

impl Style {
    /// Plain 80 columns (tests and snapshots).
    #[cfg(test)]
    pub const PLAIN: Style = Style { width: 80, color: false };

    /// For stdout of this process.
    pub fn detect() -> Style {
        use std::io::IsTerminal;
        let tty = std::io::stdout().is_terminal();
        let cols = std::env::var("COLUMNS").ok().and_then(|v| v.trim().parse::<usize>().ok()).filter(|w| *w > 0);
        let term = if tty { crossterm::terminal::size().ok().map(|(w, _)| w as usize).filter(|w| *w > 0) } else { None };
        let width = cols.or(term).unwrap_or(80).clamp(40, 160);
        Style { width, color: tty && color_allowed(std::env::var_os("NO_COLOR").as_deref(), std::env::var("TERM").ok().as_deref()) && ansi() }
    }
}

/// https://no-color.org: any non-empty NO_COLOR turns colour off; so does TERM=dumb.
pub fn color_allowed(no_color: Option<&std::ffi::OsStr>, term: Option<&str>) -> bool {
    !no_color.is_some_and(|v| !v.is_empty()) && term != Some("dumb")
}

#[cfg(windows)]
fn ansi() -> bool {
    crossterm::ansi_support::supports_ansi()
}
#[cfg(not(windows))]
fn ansi() -> bool {
    true
}

fn opt_help(cmd: &str, name: &str) -> (&'static str, &'static str) {
    OPTS.iter().find(|o| o.0 == cmd && o.1 == name).or_else(|| OPTS.iter().find(|o| o.0.is_empty() && o.1 == name)).map(|o| (o.2, o.3)).unwrap_or(("", ""))
}

pub fn cmd_help(cmd: &str) -> Option<&'static (&'static str, &'static str, &'static str)> {
    CMDS.iter().find(|c| c.0 == cmd)
}

/// Splits `s` into lines of at most `w` display columns (words longer than that stay whole).
pub fn wrap(s: &str, w: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in s.split('\n') {
        let mut line = String::new();
        for word in para.split(' ').filter(|x| !x.is_empty()) {
            if !line.is_empty() && line.width() + 1 + word.width() > w {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        out.push(line);
    }
    out
}

struct Page {
    st: Style,
    out: String,
}

impl Page {
    fn heading(&mut self, h: &str) {
        if !self.out.is_empty() {
            self.out.push('\n');
        }
        if self.st.color {
            self.out.push_str(&format!("\x1b[1m{h}\x1b[0m\n"));
        } else {
            self.out.push_str(h);
            self.out.push('\n');
        }
    }

    fn text(&mut self, s: &str) {
        for l in wrap(s, self.st.width.saturating_sub(2)) {
            self.out.push_str(&format!("  {l}\n").replace("  \n", "\n"));
        }
    }

    /// `label` in the left column, `desc` wrapped in the right one (on the next line when the
    /// label is too wide or the terminal is narrow).
    fn row(&mut self, label: &str, desc: &str) {
        let col = if self.st.width < 60 { 6 } else { 28 };
        let avail = self.st.width.saturating_sub(col).max(16);
        let lines = wrap(desc, avail);
        let lead = format!("  {label}");
        let mut it = lines.into_iter();
        if lead.width() + 2 <= col {
            let first = it.next().unwrap_or_default();
            self.out.push_str(&format!("{lead}{}{first}\n", " ".repeat(col - lead.width())));
        } else {
            // a long label (the `gui` synopsis) wraps as well, continued further indented
            for (i, l) in wrap(label, self.st.width.saturating_sub(4)).into_iter().enumerate() {
                self.out.push_str(if i == 0 { "  " } else { "    " });
                self.out.push_str(&l);
                self.out.push('\n');
            }
        }
        for l in it {
            self.out.push_str(&format!("{}{l}\n", " ".repeat(col)));
        }
    }

    fn options(&mut self, l: Lang, cmd: &str, opts: &[Opt]) {
        for o in opts {
            let (ph, desc) = opt_help(cmd, o.0);
            let mut label = match o.2 {
                Some(c) => format!("-{c}, --{}", o.0),
                None => format!("--{}", o.0),
            };
            if !ph.is_empty() {
                label.push(' ');
                label.push_str(t_in(l, ph));
            }
            self.row(&label, t_in(l, desc));
        }
    }
}

/// `shield help`: all commands, the general options and the exit codes.
pub fn overview(l: Lang, st: Style, version: &str) -> String {
    let mut p = Page { st, out: String::new() };
    for line in wrap(&crate::i18n::fill(t_in(l, "cli.h_title"), &[&version]), st.width) {
        p.out.push_str(&line);
        p.out.push('\n');
    }
    p.heading(t_in(l, "cli.hd_usage"));
    p.text(t_in(l, "cli.h_usage_line"));
    p.heading(t_in(l, "cli.hd_commands"));
    for (c, syn, sum) in CMDS {
        let label = if syn.is_empty() { c.to_string() } else { format!("{c} {}", t_in(l, syn)) };
        p.row(&label, t_in(l, sum));
    }
    p.heading(t_in(l, "cli.hd_general"));
    p.options(l, "", COMMON);
    p.text(t_in(l, "cli.h_end_opts"));
    p.heading(t_in(l, "cli.hd_exit"));
    p.text(t_in(l, "cli.h_exit"));
    p.out.push('\n');
    p.text(t_in(l, "cli.h_more"));
    p.out
}

/// `shield help <command>` / `shield <command> --help`. None for an unknown command.
pub fn command(l: Lang, st: Style, cmd: &str) -> Option<String> {
    let s = spec(cmd)?;
    let (_, syn, sum) = cmd_help(cmd)?;
    let mut p = Page { st, out: String::new() };
    p.heading(t_in(l, "cli.hd_usage"));
    let opts = if cmd == "gui" { "" } else { t_in(l, "cli.v_options") };
    let syn = if syn.is_empty() { "" } else { t_in(l, syn) };
    p.text(&[format!("shield {cmd}"), opts.to_string(), syn.to_string()].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(" "));
    p.out.push('\n');
    p.text(t_in(l, sum));
    if !s.1.is_empty() {
        p.heading(t_in(l, "cli.hd_options"));
        p.options(l, cmd, s.1);
    }
    if s.2 {
        p.heading(t_in(l, "cli.hd_cred"));
        p.options(l, cmd, CRED);
    }
    if s.3 {
        p.heading(t_in(l, "cli.hd_new_cred"));
        p.options(l, cmd, NEW_CRED);
    }
    if cmd != "gui" {
        p.heading(t_in(l, "cli.hd_general"));
        p.options(l, cmd, COMMON);
    }
    Some(p.out)
}

/// The closest command name for a typo (edit distance <= 2, or a unique prefix).
pub fn suggest(x: &str) -> Option<&'static str> {
    fn dist(a: &str, b: &str) -> usize {
        let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for i in 1..=a.len() {
            let mut cur = vec![i; b.len() + 1];
            for j in 1..=b.len() {
                cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + usize::from(a[i - 1] != b[j - 1]));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let x = x.trim_start_matches('-').to_lowercase();
    if x.is_empty() || x.chars().count() > 40 {
        return None;
    }
    let names = COMMANDS.iter().map(|s| s.0);
    let pre: Vec<_> = names.clone().filter(|n| n.starts_with(&x)).collect();
    if pre.len() == 1 {
        return Some(pre[0]);
    }
    names.map(|n| (dist(&x, n), n)).filter(|(d, _)| *d <= 2).min().map(|(_, n)| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_and_option_has_help_in_both_languages() {
        for s in COMMANDS {
            assert!(cmd_help(s.0).is_some(), "no help for command {}", s.0);
            let mut sets: Vec<&[Opt]> = vec![COMMON, s.1];
            if s.2 {
                sets.push(CRED);
            }
            if s.3 {
                sets.push(NEW_CRED);
            }
            for o in sets.iter().flat_map(|x| x.iter()) {
                let (ph, d) = opt_help(s.0, o.0);
                assert!(!d.is_empty(), "no help for {} --{}", s.0, o.0);
                for l in [Lang::Ko, Lang::En] {
                    assert_ne!(t_in(l, d), d, "{l:?} misses {d}");
                    if !ph.is_empty() {
                        assert_ne!(t_in(l, ph), ph, "{l:?} misses {ph}");
                    }
                }
            }
            for l in [Lang::Ko, Lang::En] {
                let page = command(l, Style::PLAIN, s.0).unwrap();
                for o in s.1 {
                    assert!(page.contains(&format!("--{}", o.0)), "{l:?} {}: --{} not shown", s.0, o.0);
                }
            }
        }
        assert_eq!(CMDS.len(), COMMANDS.len(), "help for a command that does not exist");
        for o in OPTS {
            assert!(COMMON.iter().chain(CRED).chain(NEW_CRED).chain(COMMANDS.iter().flat_map(|s| s.1.iter())).any(|x| x.0 == o.1), "help for unknown option {}", o.1);
        }
    }

    #[test]
    fn wrapped_to_the_width_and_plain_without_colour() {
        for l in [Lang::Ko, Lang::En] {
            for w in [40, 60, 80, 120] {
                let st = Style { width: w, color: false };
                let mut pages = vec![overview(l, st, "3.0.0")];
                pages.extend(COMMANDS.iter().map(|s| command(l, st, s.0).unwrap()));
                for p in pages {
                    for line in p.lines() {
                        // a single word wider than the column may stay whole (paths, option names)
                        let long_word = line.split(' ').any(|x| x.width() > w.saturating_sub(28).max(16));
                        assert!(line.width() <= w || long_word, "{l:?} w={w}: {line:?}");
                        assert!(!line.contains('\x1b'), "no escape codes without colour");
                        assert_eq!(line.trim_end(), line, "trailing space");
                    }
                }
            }
        }
        let c = overview(Lang::En, Style { width: 80, color: true }, "3.0.0");
        assert!(c.contains("\x1b[1m"), "bold headings on a colour terminal");
        assert!(wrap("한글 단어 여러 개를 좁게", 10).iter().all(|l| l.width() <= 10), "Hangul counts two columns");
    }

    #[test]
    fn no_color_and_dumb_terminals() {
        use std::ffi::OsStr;
        assert!(color_allowed(None, Some("xterm-256color")));
        assert!(!color_allowed(Some(OsStr::new("1")), None));
        assert!(color_allowed(Some(OsStr::new("")), None), "empty NO_COLOR does not count");
        assert!(!color_allowed(None, Some("dumb")));
    }

    #[test]
    fn typos_get_a_suggestion() {
        assert_eq!(suggest("encrpyt"), Some("encrypt"));
        assert_eq!(suggest("dec"), Some("decrypt"));
        assert_eq!(suggest("lst"), Some("list"));
        assert_eq!(suggest("--rekye"), Some("rekey"));
        assert_eq!(suggest("zzzzzz"), None);
        assert_eq!(suggest("e"), None, "encrypt / entropy: not unique");
    }

    /// Snapshots: `SHIELD_BLESS=1 cargo test -p shield-cli help` writes them after a deliberate change.
    #[test]
    fn help_snapshots() {
        for (l, name) in [(Lang::Ko, "help_ko.txt"), (Lang::En, "help_en.txt")] {
            let mut all = overview(l, Style::PLAIN, "X.Y.Z");
            for s in COMMANDS {
                all.push_str(&format!("\n===== {}\n", s.0));
                all.push_str(&command(l, Style::PLAIN, s.0).unwrap());
            }
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots").join(name);
            if std::env::var_os("SHIELD_BLESS").is_some() {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, &all).unwrap();
                continue;
            }
            let want = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing {}: run with SHIELD_BLESS=1", p.display()));
            assert_eq!(all.replace("\r\n", "\n"), want.replace("\r\n", "\n"), "{name} changed: check the output, then SHIELD_BLESS=1");
        }
    }
}
