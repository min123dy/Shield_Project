//! Command-line parsing (small and table driven, so errors and help stay translated).
//! `shield <command> [options] [items...]`; `--` ends the options; unknown options are errors.

use std::collections::BTreeMap;

/// One option: name (without `--`), takes a value, short alias.
pub struct Opt(pub &'static str, pub bool, pub Option<char>);

pub const COMMON: &[Opt] = &[Opt("quiet", false, Some('q')), Opt("json", false, None), Opt("yes", false, Some('y')), Opt("lang", true, None)];
pub const CRED: &[Opt] = &[
    Opt("keyfile", true, Some('k')),
    Opt("pim", true, None),
    Opt("reveal", false, None),
    Opt("password", true, None),
    Opt("allow-arg-secrets", false, None),
];
pub const NEW_CRED: &[Opt] = &[Opt("new-keyfile", true, None), Opt("new-pim", true, None), Opt("new-password", true, None)];

/// (command, own options, uses credentials, uses new credentials, min items, max items)
pub struct Spec(pub &'static str, pub &'static [Opt], pub bool, pub bool, pub usize, pub usize);

pub const COMMANDS: &[Spec] = &[
    Spec(
        "encrypt",
        &[
            Opt("output", true, Some('o')),
            Opt("separate", false, None),
            Opt("shred", false, None),
            Opt("passes", true, None),
            Opt("wipe-free", false, None),
            Opt("strength", true, None),
            Opt("include-streams", false, None),
        ],
        true,
        false,
        1,
        usize::MAX,
    ),
    Spec("decrypt", &[Opt("output", true, Some('o'))], true, false, 1, 1),
    Spec("list", &[], true, false, 1, 1),
    Spec("add", &[Opt("into", true, None), Opt("overwrite", false, None), Opt("shred", false, None), Opt("passes", true, None), Opt("strength", true, None)], true, false, 2, usize::MAX),
    Spec("remove", &[Opt("passes", true, None), Opt("strength", true, None)], true, false, 2, usize::MAX),
    Spec("change-password", &[], true, true, 1, 1),
    Spec("rekey", &[Opt("passes", true, None)], true, true, 1, 1),
    Spec("keyfile", &[Opt("size", true, None)], false, false, 1, 1),
    Spec("verify", &[Opt("key", true, None)], false, false, 2, 2),
    Spec("update", &[Opt("check", false, None)], false, false, 0, 0),
    Spec("entropy", &[Opt("enable", true, None), Opt("disable", true, None)], false, false, 0, 0),
    Spec("version", &[], false, false, 0, 0),
    Spec("help", &[], false, false, 0, 1),
    Spec("gui", &[], false, false, 0, usize::MAX),
];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Args {
    pub cmd: String,
    pub items: Vec<String>,
    /// option -> values (flags have one empty value per use)
    pub opts: BTreeMap<String, Vec<String>>,
}

impl Args {
    pub fn has(&self, k: &str) -> bool {
        self.opts.contains_key(k)
    }
    pub fn val(&self, k: &str) -> Option<&str> {
        self.opts.get(k).and_then(|v| v.last()).map(String::as_str)
    }
    pub fn vals(&self, k: &str) -> &[String] {
        self.opts.get(k).map(Vec::as_slice).unwrap_or(&[])
    }
}

pub fn spec(cmd: &str) -> Option<&'static Spec> {
    COMMANDS.iter().find(|s| s.0 == cmd)
}

fn find<'a>(sets: &[&'a [Opt]], name: &str, short: Option<char>) -> Option<&'a Opt> {
    sets.iter().flat_map(|s| s.iter()).find(|o| if let Some(c) = short { o.2 == Some(c) } else { o.0 == name })
}

/// Error text is a translation key plus its argument.
pub type ParseErr = (&'static str, String);

/// Help flags after a command (`shield encrypt --help`); first word also `help`, `-?`, `/?` (3.0.0 §7).
pub const HELP_FLAGS: &[&str] = &["-h", "--help", "-help"];

/// An option as it may be shown in an error: never its `=value` part (it could be a password).
fn opt_shown(x: &str) -> String {
    x.split('=').next().unwrap_or(x).chars().take(64).collect()
}

pub fn parse(argv: &[String]) -> Result<Args, ParseErr> {
    let Some(cmd) = argv.first() else { return Ok(Args { cmd: "help".into(), ..Default::default() }) };
    let cmd = match cmd.as_str() {
        "-h" | "--help" | "-help" | "-?" | "/?" => "help",
        "-V" | "--version" => "version",
        c => c,
    };
    let s = spec(cmd).ok_or(("cli.unknown_cmd", opt_shown(cmd)))?;
    // `shield <command> ... --help`: that command's help, whatever else is given (nothing runs)
    if cmd != "help" {
        let scan = if cmd == "gui" { &argv[1..argv.len().min(2)] } else { &argv[1..] };
        let opts: Vec<&String> = scan.iter().take_while(|x| *x != "--").collect();
        if opts.iter().any(|x| HELP_FLAGS.contains(&x.as_str())) {
            let mut a = Args { cmd: "help".into(), items: vec![cmd.to_string()], ..Default::default() };
            for (i, x) in opts.iter().enumerate() {
                let lang = x.strip_prefix("--lang=").map(str::to_string).or_else(|| (*x == "--lang").then(|| opts.get(i + 1).map(|v| v.to_string())).flatten());
                if let Some(l) = lang {
                    a.opts.entry("lang".into()).or_default().push(l);
                }
            }
            return Ok(a);
        }
    }
    let mut sets: Vec<&[Opt]> = vec![COMMON, s.1];
    if s.2 {
        sets.push(CRED);
    }
    if s.3 {
        sets.push(NEW_CRED);
    }
    let mut a = Args { cmd: cmd.to_string(), ..Default::default() };
    let mut it = argv[1..].iter();
    let mut only_items = cmd == "gui";
    while let Some(x) = it.next() {
        if only_items || x == "-" || !x.starts_with('-') {
            a.items.push(x.clone());
            continue;
        }
        if x == "--" {
            only_items = true;
            continue;
        }
        let (o, inline) = if let Some(long) = x.strip_prefix("--") {
            let (n, v) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            (find(&sets, n, None).ok_or(("cli.unknown_opt", opt_shown(x)))?, v)
        } else {
            let mut cs = x[1..].chars();
            let (Some(c), None) = (cs.next(), cs.next()) else { return Err(("cli.unknown_opt", opt_shown(x))) };
            (find(&sets, "", Some(c)).ok_or(("cli.unknown_opt", opt_shown(x)))?, None)
        };
        let v = match (o.1, inline) {
            (true, Some(v)) => v,
            (true, None) => it.next().cloned().ok_or(("cli.needs_value", format!("--{}", o.0)))?,
            (false, Some(_)) => return Err(("cli.no_value", format!("--{}", o.0))),
            (false, None) => String::new(),
        };
        a.opts.entry(o.0.to_string()).or_default().push(v);
    }
    if a.items.len() < s.4 || a.items.len() > s.5 {
        return Err(("cli.item_count", cmd.to_string()));
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(v: &[&str]) -> Result<Args, ParseErr> {
        parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn commands_options_and_items() {
        let a = p(&["encrypt", "a.txt", "b dir", "-o", "x.shd", "--shred", "--passes=3", "-k", "k1", "-k", "k2"]).unwrap();
        assert_eq!(a.cmd, "encrypt");
        assert_eq!(a.items, ["a.txt", "b dir"]);
        assert_eq!(a.val("output"), Some("x.shd"));
        assert_eq!(a.val("passes"), Some("3"));
        assert!(a.has("shred") && !a.has("separate"));
        assert_eq!(a.vals("keyfile"), ["k1", "k2"]);
        let a = p(&["decrypt", "--", "-odd name.shd"]).unwrap();
        assert_eq!(a.items, ["-odd name.shd"]);
        assert_eq!(p(&[]).unwrap().cmd, "help");
        assert_eq!(p(&["--version"]).unwrap().cmd, "version");
        let g = p(&["gui", "encrypt", "--x", "a"]).unwrap();
        assert_eq!(g.items, ["encrypt", "--x", "a"], "gui passes everything through");
    }

    #[test]
    fn mistakes_are_usage_errors() {
        assert_eq!(p(&["encrypt"]).unwrap_err().0, "cli.item_count");
        assert_eq!(p(&["decrypt", "a", "b"]).unwrap_err().0, "cli.item_count");
        assert_eq!(p(&["frobnicate"]).unwrap_err().0, "cli.unknown_cmd");
        assert_eq!(p(&["encrypt", "a", "--bogus"]).unwrap_err().0, "cli.unknown_opt");
        assert_eq!(p(&["encrypt", "a", "-o"]).unwrap_err().0, "cli.needs_value");
        assert_eq!(p(&["encrypt", "a", "--shred=yes"]).unwrap_err().0, "cli.no_value");
        assert_eq!(p(&["keyfile", "k", "--password", "x"]).unwrap_err().0, "cli.unknown_opt", "no secrets where none are used");
        assert_eq!(p(&["list", "a", "-xy"]).unwrap_err().0, "cli.unknown_opt");
        assert_eq!(p(&["decrypt", "a", "--new-password", "x"]).unwrap_err().0, "cli.unknown_opt");
    }

    #[test]
    fn every_way_of_asking_for_help() {
        for first in ["-h", "--help", "-help", "help", "-?", "/?"] {
            let a = p(&[first]).unwrap();
            assert_eq!((a.cmd.as_str(), a.items.len()), ("help", 0), "{first}");
        }
        assert_eq!(p(&["help", "encrypt"]).unwrap().items, ["encrypt"]);
        assert_eq!(p(&["--help", "rekey", "--lang", "en"]).unwrap().val("lang"), Some("en"));
        for flag in HELP_FLAGS {
            // also where the command would otherwise be a usage error (no items)
            let a = p(&["encrypt", flag]).unwrap();
            assert_eq!((a.cmd.as_str(), a.items.as_slice()), ("help", &["encrypt".to_string()][..]), "{flag}");
        }
        let a = p(&["decrypt", "x.shd", "--lang=ko", "-h"]).unwrap();
        assert_eq!((a.cmd.as_str(), a.val("lang")), ("help", Some("ko")));
        // after `--` it is a file name; `gui` passes its arguments on except a first help flag
        assert_eq!(p(&["decrypt", "--", "--help"]).unwrap().cmd, "decrypt");
        assert_eq!(p(&["gui", "--help"]).unwrap().cmd, "help");
        assert_eq!(p(&["gui", "encrypt", "--help"]).unwrap().cmd, "gui");
        assert_eq!(p(&["frobnicate", "--help"]).unwrap_err().0, "cli.unknown_cmd");
    }

    #[test]
    fn errors_never_repeat_an_option_value() {
        let e = p(&["decrypt", "a.shd", "--pasword=Secret-123"]).unwrap_err();
        assert_eq!(e, ("cli.unknown_opt", "--pasword".to_string()));
        let e = p(&["decrypt", "a.shd", "--reveal=Secret-123"]).unwrap_err();
        assert!(!e.1.contains("Secret"), "{e:?}");
    }
}
