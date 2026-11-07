//! `shield` - Shield's console program (3.0 §6). Same engine and container format as the windows.
//! Console commands never collect mouse, keyboard-timing or window entropy (those sources are
//! GUI-only); the OS random generator is always the base.
//!
//! Signals: the first Ctrl+C / SIGTERM / SIGHUP cancels the running job (temporary files and
//! keys are dropped and wiped on the normal path); a second one wipes the entropy pool and exits.

pub use shield_core::*;

mod args;
mod cli_help;
mod cmds;
mod cred;
mod out;
mod secret;
mod tools;

use out::{code, Out};
use std::sync::atomic::{AtomicU32, Ordering};

static SIGNALS: AtomicU32 = AtomicU32::new(0);

/// Commands that read passwords, key files or keys.
const SECRET_CMDS: &[&str] = &["encrypt", "decrypt", "list", "add", "remove", "change-password", "rekey", "keyfile"];

fn on_signal() {
    if SIGNALS.fetch_add(1, Ordering::SeqCst) == 0 {
        progress::CANCEL.store(true, Ordering::SeqCst);
        eprintln!("\n{}", i18n::t("cli.cancelling"));
    } else {
        entropy::clear_pool();
        let _ = crossterm::terminal::disable_raw_mode();
        std::process::exit(130);
    }
}

#[cfg(feature = "gui")]
fn gui(items: &[String]) -> i32 {
    use shield_gui::Start;
    let rest = || items.iter().skip(1).map(std::path::PathBuf::from);
    let start = match items.first().map(String::as_str) {
        None => Start::Default,
        Some("encrypt") => Start::Encrypt(rest().collect()),
        Some("decrypt") => Start::Decrypt(rest().next()),
        Some("explorer") => Start::Explorer(rest().next()),
        Some("settings") => Start::Settings,
        Some("open") if items.len() == 2 => Start::Explorer(rest().next()),
        Some(_) => {
            eprintln!("{} {}", i18n::t("cli.error"), i18n::t("cli.gui_usage"));
            return code::USAGE;
        }
    };
    shield_gui::run(start)
}

#[cfg(not(feature = "gui"))]
fn gui(_: &[String]) -> i32 {
    eprintln!("{} {}", i18n::t("cli.error"), i18n::t("cli.no_gui"));
    code::USAGE
}

fn real_main(mut argv: Vec<String>) -> i32 {
    // TRIM after shredding may restart this program elevated (UAC) with a helper argument
    if let Some(c) = shield_platform::sys::elevated_helper(&argv) {
        return c;
    }
    harden::harden_process();
    let set = settings::Settings::load();
    i18n::set_lang(set.effective_lang());
    // the windows start this program again with their launcher flags (`--open x.shd` ...)
    #[cfg(feature = "gui")]
    if argv.first().is_some_and(|a| ["--open", "--manager", "--encrypt", "--encrypt-multi", "--decrypt", "--explorer", "--settings"].contains(&a.as_str())) {
        return shield_gui::run(shield_gui::parse_args(&argv));
    }
    let parsed = args::parse(&argv);
    // the command named in an error hint (`shield <command> --help`); only a known name
    let hint = argv.first().and_then(|c| args::spec(c)).map(|s| s.0).filter(|c| *c != "help");
    // our copies of the arguments are wiped (the operating system keeps its own; see the docs)
    for a in argv.iter_mut() {
        zeroize::Zeroize::zeroize(a);
    }
    let a = match parsed {
        Ok(a) => a,
        Err((k, x)) => {
            eprintln!("{} {}", i18n::t("cli.error"), i18n::tf(k, &[&x]));
            if k == "cli.unknown_cmd" {
                if let Some(s) = cli_help::suggest(&x) {
                    eprintln!("{}", i18n::tf("cli.did_you_mean", &[&s]));
                }
            }
            match hint {
                Some(c) => eprintln!("{}", i18n::tf("cli.see_cmd_help", &[&c])),
                None => eprintln!("{}", i18n::t("cli.see_help")),
            }
            return code::USAGE;
        }
    };
    match a.val("lang") {
        Some("ko") => i18n::set_lang(i18n::Lang::Ko),
        Some("en") => i18n::set_lang(i18n::Lang::En),
        Some(x) => {
            eprintln!("{} {}", i18n::t("cli.error"), i18n::tf("cli.bad_lang", &[&x]));
            return code::USAGE;
        }
        None => {}
    }
    let o = Out { quiet: a.has("quiet"), json: a.has("json"), yes: a.has("yes") };
    if a.cmd == "gui" {
        return gui(&a.items);
    }
    if a.cmd == "help" {
        return help(a.items.first().map(String::as_str));
    }
    entropy::set_gui(false);
    set.apply_entropy();
    entropy::set_mouse_enabled(false);
    let _ = ctrlc::set_handler(on_signal);
    // 3.0.0 §4: protections that failed are not skipped silently; jobs with secrets ask first
    // (--yes accepts; without a terminal and without --yes the job is refused)
    if SECRET_CMDS.contains(&a.cmd.as_str()) {
        let d = harden::degraded();
        if !d.is_empty() {
            eprintln!("{} {}", i18n::t("cli.warning"), i18n::t("harden.degraded_title"));
            match o.confirm(&d, i18n::t("harden.degraded_body")) {
                Ok(true) => {}
                Ok(false) => return finish(code::CANCELLED),
                Err(e) => {
                    o.error(&e, code::CANCELLED);
                    return finish(code::CANCELLED);
                }
            }
        }
    }
    let mut cx = cred::Ctx { o, set, a };
    let r = match cx.a.cmd.as_str() {
        "encrypt" => cmds::encrypt(&mut cx),
        "decrypt" => cmds::decrypt(&mut cx),
        "list" => cmds::list(&mut cx),
        "add" => cmds::add(&mut cx),
        "remove" => cmds::remove(&mut cx),
        "change-password" => cmds::change_password(&mut cx),
        "rekey" => cmds::rekey(&mut cx),
        "keyfile" => tools::keyfile(&mut cx),
        "verify" => match tools::verify(&mut cx) {
            Ok(c) => return finish(c),
            Err(e) => Err(e),
        },
        "update" => tools::update(&mut cx),
        "entropy" => tools::entropy(&mut cx),
        "version" => tools::version(&mut cx),
        _ => unreachable!("parser accepts only known commands"),
    };
    finish(match r {
        Ok(()) => code::OK,
        Err(e) => {
            let c = out::exit_for(&e);
            cx.o.error(&e, c);
            c
        }
    })
}

/// 3.0.0 §7: prints help to stdout and does nothing else (no files, no prompts, no network).
fn help(cmd: Option<&str>) -> i32 {
    let st = cli_help::Style::detect();
    let l = i18n::lang();
    let page = match cmd {
        None => cli_help::overview(l, st, buildinfo::VERSION),
        Some(c) => match cli_help::command(l, st, c) {
            Some(p) => p,
            None => {
                eprintln!("{} {}", i18n::t("cli.error"), i18n::tf("cli.unknown_cmd", &[&c]));
                if let Some(s) = cli_help::suggest(c) {
                    eprintln!("{}", i18n::tf("cli.did_you_mean", &[&s]));
                }
                eprintln!("{}", i18n::t("cli.see_help"));
                return code::USAGE;
            }
        },
    };
    use std::io::Write;
    let mut o = std::io::stdout().lock();
    // a closed pipe (`shield help | head`) is not an error
    let _ = o.write_all(page.as_bytes()).and_then(|_| o.flush());
    code::OK
}

fn finish(c: i32) -> i32 {
    entropy::clear_pool();
    c
}

fn main() {
    // non-UTF-8 arguments are refused instead of being changed (a changed path is another file)
    let argv: Result<Vec<String>, _> = std::env::args_os().skip(1).map(|a| a.into_string()).collect();
    match argv {
        Ok(a) => std::process::exit(real_main(a)),
        Err(_) => {
            eprintln!("{} {}", i18n::t("cli.error"), i18n::t("cli.bad_encoding"));
            std::process::exit(code::USAGE);
        }
    }
}

#[cfg(test)]
mod cli_tests;
