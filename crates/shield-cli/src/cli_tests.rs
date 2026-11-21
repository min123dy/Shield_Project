//! End-to-end tests of the console commands (in process; passwords through the guarded argument
//! mode, which the test settings allow).

use crate::args::parse;
use crate::cred::Ctx;
use crate::out::{code, exit_for, Out};
use crate::settings::Settings;
use std::path::{Path, PathBuf};

const PW: &str = "console test password with words 42";

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_cli_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn ctx(argv: &[&str]) -> Ctx {
    // TRIM would ask for elevation (UAC) on Windows: nobody answers in a test
    crate::wipe::TRIM_ENABLED.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut v: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    if crate::args::spec(argv[0]).is_some_and(|s| s.2) {
        v.extend(["--password", PW, "--allow-arg-secrets", "--pim", "0"].map(String::from));
    }
    // PIM 0 is below the default: a warning; review E: only --allow-weak accepts it, not --yes
    if argv[0] == "encrypt" {
        v.push("--allow-weak".into());
    }
    let set = Settings { allow_arg_secrets: true, ..Settings::default() };
    Ctx { o: Out { quiet: true, json: false, yes: true }, set, a: parse(&v).unwrap() }
}

fn run(argv: &[&str]) -> Result<(), String> {
    let mut cx = ctx(argv);
    match argv[0] {
        "encrypt" => crate::cmds::encrypt(&mut cx),
        "decrypt" => crate::cmds::decrypt(&mut cx),
        "list" => crate::cmds::list(&mut cx),
        "add" => crate::cmds::add(&mut cx),
        "remove" => crate::cmds::remove(&mut cx),
        "keyfile" => crate::tools::keyfile(&mut cx),
        "entropy" => crate::tools::entropy(&mut cx),
        c => panic!("{c}"),
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn encrypt_list_add_remove_decrypt() {
    let d = dir();
    let src = d.join("docs");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(d.join("extra.txt"), b"extra").unwrap();
    let shd = d.join("docs.shd");
    run(&["encrypt", s(&src), "-o", s(&shd)]).unwrap();
    assert!(shd.is_file());
    run(&["list", s(&shd)]).unwrap();
    run(&["add", s(&shd), s(&d.join("extra.txt")), "--passes", "3"]).unwrap();
    let e = run(&["add", s(&shd), s(&d.join("extra.txt"))]).unwrap_err();
    assert!(e.contains("extra.txt"), "a clash is refused without --overwrite: {e}");
    run(&["remove", s(&shd), "docs/a.txt", "--passes", "3"]).unwrap();
    assert!(run(&["remove", s(&shd), "nothing.txt"]).is_err());
    let out = d.join("out");
    std::fs::create_dir_all(&out).unwrap();
    run(&["decrypt", s(&shd), "-o", s(&out)]).unwrap();
    // two top-level items now: they are kept together in a folder named after the container
    let top = out.join("docs");
    assert_eq!(std::fs::read(top.join("extra.txt")).unwrap(), b"extra");
    assert!(top.join("docs").is_dir() && !top.join("docs").join("a.txt").exists(), "removed entry stays removed");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn several_items_bundled_or_separate() {
    let d = dir().join("Set");
    std::fs::create_dir_all(&d).unwrap();
    let (a, b) = (d.join("a.txt"), d.join("b.txt"));
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    run(&["encrypt", s(&a), s(&b)]).unwrap();
    assert!(d.join("Set.shd").is_file(), "one container named after the folder");
    run(&["encrypt", "--separate", s(&a), s(&b)]).unwrap();
    assert!(d.join("a.txt.shd").is_file() && d.join("b.txt.shd").is_file());
    let e = run(&["encrypt", s(&d.join("missing.txt"))]).unwrap_err();
    assert!(e.contains("missing.txt"));
    let _ = std::fs::remove_dir_all(d.parent().unwrap());
}

#[test]
fn wrong_password_and_refused_argument_secrets() {
    let d = dir();
    let f = d.join("x.txt");
    std::fs::write(&f, b"x").unwrap();
    run(&["encrypt", s(&f)]).unwrap();
    let shd = d.join("x.txt.shd");
    let v: Vec<String> = ["list", s(&shd), "--password", "not the password at all 1", "--allow-arg-secrets", "--pim", "0"].iter().map(|x| x.to_string()).collect();
    let mut cx = Ctx { o: Out { quiet: true, ..Default::default() }, set: Settings { allow_arg_secrets: true, ..Default::default() }, a: parse(&v).unwrap() };
    let e = crate::cmds::list(&mut cx).unwrap_err();
    assert_eq!(exit_for(&e), code::CREDENTIALS, "{e}");
    // allowed in the settings but the flag is missing / flag given but not allowed
    let v: Vec<String> = ["list", s(&shd), "--password", PW].iter().map(|x| x.to_string()).collect();
    let mut cx = Ctx { o: Out::default(), set: Settings { allow_arg_secrets: true, ..Default::default() }, a: parse(&v).unwrap() };
    assert!(crate::cmds::list(&mut cx).unwrap_err().contains("--allow-arg-secrets"));
    let v: Vec<String> = ["list", s(&shd), "--password", PW, "--allow-arg-secrets"].iter().map(|x| x.to_string()).collect();
    let mut cx = Ctx { o: Out::default(), set: Settings::default(), a: parse(&v).unwrap() };
    assert_eq!(crate::cmds::list(&mut cx).unwrap_err(), crate::i18n::t("cli.arg_secrets_off"));
    assert!(!cx.a.has("password"), "the argument copy was taken out and wiped");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn keyfile_and_signature_commands() {
    let d = dir();
    let kf = d.join("k.key");
    run(&["keyfile", s(&kf), "--size", "2"]).unwrap();
    assert_eq!(std::fs::metadata(&kf).unwrap().len(), 2048);
    assert!(run(&["keyfile", s(&d.join("big.key")), "--size", "999999"]).is_err());
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("../shield-core/tests/fixtures/pgp");
    let verify = |data: &str, sig: &str, key: &str| {
        let v: Vec<String> = ["verify", s(&fx.join(data)), s(&fx.join(sig)), "--key", s(&fx.join(key))].iter().map(|x| x.to_string()).collect();
        let mut cx = Ctx { o: Out { quiet: true, ..Default::default() }, set: Settings::default(), a: parse(&v).unwrap() };
        crate::tools::verify(&mut cx).unwrap()
    };
    assert_eq!(verify("data.txt", "data.bp256.sig", "bp256.asc"), code::OK);
    assert_eq!(verify("data.txt", "data.bp256.sig", "bp384.asc"), code::VERIFY, "other key");
    assert_eq!(verify("bp256.asc", "data.bp256.sig", "bp256.asc"), code::VERIFY, "other data");
    // 3.1.0 review 3: a huge --key file is refused before it is read (an error, not a crash)
    let huge = d.join("huge.asc");
    std::fs::File::create(&huge).unwrap().set_len(512 << 20).unwrap();
    let v: Vec<String> = ["verify", s(&fx.join("data.txt")), s(&fx.join("data.bp256.sig")), "--key", s(&huge)].iter().map(|x| x.to_string()).collect();
    let mut cx = Ctx { o: Out { quiet: true, ..Default::default() }, set: Settings::default(), a: parse(&v).unwrap() };
    let t = std::time::Instant::now();
    assert!(crate::tools::verify(&mut cx).is_err());
    assert!(t.elapsed().as_secs() < 10);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn entropy_status_and_protected_switches() {
    run(&["entropy"]).unwrap();
    // without a settings password the switches cannot change; the OS generator never
    assert_eq!(run(&["entropy", "--disable", "os"]).unwrap_err(), crate::i18n::t("cli.os_required"));
    assert!(run(&["entropy", "--disable", "nope"]).is_err());
    assert_eq!(run(&["entropy", "--disable", "disk"]).unwrap_err(), crate::i18n::t("set.pw_setup_needed"));
    // console commands never report the GUI-only sources as active
    crate::entropy::set_gui(false);
    for (src, st) in crate::entropy::status() {
        if src.gui_only() {
            assert_eq!(st, crate::entropy::SourceStatus::Unavailable, "{src:?}");
        }
    }
}

// ---- 3.1.0 #5 ----

#[test]
fn shred_question_names_at_most_twenty_targets() {
    let ps: Vec<PathBuf> = (0..25).map(|i| PathBuf::from(format!("f{i}.txt"))).collect();
    let refs: Vec<&Path> = ps.iter().map(PathBuf::as_path).collect();
    let l = crate::cmds::shred_target_lines(&refs);
    assert_eq!(l.len(), 1 + crate::cmds::SHRED_LIST_MAX + 1);
    assert!(l[0].contains("25"), "{}", l[0]);
    assert!(l.last().unwrap().contains('5'), "and 5 more");
    let l = crate::cmds::shred_target_lines(&refs[..2]);
    assert_eq!(l.len(), 3, "no 'more' line");
    let odd = [Path::new("a\u{202E}txt.exe")];
    assert!(crate::cmds::shred_target_lines(&odd)[1].contains("<U+202E>"));
}

#[test]
fn shred_without_terminal_needs_yes_and_touches_nothing() {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return; // only meaningful where nobody can answer
    }
    let d = dir();
    let f = d.join("keep.txt");
    std::fs::write(&f, b"keep").unwrap();
    let mut cx = ctx(&["encrypt", s(&f), "--shred", "-o", s(&d.join("k.shd"))]);
    cx.o.yes = false;
    let e = crate::cmds::encrypt(&mut cx).unwrap_err();
    assert_eq!(e, crate::i18n::t("cli.needs_yes"));
    assert_eq!(std::fs::read(&f).unwrap(), b"keep");
    assert!(!d.join("k.shd").exists(), "nothing is encrypted before the answer");
    let _ = std::fs::remove_dir_all(d);
}

/// 3.1.0 final, review E: `--yes` never accepts a password with warnings; without a terminal the
/// job is refused unless `--allow-weak` is given.
#[test]
fn yes_does_not_accept_a_weak_password() {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return; // a terminal would ask; the refusal path is for scripts
    }
    let d = dir();
    let f = d.join("x.txt");
    std::fs::write(&f, b"x").unwrap();
    let v: Vec<String> = ["encrypt", s(&f), "--yes", "--password", "short pass 1", "--allow-arg-secrets"].iter().map(|x| x.to_string()).collect();
    let mut cx = Ctx { o: Out { quiet: true, yes: true, ..Default::default() }, set: Settings { allow_arg_secrets: true, ..Default::default() }, a: parse(&v).unwrap() };
    let e = crate::cmds::encrypt(&mut cx).unwrap_err();
    assert_eq!(e, crate::i18n::t("cli.weak_needs_flag"));
    assert!(!d.join("x.txt.shd").exists(), "nothing was created");
    let _ = std::fs::remove_dir_all(d);
}

fn wipe(argv: &[&str]) -> i32 {
    let mut cx = ctx(argv);
    match crate::wipe_cmd::wipe(&mut cx) {
        Ok(c) => c,
        Err(e) => exit_for(&e),
    }
}

/// 3.1.0 final: `shield wipe` without a terminal: dry run, token, acknowledgement, exit codes.
#[test]
fn wipe_needs_a_token_and_the_acknowledgement_without_a_terminal() {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return; // with a terminal the three interactive steps run instead
    }
    let d = dir();
    let f = d.join("gone.txt");
    std::fs::write(&f, b"secret").unwrap();
    let folder = d.join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("in.txt"), b"x").unwrap();
    // dry run: nothing changes, exit 0
    assert_eq!(wipe(&["wipe", "--dry-run", s(&f)]), code::OK);
    assert!(f.exists());
    // no token: refused, --yes changes nothing
    assert_eq!(wipe(&["wipe", s(&f)]), code::REFUSED);
    assert_eq!(wipe(&["wipe", "--yes", s(&f)]), code::REFUSED);
    assert!(f.exists());
    let tok = crate::secure_delete::scan(std::slice::from_ref(&f), crate::wipe::Passes::Three).unwrap().token();
    // token without the acknowledgement, or a wrong one: refused
    assert_eq!(wipe(&["wipe", "--passes", "3", "--confirm-token", &tok, s(&f)]), code::REFUSED);
    assert_eq!(wipe(&["wipe", "--passes", "3", "--confirm-token", "0123", "--i-understand-irreversible", s(&f)]), code::REFUSED);
    assert_eq!(wipe(&["wipe", "--passes", "7", "--confirm-token", &tok, "--i-understand-irreversible", s(&f)]), code::REFUSED, "another pass count is another plan");
    assert!(f.exists());
    assert_eq!(wipe(&["wipe", "--passes", "3", "--confirm-token", &tok, "--i-understand-irreversible", s(&f)]), code::OK);
    assert!(!f.exists());
    // folders only with -r
    assert_eq!(wipe(&["wipe", "--dry-run", s(&folder)]), code::USAGE);
    let tok = crate::secure_delete::scan(std::slice::from_ref(&folder), crate::wipe::Passes::Three).unwrap().token();
    assert_eq!(wipe(&["wipe", "-r", "--passes", "3", "--confirm-token", &tok, "--i-understand-irreversible", s(&folder)]), code::OK);
    assert!(!folder.exists());
    // protected: refused before any confirmation
    let exe = std::env::current_exe().unwrap();
    assert_eq!(wipe(&["wipe", "--dry-run", s(&exe)]), code::REFUSED);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn wipe_options_parse_and_yes_is_no_wipe_option_of_its_own() {
    let a = parse(&["wipe", "-r", "--dry-run", "--passes", "7", "a", "b"].map(String::from)).unwrap();
    assert!(a.has("recursive") && a.has("dry-run"));
    assert_eq!(a.items, ["a", "b"]);
    assert_eq!(parse(&["wipe".to_string()]).unwrap_err().0, "cli.item_count");
    assert_eq!(parse(&["wipe", "--password", "x", "a"].map(String::from)).unwrap_err().0, "cli.unknown_opt", "wipe takes no credentials");
}

/// With a settings password and the secure delete switch on, even a valid token run needs the
/// settings password, which only a terminal can give: without one nothing is deleted (exit 8).
#[test]
fn wipe_needs_the_settings_password_when_the_settings_ask_for_it() {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return; // with a terminal the password prompt would wait for input
    }
    let d = dir();
    let f = d.join("kept.txt");
    std::fs::write(&f, b"secret").unwrap();
    let mut set = Settings::default();
    crate::settings_auth::set_password(&mut set, b"cli settings pw", None).unwrap();
    assert!(set.wipe_needs_pw);
    let tok = crate::secure_delete::scan(std::slice::from_ref(&f), crate::wipe::Passes::Three).unwrap().token();
    let mut cx = ctx(&["wipe", "--passes", "3", "--confirm-token", &tok, "--i-understand-irreversible", s(&f)]);
    cx.set = set;
    let r = crate::wipe_cmd::wipe(&mut cx).unwrap_or_else(|e| exit_for(&e));
    assert_eq!(r, code::REFUSED);
    assert_eq!(std::fs::read(&f).unwrap(), b"secret", "nothing was overwritten or deleted");
    let _ = std::fs::remove_dir_all(d);
}
