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
