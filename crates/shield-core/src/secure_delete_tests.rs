//! Secure delete (3.1.0 final, docs/10): confirmation state machine, token binding, refusals,
//! execution on real temporary files, the overwrite loop.
//! Cancelling is tested in its own test program (tests/wipe_cancel.rs): the cancel flag is global
//! and the tests here run in parallel.

use super::*;
use std::time::{Duration, Instant};

fn base(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_sd_{name}_{}", crate::entropy::rand_hex().unwrap()));
    fs::create_dir_all(&d).unwrap();
    fs::canonicalize(&d).map(|p| strip_verbatim(&p)).unwrap()
}

fn file(p: &Path, data: &[u8]) -> PathBuf {
    fs::write(p, data).unwrap();
    p.to_path_buf()
}

/// No OS list: only what the test gives (temporary folders may be inside a protected profile).
fn open_guard() -> Guard {
    Guard::with(vec![], vec![], vec![])
}

fn plan_of(items: &[PathBuf]) -> Plan {
    scan_with(items, Passes::Three, &open_guard()).unwrap()
}

/// Walks a confirmation through every step with the right answers.
fn confirm_all(mut c: Confirmation) -> ConfirmedWipePlan {
    let t0 = Instant::now();
    c.accept_warning(t0).unwrap();
    c.accept_limits(true, t0).unwrap();
    let code = c.code().unwrap().to_string();
    assert_eq!(c.submit(&code, t0 + CODE_WAIT).unwrap(), Answer::Accepted);
    c.finish().map_err(|_| "not finished").unwrap()
}

/// The permit of settings that do not ask for the settings password.
fn no_pw() -> WipePermit {
    permit_with(&Settings::default(), &Settings::default(), None).unwrap()
}

// ------------------------------------------------------------------ confirmation (2-2, 2-3)

#[test]
fn every_step_is_needed_in_order() {
    let b = base("steps");
    let f = file(&b.join("a.txt"), b"secret");
    let mut c = Confirmation::new(plan_of(std::slice::from_ref(&f)));
    let t0 = Instant::now();
    assert_eq!((c.step(), c.step_no(), c.steps_total()), (Step::Warning, 1, 3));
    assert_eq!(c.code(), None, "no code before the code step");
    assert_eq!(c.submit("ANYTHING", t0 + CODE_WAIT).unwrap(), Answer::NotNow);
    // the limits step can't be skipped and needs the acknowledgement
    c.accept_limits(true, t0).unwrap();
    assert_eq!(c.step(), Step::Warning, "limits before the warning does nothing");
    c.accept_warning(t0).unwrap();
    assert_eq!((c.step(), c.step_no()), (Step::Limits, 2));
    c.accept_limits(false, t0).unwrap();
    assert_eq!(c.step(), Step::Limits, "not without the tick");
    c.accept_limits(true, t0).unwrap();
    assert_eq!((c.step(), c.step_no()), (Step::Code, 3));
    let code = c.code().unwrap().to_string();
    assert_eq!(code.len(), CODE_LEN);
    assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)), "{code}");
    assert!(c.finish().is_err(), "not done yet: no confirmed plan");
    assert!(f.exists());
    // the confirmed plan only after the code
    let done = confirm_all(Confirmation::new(plan_of(std::slice::from_ref(&f))));
    assert_eq!(done.plan().files(), 1);
    let _ = fs::remove_dir_all(b);
}

#[test]
fn code_waits_three_seconds_and_ignores_case_and_spaces() {
    let b = base("code");
    let f = file(&b.join("a.txt"), b"x");
    let mut c = Confirmation::new(plan_of(&[f]));
    let t0 = Instant::now();
    c.accept_warning(t0).unwrap();
    c.accept_limits(true, t0).unwrap();
    let code = c.code().unwrap().to_string();
    // too early: not counted, the code stays
    assert_eq!(c.submit(&code, t0 + CODE_WAIT - Duration::from_millis(1)).unwrap(), Answer::TooEarly);
    assert_eq!(c.tries_left(), MAX_FAILS);
    assert_eq!(c.code(), Some(code.as_str()));
    assert!(!c.wait_left(t0).is_zero() && c.wait_left(t0 + CODE_WAIT).is_zero());
    let spaced: String = code.to_lowercase().chars().flat_map(|ch| [' ', ch]).collect();
    assert_eq!(c.submit(&spaced, t0 + CODE_WAIT).unwrap(), Answer::Accepted);
    assert_eq!(c.step(), Step::Done);
    let _ = fs::remove_dir_all(b);
}

#[test]
fn wrong_codes_get_a_new_code_and_three_abort_everything() {
    let b = base("fails");
    let f = file(&b.join("a.txt"), b"x");
    let mut c = Confirmation::new(plan_of(std::slice::from_ref(&f)));
    let t0 = Instant::now();
    c.accept_warning(t0).unwrap();
    c.accept_limits(true, t0).unwrap();
    let first = c.code().unwrap().to_string();
    assert_eq!(c.submit("", t0 + CODE_WAIT).unwrap(), Answer::Wrong(2), "empty is wrong");
    let second = c.code().unwrap().to_string();
    // a new code is shown and must be waited for again (a code can repeat by chance: 1 in 887 million)
    assert!(!c.wait_left(t0 + CODE_WAIT).is_zero(), "the new code has its own wait");
    let t1 = t0 + CODE_WAIT + CODE_WAIT;
    if first != second {
        assert_eq!(c.submit(&first, t1).unwrap(), Answer::Wrong(1), "the old code is no longer valid");
    } else {
        assert_eq!(c.submit("ZZZZZZ2", t1).unwrap(), Answer::Wrong(1));
    }
    let t2 = t1 + CODE_WAIT;
    assert_eq!(c.submit("WRONG!", t2).unwrap(), Answer::Aborted);
    assert_eq!(c.step(), Step::Aborted);
    assert_eq!(c.code(), None);
    assert_eq!(c.submit("anything", t2 + CODE_WAIT).unwrap(), Answer::NotNow, "nothing after an abort");
    assert!(c.finish().is_err());
    assert!(f.exists());
    let _ = fs::remove_dir_all(b);
}

#[test]
fn cancel_at_any_step_ends_the_confirmation() {
    let b = base("cancel");
    let f = file(&b.join("a.txt"), b"x");
    for at in 0..3 {
        let mut c = Confirmation::new(plan_of(std::slice::from_ref(&f)));
        let t0 = Instant::now();
        if at > 0 {
            c.accept_warning(t0).unwrap();
        }
        if at > 1 {
            c.accept_limits(true, t0).unwrap();
        }
        c.cancel();
        assert_eq!(c.step(), Step::Aborted);
        c.accept_warning(t0).unwrap();
        c.accept_limits(true, t0).unwrap();
        assert_eq!(c.step(), Step::Aborted, "no way back from a cancel");
        assert!(c.finish().is_err());
    }
    let _ = fs::remove_dir_all(b);
}

#[test]
fn containers_only_skip_the_limits_step() {
    let b = base("shd");
    let f = file(&b.join("old.shd"), b"not really a container");
    let mut c = Confirmation::new(plan_of(&[f]));
    assert_eq!(c.steps_total(), 2);
    c.accept_warning(Instant::now()).unwrap();
    assert_eq!((c.step(), c.step_no()), (Step::Code, 2), "warning, then the code");
    let g = file(&b.join("mixed.txt"), b"x");
    let c = Confirmation::new(plan_of(&[b.join("old.shd"), g]));
    assert_eq!(c.steps_total(), 3, "one other file brings the limits step back");
    let _ = fs::remove_dir_all(b);
}

#[test]
fn every_plan_gets_its_own_random_code() {
    let b = base("codes");
    let f = file(&b.join("a.txt"), b"x");
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        let mut c = Confirmation::new(plan_of(std::slice::from_ref(&f)));
        c.accept_warning(Instant::now()).unwrap();
        c.accept_limits(true, Instant::now()).unwrap();
        seen.insert(c.code().unwrap().to_string());
    }
    assert!(seen.len() >= 19, "codes repeat: {seen:?}");
    let _ = fs::remove_dir_all(b);
}

// ------------------------------------------------------------------ token (scripts)

#[test]
fn token_binds_the_plan_and_needs_the_acknowledgement() {
    let b = base("token");
    let f = file(&b.join("a.txt"), b"1234");
    let tok = plan_of(std::slice::from_ref(&f)).token();
    assert_eq!(tok.len(), 32);
    assert_eq!(plan_of(std::slice::from_ref(&f)).token(), tok, "same plan, same token");
    assert!(is_refusal(&confirm_with_token(plan_of(std::slice::from_ref(&f)), &tok, false).unwrap_err()), "--i-understand-irreversible missing");
    assert!(is_refusal(&confirm_with_token(plan_of(std::slice::from_ref(&f)), "00", true).unwrap_err()));
    assert!(confirm_with_token(plan_of(std::slice::from_ref(&f)), &tok.to_uppercase(), true).is_ok(), "case of the hex does not matter");
    // anything that changes the plan changes the token
    assert_ne!(scan_with(std::slice::from_ref(&f), Passes::Seven, &open_guard()).unwrap().token(), tok, "passes");
    fs::write(&f, b"12345").unwrap();
    assert_ne!(plan_of(std::slice::from_ref(&f)).token(), tok, "size");
    let g = file(&b.join("b.txt"), b"1");
    assert_ne!(plan_of(&[f.clone(), g]).token(), tok, "another item");
    assert!(is_refusal(&confirm_with_token(plan_of(std::slice::from_ref(&f)), &tok, true).unwrap_err()), "a stale token is refused");
    let _ = fs::remove_dir_all(b);
}

// ------------------------------------------------------------------ refusals (2-4)

#[test]
fn protected_paths_are_refused_in_both_directions() {
    let b = base("guard");
    let sys = b.join("system");
    let sub = sys.join("inner");
    fs::create_dir_all(&sub).unwrap();
    let keep = file(&b.join("keep.exe"), b"x");
    let home = b.join("home");
    fs::create_dir_all(home.join("user")).unwrap();
    let g = Guard::with(vec![home.clone()], vec![sys.clone()], vec![keep.clone()]);
    for p in [&sys, &sub] {
        assert!(is_refusal(&scan_with(std::slice::from_ref(p), Passes::Three, &g).unwrap_err()), "inside a protected subtree: {}", p.display());
    }
    for p in [&b, &home] {
        // a folder that contains something protected
        assert!(is_refusal(&scan_with(std::slice::from_ref(p), Passes::Three, &g).unwrap_err()), "contains a protected path: {}", p.display());
    }
    assert!(is_refusal(&scan_with(std::slice::from_ref(&keep), Passes::Three, &g).unwrap_err()), "Shield's own file");
    assert!(scan_with(&[home.join("user")], Passes::Three, &g).is_ok(), "below an exact-only path is allowed");
    // the real list: roots, the running program, the system folders
    let root = if cfg!(windows) { PathBuf::from(r"C:\") } else { PathBuf::from("/") };
    assert!(is_refusal(&scan(&[root], Passes::Three).unwrap_err()), "drive root");
    assert!(is_refusal(&scan(&[std::env::current_exe().unwrap()], Passes::Three).unwrap_err()), "the running program");
    let sysdir = if cfg!(windows) { std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| r"C:\Windows".into()) } else { PathBuf::from("/usr/bin") };
    if sysdir.exists() {
        assert!(is_refusal(&scan(&[sysdir], Passes::Three).unwrap_err()), "system folder");
    }
    if let Ok(d) = crate::settings::data_dir() {
        assert!(is_refusal(&scan(&[d], Passes::Three).unwrap_err()), "Shield's data folder");
    }
    let _ = fs::remove_dir_all(b);
}

#[test]
fn shield_data_folder_children_are_protected_in_both_directions() {
    let b = base("shield_data_guard");
    let data = b.join("Shield");
    let nested = data.join("cache");
    fs::create_dir_all(&nested).unwrap();
    let settings = file(&data.join("settings"), b"settings");
    let key = file(&data.join("settings.key"), b"key");
    let journal = file(&nested.join("staging.lst"), b"journal");
    let g = Guard::with(vec![], vec![], vec![data.clone()]);

    for p in [&settings, &key, &journal, &nested] {
        let e = scan_with(std::slice::from_ref(p), Passes::Three, &g).unwrap_err();
        assert!(is_refusal(&e), "Shield data descendant was not protected: {} ({e})", p.display());
    }
    for p in [&data, &b] {
        let e = scan_with(std::slice::from_ref(p), Passes::Three, &g).unwrap_err();
        assert!(is_refusal(&e), "Shield data ancestor was not protected: {} ({e})", p.display());
    }

    let unrelated = file(&b.join("unrelated.txt"), b"safe to select");
    assert!(scan_with(&[unrelated], Passes::Three, &g).is_ok());
    let _ = fs::remove_dir_all(b);
}

#[test]
fn duplicates_overlaps_missing_and_empty_are_refused() {
    let b = base("overlap");
    let d = b.join("d");
    fs::create_dir_all(&d).unwrap();
    let f = file(&d.join("f.txt"), b"x");
    assert!(is_refusal(&scan_with(&[f.clone(), f.clone()], Passes::Three, &open_guard()).unwrap_err()), "twice");
    assert!(is_refusal(&scan_with(&[d.clone(), f.clone()], Passes::Three, &open_guard()).unwrap_err()), "inside another item");
    let e = scan_with(&[b.join("nope")], Passes::Three, &open_guard()).unwrap_err();
    assert!(!is_refusal(&e) && !e.is_empty(), "missing: an error, not a refusal");
    assert!(scan_with(&[], Passes::Three, &open_guard()).is_err());
    assert!(scan_with(&[PathBuf::new()], Passes::Three, &open_guard()).is_err(), "empty name");
    let _ = fs::remove_dir_all(b);
}

#[test]
fn relative_items_are_resolved_to_the_real_path() {
    let b = base("rel");
    let f = file(&b.join("x.txt"), b"x");
    let cwd = std::env::current_dir().unwrap();
    // a path with `..` in it is shown and removed as the real one
    let odd = b.join("sub").join("..").join("x.txt");
    fs::create_dir_all(b.join("sub")).unwrap();
    let p = plan_of(std::slice::from_ref(&odd));
    assert_eq!(path_key(&p.targets()[0].path), path_key(&f), "{:?}", p.targets()[0].path);
    assert_eq!(p.targets()[0].given, odd, "the given name is kept for the 'list changed' check");
    assert!(p.same_selection(&[odd]) && !p.same_selection(std::slice::from_ref(&f)));
    assert_eq!(std::env::current_dir().unwrap(), cwd);
    let _ = fs::remove_dir_all(b);
}

// ------------------------------------------------------------------ execution (2-5)

#[test]
fn files_and_folders_are_overwritten_and_removed() {
    let b = base("run");
    let top = b.join("tree");
    fs::create_dir_all(top.join("a").join("b")).unwrap();
    file(&top.join("one.txt"), &[7u8; 5000]);
    file(&top.join("a").join("two.bin"), &[1u8; 3 << 20]);
    file(&top.join("a").join("b").join("empty"), b"");
    let single = file(&b.join("single.txt"), b"top secret");
    let plan = plan_of(&[top.clone(), single.clone()]);
    assert_eq!((plan.files(), plan.dirs()), (4, 3));
    assert_eq!(plan.bytes(), 5000 + (3 << 20) + 10);
    // children before their folder
    let pos = |p: &Path| plan.entries().iter().position(|e| e.path == p).unwrap();
    assert!(pos(&top.join("a").join("two.bin")) < pos(&top.join("a")) && pos(&top.join("a")) < pos(&top));
    let rep = execute(confirm_all(Confirmation::new(plan)), no_pw());
    assert!(rep.all_ok(), "{:?}", rep.results);
    assert_eq!(rep.done(), 7);
    assert!(!top.exists() && !single.exists());
    // no renamed leftovers either
    assert_eq!(fs::read_dir(&b).unwrap().count(), 0, "folder {} not empty", b.display());
    assert!(rep.summary().contains('7'), "{}", rep.summary());
    let _ = fs::remove_dir_all(b);
}

#[test]
fn a_file_changed_after_the_confirmation_is_not_touched() {
    let b = base("changed");
    let f = file(&b.join("a.txt"), b"before");
    let g = file(&b.join("b.txt"), b"other");
    let confirmed = confirm_all(Confirmation::new(plan_of(&[f.clone(), g.clone()])));
    fs::write(&f, b"after, and longer").unwrap();
    let rep = execute(confirmed, no_pw());
    assert!(!rep.all_ok());
    let r = rep.results.iter().find(|r| r.path == f).unwrap();
    assert!(matches!(r.outcome, Outcome::Skipped(_)), "{:?}", r.outcome);
    assert_eq!(fs::read(&f).unwrap(), b"after, and longer", "untouched");
    assert!(!g.exists(), "the other file was still removed");
    assert_eq!((rep.done(), rep.skipped()), (1, 1));
    assert!(!rep.problem_lines(10).is_empty());
    let _ = fs::remove_dir_all(b);
}

#[test]
fn a_file_replaced_after_the_confirmation_is_not_touched() {
    let b = base("replaced");
    let f = file(&b.join("a.txt"), b"same!");
    let confirmed = confirm_all(Confirmation::new(plan_of(std::slice::from_ref(&f))));
    // same name, same size, another object
    fs::remove_file(&f).unwrap();
    fs::write(&f, b"same!").unwrap();
    let rep = execute(confirmed, no_pw());
    assert!(matches!(rep.results[0].outcome, Outcome::Skipped(_)), "{:?}", rep.results[0].outcome);
    assert!(f.exists());
    let _ = fs::remove_dir_all(b);
}

#[test]
fn read_only_files_are_removed_too() {
    let b = base("ro");
    let f = file(&b.join("ro.txt"), b"locked");
    let mut perm = fs::metadata(&f).unwrap().permissions();
    perm.set_readonly(true);
    fs::set_permissions(&f, perm).unwrap();
    let rep = execute(confirm_all(Confirmation::new(plan_of(std::slice::from_ref(&f)))), no_pw());
    assert!(rep.all_ok(), "{:?}", rep.results);
    assert!(!f.exists());
    let _ = fs::remove_dir_all(b);
}

#[test]
fn links_are_removed_but_never_followed() {
    let b = base("links");
    let outside = b.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let precious = file(&outside.join("precious.txt"), b"keep me");
    let dir = b.join("dir");
    fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&outside, dir.join("to_outside")).and_then(|_| std::os::unix::fs::symlink(&precious, b.join("file_link")));
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(&outside, dir.join("to_outside")).and_then(|_| std::os::windows::fs::symlink_file(&precious, b.join("file_link")));
    if made.is_err() {
        eprintln!("symbolic links not available here (Windows without developer mode): skipped");
        let _ = fs::remove_dir_all(b);
        return;
    }
    // a link inside a folder and a link selected itself
    let plan = plan_of(&[dir.clone(), b.join("file_link")]);
    assert_eq!(plan.links(), 2);
    assert_eq!(plan.files(), 0, "nothing behind a link is listed");
    assert!(plan.target_lines().iter().any(|l| l.contains(t("sd.link_only"))));
    let rep = execute(confirm_all(Confirmation::new(plan)), no_pw());
    assert!(rep.all_ok(), "{:?}", rep.results);
    assert!(!dir.exists() && fs::symlink_metadata(b.join("file_link")).is_err());
    assert_eq!(fs::read(&precious).unwrap(), b"keep me", "the target is untouched");
    let _ = fs::remove_dir_all(b);
}

// ------------------------------------------------------------------ overwrite loop

struct Mock {
    len: u64,
    pos: u64,
    written: u64,
    syncs: usize,
    last: Vec<u8>,
}
impl std::io::Write for Mock {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        assert!(self.pos + b.len() as u64 <= self.len, "never past the end");
        self.pos += b.len() as u64;
        self.written += b.len() as u64;
        self.last = b.to_vec();
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl std::io::Seek for Mock {
    fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
        assert_eq!(p, std::io::SeekFrom::Start(0));
        self.pos = 0;
        Ok(0)
    }
}
impl Sink for Mock {
    fn sync(&mut self) -> std::io::Result<()> {
        self.syncs += 1;
        Ok(())
    }
}

#[test]
fn every_pass_covers_the_whole_file_and_is_synced() {
    for (p, n) in [(Passes::Three, 3usize), (Passes::Seven, 7)] {
        let len = (wipe::BUF as u64) * 2 + 12345;
        let mut m = Mock { len, pos: 0, written: 0, syncs: 0, last: vec![] };
        assert_eq!(overwrite_passes(&mut m, len, p).unwrap(), n);
        assert_eq!(m.written, len * n as u64);
        assert_eq!(m.syncs, n, "synced after each pass");
        assert_eq!(m.last.len(), 12345, "one buffer, the tail last");
        if let Some(Some(b)) = p.patterns().last() {
            assert!(m.last.iter().all(|x| x == b));
        }
    }
    let mut m = Mock { len: 0, pos: 0, written: 0, syncs: 0, last: vec![] };
    assert_eq!(overwrite_passes(&mut m, 0, Passes::Three).unwrap(), 3, "an empty file still counts its passes");
}

#[test]
fn shown_paths_are_safe_for_terminals() {
    let p = PathBuf::from("evil\u{1b}[2Jname\u{202e}txt.exe");
    let s = crate::ui_fmt::path_shown(&p);
    assert!(!s.contains('\u{1b}') && !s.contains('\u{202e}'), "{s:?}");
    let long = PathBuf::from("x".repeat(5000));
    assert!(crate::ui_fmt::path_shown(&long).chars().count() <= crate::ui_fmt::PATH_SHOWN_MAX + 3);
}

/// A disk that fails: an error after `fail_at` bytes, or (`zero`) a write that takes nothing.
struct Failing {
    fail_at: u64,
    pos: u64,
    zero: bool,
    syncs: usize,
}
impl std::io::Write for Failing {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.zero && self.pos >= self.fail_at {
            return Ok(0);
        }
        if self.pos >= self.fail_at {
            return Err(std::io::Error::other("injected write error"));
        }
        let n = (b.len() as u64).min(self.fail_at - self.pos).max(1) as usize;
        self.pos += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl std::io::Seek for Failing {
    fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
        Ok(0)
    }
}
impl Sink for Failing {
    fn sync(&mut self) -> std::io::Result<()> {
        self.syncs += 1;
        Ok(())
    }
}

#[test]
fn a_failing_or_short_write_fails_the_pass() {
    // 2-8: a write error in the second pass is an error (that pass is not counted as done), and a
    // disk that silently takes nothing (Ok(0)) is never reported as overwritten
    let len = (wipe::BUF as u64) * 3;
    let mut f = Failing { fail_at: len + 10, pos: 0, zero: false, syncs: 0 };
    let e = overwrite_passes(&mut f, len, Passes::Three).unwrap_err();
    assert!(e.contains("injected"), "{e}");
    assert_eq!(f.syncs, 1, "only the first pass finished");
    let mut z = Failing { fail_at: 100, pos: 0, zero: true, syncs: 0 };
    assert!(overwrite_passes(&mut z, len, Passes::Three).is_err(), "short write");
    assert_eq!(z.syncs, 0);
}

#[test]
fn hard_links_are_counted_and_named_in_the_limits() {
    // 2-8: a file with another name is warned about (its data changes under every name)
    let d = base("hardlink");
    let a = file(&d.join("a.txt"), b"shared data");
    if fs::hard_link(&a, d.join("other name.txt")).is_err() {
        eprintln!("no hard links on this file system: skipped");
        return;
    }
    let p = plan_of(std::slice::from_ref(&a));
    assert_eq!(p.hardlinked(), 1);
    let lines = p.limit_lines().join("\n");
    assert!(lines.contains(&tf("sd.lim_hardlinks", &[&1])), "{lines}");
    let none = plan_of(&[file(&d.join("single.txt"), b"x")]);
    assert_eq!(none.hardlinked(), 0);
    assert!(none.limit_lines().join("\n").contains(t("sd.lim_hardlinks_none")));
    let _ = fs::remove_dir_all(d);
}

#[test]
fn more_than_max_items_is_refused() {
    // 2-5: the plan never grows past MAX_ITEMS (memory); the scan stops with a refusal
    let d = base("max");
    let f = file(&d.join("x"), b"x");
    let info = pfs::entry_info(&f).unwrap();
    let mut p = plan_of(std::slice::from_ref(&f));
    let one = p.entries[0].clone();
    p.entries = vec![one; MAX_ITEMS - 1];
    let mut s = Scan { plan: p, mounts: vec![], vols: BTreeSet::new() };
    s.push(f.clone(), Kind::File, &info).unwrap();
    let e = s.push(f.clone(), Kind::File, &info).unwrap_err();
    assert!(is_refusal(&e) && e.contains(&MAX_ITEMS.to_string()), "{e}");
    assert_eq!(s.plan.entries.len(), MAX_ITEMS);
    let _ = fs::remove_dir_all(d);
}

// ------------------------------------------------------------------ settings password (3.1.0 final+)

fn with_password(pw: &[u8]) -> Settings {
    let mut s = Settings::default();
    crate::settings_auth::set_password(&mut s, pw, None).unwrap();
    s
}

#[test]
fn the_settings_password_is_needed_only_when_set_and_asked_for() {
    let none = Settings::default();
    assert!(none.wipe_needs_pw, "on by default");
    assert!(permit_with(&none, &none, None).is_ok(), "no settings password: nothing to ask");
    let set = with_password(b"settings pw 1");
    let off = Settings { wipe_needs_pw: false, ..set.clone() };
    assert!(permit_with(&off, &off, None).is_ok(), "switched off");
    for (cur, disk) in [(&set, &none), (&none, &set), (&set, &set), (&off, &set), (&set, &off)] {
        let e = permit_with(cur, disk, None).unwrap_err();
        assert!(is_refusal(&e) && crate::i18n::has_code(&e, C_SET_PW), "no password given: {e}");
        let e = permit_with(cur, disk, Some(b"")).unwrap_err();
        assert!(crate::i18n::has_code(&e, C_SET_PW), "empty password: {e}");
    }
    let e = permit_with(&set, &set, Some(b"wrong")).unwrap_err();
    assert!(is_refusal(&e) && crate::i18n::has_code(&e, crate::settings_auth::C_WRONG_PW), "{e}");
    assert!(permit_with(&set, &set, Some(b"settings pw 1")).is_ok());
}

#[test]
fn the_file_password_counts_when_both_ask() {
    // another window changed the settings password: the one in the file now is the one asked for
    let old = with_password(b"old settings pw");
    let new = with_password(b"new settings pw");
    assert!(permit_with(&old, &new, Some(b"old settings pw")).is_err());
    assert!(permit_with(&old, &new, Some(b"new settings pw")).is_ok());
}

#[test]
fn a_selected_link_is_checked_and_shown_where_it_really_is() {
    // S-11: `b/via/name` where `b/via` links to the protected folder: the link really removed is
    // `protected/name`, so the guard must see (and the warning show) that path
    let b = base("linkparent");
    let prot = b.join("protected");
    fs::create_dir_all(&prot).unwrap();
    let target = file(&b.join("target.txt"), b"x");
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&target, prot.join("name")).and_then(|_| std::os::unix::fs::symlink(&prot, b.join("via")));
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&target, prot.join("name")).and_then(|_| std::os::windows::fs::symlink_dir(&prot, b.join("via")));
    if made.is_err() {
        eprintln!("symbolic links not available here (Windows without developer mode): skipped");
        let _ = fs::remove_dir_all(b);
        return;
    }
    let via = b.join("via").join("name");
    let guard = Guard::with(vec![], vec![prot.clone()], vec![]);
    let e = scan_with(std::slice::from_ref(&via), Passes::Three, &guard).unwrap_err();
    assert!(is_refusal(&e), "a link inside a protected folder reached through another link: {e}");
    let plan = plan_of(std::slice::from_ref(&via));
    assert_eq!(path_key(&plan.targets()[0].path), path_key(&prot.join("name")), "the real path is what is shown and removed");
    assert_eq!(plan.targets()[0].given, via, "the selection stays as given");
    let _ = fs::remove_dir_all(b);
}
