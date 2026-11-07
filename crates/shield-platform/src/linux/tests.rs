use super::*;
use std::{fs as sfs, os::unix::fs::PermissionsExt};

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_plat_{}_{}", std::process::id(), crate::cpu::cycle_counter().unwrap_or(0)));
    sfs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn private_objects_are_owner_only() {
    let d = dir();
    let p = d.join("priv");
    fs::create_private_dir(&p).unwrap();
    assert_eq!(sfs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(fs::create_private_dir(&p).is_err(), "existing folder refused");
    let f = p.join("k");
    drop(fs::create_private_file(&f).unwrap());
    assert_eq!(sfs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(fs::create_private_file(&f).is_err());
    let g = d.join("g");
    sfs::write(&g, b"x").unwrap();
    sfs::set_permissions(&g, sfs::Permissions::from_mode(0o666)).unwrap();
    OS.restrict_file_permissions(&g).unwrap();
    assert_eq!(sfs::metadata(&g).unwrap().permissions().mode() & 0o777, 0o600);
    let link = d.join("link");
    std::os::unix::fs::symlink(&g, &link).unwrap();
    assert!(OS.restrict_file_permissions(&link).is_err(), "symlink refused");
    assert!(fs::open_no_follow(&link, false).is_err(), "O_NOFOLLOW");
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn renames_never_overwrite_and_replace_keeps_old_fd() {
    use std::io::Read;
    let d = dir();
    let (a, b) = (d.join("a"), d.join("b"));
    sfs::write(&a, b"A").unwrap();
    sfs::write(&b, b"B").unwrap();
    assert_eq!(fs::rename_noreplace(&a, &b).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(sfs::read(&b).unwrap(), b"B");
    let c = d.join("c");
    fs::rename_noreplace(&a, &c).unwrap();
    assert!(!a.exists() && c.exists());
    match fs::replace_keep_old(&c, &b, &d.join("unused")).unwrap() {
        Retained::Open(mut f) => {
            let mut s = Vec::new();
            f.read_to_end(&mut s).unwrap();
            assert_eq!(s, b"B", "old contents still reachable");
        }
        Retained::Path(_) => panic!("Linux keeps an fd"),
    }
    assert_eq!(sfs::read(&b).unwrap(), b"A");
    let f = fs::open_no_follow(&b, true).unwrap();
    sfs::rename(&b, d.join("moved")).unwrap();
    sfs::write(&b, b"other").unwrap();
    assert!(fs::delete_checked(f, &b).is_err(), "a different file under the name is not deleted");
    assert!(b.exists());
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn xattr_streams_and_download_mark() {
    let d = dir();
    let (src, out) = (d.join("src.shd"), d.join("out"));
    sfs::write(&src, b"c").unwrap();
    if fs::set_xattr_for_test(&src, fs::MARKS[0], b"https://example.com/x").is_err() {
        eprintln!("user xattrs unsupported here; skipped");
        let _ = sfs::remove_dir_all(d);
        return;
    }
    sfs::create_dir_all(out.join("sub")).unwrap();
    sfs::write(out.join("sub").join("f"), b"f").unwrap();
    let r = OS.mark_of_the_web_propagate(&src, std::slice::from_ref(&out)).unwrap();
    assert!(r.had_mark && r.marked == 1, "{r:?}");
    let st = fs::list_streams(&out.join("sub").join("f")).unwrap();
    assert!(st.iter().any(|s| s.is_mark));
    fs::set_xattr_for_test(&src, "user.secret", b"hidden").unwrap();
    let mut passes = Vec::new();
    assert_eq!(OS.strip_extra_streams(&src, 3, &mut |b, p| { b.fill(p as u8); passes.push(p) }).unwrap(), 2);
    assert!(fs::list_streams(&src).unwrap().is_empty());
    assert_eq!(passes.len(), 6);
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn system_queries_are_sane() {
    assert!(sys::process_start(std::process::id()).is_some());
    assert!(sys::process_start(0).is_none());
    assert!(sys::process_start(u32::MAX - 7).is_none());
    assert!(sys::avail_mem() > 0);
    let t = sys::local_time(1_700_000_000).unwrap();
    assert!(t.y == 2023 && (1..=12).contains(&t.mo));
    assert!(fs::free_space(&std::env::temp_dir()).is_some());
    assert!(fs::forbidden_parent(Path::new("/")) && fs::forbidden_parent(Path::new("/etc")) && fs::forbidden_parent(Path::new("/proc/1")));
    assert!(!fs::forbidden_parent(Path::new("/home/u/x")));
    let k = OS.detect_storage_kind(&std::env::temp_dir());
    assert!(matches!(k, StorageKind::Ssd | StorageKind::Hdd | StorageKind::Unknown));
    let _ = OS.snapshot_warning(&std::env::temp_dir());
    assert!(matches!(OS.set_capture_protection(None, true), Err(PlatformError::Unsupported(_))));
    let h = OS.secure_memory_init();
    assert!(h.items.iter().any(|(i, ok)| *i == HardenItem::NoCoreDumps && *ok));
}

#[test]
fn trim_without_rights_gives_a_hint_or_a_clear_answer() {
    match OS.run_trim(&std::env::temp_dir()) {
        Ok(_) => {}
        Err(PlatformError::NeedsPrivilege { hint }) => assert!(hint.starts_with("sudo fstrim -v '")),
        Err(PlatformError::Unsupported(_)) | Err(PlatformError::Io(_)) => {}
        Err(x) => panic!("{x}"),
    }
}

#[test]
fn entropy_sources_report_and_console_skips_gui_ones() {
    let all = |_: Source| true;
    let mut seen = std::collections::BTreeSet::new();
    OS.entropy_extra(Poll::Slow, &EntropyCtx { gui: false, enabled: &all }, &mut |s, _| {
        seen.insert(s);
    });
    for s in [Source::Timers, Source::Memory, Source::Process, Source::Ids, Source::SystemTimes, Source::CpuJitter, Source::ProcFs, Source::Processes] {
        assert!(seen.contains(&s), "{s:?} missing: {seen:?}");
    }
    assert!(!seen.iter().any(|s| s.gui_only()));
}

#[test]
fn only_own_closed_folders_count_as_private() {
    // security review 2026-11-08: spool / update folders are reused only when they pass this
    let d = dir();
    let own = d.join("own");
    fs::create_private_dir(&own).unwrap();
    assert!(fs::is_private_dir(&own));
    let open = d.join("open");
    sfs::create_dir(&open).unwrap();
    sfs::set_permissions(&open, sfs::Permissions::from_mode(0o777)).unwrap();
    assert!(!fs::is_private_dir(&open), "writable by others");
    sfs::set_permissions(&open, sfs::Permissions::from_mode(0o755)).unwrap();
    assert!(fs::is_private_dir(&open), "own, others can only read");
    let link = d.join("link");
    std::os::unix::fs::symlink(&own, &link).unwrap();
    assert!(!fs::is_private_dir(&link), "a link to a private folder is not one");
    if unsafe { libc::geteuid() } != 0 {
        assert!(!fs::is_private_dir(std::path::Path::new("/")), "owned by root");
    }
    assert!(!fs::is_private_dir(&d.join("missing")));
    let _ = sfs::remove_dir_all(d);
}
