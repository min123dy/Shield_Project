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

// ---- 3.1.0 #1: update helper ----

#[test]
fn update_helper_runs_only_as_root_from_pkexec() {
    use std::ffi::OsStr;
    assert!(install::helper_allowed(0, Some(OsStr::new("1000"))));
    assert!(!install::helper_allowed(1000, Some(OsStr::new("1000"))), "euid != 0 refused");
    assert!(!install::helper_allowed(0, None), "root without pkexec refused");
    assert!(!install::helper_allowed(0, Some(OsStr::new(""))));
    assert!(!install::helper_allowed(0, Some(OsStr::new("10x0"))));
    // a test run is not started by pkexec
    if std::env::var_os("PKEXEC_UID").is_none() {
        assert!(!install::update_helper_allowed());
    }
}

#[test]
fn update_folders_must_be_root_owned_and_closed() {
    assert!(install::root_dir_ok(0, 0o040755, true, false));
    assert!(install::root_dir_ok(0, 0o040700, true, false));
    for (uid, mode, dir, link) in [(1000, 0o040755, true, false), (0, 0o040775, true, false), (0, 0o040777, true, false), (0, 0o041777, true, false), (0, 0o040755, false, false), (0, 0o120777, true, true)] {
        assert!(!install::root_dir_ok(uid, mode, dir, link), "{uid} {mode:o} {dir} {link}");
    }
}

#[test]
fn update_files_are_new_and_private_until_verified() {
    // (3.1.0 first version: "update_files_are_new_and_world_readable", 0644 at creation; changed
    // by review 2 #1, see docs/06_3.1.0 section 16)
    let d = dir();
    let p = d.join("package.deb");
    drop(install::create_update_file(&p).unwrap());
    assert_eq!(sfs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "nobody else reads an unverified copy");
    assert!(install::create_update_file(&p).is_err(), "existing file refused");
    // after verification the package is opened to apt's _apt user
    install::open_to_apt(&p).unwrap();
    assert_eq!(sfs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644, "apt's _apt user must read it");
    let link = d.join("link.deb");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    assert!(install::create_update_file(&link).is_err(), "a link is never written through");
    sfs::set_permissions(&p, sfs::Permissions::from_mode(0o600)).unwrap();
    assert!(install::open_to_apt(&link).is_err(), "never through a link");
    assert_eq!(sfs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    // an AppImage copy that fails the hash check is not renamed over the target
    assert!(install::install_package(&p, &|_| false).is_err());
    let _ = sfs::remove_dir_all(d);
}

// ---- 3.1.0 review 2 #1: the helper reads only the caller's own files ----

#[test]
fn update_inputs_must_belong_to_the_pkexec_caller() {
    use std::ffi::OsStr;
    assert!(install::input_owner_ok(1000, Some(OsStr::new("1000")), 0));
    assert!(!install::input_owner_ok(0, Some(OsStr::new("1000")), 0), "a root file is refused although the helper is root");
    assert!(!install::input_owner_ok(1001, Some(OsStr::new("1000")), 1001), "PKEXEC_UID decides, not the real uid");
    for bad in ["", "10x0", "-1", " 1000", "99999999999"] {
        assert!(!install::input_owner_ok(1000, Some(OsStr::new(bad)), 1000), "{bad:?}");
    }
    assert!(install::input_owner_ok(1000, None, 1000) && !install::input_owner_ok(0, None, 1000));
    // the real check: our own file passes; as a normal user, a root file does not
    if std::env::var_os("PKEXEC_UID").is_none() {
        let d = dir();
        let p = d.join("own");
        sfs::write(&p, b"x").unwrap();
        assert!(install::update_input_owner_ok(&sfs::metadata(&p).unwrap()));
        if unsafe { libc::getuid() } != 0 {
            assert!(!install::update_input_owner_ok(&sfs::metadata("/etc/passwd").unwrap()));
        }
        let _ = sfs::remove_dir_all(d);
    }
}

#[test]
fn update_folders_cannot_be_listed_by_others() {
    assert_eq!(install::PRIVATE_DIR_MODE, 0o711);
    assert!(install::root_dir_ok(0, 0o040000 | install::PRIVATE_DIR_MODE, true, false));
    let src = include_str!("install.rs");
    assert!(!src.contains("mode(0o644).custom_flags"), "copies are not created readable");
    let i = src.find("pub fn install_from_private").unwrap();
    let body = &src[i..];
    assert!(body.find("open_to_apt(pkg)").unwrap() < body.find("apt-get").unwrap(), "opened to apt only here, after verification");
}

// ---- 3.1.0 #11: rename without RENAME_NOREPLACE ----

#[test]
fn folder_fallback_rule_table() {
    for (uid, mode, euid, ok) in [
        (1000, 0o040700, 1000, true),
        (1000, 0o040755, 1000, true),
        (1000, 0o040750, 1000, true),
        (1000, 0o040775, 1000, false), // group may create the name in between
        (1000, 0o040757, 1000, false), // others may
        (1000, 0o041777, 1000, false), // sticky /tmp-like: still writable by all
        (0, 0o040755, 1000, false),    // somebody else's folder
        (1000, 0o040700, 0, false),
        (0, 0o040755, 0, true),
    ] {
        assert_eq!(fs::dir_fallback_ok(uid, mode, euid), ok, "{uid} {mode:o} {euid}");
    }
}

#[test]
fn fallback_moves_files_by_link_and_folders_only_into_closed_folders() {
    let d = dir();
    sfs::set_permissions(&d, sfs::Permissions::from_mode(0o700)).unwrap();
    // files: never replace
    let (a, b) = (d.join("a"), d.join("b"));
    sfs::write(&a, b"A").unwrap();
    sfs::write(&b, b"B").unwrap();
    assert_eq!(fs::rename_noreplace_fallback(&a, &b).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(sfs::read(&b).unwrap(), b"B");
    fs::rename_noreplace_fallback(&a, &d.join("c")).unwrap();
    assert!(!a.exists() && sfs::read(d.join("c")).unwrap() == b"A");
    // folders: into an owner-only folder
    let src = d.join("dir1");
    sfs::create_dir(&src).unwrap();
    fs::rename_noreplace_fallback(&src, &d.join("dir2")).unwrap();
    assert!(d.join("dir2").is_dir());
    assert_eq!(fs::rename_noreplace_fallback(&d.join("dir2"), &b).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    // into a folder others can write: refused, nothing moved
    let open = d.join("open");
    sfs::create_dir(&open).unwrap();
    sfs::set_permissions(&open, sfs::Permissions::from_mode(0o777)).unwrap();
    let e = fs::rename_noreplace_fallback(&d.join("dir2"), &open.join("dir3")).unwrap_err();
    assert_eq!(e.to_string(), crate::NOREPLACE_DIR_REFUSED);
    assert!(d.join("dir2").is_dir() && !open.join("dir3").exists());
    // a file may still go there (link(2) never replaces)
    fs::rename_noreplace_fallback(&d.join("c"), &open.join("c")).unwrap();
    let _ = sfs::remove_dir_all(d);
}

/// 3.1.0 final (review D): no /tmp fallback. XDG_CONFIG_HOME only when absolute, else
/// <home>/.config, else an error.
#[test]
fn config_folder_has_no_fallback() {
    let home = Some(PathBuf::from("/home/u"));
    assert_eq!(config_base(Some("/x/cfg".into()), home.clone()).unwrap(), PathBuf::from("/x/cfg"));
    assert_eq!(config_base(Some("relative/cfg".into()), home.clone()).unwrap(), PathBuf::from("/home/u/.config"), "a relative XDG value is ignored");
    assert_eq!(config_base(None, home).unwrap(), PathBuf::from("/home/u/.config"));
    assert!(config_base(None, None).is_err(), "neither set: an error, not /tmp");
    assert!(config_base(Some("rel".into()), Some(PathBuf::from("rel_home"))).is_err());
}

/// 3.1.0 final (review D): the data folder is a real 0700 folder of this user; looser permissions
/// are tightened, a link, a file or another owner's folder is refused (and left unchanged).
#[test]
fn data_folder_must_be_own_private_real_folder() {
    use std::os::unix::fs::MetadataExt;
    let d = dir();
    let fresh = d.join("new").join("shield");
    erase::ensure_data_dir(&fresh).unwrap();
    assert_eq!(sfs::symlink_metadata(&fresh).unwrap().mode() & 0o777, 0o700);
    let loose = d.join("loose");
    sfs::create_dir(&loose).unwrap();
    sfs::set_permissions(&loose, sfs::Permissions::from_mode(0o775)).unwrap();
    erase::ensure_data_dir(&loose).unwrap();
    assert_eq!(sfs::symlink_metadata(&loose).unwrap().mode() & 0o777, 0o700, "tightened");
    let link = d.join("link");
    std::os::unix::fs::symlink(&loose, &link).unwrap();
    assert!(erase::ensure_data_dir(&link).is_err(), "a link to a folder");
    let file = d.join("file");
    sfs::write(&file, b"x").unwrap();
    assert!(erase::ensure_data_dir(&file).is_err(), "a file");
    // another owner: only possible to set up as root (the Docker test run); skipped otherwise
    let other = d.join("other");
    sfs::create_dir(&other).unwrap();
    sfs::set_permissions(&other, sfs::Permissions::from_mode(0o755)).unwrap();
    let c = std::ffi::CString::new(other.as_os_str().as_encoded_bytes()).unwrap();
    if unsafe { libc::chown(c.as_ptr(), 4242, 4242) } == 0 {
        let e = erase::ensure_data_dir(&other).unwrap_err();
        assert!(e.to_string().contains("another user"), "{e}");
        assert_eq!(sfs::symlink_metadata(&other).unwrap().mode() & 0o777, 0o755, "left unchanged");
    } else {
        eprintln!("not root: the other-owner case is not checked here");
    }
    let _ = sfs::remove_dir_all(d);
}

/// 3.1.0 final (review D): settings and settings.key are used only when they are this user's own
/// files that others can't change (the key: not readable by others either).
#[test]
fn settings_files_must_be_own_and_not_writable_by_others() {
    let d = dir();
    let f = d.join("settings.toml");
    sfs::write(&f, b"x").unwrap();
    let check = |mode: u32, key: bool| {
        sfs::set_permissions(&f, sfs::Permissions::from_mode(mode)).unwrap();
        erase::private_file_ok(&sfs::File::open(&f).unwrap(), key)
    };
    assert!(check(0o600, true) && check(0o600, false));
    assert!(!check(0o640, true) && check(0o644, false), "key 0600 only; settings may be readable");
    assert!(!check(0o664, false) && !check(0o646, false), "writable by group / others");
    let c = std::ffi::CString::new(f.as_os_str().as_encoded_bytes()).unwrap();
    sfs::set_permissions(&f, sfs::Permissions::from_mode(0o600)).unwrap();
    if unsafe { libc::chown(c.as_ptr(), 4242, 4242) } == 0 {
        assert!(!erase::private_file_ok(&sfs::File::open(&f).unwrap(), false), "another owner");
    }
    let _ = sfs::remove_dir_all(d);
}
