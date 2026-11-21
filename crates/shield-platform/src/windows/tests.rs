use super::*;
use std::fs as sfs;

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_plat_{}_{}", std::process::id(), crate::cpu::cycle_counter().unwrap_or(0)));
    sfs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn disk_type_and_seek_penalty_bounds() {
    let d = OS.detect_storage_kind(&std::env::temp_dir());
    assert!(matches!(d, StorageKind::Ssd | StorageKind::Hdd | StorageKind::Unknown));
    assert_eq!(storage::seek_penalty('1'), None);
}

#[test]
fn retrim_helper_rejects_bad_arguments() {
    for a in [None, Some(""), Some("CD"), Some("C:"), Some("1"), Some("C' OR 1=1")] {
        assert_eq!(storage::retrim_main(a), 2, "{a:?}");
    }
    assert_eq!(sys::elevated_helper(&["--other".into()]), None);
}

#[test]
fn msft_volume_of_the_system_drive() {
    let con = wmi::WMIConnection::with_namespace_path(r"ROOT\Microsoft\Windows\Storage").unwrap();
    let l = storage::drive_letter(&fs::system_dir().unwrap()).unwrap();
    assert!(storage::volume_path(&con, l).unwrap().contains("MSFT_Volume"));
    assert!(storage::volume_path(&con, '1').is_err());
}

#[test]
fn snapshot_query_never_claims_none_without_rights() {
    let s = OS.snapshot_warning(&std::env::temp_dir());
    assert_eq!(s.found.len(), 1);
    assert_eq!(s.found[0].0, SnapshotKind::Vss);
}

#[test]
fn streams_list_classify_overwrite_and_motw() {
    let d = dir();
    let (plain, zone, hidden) = (d.join("plain.txt"), d.join("zone.txt"), d.join("hidden.txt"));
    for f in [&plain, &zone, &hidden] {
        sfs::write(f, b"main").unwrap();
    }
    let z = b"[ZoneTransfer]\r\nZoneId=3\r\n";
    fs::write_stream(&zone, fs::ZONE, z).unwrap();
    fs::write_stream(&hidden, "secret", b"hidden data").unwrap();
    assert!(fs::list_streams(&plain).unwrap().is_empty());
    assert_eq!(fs::list_streams(&hidden).unwrap(), vec![Stream { name: "secret".into(), size: 11, is_mark: false }]);
    assert!(fs::list_streams(&zone).unwrap()[0].is_mark);
    let mut passes = Vec::new();
    assert_eq!(OS.strip_extra_streams(&hidden, 3, &mut |b, p| { b.fill(p as u8); passes.push(p) }).unwrap(), 1);
    assert_eq!(fs::read_stream(&hidden, "secret").unwrap().len(), 0, "stream emptied");
    assert_eq!(passes, vec![0, 1, 2]);
    let out = d.join("out");
    sfs::create_dir_all(out.join("sub")).unwrap();
    sfs::write(out.join("a.docx"), b"a").unwrap();
    sfs::write(out.join("sub").join("b.exe"), b"b").unwrap();
    assert!(!OS.mark_of_the_web_propagate(&plain, std::slice::from_ref(&out)).unwrap().had_mark);
    let r = OS.mark_of_the_web_propagate(&zone, std::slice::from_ref(&out)).unwrap();
    assert!(r.had_mark && r.marked == 2 && r.failed.is_empty(), "{r:?}");
    assert_eq!(fs::read_stream(&out.join("sub").join("b.exe"), fs::ZONE).unwrap(), z);
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn replace_keeps_old_contents_under_backup() {
    let d = dir();
    let (t, n, b) = (d.join("box.shd"), d.join("new.part"), d.join("old.bak"));
    sfs::write(&t, b"old").unwrap();
    sfs::write(&n, b"new").unwrap();
    match fs::replace_keep_old(&n, &t, &b).unwrap() {
        Retained::Path(p) => assert_eq!(sfs::read(p).unwrap(), b"old"),
        Retained::Open(_) => panic!("Windows keeps a backup path"),
    }
    assert_eq!(sfs::read(&t).unwrap(), b"new");
    assert!(!n.exists());
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn restrict_permissions_leaves_one_user_ace() {
    let d = dir();
    let p = d.join("k.bin");
    sfs::write(&p, b"x").unwrap();
    OS.restrict_file_permissions(&p).unwrap();
    let out = std::process::Command::new(fs::system_dir().unwrap().join("icacls.exe")).arg(&p).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(!text.contains("(I)"), "nothing inherited: {text}");
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn dpapi_round_trip() {
    let s = sys::seal(b"mac key").unwrap();
    assert!(s.os_protected && s.bytes != b"mac key");
    assert_eq!(sys::unseal(&s.bytes).unwrap(), b"mac key");
    assert!(sys::unseal(b"garbage").is_err());
    // security review 2026-11-08: a tool that unseals without Shield's entropy gets nothing,
    // and a key file written by 3.0.0 (no entropy) still opens
    assert!(sys::unseal_without_entropy(&s.bytes).is_err(), "entropy required");
    let old = sys::seal_3_0_0(b"old mac key").unwrap();
    assert_eq!(sys::unseal(&old).unwrap(), b"old mac key");
}

#[test]
fn entropy_sources_report_and_console_skips_gui_ones() {
    let all = |_: Source| true;
    let mut seen = std::collections::BTreeSet::new();
    OS.entropy_extra(Poll::Slow, &EntropyCtx { gui: false, enabled: &all }, &mut |s, _| {
        seen.insert(s);
    });
    for s in [Source::Timers, Source::Memory, Source::Process, Source::Ids, Source::SystemTimes, Source::CpuJitter, Source::Processes] {
        assert!(seen.contains(&s), "{s:?} missing: {seen:?}");
    }
    assert!(!seen.contains(&Source::WindowState), "console context reads no window state");
    let only_timers = |s: Source| s == Source::Timers;
    let mut n = 0;
    OS.entropy_extra(Poll::Fast, &EntropyCtx { gui: true, enabled: &only_timers }, &mut |s, _| {
        assert_eq!(s, Source::Timers);
        n += 1;
    });
    assert_eq!(n, 1);
}

/// Child side of `hardened_process_can_be_ended_but_not_read`: hardens itself, says so, waits.
#[test]
#[ignore = "started by hardened_process_can_be_ended_but_not_read"]
fn hardened_child_helper() {
    if std::env::var_os("SHIELD_HARDEN_CHILD").is_none() {
        return;
    }
    let rep = mem::harden_process();
    assert!(rep.items.iter().any(|(k, ok)| matches!(k, crate::HardenItem::ProcessDacl) && *ok), "{rep:?}");
    use std::io::Write;
    println!("SHIELD_HARDENED");
    let _ = std::io::stdout().flush();
    std::thread::sleep(std::time::Duration::from_secs(60));
}

/// 3.0.0 fix: a hardened Shield that stopped responding must be possible to end from Task Manager
/// (same user, not elevated), while its memory stays closed to other same-user processes.
#[test]
fn hardened_process_can_be_ended_but_not_read() {
    use std::io::BufRead;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "imp::tests::hardened_child_helper", "--nocapture", "--test-threads=1"])
        .env("SHIELD_HARDEN_CHILD", "1")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let mut ready = false;
    while out.read_line(&mut line).unwrap_or(0) > 0 {
        if line.contains("SHIELD_HARDENED") {
            ready = true;
            break;
        }
        line.clear();
    }
    if !ready {
        let _ = child.kill();
        panic!("the child never reported that it was hardened");
    }
    let pid = child.id();
    unsafe {
        for (name, right) in [("VM_READ", PROCESS_VM_READ), ("VM_WRITE", PROCESS_VM_WRITE), ("VM_OPERATION", PROCESS_VM_OPERATION), ("CREATE_THREAD", PROCESS_CREATE_THREAD), ("DUP_HANDLE", PROCESS_DUP_HANDLE), ("WRITE_DAC", WRITE_DAC)] {
            let h = OpenProcess(right, 0, pid);
            if h != 0 {
                CloseHandle(h);
                let _ = child.kill();
                panic!("{name} must be denied to same-user processes");
            }
        }
        // what Task Manager / taskkill / Stop-Process ask for
        let h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, 0, pid);
        if h == 0 {
            let _ = child.kill(); // the handle from spawn still has full rights
            panic!("PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION must be allowed (Task Manager / taskkill)");
        }
        CloseHandle(h);
    }
    // the real tool, not elevated
    let out = std::process::Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"]).output().unwrap();
    if !out.status.success() {
        let _ = child.kill();
        panic!("taskkill could not end it: {}", String::from_utf8_lossy(&out.stderr));
    }
    let st = child.wait().unwrap();
    assert!(!st.success(), "ended by taskkill, not finished on its own");
}

#[test]
fn only_own_real_folders_count_as_private() {
    // security review 2026-11-08: spool / update folders are reused only when they pass this
    let d = dir();
    let own = d.join("own");
    fs::create_private_dir(&own).unwrap();
    assert!(fs::is_private_dir(&own));
    assert!(!fs::is_private_dir(&fs::system_dir().unwrap()), "System32 belongs to TrustedInstaller");
    let j = d.join("junction");
    let st = std::process::Command::new(fs::system_dir().unwrap().join("cmd.exe")).args(["/c", "mklink", "/J"]).arg(&j).arg(&own).output().unwrap();
    assert!(st.status.success(), "mklink /J: {}", String::from_utf8_lossy(&st.stdout));
    assert!(!fs::is_private_dir(&j), "a junction to a private folder is not one");
    assert!(!fs::is_private_dir(&d.join("missing")));
    let _ = sfs::remove_dir(&j);
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn an_oversized_or_odd_mark_still_marks_the_output() {
    // security review 2026-11-08: a Zone.Identifier over 64 KiB used to count as "no mark"
    let d = dir();
    let (src, dst) = (d.join("c.shd"), d.join("out.txt"));
    sfs::write(&src, b"x").unwrap();
    sfs::write(&dst, b"y").unwrap();
    let mut big = b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec();
    big.resize(70 * 1024, b' ');
    fs::write_stream(&src, "Zone.Identifier", &big).unwrap();
    let rep = fs::motw_propagate(&src, std::slice::from_ref(&dst));
    assert!(rep.had_mark && rep.failed.is_empty() && rep.marked == 1);
    let got = fs::read_zone(&dst).unwrap();
    assert!(String::from_utf8_lossy(&got).contains("ZoneId=3"), "Internet zone");
    // no mark stays no mark
    let plain = d.join("plain.shd");
    sfs::write(&plain, b"x").unwrap();
    assert!(fs::read_zone(&plain).is_none());
    assert!(!fs::motw_propagate(&plain, std::slice::from_ref(&dst)).had_mark);
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn trim_elevates_only_a_system32_tool() {
    // security review 2026-11-08: the administrator prompt never runs this (maybe portable) exe
    let sys32 = fs::system_dir().unwrap();
    let (exe, params) = storage::elevated_trim_command('c').unwrap();
    assert_eq!(exe, sys32.join("defrag.exe"));
    assert_eq!(params, "C: /L");
    assert!(exe.is_file());
    assert!(storage::elevated_trim_command('1').is_none());
    let me = std::env::current_exe().unwrap();
    let e = sys::run_elevated(&me, "--retrim C").unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "refused before any UAC prompt");
    let e = sys::run_elevated(&sys32.join("..").join("System32").join("defrag.exe"), "C: /L").unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "only the exact System32 folder");
}


// ---- 3.1.0 #1: update helper ----

#[test]
fn update_private_folder_has_admin_only_protected_dacl() {
    let d = dir();
    let p = d.join("upd");
    install::create_admin_dir(&p).unwrap();
    assert!(install::create_admin_dir(&p).is_err(), "an existing folder is refused");
    let sddl = install::dacl_sddl(&p).unwrap();
    assert_eq!(sddl, install::ADMIN_DACL, "SYSTEM + Administrators only, protected (no inheritance)");
    // the same seen through icacls (locale-neutral checks: two ACEs, nothing inherited)
    let out = std::process::Command::new(fs::system_dir().unwrap().join("icacls.exe")).arg(&p).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(text.lines().filter(|l| l.contains(":(")).count(), 2, "{text}");
    assert!(!text.contains("(I)"), "nothing inherited: {text}");
    // clean up as the owner (an owner may always rewrite the DACL)
    OS.restrict_file_permissions(&p).unwrap();
    let _ = sfs::remove_dir_all(d);
}

// ---- 3.1.0 review 2 #3: an existing update folder is not taken over ----

#[test]
fn update_folder_owners_that_count() {
    for s in ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"] {
        assert!(install::trusted_owner_sid(s), "{s}");
    }
    for s in ["S-1-5-32-545", "S-1-1-0", "S-1-5-11", "S-1-5-21-1-2-3-1001", "S-1-5-80-0", "", "S-1-5-18-1"] {
        assert!(!install::trusted_owner_sid(s), "{s}");
    }
}

#[test]
fn a_folder_made_by_a_normal_account_or_a_junction_is_refused_unchanged() {
    // the test runs as a normal (not elevated) account: the folder it makes is its own
    let d = dir();
    let own = d.join("Shield");
    sfs::create_dir(&own).unwrap();
    let before = install::dacl_sddl(&own).unwrap();
    let owner = install::owner_sid(&sfs::File::open(&own).or_else(|_| {
        use std::os::windows::fs::OpenOptionsExt;
        sfs::OpenOptions::new().read(true).custom_flags(0x0200_0000).open(&own)
    }).unwrap()).unwrap();
    assert!(owner.starts_with("S-1-5-"), "{owner}");
    if !install::trusted_owner_sid(&owner) {
        let e = install::secure_parent_for_test(&own).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
        assert_eq!(install::dacl_sddl(&own).unwrap(), before, "nothing changed");
    }
    // a junction in place of the folder is refused without touching its target
    let j = d.join("ShieldJ");
    let st = std::process::Command::new(fs::system_dir().unwrap().join("cmd.exe")).args(["/c", "mklink", "/J"]).arg(&j).arg(&own).output().unwrap();
    assert!(st.status.success(), "mklink /J: {}", String::from_utf8_lossy(&st.stdout));
    let e = install::secure_parent_for_test(&j).unwrap_err();
    assert!(e.to_string().contains("not a real folder"), "{e}");
    assert_eq!(install::dacl_sddl(&own).unwrap(), before, "the junction target is untouched");
    // the takeover by path is gone
    let src = include_str!("install.rs");
    assert!(!src.contains("SetNamedSecurityInfoW("), "no security change by path");
    let _ = sfs::remove_dir(&j);
    let _ = sfs::remove_dir_all(d);
}

#[test]
fn helper_command_line_quoting_refuses_what_it_cannot_quote() {
    assert_eq!(install::quote_arg(Path::new(r"C:\Users\a b\x.msi")).unwrap(), r#""C:\Users\a b\x.msi""#);
    for bad in [r#"C:\a"b.msi"#, r"C:\dir\"] {
        assert!(install::quote_arg(Path::new(bad)).is_err(), "{bad}");
    }
}

#[test]
fn only_programs_below_program_files_are_elevated_for_updates() {
    // a test binary lives in target\, not below Program Files: refused before any prompt
    let me = std::env::current_exe().unwrap();
    assert!(sys::run_elevated_installed(&me, "--install-update").is_err());
    let files = [me.as_path(); 4];
    assert!(matches!(sys::run_update_helper(&files), Err(PlatformError::Unsupported(_))));
    assert!(!install::below(&me, &std::env::temp_dir().join("nowhere")));
}

#[test]
fn second_stage_arguments_are_checked() {
    let root = dir();
    let run = root.join("abc");
    sfs::create_dir_all(&run).unwrap();
    let me = run.join("shield-update-run.exe");
    let arg = |p: &Path| vec![p.to_string_lossy().into_owned()];
    assert_eq!(install::check_run_args(&arg(&run), &me, &root), Err(3), "no package yet");
    sfs::write(run.join(install::PKG_FILE), b"msi").unwrap();
    assert_eq!(install::check_run_args(&arg(&run), &me, &root), Ok(run.join(install::PKG_FILE)));
    assert_eq!(install::check_run_args(&[], &me, &root), Err(2));
    assert_eq!(install::check_run_args(&arg(&root), &me, &root), Err(2), "not a folder in the update root");
    assert_eq!(install::check_run_args(&arg(Path::new("abc")), &me, &root), Err(2), "relative");
    assert_eq!(install::check_run_args(&arg(&run), &root.join("other.exe"), &root), Err(2), "not run from that folder");
    if !install::is_elevated() {
        assert_eq!(install::run_stage2(&arg(&run)), 71, "unelevated second stage refused");
    }
    let _ = sfs::remove_dir_all(root);
}