use super::*;
use crate::manifest::Manifest;

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_wipe_{}", crate::entropy::rand_hex().unwrap()));
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn pass_counts_and_patterns() {
    assert_eq!(Passes::Three.count(), 3);
    assert_eq!(Passes::Seven.count(), 7);
    assert_eq!(Passes::default(), Passes::Seven);
    assert_eq!(Passes::from_count(3), Some(Passes::Three));
    assert_eq!(Passes::from_count(1), None, "1 pass is no longer offered");
    assert_eq!(KEY_PASSES, Passes::Seven);
    assert_eq!(Passes::Three.patterns(), &[Some(0), Some(0xFF), None]);
}

#[test]
fn shred_checked_removes_listed_file_and_refuses_changed_ones() {
    let d = dir();
    let (a, b) = (d.join("a.txt"), d.join("b.txt"));
    fs::write(&a, b"secret a").unwrap();
    fs::write(&b, b"secret b").unwrap();
    let mut m = Manifest::default();
    Manifest::scan(&a, "", &mut m).unwrap();
    Manifest::scan(&b, "", &mut m).unwrap();
    fs::write(&b, b"changed after the list was fixed").unwrap();
    assert!(shred_checked(&m.files[0], Passes::Three, false).is_ok());
    assert!(!a.exists());
    assert!(matches!(shred_checked(&m.files[1], Passes::Three, false), Err(ShredSkip::Changed)));
    assert!(b.exists());
    let _ = fs::remove_dir_all(d);
}

#[test]
fn replace_and_shred_leaves_only_the_new_file() {
    let d = dir();
    let (t, n) = (d.join("box.shd"), d.join("new.part"));
    fs::write(&t, vec![0x5Au8; 5000]).unwrap();
    fs::write(&n, b"new contents").unwrap();
    assert_eq!(replace_and_shred(&n, &t, Passes::Three).unwrap(), None);
    assert_eq!(fs::read(&t).unwrap(), b"new contents");
    let left: Vec<_> = fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(left.len(), 1, "no backup or part left: {left:?}");
    let _ = fs::remove_dir_all(d);
}

#[test]
fn exposure_and_trim_never_fail_the_job() {
    let d = dir();
    let ex = exposure(&[d.as_path(), d.join("missing/file").as_path()]);
    assert!(ex.snapshot_lines.iter().all(|l| !l.is_empty()));
    let (ok, msg) = trim(&d);
    assert!(ok && !msg.is_empty(), "skipped in tests: {msg}");
    let _ = fs::remove_dir_all(d);
}

#[test]
fn own_tree_reports_and_clears_read_only() {
    let d = dir();
    fs::create_dir_all(d.join("sub")).unwrap();
    let f = d.join("sub").join("ro.txt");
    fs::write(&f, b"secret").unwrap();
    let mut perm = fs::metadata(&f).unwrap().permissions();
    perm.set_readonly(true);
    fs::set_permissions(&f, perm).unwrap();
    let rep = shred_own_tree_report(&d);
    assert!(rep.ok(), "{}", rep.message());
    assert!(!d.exists());
}

/// Windows only: a second handle without delete sharing makes overwrite and delete fail visibly.
#[cfg(windows)]
#[test]
fn own_tree_reports_an_undeletable_file() {
    use std::os::windows::fs::OpenOptionsExt;
    let d = dir();
    let f = d.join("busy.bin");
    fs::write(&f, b"secret").unwrap();
    let h = fs::OpenOptions::new().read(true).share_mode(1).open(&f).unwrap();
    let rep = shred_own_tree_report(&d);
    assert!(!rep.ok());
    assert!(!rep.overwrite_failed.is_empty() && !rep.delete_failed.is_empty(), "{rep:?}");
    drop(h);
    assert!(shred_own_tree(&d).is_ok());
}
