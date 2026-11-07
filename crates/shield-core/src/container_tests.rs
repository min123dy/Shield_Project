use super::*;
use crate::engine::{do_encrypt, tests_support::*};
use crate::i18n::has_code;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::io::{Cursor, Read};

fn sample(dir: &Path) -> (PathBuf, Cred) {
    let src = dir.join("Docs");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    fs::write(src.join("sub").join("b.txt"), vec![b'b'; 100_000]).unwrap();
    let c = cred("container password 1", 0);
    let dst = dir.join("Docs.shd");
    do_encrypt(&src, &dst, &c, &opts()).unwrap();
    (dst, c)
}

fn names(o: &Opened) -> Vec<String> {
    let mut v: Vec<String> = o.entries.iter().map(|x| x.name.to_string()).collect();
    v.sort();
    v
}

fn ao() -> AddOpts {
    AddOpts { overwrite: false, shred_src: false, passes: crate::wipe::Passes::Three, strength: Strength::Auto, keyfiles: vec![] }
}

#[test]
fn open_list_info_and_wrong_password() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let o = open(&p, c.duplicate()).unwrap();
    assert_eq!(names(&o), vec!["Docs", "Docs/a.txt", "Docs/sub", "Docs/sub/b.txt"]);
    assert_eq!(o.total, 100_005);
    assert_eq!(o.meta.file_count, 2);
    assert_eq!(o.file_len, fs::metadata(&p).unwrap().len());
    assert_eq!(o.body, BodyCheck::NotChecked);
    assert!(verify_body(&o, c.duplicate()).is_ok());
    assert!(has_code(&open(&p, cred("wrong password 1", 0)).err().unwrap(), C_OPEN_BAD));
    // a random file that is not a Shield container reads the same
    let junk = dir.join("junk.shd");
    fs::write(&junk, vec![7u8; 5000]).unwrap();
    assert_eq!(open(&junk, c.duplicate()).err().unwrap(), open_bad());
    // tampered body: open still works (headers only) but the full check fails
    let mut bytes = fs::read(&p).unwrap();
    let n = bytes.len();
    bytes[n - 20] ^= 1;
    let t = dir.join("tampered.shd");
    fs::write(&t, &bytes).unwrap();
    if let Ok(o2) = open(&t, c.duplicate()) {
        assert!(verify_body(&o2, c).is_err());
    }
    let _ = fs::remove_dir_all(dir);
}

/// A-4: an open container keeps no key. Every operation derives the key again from the
/// credentials it is given, so wrong or empty credentials fail even though the list is open.
#[test]
fn open_container_keeps_no_key() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let all: HashSet<String> = ["Docs".to_string()].into();
    assert!(has_code(&verify_body(&o, cred("wrong password 1", 0)).unwrap_err(), C_OPEN_BAD));
    for bad in [cred("wrong password 1", 0), cred("", 0), cred("container password 1", 1)] {
        assert!(verify_body(&o, bad.duplicate()).is_err());
        assert!(extract_selected(&o, bad.duplicate(), &all, "", &out, DecOpts::default()).is_err());
        assert!(add_files(&mut o, bad.duplicate(), &[], "", &ao()).is_err());
        assert!(remove_entries(&mut o, bad, &all, Strength::Auto, crate::wipe::Passes::Three).is_err());
    }
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0, "nothing extracted");
    // the type has no field that could hold a key, a password or a key file digest
    let Opened { path: _, stamp: _, meta: _, file_len: _, entries: _, total: _, body: _ } = &o;
    extract_selected(&o, c, &all, "", &out, DecOpts::default()).unwrap();
    assert!(out.join("Docs").join("a.txt").is_file());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn selective_extraction() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let o = open(&p, c.duplicate()).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let sel: HashSet<String> = ["Docs/sub".to_string()].into();
    extract_selected(&o, c.duplicate(), &sel, "Docs", &out, DecOpts::default()).unwrap();
    assert_eq!(fs::read(out.join("sub").join("b.txt")).unwrap().len(), 100_000);
    assert!(!out.join("a.txt").exists());
    let one: HashSet<String> = ["Docs/a.txt".to_string()].into();
    extract_selected(&o, c, &one, "", &out, DecOpts::default()).unwrap();
    assert_eq!(fs::read(out.join("Docs").join("a.txt")).unwrap(), b"alpha");
    let names: Vec<_> = fs::read_dir(&out).unwrap().flatten().map(|d| d.file_name()).collect();
    assert!(names.iter().all(|n| !n.to_string_lossy().starts_with(".shd_")), "no staging left");
    assert_eq!(selection_map("Docs/sub/b.txt", "Docs", &sel).as_deref(), Some("sub/b.txt"));
    assert_eq!(selection_map("Docs/a.txt", "Docs", &sel), None);
    let _ = fs::remove_dir_all(dir);
}

/// B-15: what an extraction already moved out is removed again when a later step fails.
#[test]
fn rollback_removes_moved_items() {
    let dir = tmpdir();
    let a = dir.join("a.txt");
    let b = dir.join("folder");
    fs::write(&a, b"moved").unwrap();
    fs::create_dir_all(b.join("x")).unwrap();
    fs::write(b.join("x").join("y.txt"), b"moved too").unwrap();
    let m = roll_back(&[a.clone(), b.clone()]);
    assert!(!a.exists() && !b.exists(), "{m}");
    assert_eq!(m, tf("cont.rolled_back", &[&2]));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn add_files_rebuilds_verifies_and_replaces() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let before = fs::read(&p).unwrap();
    let mut o = open(&p, c.duplicate()).unwrap();
    let extra = dir.join("new.txt");
    fs::write(&extra, b"added later").unwrap();
    add_files(&mut o, c.duplicate(), std::slice::from_ref(&extra), "Docs", &ao()).unwrap();
    assert!(names(&o).contains(&"Docs/new.txt".to_string()));
    assert_ne!(fs::read(&p).unwrap()[..64], before[..64], "new salts and slots after the rebuild");
    // reopen from disk with the password: old and new entries are all there
    let o2 = open(&p, c.duplicate()).unwrap();
    assert_eq!(names(&o2), vec!["Docs", "Docs/a.txt", "Docs/new.txt", "Docs/sub", "Docs/sub/b.txt"]);
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    dec(&p, &out, &c).unwrap();
    assert_eq!(fs::read(out.join("Docs").join("new.txt")).unwrap(), b"added later");
    assert_eq!(fs::read(out.join("Docs").join("sub").join("b.txt")).unwrap().len(), 100_000);
    // same name again: refused without overwrite, replaced with it
    let mut o3 = open(&p, c.duplicate()).unwrap();
    fs::write(&extra, b"second version").unwrap();
    assert!(add_files(&mut o3, c.duplicate(), std::slice::from_ref(&extra), "Docs", &ao()).is_err());
    let ow = AddOpts { overwrite: true, ..ao() };
    add_files(&mut o3, c.duplicate(), std::slice::from_ref(&extra), "Docs", &ow).unwrap();
    let o4 = open(&p, c).unwrap();
    assert_eq!(o4.entries.iter().filter(|x| x.name.as_str() == "Docs/new.txt").count(), 1);
    let left: Vec<String> = fs::read_dir(&dir).unwrap().flatten().map(|d| d.file_name().to_string_lossy().into_owned()).collect();
    assert!(left.iter().all(|n| !n.starts_with(".shd_")), "no temp files left: {left:?}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn remove_entries_rebuilds_without_them() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let sel: HashSet<String> = ["Docs/sub".to_string()].into();
    remove_entries(&mut o, c.duplicate(), &sel, Strength::Auto, crate::wipe::Passes::Three).unwrap();
    assert_eq!(names(&o), vec!["Docs", "Docs/a.txt"]);
    let o2 = open(&p, c.duplicate()).unwrap();
    assert_eq!((o2.meta.file_count, o2.total), (1, 5));
    assert!(remove_entries(&mut o, c, &HashSet::new(), Strength::Auto, crate::wipe::Passes::Three).is_err(), "nothing selected");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn add_refuses_when_container_changed_and_keeps_original() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let before = fs::read(&p).unwrap();
    // touch the container after opening (same bytes, new modification time)
    let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)).unwrap();
    drop(f);
    let extra = dir.join("x.txt");
    fs::write(&extra, b"x").unwrap();
    let err = add_files(&mut o, c, &[extra], "", &ao()).unwrap_err();
    assert!(has_code(&err, C_CHANGED), "{err}");
    assert_eq!(fs::read(&p).unwrap(), before);
    let _ = fs::remove_dir_all(dir);
}

/// B-2: while another task writes the container, opening waits and then reports E_BUSY.
#[test]
fn open_reports_busy_during_a_write() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let held = crate::lock::lock_container(&p, Mode::Exclusive).unwrap();
    let err = open(&p, c.duplicate()).err().unwrap();
    assert!(crate::lock::is_busy(&err), "{err}");
    drop(held);
    let _shared = crate::lock::lock_container(&p, Mode::Shared).unwrap();
    assert!(open(&p, c).is_ok(), "readers share the lock");
    let _ = fs::remove_dir_all(dir);
}

fn evil_archive(name: &str) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        z.push_archive_entry(ArchiveEntry::new_file(name), Some(&b"pwned"[..])).unwrap();
        z.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn path_attacks_are_blocked() {
    for bad in ["../evil.txt", "a/../../evil", "C:/Windows/evil", "/abs", "NUL", "a/con.txt", "x:ads", "dir/trail. ", "a\\..\\evil", "sub\\x.txt"] {
        let mut c = Cursor::new(evil_archive(bad));
        let len = c.get_ref().len() as u64;
        assert!(archive::inspect(&mut c, len).is_err(), "{bad}");
        let dir = tmpdir();
        assert!(archive::extract(&mut c, &dir, 5, &|n| Some(n.to_string())).is_err(), "{bad}");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(dir);
    }
    // case-only duplicates
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        z.push_archive_entry(ArchiveEntry::new_file("A.txt"), Some(&b"1"[..])).unwrap();
        z.push_archive_entry(ArchiveEntry::new_file("a.txt"), Some(&b"2"[..])).unwrap();
        z.finish().unwrap();
    }
    let len = buf.get_ref().len() as u64;
    assert!(archive::inspect(&mut buf, len).is_err());
    // link entries (reparse attribute)
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        let mut en = ArchiveEntry::new_file("link");
        en.has_windows_attributes = true;
        en.windows_attributes = 0x400;
        z.push_archive_entry(en, Some(&b"target"[..])).unwrap();
        z.finish().unwrap();
    }
    let len = buf.get_ref().len() as u64;
    assert!(archive::inspect(&mut buf, len).is_err());
}

/// 1.2 GiB of zeros compressed with Zstandard: the ratio limit rejects it before extraction.
#[test]
fn compression_bomb_ratio_is_rejected() {
    struct Zeros(u64);
    impl Read for Zeros {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = (b.len() as u64).min(self.0) as usize;
            b[..n].fill(0);
            self.0 -= n as u64;
            Ok(n)
        }
    }
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        z.set_content_methods(vec![sevenz_rust2::encoder_options::ZstandardOptions::from_level(1).into()]);
        z.push_archive_entry(ArchiveEntry::new_file("zeros.bin"), Some(Zeros(1_200 << 20))).unwrap();
        z.finish().unwrap();
    }
    let len = buf.get_ref().len() as u64;
    let err = archive::inspect(&mut buf, len).err().unwrap();
    assert_eq!(err, t("arc.bomb"));
}

#[test]
fn reads_same_as_bad_password_before_auth() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut bytes = fs::read(&p).unwrap();
    bytes[3] ^= 0xFF; // a slot byte: the real slot may be either one
    bytes[SLOT + 3] ^= 0xFF;
    fs::write(&p, &bytes).unwrap();
    let r = open(&p, c).err().unwrap();
    assert_eq!(r, open_bad());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn listing_is_written_back_after_writes() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let extra = dir.join("z.txt");
    fs::write(&extra, b"zz").unwrap();
    add_files(&mut o, c.duplicate(), &[extra], "", &ao()).unwrap();
    assert_eq!(o.body, BodyCheck::Ok);
    assert_eq!(o.stamp, stamp(&p).unwrap());
    // the refreshed state is the one a later operation checks against
    assert!(verify_body(&o, c).is_ok());
    let _ = fs::remove_dir_all(dir);
}
