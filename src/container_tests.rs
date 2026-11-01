use super::*;
use crate::engine::{do_encrypt, tests_support::*};
use crate::format::BAD;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::io::{Cursor, Read, Write};

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

#[test]
fn open_list_info_and_wrong_password() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let o = open(&p, c.duplicate(), vec![]).unwrap();
    assert_eq!(names(&o), vec!["Docs", "Docs/a.txt", "Docs/sub", "Docs/sub/b.txt"]);
    assert_eq!(o.total, 100_005);
    assert_eq!(o.hdr.meta.file_count, 2);
    assert_eq!(o.hdr.file_len, fs::metadata(&p).unwrap().len());
    assert_eq!(o.body, BodyCheck::NotChecked);
    assert!(verify_body(&o).is_ok());
    assert_eq!(open(&p, cred("wrong password 1", 0), vec![]).err().unwrap(), OPEN_BAD);
    // a random file that is not a Shield container reads the same
    let junk = dir.join("junk.shd");
    fs::write(&junk, vec![7u8; 5000]).unwrap();
    assert_eq!(open(&junk, c.duplicate(), vec![]).err().unwrap(), OPEN_BAD);
    // tampered body: open still works (headers only) but the full check fails
    let mut bytes = fs::read(&p).unwrap();
    let n = bytes.len();
    bytes[n - 20] ^= 1;
    let t = dir.join("tampered.shd");
    fs::write(&t, &bytes).unwrap();
    if let Ok(o2) = open(&t, c.duplicate(), vec![]) {
        assert!(verify_body(&o2).is_err());
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn selective_extraction() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let o = open(&p, c, vec![]).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let sel: HashSet<String> = ["Docs/sub".to_string()].into();
    extract_selected(&o, &sel, "Docs", &out).unwrap();
    assert_eq!(fs::read(out.join("sub").join("b.txt")).unwrap().len(), 100_000);
    assert!(!out.join("a.txt").exists());
    let one: HashSet<String> = ["Docs/a.txt".to_string()].into();
    extract_selected(&o, &one, "", &out).unwrap();
    assert_eq!(fs::read(out.join("Docs").join("a.txt")).unwrap(), b"alpha");
    let names: Vec<_> = fs::read_dir(&out).unwrap().flatten().map(|d| d.file_name()).collect();
    assert!(names.iter().all(|n| !n.to_string_lossy().starts_with(".shd_")), "no staging left");
    assert_eq!(selection_map("Docs/sub/b.txt", "Docs", &sel).as_deref(), Some("sub/b.txt"));
    assert_eq!(selection_map("Docs/a.txt", "Docs", &sel), None);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn add_files_rebuilds_verifies_and_replaces() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let dek_before = {
        let o = open(&p, c.duplicate(), vec![]).unwrap();
        *o.hdr.dek
    };
    let mut o = open(&p, c.duplicate(), vec![]).unwrap();
    let extra = dir.join("new.txt");
    fs::write(&extra, b"added later").unwrap();
    let ao = AddOpts { overwrite: false, shred_src: false, strength: Strength::Auto };
    let m = add_files(&mut o, std::slice::from_ref(&extra), "Docs", &ao).unwrap();
    assert!(m.contains("1개 추가"), "{m}");
    assert!(names(&o).contains(&"Docs/new.txt".to_string()));
    assert_ne!(*o.hdr.dek, dek_before, "new DEK after rebuild");
    // reopen from disk with the password: old and new entries are all there
    let o2 = open(&p, c.duplicate(), vec![]).unwrap();
    assert_eq!(names(&o2), vec!["Docs", "Docs/a.txt", "Docs/new.txt", "Docs/sub", "Docs/sub/b.txt"]);
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    crate::engine::do_decrypt(&p, &out, &c).unwrap();
    assert_eq!(fs::read(out.join("Docs").join("new.txt")).unwrap(), b"added later");
    assert_eq!(fs::read(out.join("Docs").join("sub").join("b.txt")).unwrap().len(), 100_000);
    // same name again: refused without overwrite, replaced with it
    let mut o3 = open(&p, c.duplicate(), vec![]).unwrap();
    fs::write(&extra, b"second version").unwrap();
    assert!(add_files(&mut o3, std::slice::from_ref(&extra), "Docs", &ao).is_err());
    let ow = AddOpts { overwrite: true, ..ao };
    add_files(&mut o3, std::slice::from_ref(&extra), "Docs", &ow).unwrap();
    let o4 = open(&p, c, vec![]).unwrap();
    assert_eq!(o4.entries.iter().filter(|x| x.name.as_str() == "Docs/new.txt").count(), 1);
    let left: Vec<String> = fs::read_dir(&dir).unwrap().flatten().map(|d| d.file_name().to_string_lossy().into_owned()).collect();
    assert!(left.iter().all(|n| !n.starts_with(".shd_")), "no temp files left: {left:?}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn add_refuses_when_container_changed_and_keeps_original() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c, vec![]).unwrap();
    let before = fs::read(&p).unwrap();
    // touch the container after opening (same bytes, new modification time / size check)
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"").unwrap();
    let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)).unwrap();
    drop(f);
    let extra = dir.join("x.txt");
    fs::write(&extra, b"x").unwrap();
    let ao = AddOpts { overwrite: false, shred_src: false, strength: Strength::Auto };
    assert!(add_files(&mut o, &[extra], "", &ao).is_err());
    assert_eq!(fs::read(&p).unwrap(), before);
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
    for bad in ["../evil.txt", "a/../../evil", "C:/Windows/evil", "/abs", "NUL", "a/con.txt", "x:ads", "dir/trail. "] {
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
    assert!(err.contains("압축 폭탄"), "{err}");
}

#[test]
fn reads_same_as_bad_password_before_auth() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut bytes = fs::read(&p).unwrap();
    bytes[3] ^= 0xFF; // a slot byte: the real slot may be either one
    bytes[SLOT_TEST + 3] ^= 0xFF;
    fs::write(&p, &bytes).unwrap();
    let r = open(&p, c, vec![]).err().unwrap();
    assert!(r == OPEN_BAD || r == BAD, "{r}");
    let _ = fs::remove_dir_all(dir);
}

const SLOT_TEST: usize = crate::format::SLOT;
