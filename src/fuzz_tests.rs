//! Randomized mutation tests ("fuzz-like", fixed seeds so failures are reproducible).
//! 1) Any change to an encrypted container must be rejected.
//! 2) The 7z layer must never panic or write outside the target folder on malformed input.

use crate::crypto::{encrypt_stream, read_header, stream_body, Cred};
use crate::format::*;
use crate::password::normalize;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::{
    fs,
    io::{self, Cursor},
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
};

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_fz_{}", crate::entropy::rand_hex().unwrap()));
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn random_container_mutations_are_rejected() {
    let dir = tmpdir();
    let c = Cred { pw: normalize("fuzz password 1234"), kf: None, pim: 0 };
    let data: Vec<u8> = (0..150_000u32).map(|i| (i * 7 + i / 300) as u8).collect();
    let p = dir.join("f.shd");
    let mut m = Meta::new("f.bin", FLAG_ARCHIVE);
    m.real_len = data.len() as u64;
    encrypt_stream(&mut Cursor::new(data.clone()), &mut fs::File::create(&p).unwrap(), &c, &mut m).unwrap();
    let orig = fs::read(&p).unwrap();
    let h = read_header(&mut fs::File::open(&p).unwrap(), &c).unwrap();
    let mut out = Vec::new();
    stream_body(&mut fs::File::open(&p).unwrap(), &h, &mut out).unwrap();
    assert_eq!(out, data);

    let mut rng = ChaCha8Rng::seed_from_u64(0x5348_4945_4c44);
    let q = dir.join("m.shd");
    // body: flip 1-3 random bytes (KDF result reused, so this is fast)
    for _ in 0..300 {
        let mut v = orig.clone();
        for _ in 0..rng.gen_range(1..=3) {
            let i = rng.gen_range(HEADER..v.len());
            v[i] ^= rng.gen_range(1..=255u8);
        }
        fs::write(&q, &v).unwrap();
        let r = stream_body(&mut fs::File::open(&q).unwrap(), &h, &mut io::sink());
        assert!(r.is_err(), "body mutation accepted");
    }
    // random truncation / extension
    for _ in 0..60 {
        let v = if rng.gen_bool(0.5) {
            orig[..rng.gen_range(HEADER..orig.len())].to_vec()
        } else {
            let mut v = orig.clone();
            v.extend((0..rng.gen_range(1..70_000)).map(|_| rng.gen::<u8>()));
            v
        };
        fs::write(&q, &v).unwrap();
        let r = stream_body(&mut fs::File::open(&q).unwrap(), &h, &mut io::sink());
        assert!(r.is_err(), "length change accepted ({} bytes)", v.len());
    }
    // slots, prefix and meta: full re-open (each one runs the KDF)
    for _ in 0..4 {
        let mut v = orig.clone();
        let i = rng.gen_range(0..HEADER);
        v[i] ^= rng.gen_range(1..=255u8);
        fs::write(&q, &v).unwrap();
        let mut f = fs::File::open(&q).unwrap();
        let ok = match read_header(&mut f, &c) {
            Ok(h2) => stream_body(&mut f, &h2, &mut io::sink()).is_ok(),
            Err(_) => false,
        };
        // a flip inside the slot that is not used is the only accepted change (it is random filler)
        let unused_slot = (1 - h.slot_idx) * SLOT..(2 - h.slot_idx) * SLOT;
        assert!(!ok || unused_slot.contains(&i), "header mutation at {i} accepted");
    }
    let _ = fs::remove_dir_all(dir);
}

fn sample_7z() -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        z.push_archive_entry::<&[u8]>(ArchiveEntry::new_directory("d"), None).unwrap();
        let text = "hello 7z ".repeat(400);
        z.push_archive_entry(ArchiveEntry::new_file("d/a.txt"), Some(text.as_bytes())).unwrap();
        let bin: Vec<u8> = (0..5000u32).map(|i| (i * 31) as u8).collect();
        z.push_archive_entry(ArchiveEntry::new_file("b.bin"), Some(&bin[..])).unwrap();
        z.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn malformed_7z_never_panics_or_escapes() {
    let root = tmpdir();
    let base = sample_7z();
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let mut panics = 0;
    for n in 0..300 {
        let mut v = base.clone();
        for _ in 0..rng.gen_range(1..=4) {
            let i = rng.gen_range(0..v.len());
            v[i] = rng.gen();
        }
        let out = root.join(format!("o{n}"));
        fs::create_dir(&out).unwrap();
        let len = v.len() as u64;
        let r = catch_unwind(AssertUnwindSafe(|| {
            let mut c = Cursor::new(v);
            if let Ok(l) = crate::archive::inspect(&mut c, len) {
                let _ = crate::archive::extract(&mut c, &out, l.total, &|x| Some(x.to_string()));
            }
        }));
        if r.is_err() {
            panics += 1;
        }
    }
    // nothing may appear next to the per-iteration folders
    for e in fs::read_dir(&root).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        assert!(name.starts_with('o') && e.path().is_dir(), "unexpected item {name}");
    }
    assert_eq!(panics, 0, "7z layer panicked on malformed input");
    let _ = fs::remove_dir_all(root);
}
