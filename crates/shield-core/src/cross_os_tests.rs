//! Cross-OS compatibility (design 3.0 §7): containers made on Windows and on Linux are the same
//! format and open on both. The fixtures were made by `make_fixture` (ignored test) on each OS:
//!   cargo test -p shield-core cross_os -- --ignored   (writes tests/fixtures/container/<os>_v3.shd)
//! and are checked here on every OS.

use crate::engine::tests_support::{cred, dec, opts, tmpdir};
use std::fs;
use std::path::{Path, PathBuf};

const PW: &str = "cross os password 1";
const TOP: &str = "Shield 샘플";

fn sample() -> Vec<(String, Vec<u8>)> {
    let bin: Vec<u8> = (0..100_000u32).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8).collect();
    vec![
        (format!("{TOP}/한글 이름.txt"), "안녕하세요 Shield\n".repeat(200).into_bytes()),
        (format!("{TOP}/sub/data.bin"), bin),
        (format!("{TOP}/empty.txt"), Vec::new()),
        (format!("{TOP}/Café é.txt"), "NFC name\n".into()),
    ]
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/container")
}

#[test]
#[ignore = "writes the fixture of this OS"]
fn make_fixture() {
    let d = tmpdir();
    for (rel, data) in sample() {
        let p = d.join(&rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }
    fs::create_dir_all(d.join(TOP).join("빈 폴더")).unwrap();
    let out = fixtures().join(format!("{}_v3.shd", std::env::consts::OS));
    fs::create_dir_all(fixtures()).unwrap();
    let _ = fs::remove_file(&out);
    crate::engine::do_encrypt(&d.join(TOP), &out, &cred(PW, 0), &opts()).unwrap();
    let _ = fs::remove_dir_all(d);
}

#[test]
fn containers_from_windows_and_linux_open_everywhere() {
    let mut seen = 0;
    for os in ["windows", "linux"] {
        let f = fixtures().join(format!("{os}_v3.shd"));
        if !f.exists() {
            continue;
        }
        seen += 1;
        let out = tmpdir();
        dec(&f, &out, &cred(PW, 0)).unwrap_or_else(|e| panic!("{os}: {e}"));
        for (rel, data) in sample() {
            let got = fs::read(out.join(&rel)).unwrap_or_else(|e| panic!("{os}: {rel}: {e}"));
            assert_eq!(got, data, "{os}: {rel}");
        }
        assert!(out.join(TOP).join("빈 폴더").is_dir(), "{os}: empty folder");
        assert!(dec(&f, &tmpdir(), &cred("wrong password 1", 0)).is_err());
        let _ = fs::remove_dir_all(out);
    }
    assert_eq!(seen, 2, "both fixtures belong to the source tree");
}
