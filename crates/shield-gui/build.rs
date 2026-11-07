//! Embeds the application icon and version info into shield.exe (Windows).
//! The icon is drawn by src/icon.rs, so no binary asset is kept in the repository.
//! Windows (MSVC): DLLs imported by the exe are looked up in System32 only. Without this the
//! loader searched the exe's own folder first, so a DLL with a system name (dwmapi.dll,
//! uxtheme.dll ...) put next to the portable exe ran inside Shield before `main` and before the
//! process hardening (security review 2026-11-08).

#[path = "src/icon.rs"]
mod icon;

fn main() {
    println!("cargo:rerun-if-changed=src/icon.rs");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // LOAD_LIBRARY_SEARCH_SYSTEM32 for the static imports (Windows 10 1607 and later)
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("shield.ico");
    std::fs::write(&out, icon::ico_bytes(&[16, 20, 24, 32, 40, 48, 64, 128, 256])).unwrap();
    let mut res = winresource::WindowsResource::new();
    res.set_icon(out.to_str().unwrap())
        .set("FileDescription", "Shield - 파일 암호화")
        .set("ProductName", "Shield")
        .set("LegalCopyright", "Shield");
    res.compile().expect("Windows 리소스 컴파일 실패 (Windows SDK의 rc.exe 필요)");
}
