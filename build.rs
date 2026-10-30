//! Embeds the application icon and version info into shield.exe (Windows).
//! The icon is drawn by src/icon.rs, so no binary asset is kept in the repository.

#[path = "src/icon.rs"]
mod icon;

fn main() {
    println!("cargo:rerun-if-changed=src/icon.rs");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
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
