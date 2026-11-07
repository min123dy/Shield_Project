//! Windows (MSVC): DLLs imported by shield.exe are looked up in System32 only.
//! Without this the loader searches the exe's own folder first, so a DLL with a system name put
//! next to a copied console exe (Downloads, a USB stick) ran inside Shield before `main`
//! (security review 2026-11-08). Same setting as shield-gui/build.rs.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // LOAD_LIBRARY_SEARCH_SYSTEM32 for the static imports (Windows 10 1607 and later)
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
