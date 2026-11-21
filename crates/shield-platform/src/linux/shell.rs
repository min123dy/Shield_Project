//! Linux desktop integration for the current user: .desktop entry and the Shield container MIME
//! type (optional extension association), plus context menu entries for Nautilus (scripts), Nemo
//! (actions), Dolphin (service menus, KF5 and KF6) and Thunar (custom actions in uca.xml).
//! All of them pass every selected item in one call (`%F` / `"$@"`).

use crate::{PResult, PlatformError};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub const MIME: &str = "application/x-shield-container";
const BEGIN: &str = "<!-- shield-begin -->";
const END: &str = "<!-- shield-end -->";
/// Largest Thunar uca.xml read (3.1.0 review 3).
const MAX_UCA: u64 = 16 << 20;

pub fn open_url(url: &str) -> PResult<()> {
    // defense in depth: the caller validated the URL already
    if !url.starts_with("https://") || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(PlatformError::Failed("not an https URL".into()));
    }
    let prog = ["/usr/bin/xdg-open", "/bin/xdg-open"].iter().map(Path::new).find(|p| p.is_file()).ok_or(PlatformError::Unsupported("xdg-open not installed"))?;
    let mut c = Command::new(prog).arg(url).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    std::thread::spawn(move || c.wait()); // reap; xdg-open returns quickly
    Ok(())
}

struct Labels {
    enc: &'static str,
    dec: &'static str,
    open: &'static str,
    wipe: &'static str,
    app: &'static str,
}

fn labels() -> Labels {
    if super::sys::system_lang_is_korean() {
        Labels { enc: "Shield로 암호화", dec: "Shield로 복호화", open: "SHIELD에서 열기", wipe: "SHIELD로 완전삭제", app: "Shield 파일 암호화" }
    } else {
        Labels { enc: "Encrypt with Shield", dec: "Decrypt with Shield", open: "Open in SHIELD", wipe: "Secure delete with SHIELD", app: "Shield file encryption" }
    }
}

fn data_home() -> PResult<PathBuf> {
    dirs::data_dir().ok_or(PlatformError::Failed("no XDG data folder".into()))
}

fn config_home() -> PResult<PathBuf> {
    dirs::config_dir().ok_or(PlatformError::Failed("no XDG config folder".into()))
}

/// Paths are written into shell scripts, .desktop Exec lines and XML: anything that would need
/// quoting rules of one of them is refused instead of escaped.
fn check_exe(exe: &Path) -> PResult<String> {
    let s = exe.to_str().ok_or(PlatformError::Failed("non UTF-8 path".into()))?;
    if !exe.is_absolute() || s.chars().any(|c| c.is_control() || "\"'`$\\%<>&;".contains(c)) {
        return Err(PlatformError::Failed("unsupported characters in the program path".into()));
    }
    Ok(s.to_string())
}

fn write(p: &Path, text: &str, exec: bool, out: &mut Vec<PathBuf>) -> PResult<()> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(p, text)?;
    fs::set_permissions(p, fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }))?;
    out.push(p.to_path_buf());
    Ok(())
}

struct Files {
    desktop: PathBuf,
    mime: PathBuf,
    nautilus: [PathBuf; 4],
    nemo: [PathBuf; 4],
    dolphin: Vec<PathBuf>,
    thunar: PathBuf,
}

fn files() -> PResult<Files> {
    let (d, c) = (data_home()?, config_home()?);
    let l = labels();
    let ns = d.join("nautilus/scripts");
    Ok(Files {
        desktop: d.join("applications/shield.desktop"),
        mime: d.join("mime/packages/shield.xml"),
        nautilus: [ns.join(l.enc), ns.join(l.dec), ns.join(l.open), ns.join(l.wipe)],
        nemo: [
            d.join("nemo/actions/shield-encrypt.nemo_action"),
            d.join("nemo/actions/shield-decrypt.nemo_action"),
            d.join("nemo/actions/shield-open.nemo_action"),
            d.join("nemo/actions/shield-wipe.nemo_action"),
        ],
        dolphin: vec![d.join("kio/servicemenus/shield.desktop"), d.join("kservices5/ServiceMenus/shield.desktop")],
        thunar: c.join("Thunar/uca.xml"),
    })
}

fn thunar_block(exe: &str, l: &Labels) -> String {
    let act = |id: &str, name: &str, arg: &str, pat: &str, dirs: bool| {
        format!(
            "<action><icon>shield</icon><name>{name}</name><unique-id>shield-{id}</unique-id><command>\"{exe}\" {arg} %F</command><description>{name}</description><patterns>{pat}</patterns>{}<audio-files/><image-files/><other-files/><text-files/><video-files/></action>",
            if dirs { "<directories/>" } else { "" }
        )
    };
    // 3.1.0 #14: "open" on every file (one: %f), whatever its name
    let open = format!(
        "<action><icon>shield</icon><name>{n}</name><unique-id>shield-open</unique-id><command>\"{exe}\" --open %f</command><description>{n}</description><patterns>*</patterns><audio-files/><image-files/><other-files/><text-files/><video-files/></action>",
        n = l.open
    );
    // 3.1.0 final: "secure delete" only opens the window (three confirmations happen there)
    format!(
        "{BEGIN}\n{}\n{}\n{open}\n{}\n{END}\n",
        act("encrypt", l.enc, "--encrypt-multi", "*", true),
        act("decrypt", l.dec, "--decrypt", "*.shd", false),
        act("wipe", l.wipe, "--wipe", "*", true)
    )
}

fn strip_block(xml: &str) -> String {
    match (xml.find(BEGIN), xml.find(END)) {
        (Some(a), Some(b)) if b > a => format!("{}{}", &xml[..a], xml[b + END.len()..].trim_start_matches('\n')),
        _ => xml.to_string(),
    }
}

pub fn register(exe: &Path) -> PResult<Vec<PathBuf>> {
    let e = check_exe(exe)?;
    let l = labels();
    let f = files()?;
    let mut out = Vec::new();
    write(
        &f.desktop,
        &format!(
            "[Desktop Entry]\nType=Application\nName=Shield\nComment={}\nExec=\"{e}\" %F\nIcon=shield\nTerminal=false\nCategories=Utility;Security;\nMimeType={MIME};\nActions=encrypt;\n\n[Desktop Action encrypt]\nName={}\nExec=\"{e}\" --encrypt\n",
            l.app, l.enc
        ),
        false,
        &mut out,
    )?;
    write(
        &f.mime,
        &format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n  <mime-type type=\"{MIME}\">\n    <comment>Shield container</comment>\n    <glob pattern=\"*.shd\"/>\n  </mime-type>\n</mime-info>\n"),
        false,
        &mut out,
    )?;
    write(&f.nautilus[0], &format!("#!/bin/sh\nexec \"{e}\" --encrypt-multi \"$@\"\n"), true, &mut out)?;
    write(&f.nautilus[1], &format!("#!/bin/sh\nexec \"{e}\" --decrypt \"$@\"\n"), true, &mut out)?;
    // one item only: Nautilus passes every selected item; the first is opened
    write(&f.nautilus[2], &format!("#!/bin/sh\n[ $# -ge 1 ] || exit 0\nexec \"{e}\" --open \"$1\"\n"), true, &mut out)?;
    // review F: Nautilus may pass names relative to the folder it runs the script in; the window
    // makes them absolute (`spool::normalize_arg`), `--` keeps names starting with - as names
    write(&f.nautilus[3], &format!("#!/bin/sh\n[ $# -ge 1 ] || exit 0\nexec \"{e}\" --wipe -- \"$@\"\n"), true, &mut out)?;
    // 3.1.0 #9-B: Quote=double, so Nemo passes names with spaces or quotes as one argument each
    write(&f.nemo[0], &format!("[Nemo Action]\nName={}\nExec=\"{e}\" --encrypt-multi %F\nIcon-Name=shield\nSelection=notnone\nExtensions=any;\nQuote=double\n", l.enc), false, &mut out)?;
    write(&f.nemo[1], &format!("[Nemo Action]\nName={}\nExec=\"{e}\" --decrypt %F\nIcon-Name=shield\nSelection=notnone\nExtensions=shd;\nQuote=double\n", l.dec), false, &mut out)?;
    write(&f.nemo[2], &format!("[Nemo Action]\nName={}\nExec=\"{e}\" --open %F\nIcon-Name=shield\nSelection=s\nExtensions=any;\nQuote=double\n", l.open), false, &mut out)?;
    write(&f.nemo[3], &format!("[Nemo Action]\nName={}\nExec=\"{e}\" --wipe %F\nIcon-Name=shield\nSelection=notnone\nExtensions=any;\nQuote=double\n", l.wipe), false, &mut out)?;
    let svc = format!(
        "[Desktop Entry]\nType=Service\nMimeType=all/allfiles;inode/directory;\nActions=shieldEncrypt;shieldDecrypt;shieldOpen;shieldWipe;\nX-KDE-ServiceTypes=KonqPopupMenu/Plugin\nX-KDE-Submenu=Shield\n\n[Desktop Action shieldEncrypt]\nName={}\nIcon=shield\nExec=\"{e}\" --encrypt-multi %F\n\n[Desktop Action shieldDecrypt]\nName={}\nIcon=shield\nExec=\"{e}\" --decrypt %F\n\n[Desktop Action shieldOpen]\nName={}\nIcon=shield\nExec=\"{e}\" --open %f\n\n[Desktop Action shieldWipe]\nName={}\nIcon=shield\nExec=\"{e}\" --wipe %F\n",
        l.enc, l.dec, l.open, l.wipe
    );
    for p in &f.dolphin {
        write(p, &svc, true, &mut out)?; // KF6 runs only executable service menus
    }
    // 3.1.0 review 3: read with a limit; a file that exists but cannot be read (too large, not
    // UTF-8, no access) is left alone instead of being replaced by one without the user's actions
    let old = match crate::bounded::read_text_limited(&f.thunar, MAX_UCA) {
        Ok(s) => s,
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(x) => return Err(std::io::Error::new(x.kind(), format!("{}: {x}", f.thunar.display())).into()),
    };
    let base = strip_block(&old);
    let xml = if base.contains("</actions>") {
        base.replacen("</actions>", &format!("{}</actions>", thunar_block(&e, &l)), 1)
    } else {
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n{}</actions>\n", thunar_block(&e, &l))
    };
    write(&f.thunar, &xml, false, &mut out)?;
    refresh(&out);
    Ok(out)
}

/// Updates the MIME / desktop databases when the tools exist (failures do not matter).
fn refresh(_written: &[PathBuf]) {
    if let Ok(d) = data_home() {
        let _ = super::sys::run_quiet(&["/usr/bin/update-mime-database"], &[d.join("mime").as_os_str()], std::time::Duration::from_secs(5));
        let _ = super::sys::run_quiet(&["/usr/bin/update-desktop-database"], &[d.join("applications").as_os_str()], std::time::Duration::from_secs(5));
    }
}

pub fn unregister() -> PResult<Vec<PathBuf>> {
    let f = files()?;
    let mut gone = Vec::new();
    // both languages: the labels (= Nautilus script names) may have changed since registering
    let ns = data_home()?.join("nautilus/scripts");
    let names = ["Shield로 암호화", "Shield로 복호화", "SHIELD에서 열기", "SHIELD로 완전삭제", "Encrypt with Shield", "Decrypt with Shield", "Open in SHIELD", "Secure delete with SHIELD"].map(|n| ns.join(n));
    for p in [f.desktop.clone(), f.mime.clone()].iter().chain(names.iter()).chain(f.nemo.iter()).chain(f.dolphin.iter()) {
        if fs::remove_file(p).is_ok() {
            gone.push(p.clone());
        }
    }
    if let Ok(x) = crate::bounded::read_text_limited(&f.thunar, MAX_UCA) {
        let s = strip_block(&x);
        if s != x {
            fs::write(&f.thunar, s)?;
            gone.push(f.thunar.clone());
        }
    }
    refresh(&gone);
    Ok(gone)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thunar_block_insert_and_strip_round_trip() {
        let l = labels();
        let base = "<?xml version=\"1.0\"?>\n<actions>\n<action><name>x</name></action>\n</actions>\n";
        let with = base.replacen("</actions>", &format!("{}</actions>", thunar_block("/usr/bin/shield-gui", &l)), 1);
        assert!(with.contains("shield-encrypt") && with.contains("\"/usr/bin/shield-gui\" --decrypt %F"));
        assert!(with.contains("<unique-id>shield-open</unique-id><command>\"/usr/bin/shield-gui\" --open %f</command>"), "3.1.0 #14");
        assert!(with.contains("<unique-id>shield-wipe</unique-id><command>\"/usr/bin/shield-gui\" --wipe %F</command>"), "3.1.0 final");
        assert_eq!(strip_block(&with), base);
        assert_eq!(strip_block(base), base);
    }
    #[test]
    fn exe_paths_needing_quotes_are_refused() {
        assert!(check_exe(Path::new("/opt/shield/shield-gui")).is_ok());
        for bad in ["relative/shield", "/opt/a\"b", "/opt/$(x)", "/opt/a%F", "/opt/a\nb", "/opt/a&b"] {
            assert!(check_exe(Path::new(bad)).is_err(), "{bad}");
        }
    }
    #[test]
    fn url_must_be_https() {
        assert!(open_url("http://example.com").is_err());
        assert!(open_url("https://x y").is_err());
    }
}
