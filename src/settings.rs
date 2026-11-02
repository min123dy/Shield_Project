//! One settings struct (E-5), read once at start-up and saved atomically (unique temp file +
//! replace) as a flat TOML file with a schema version.
//!
//! Location: `%LOCALAPPDATA%\Shield\settings.toml`; portable mode (a `Shield_data` folder next to
//! the exe, or an exe name ending in `_portable`, as built by `build.ps1 -UpxPath`) keeps it next to
//! the exe instead. Never stored: passwords, keys, key files or their paths, container paths,
//! folder paths, recent files. A missing, unreadable or damaged file gives the defaults, which have
//! capture protection ON; a damaged value falls back to its own default.

use std::path::{Path, PathBuf};

pub const SCHEMA: u32 = 1;
pub const FILE: &str = "settings.toml";
pub const SCALES: [u32; 7] = [90, 100, 110, 120, 130, 140, 150];
pub const LOCK_MINUTES: [u32; 4] = [1, 5, 10, 30];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LangPref {
    System,
    Ko,
    En,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThemePref {
    System,
    Light,
    Dark,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DateFmt {
    Iso,
    Dots,
    Us,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartScreen {
    Encrypt,
    Decrypt,
    Manager,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Naming {
    /// report.pdf -> report.pdf.shd
    Append,
    /// report.pdf -> report.shd
    Replace,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartFolder {
    Drives,
    Home,
    Documents,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortBy {
    Name,
    Size,
    Date,
    Kind,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    // General
    pub lang: LangPref,
    pub theme: ThemePref,
    pub ui_scale: u32,
    pub date_fmt: DateFmt,
    pub date_seconds: bool,
    pub start_screen: StartScreen,
    // Security
    pub capture_protect: bool,
    pub mouse_entropy: bool,
    pub auto_lock_min: u32,
    pub lock_on_minimize: bool,
    pub lock_on_focus_loss: bool,
    pub allow_reveal: bool,
    pub clipboard_clear: bool,
    pub recent_files: bool,
    pub strict_motw: bool,
    // Encryption / compression
    pub strength: crate::compress::Strength,
    pub default_pim: u32,
    pub keyfile_kib: u32,
    pub shred_default: bool,
    pub naming: Naming,
    // Explorer
    pub show_hidden: bool,
    pub start_folder: StartFolder,
    pub sort: SortBy,
    pub confirm_delete: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            lang: LangPref::System,
            theme: ThemePref::System,
            ui_scale: 100,
            date_fmt: DateFmt::Iso,
            date_seconds: false,
            start_screen: StartScreen::Encrypt,
            capture_protect: true,
            mouse_entropy: true,
            auto_lock_min: 5,
            lock_on_minimize: true,
            lock_on_focus_loss: false,
            allow_reveal: true,
            clipboard_clear: true,
            recent_files: false,
            strict_motw: false,
            strength: crate::compress::Strength::Auto,
            default_pim: crate::format::DEFAULT_PIM,
            keyfile_kib: crate::keyfile::KF_DEFAULT_KIB,
            shred_default: false,
            naming: Naming::Append,
            show_hidden: false,
            start_folder: StartFolder::Drives,
            sort: SortBy::Name,
            confirm_delete: true,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    General,
    Security,
    Encryption,
    Explorer,
}

macro_rules! enum_codec {
    ($t:ty, $($v:ident = $s:literal),+) => {
        impl $t {
            pub fn code(self) -> &'static str { match self { $(<$t>::$v => $s),+ } }
            pub fn parse(s: &str) -> Option<Self> { match s { $($s => Some(<$t>::$v),)+ _ => None } }
        }
    };
}
enum_codec!(LangPref, System = "system", Ko = "ko", En = "en");
enum_codec!(ThemePref, System = "system", Light = "light", Dark = "dark");
enum_codec!(DateFmt, Iso = "iso", Dots = "dots", Us = "us");
enum_codec!(StartScreen, Encrypt = "encrypt", Decrypt = "decrypt", Manager = "manager");
enum_codec!(Naming, Append = "append", Replace = "replace");
enum_codec!(StartFolder, Drives = "drives", Home = "home", Documents = "documents");
enum_codec!(SortBy, Name = "name", Size = "size", Date = "date", Kind = "kind");

fn strength_code(s: crate::compress::Strength) -> &'static str {
    use crate::compress::Strength::*;
    match s {
        Auto => "auto",
        Fast => "fast",
        Balanced => "balanced",
        Max => "max",
    }
}
fn strength_parse(s: &str) -> Option<crate::compress::Strength> {
    crate::compress::Strength::ALL.into_iter().find(|x| strength_code(*x) == s)
}

impl Settings {
    /// Restores one category to its defaults.
    pub fn reset(&mut self, c: Category) {
        let d = Settings::default();
        match c {
            Category::General => {
                (self.lang, self.theme, self.ui_scale) = (d.lang, d.theme, d.ui_scale);
                (self.date_fmt, self.date_seconds, self.start_screen) = (d.date_fmt, d.date_seconds, d.start_screen);
            }
            Category::Security => {
                (self.capture_protect, self.mouse_entropy, self.auto_lock_min) = (d.capture_protect, d.mouse_entropy, d.auto_lock_min);
                (self.lock_on_minimize, self.lock_on_focus_loss, self.allow_reveal) = (d.lock_on_minimize, d.lock_on_focus_loss, d.allow_reveal);
                (self.clipboard_clear, self.recent_files, self.strict_motw) = (d.clipboard_clear, d.recent_files, d.strict_motw);
            }
            Category::Encryption => {
                (self.strength, self.default_pim, self.keyfile_kib) = (d.strength, d.default_pim, d.keyfile_kib);
                (self.shred_default, self.naming) = (d.shred_default, d.naming);
            }
            Category::Explorer => {
                (self.show_hidden, self.start_folder, self.sort, self.confirm_delete) = (d.show_hidden, d.start_folder, d.sort, d.confirm_delete);
            }
        }
    }

    pub fn to_toml(&self) -> String {
        let b = |v: bool| if v { "true" } else { "false" };
        let q = |s: &str| format!("\"{s}\"");
        let rows: Vec<(&str, String)> = vec![
            ("schema", SCHEMA.to_string()),
            ("lang", q(self.lang.code())),
            ("theme", q(self.theme.code())),
            ("ui_scale", self.ui_scale.to_string()),
            ("date_format", q(self.date_fmt.code())),
            ("date_seconds", b(self.date_seconds).into()),
            ("start_screen", q(self.start_screen.code())),
            ("capture_protect", b(self.capture_protect).into()),
            ("mouse_entropy", b(self.mouse_entropy).into()),
            ("auto_lock_minutes", self.auto_lock_min.to_string()),
            ("lock_on_minimize", b(self.lock_on_minimize).into()),
            ("lock_on_focus_loss", b(self.lock_on_focus_loss).into()),
            ("allow_reveal", b(self.allow_reveal).into()),
            ("clipboard_clear", b(self.clipboard_clear).into()),
            ("recent_files", b(self.recent_files).into()),
            ("strict_motw", b(self.strict_motw).into()),
            ("strength", q(strength_code(self.strength))),
            ("default_pim", self.default_pim.to_string()),
            ("keyfile_kib", self.keyfile_kib.to_string()),
            ("shred_default", b(self.shred_default).into()),
            ("naming", q(self.naming.code())),
            ("show_hidden", b(self.show_hidden).into()),
            ("start_folder", q(self.start_folder.code())),
            ("sort", q(self.sort.code())),
            ("confirm_delete", b(self.confirm_delete).into()),
        ];
        let mut s = String::from("# Shield settings. Secrets and file locations are never stored here.\n");
        for (k, v) in rows {
            s += &format!("{k} = {v}\n");
        }
        s
    }

    /// Parses leniently: unknown keys are ignored; a bad or out-of-range value keeps its default.
    pub fn from_toml(text: &str) -> Settings {
        let mut s = Settings::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            let sv = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or("");
            let bv = match v {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            };
            let nv: Option<u32> = v.parse().ok();
            match k {
                "lang" => s.lang = LangPref::parse(sv).unwrap_or(s.lang),
                "theme" => s.theme = ThemePref::parse(sv).unwrap_or(s.theme),
                "ui_scale" => s.ui_scale = nv.filter(|n| SCALES.contains(n)).unwrap_or(s.ui_scale),
                "date_format" => s.date_fmt = DateFmt::parse(sv).unwrap_or(s.date_fmt),
                "date_seconds" => s.date_seconds = bv.unwrap_or(s.date_seconds),
                "start_screen" => s.start_screen = StartScreen::parse(sv).unwrap_or(s.start_screen),
                "capture_protect" => s.capture_protect = bv.unwrap_or(true),
                "mouse_entropy" => s.mouse_entropy = bv.unwrap_or(s.mouse_entropy),
                "auto_lock_minutes" => s.auto_lock_min = nv.filter(|n| LOCK_MINUTES.contains(n)).unwrap_or(s.auto_lock_min),
                "lock_on_minimize" => s.lock_on_minimize = bv.unwrap_or(s.lock_on_minimize),
                "lock_on_focus_loss" => s.lock_on_focus_loss = bv.unwrap_or(s.lock_on_focus_loss),
                "allow_reveal" => s.allow_reveal = bv.unwrap_or(s.allow_reveal),
                "clipboard_clear" => s.clipboard_clear = bv.unwrap_or(s.clipboard_clear),
                "recent_files" => s.recent_files = bv.unwrap_or(s.recent_files),
                "strict_motw" => s.strict_motw = bv.unwrap_or(s.strict_motw),
                "strength" => s.strength = strength_parse(sv).unwrap_or(s.strength),
                "default_pim" => s.default_pim = nv.filter(|n| *n <= crate::format::MAX_PIM).unwrap_or(s.default_pim),
                "keyfile_kib" => s.keyfile_kib = nv.filter(|n| (1..=crate::keyfile::KF_MAX_KIB).contains(n)).unwrap_or(s.keyfile_kib),
                "shred_default" => s.shred_default = bv.unwrap_or(s.shred_default),
                "naming" => s.naming = Naming::parse(sv).unwrap_or(s.naming),
                "show_hidden" => s.show_hidden = bv.unwrap_or(s.show_hidden),
                "start_folder" => s.start_folder = StartFolder::parse(sv).unwrap_or(s.start_folder),
                "sort" => s.sort = SortBy::parse(sv).unwrap_or(s.sort),
                "confirm_delete" => s.confirm_delete = bv.unwrap_or(s.confirm_delete),
                _ => {}
            }
        }
        s
    }

    pub fn load_from(p: &Path) -> Settings {
        match std::fs::read(p) {
            Ok(b) if b.len() <= 64 * 1024 => std::str::from_utf8(&b).map(Settings::from_toml).unwrap_or_default(),
            _ => Settings::default(),
        }
    }

    pub fn save_to(&self, p: &Path) -> Result<(), String> {
        let dir = p.parent().ok_or("no folder")?;
        std::fs::create_dir_all(dir).map_err(|x| x.to_string())?;
        let tmp = dir.join(format!("settings.{}.{}.tmp", std::process::id(), crate::entropy::rand_hex()?));
        let r = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(self.to_toml().as_bytes())?;
            f.sync_all()?;
            drop(f);
            crate::sysinfo::rename_replace(&tmp, p)
        })();
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r.map_err(|x| crate::i18n::tf("set.save_failed", &[&x]))
    }

    pub fn load() -> Settings {
        Settings::load_from(&settings_path())
    }
    pub fn save(&self) -> Result<(), String> {
        self.save_to(&settings_path())
    }

    /// Language to use (System = Windows UI language).
    pub fn effective_lang(&self) -> crate::i18n::Lang {
        match self.lang {
            LangPref::Ko => crate::i18n::Lang::Ko,
            LangPref::En => crate::i18n::Lang::En,
            LangPref::System => crate::i18n::system_lang(),
        }
    }
}

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

/// Portable mode: `Shield_data` next to the exe, or an exe whose name ends in `_portable`.
pub fn portable_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe_dir()?.join("Shield_data");
    let named = exe.file_stem().is_some_and(|s| s.to_string_lossy().to_lowercase().ends_with("_portable"));
    (dir.is_dir() || named).then_some(dir)
}

/// Folder for settings, the staging journal and lock files.
pub fn data_dir() -> PathBuf {
    if let Some(p) = portable_dir() {
        return p;
    }
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("HOME")).map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("Shield")
}

pub fn settings_path() -> PathBuf {
    data_dir().join(FILE)
}

/// "Delete settings file" button: the defaults apply from the next start.
pub fn delete_file() -> Result<(), String> {
    match std::fs::remove_file(settings_path()) {
        Ok(()) => Ok(()),
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(x) => Err(x.to_string()),
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
