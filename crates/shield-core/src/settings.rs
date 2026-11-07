//! One settings struct (E-5), read once at start-up and saved atomically (unique temp file +
//! replace) as a flat TOML file with a schema version.
//!
//! Location: `%LOCALAPPDATA%\Shield\settings.toml` (Windows) or `$XDG_CONFIG_HOME/shield/settings.toml`
//! (Linux, usually `~/.config/shield`, folder 0700 / file 0600); portable mode (a `Shield_data` folder
//! next to the exe, or an exe name ending in `_portable`) keeps it next to the exe instead. Never
//! stored: passwords, keys, key files or their paths, container paths, folder paths, recent files.
//! A missing, unreadable or damaged file gives the defaults, which have capture protection ON,
//! updates OFF and secrets on the command line OFF; a damaged value falls back to its own default.
//!
//! The security-relevant ("protected") values can be locked with a settings password and are
//! covered by a MAC (see `settings_auth`): changing them needs the password, and a file edited
//! outside Shield is detected and those values return to their defaults.

use std::path::{Path, PathBuf};

/// 2 (3.0.0): `ui_*` rows (remembered window positions and tab options). A version-1 file is
/// read as is (the new rows take their defaults); unknown rows of a newer version are ignored.
pub const SCHEMA: u32 = 2;
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
/// Update check / install (both off by default; installing always asks first).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateMode {
    Off,
    /// Check at start-up and show a "new version" button.
    Check,
    /// Check, download and verify in the background, then ask before installing.
    Auto,
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
    /// Secrets on the command line (`--password` ...): off unless enabled here or `--allow-arg-secrets`.
    pub allow_arg_secrets: bool,
    /// Entropy sources switched off (codes of `shield_platform::Source`; the OS CSPRNG can't be).
    pub entropy_disabled: Vec<String>,
    pub update: UpdateMode,
    /// Default overwrite passes (3 or 7) offered for shredding, rekey, add and remove.
    pub shred_passes: crate::wipe::Passes,
    /// Settings password (salt, verifier); None = no password set.
    pub auth: Option<crate::settings_auth::Auth>,
    /// Runtime only: the protected values failed the MAC check at load and were reset.
    pub tampered: bool,
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
    /// Remembered window positions and tab options (`ui_prefs.rs`).
    pub ui: crate::ui_prefs::UiPrefs,
    /// Runtime only (3.0.0 §4): features that are switched on in the file but could not work in
    /// this environment. Their value above is `false` (shown and used as off); the file keeps the
    /// user's value (`file_view`), and the next start tries again.
    pub env_off: Vec<EnvOff>,
    /// Runtime only: rows of the file that were damaged or had impossible values (they got their
    /// defaults). Shown once at start-up.
    pub load_issues: Vec<String>,
}

/// A feature that depends on the environment (OS, display server, build options).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvKey {
    CaptureProtect,
    RememberWindowPos,
    /// No release repository was built in: there is nothing to check.
    Update,
}

/// Why a feature is off although the user switched it on, and the value to keep in the file.
#[derive(Clone, PartialEq, Debug)]
pub struct EnvOff {
    pub key: EnvKey,
    pub reason: String,
    /// The value before it was switched off (only `Update` has more than on / off).
    saved_update: UpdateMode,
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
            allow_arg_secrets: false,
            entropy_disabled: Vec::new(),
            update: UpdateMode::Off,
            shred_passes: crate::wipe::Passes::Seven,
            auth: None,
            tampered: false,
            strength: crate::compress::Strength::Auto,
            default_pim: crate::format::DEFAULT_PIM,
            keyfile_kib: crate::keyfile::KF_DEFAULT_KIB,
            shred_default: false,
            naming: Naming::Append,
            show_hidden: false,
            start_folder: StartFolder::Drives,
            sort: SortBy::Name,
            confirm_delete: true,
            ui: crate::ui_prefs::UiPrefs::default(),
            env_off: Vec::new(),
            load_issues: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    General,
    Security,
    Encryption,
    Explorer,
    /// Update check / install, developer link, release key.
    Update,
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
enum_codec!(UpdateMode, Off = "off", Check = "check", Auto = "auto");

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
    fn env_value(&mut self, k: EnvKey) -> &mut bool {
        match k {
            EnvKey::CaptureProtect => &mut self.capture_protect,
            EnvKey::RememberWindowPos => &mut self.ui.remember_window_pos,
            EnvKey::Update => unreachable!("update is not a switch"),
        }
    }

    fn env_is_on(&mut self, k: EnvKey) -> bool {
        match k {
            EnvKey::Update => self.update != UpdateMode::Off,
            _ => *self.env_value(k),
        }
    }

    fn env_switch_off(&mut self, k: EnvKey) {
        match k {
            EnvKey::Update => self.update = UpdateMode::Off,
            _ => *self.env_value(k) = false,
        }
    }

    /// 3.0.0 §4: `k` could not be applied here. The setting becomes off (one value: what is shown
    /// is what is used); the file keeps the value the user chose. Does nothing when it is off.
    pub fn suppress(&mut self, k: EnvKey, reason: impl Into<String>) {
        let reason = reason.into();
        let on = self.env_is_on(k);
        let saved_update = self.update;
        if let Some(e) = self.env_off.iter_mut().find(|e| e.key == k) {
            e.reason = reason;
            if on {
                // switched on again by the user while unavailable: that choice is what the file keeps
                if k == EnvKey::Update {
                    e.saved_update = saved_update;
                }
                self.env_switch_off(k);
            }
            return;
        }
        if !on {
            return;
        }
        self.env_switch_off(k);
        self.env_off.push(EnvOff { key: k, reason, saved_update });
    }

    /// The user changed `k` (or it works now): it is no longer marked as switched off.
    pub fn unsuppress(&mut self, k: EnvKey) {
        self.env_off.retain(|e| e.key != k);
    }

    pub fn off_reason(&self, k: EnvKey) -> Option<&str> {
        self.env_off.iter().find(|e| e.key == k).map(|e| e.reason.as_str())
    }

    /// What the file holds: switched-off features get back the value the user chose.
    pub fn file_view(&self) -> Settings {
        let mut f = self.clone();
        for e in &self.env_off {
            match e.key {
                EnvKey::Update => f.update = e.saved_update,
                k => *f.env_value(k) = true,
            }
        }
        f.env_off.clear();
        f.load_issues.clear();
        f
    }

    /// Restores one category to its defaults.
    pub fn reset(&mut self, c: Category) {
        let d = Settings::default();
        match c {
            Category::General => {
                (self.lang, self.theme, self.ui_scale) = (d.lang, d.theme, d.ui_scale);
                (self.date_fmt, self.date_seconds, self.start_screen) = (d.date_fmt, d.date_seconds, d.start_screen);
                self.ui.remember_window_pos = d.ui.remember_window_pos;
            }
            Category::Security => {
                (self.capture_protect, self.mouse_entropy, self.auto_lock_min) = (d.capture_protect, d.mouse_entropy, d.auto_lock_min);
                (self.lock_on_minimize, self.lock_on_focus_loss, self.allow_reveal) = (d.lock_on_minimize, d.lock_on_focus_loss, d.allow_reveal);
                (self.clipboard_clear, self.recent_files, self.strict_motw) = (d.clipboard_clear, d.recent_files, d.strict_motw);
                self.reset_protected();
            }
            Category::Encryption => {
                (self.strength, self.default_pim, self.keyfile_kib) = (d.strength, d.default_pim, d.keyfile_kib);
                (self.shred_default, self.naming) = (d.shred_default, d.naming);
            }
            Category::Update => self.update = d.update,
            Category::Explorer => {
                (self.show_hidden, self.start_folder, self.sort, self.confirm_delete) = (d.show_hidden, d.start_folder, d.sort, d.confirm_delete);
            }
        }
    }

    /// The security-relevant values back to their (safe) defaults.
    pub fn reset_protected(&mut self) {
        let d = Settings::default();
        (self.capture_protect, self.mouse_entropy, self.strict_motw) = (d.capture_protect, d.mouse_entropy, d.strict_motw);
        (self.allow_arg_secrets, self.update, self.shred_passes) = (d.allow_arg_secrets, d.update, d.shred_passes);
        (self.auto_lock_min, self.lock_on_minimize, self.allow_reveal, self.clipboard_clear) = (d.auto_lock_min, d.lock_on_minimize, d.allow_reveal, d.clipboard_clear);
        self.lock_on_focus_loss = d.lock_on_focus_loss;
        self.entropy_disabled.clear();
    }

    /// True when every protected value is its default (what a file without a settings password
    /// may hold: without the password only the defaults can be saved, see `settings_auth`).
    pub fn protected_is_default(&self) -> bool {
        let mut d = Settings::default();
        d.auth.clone_from(&self.auth);
        d.protected_text() == self.protected_text()
    }

    /// Takes over the protected values of `o` (used to undo a change the password did not allow).
    pub fn copy_protected_from(&mut self, o: &Settings) {
        (self.capture_protect, self.mouse_entropy, self.strict_motw) = (o.capture_protect, o.mouse_entropy, o.strict_motw);
        (self.allow_arg_secrets, self.update, self.shred_passes) = (o.allow_arg_secrets, o.update, o.shred_passes);
        (self.auto_lock_min, self.lock_on_minimize, self.allow_reveal, self.clipboard_clear) = (o.auto_lock_min, o.lock_on_minimize, o.allow_reveal, o.clipboard_clear);
        self.lock_on_focus_loss = o.lock_on_focus_loss;
        self.entropy_disabled.clone_from(&o.entropy_disabled);
        self.auth.clone_from(&o.auth);
    }

    /// Canonical text of the protected values: what the settings MAC covers and what a change
    /// without the settings password may not alter.
    pub fn protected_text(&self) -> String {
        if !self.env_off.is_empty() {
            return self.file_view().protected_text();
        }
        let mut dis = self.entropy_disabled.clone();
        dis.sort();
        dis.dedup();
        format!(
            "capture_protect={}\nmouse_entropy={}\nstrict_motw={}\nallow_arg_secrets={}\nupdate={}\nshred_passes={}\nauto_lock_minutes={}\nlock_on_minimize={}\nlock_on_focus_loss={}\nallow_reveal={}\nclipboard_clear={}\nentropy_disabled={}\nauth={}\n",
            self.capture_protect,
            self.mouse_entropy,
            self.strict_motw,
            self.allow_arg_secrets,
            self.update.code(),
            self.shred_passes.count(),
            self.auto_lock_min,
            self.lock_on_minimize,
            self.lock_on_focus_loss,
            self.allow_reveal,
            self.clipboard_clear,
            dis.join(","),
            self.auth.as_ref().map(|a| a.text()).unwrap_or_default(),
        )
    }

    pub fn to_toml(&self) -> String {
        if !self.env_off.is_empty() {
            return self.file_view().to_toml();
        }
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
            ("allow_arg_secrets", b(self.allow_arg_secrets).into()),
            ("entropy_disabled", q(&self.entropy_disabled.join(","))),
            ("update", q(self.update.code())),
            ("shred_passes", self.shred_passes.count().to_string()),
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
        let rows = rows.into_iter().chain(self.ui.rows());
        let mut s = String::from("# Shield settings. Secrets and file locations are never stored here.\n");
        for (k, v) in rows {
            s += &format!("{k} = {v}\n");
        }
        if let Some(a) = &self.auth {
            s += &a.to_toml();
        }
        s
    }

    /// Parses leniently: unknown keys are ignored (a newer version may have more); a bad or
    /// out-of-range value keeps its default and its key is listed in `load_issues`.
    pub fn from_toml(text: &str) -> Settings {
        // Some(..) = parsed, None = damaged (the default stays)
        fn put<T>(dst: &mut T, v: Option<T>) -> bool {
            v.map(|v| *dst = v).is_some()
        }
        let mut s = Settings::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                s.load_issues.push(line.chars().take(40).collect());
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            let sv = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or("");
            let bv = match v {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            };
            let nv: Option<u32> = v.parse().ok();
            let ok = match k {
                "schema" => nv.is_some(),
                "lang" => put(&mut s.lang, LangPref::parse(sv)),
                "theme" => put(&mut s.theme, ThemePref::parse(sv)),
                "ui_scale" => put(&mut s.ui_scale, nv.filter(|n| SCALES.contains(n))),
                "date_format" => put(&mut s.date_fmt, DateFmt::parse(sv)),
                "date_seconds" => put(&mut s.date_seconds, bv),
                "start_screen" => put(&mut s.start_screen, StartScreen::parse(sv)),
                "capture_protect" => put(&mut s.capture_protect, bv),
                "mouse_entropy" => put(&mut s.mouse_entropy, bv),
                "auto_lock_minutes" => put(&mut s.auto_lock_min, nv.filter(|n| LOCK_MINUTES.contains(n))),
                "lock_on_minimize" => put(&mut s.lock_on_minimize, bv),
                "lock_on_focus_loss" => put(&mut s.lock_on_focus_loss, bv),
                "allow_reveal" => put(&mut s.allow_reveal, bv),
                "clipboard_clear" => put(&mut s.clipboard_clear, bv),
                "recent_files" => put(&mut s.recent_files, bv),
                "strict_motw" => put(&mut s.strict_motw, bv),
                "allow_arg_secrets" => put(&mut s.allow_arg_secrets, bv),
                "entropy_disabled" => {
                    let codes: Vec<&str> = sv.split(',').filter(|c| !c.is_empty()).collect();
                    let good: Vec<String> = codes.iter().filter(|c| shield_platform::Source::from_code(c).is_some_and(|x| x != shield_platform::Source::OsCsprng)).map(|c| c.to_string()).collect();
                    let all_good = good.len() == codes.len();
                    s.entropy_disabled = good;
                    all_good
                }
                "update" => put(&mut s.update, UpdateMode::parse(sv)),
                "shred_passes" => put(&mut s.shred_passes, v.parse().ok().and_then(crate::wipe::Passes::from_count)),
                k if k.starts_with("auth_") => {
                    crate::settings_auth::Auth::parse_line(&mut s.auth, k, sv);
                    true
                }
                "strength" => put(&mut s.strength, strength_parse(sv)),
                "default_pim" => put(&mut s.default_pim, nv.filter(|n| *n <= crate::format::MAX_PIM)),
                "keyfile_kib" => put(&mut s.keyfile_kib, nv.filter(|n| (1..=crate::keyfile::KF_MAX_KIB).contains(n))),
                "shred_default" => put(&mut s.shred_default, bv),
                "naming" => put(&mut s.naming, Naming::parse(sv)),
                "show_hidden" => put(&mut s.show_hidden, bv),
                "start_folder" => put(&mut s.start_folder, StartFolder::parse(sv)),
                "sort" => put(&mut s.sort, SortBy::parse(sv)),
                "confirm_delete" => put(&mut s.confirm_delete, bv),
                k if k.starts_with("ui_") => s.ui.parse_line(k, v) || !UI_KEYS.contains(&k),
                _ => true,
            };
            if !ok {
                s.load_issues.push(k.chars().take(40).collect());
            }
        }
        s
    }

    /// Reads the file and checks the MAC of the protected values (`settings_auth::check`). A file
    /// that exists but can't be used gives the defaults with a `load_issues` entry.
    pub fn load_from(p: &Path) -> Settings {
        let damaged = || Settings { load_issues: vec![FILE.into()], ..Default::default() };
        let mut legacy = false;
        let mut s = match std::fs::read(p) {
            Ok(b) if b.len() <= MAX_FILE => match std::str::from_utf8(&b) {
                Ok(text) => {
                    legacy = file_schema(text).is_some_and(|v| v < SCHEMA);
                    Settings::from_toml(text)
                }
                Err(_) => damaged(),
            },
            Err(x) if x.kind() == std::io::ErrorKind::NotFound => Settings::default(),
            _ => damaged(),
        };
        crate::settings_auth::check(&mut s, p, legacy);
        s
    }

    /// Saves what this process changed since `base` (what it loaded or saved last) on top of the
    /// file as it is now, under a lock: two windows (or two Shield processes) that change
    /// different options don't undo each other, and the last change of one option wins (3.0.0
    /// §3). Values switched off by the environment are written as the user chose them (§4).
    /// Returns the settings now on disk (with this process's runtime state), to use as the new
    /// `base` and current settings.
    pub fn save_merged(&self, base: &Settings, p: &Path, unlocked: Option<&crate::settings_auth::Unlocked>) -> Result<Settings, String> {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|x| crate::i18n::tf("set.save_failed", &[&x]))?;
        }
        let _guard = crate::lock::acquire(&p.with_file_name("settings.lock"), crate::lock::Mode::Exclusive, std::time::Duration::from_secs(3))?;
        let disk = match std::fs::read(p) {
            Ok(b) if b.len() <= MAX_FILE => std::str::from_utf8(&b).ok().map(Settings::from_toml),
            _ => None,
        };
        let mut merged = match disk {
            Some(d) => {
                let mine = rows_of(&self.to_toml());
                let before = rows_of(&base.to_toml());
                let mut text = d.to_toml();
                for (k, v) in &mine {
                    let changed = before.iter().find(|(bk, _)| bk == k).map(|(_, bv)| bv) != Some(v);
                    if changed && !k.starts_with("auth_") {
                        text = set_row(&text, k, v);
                    }
                }
                let mut m = Settings::from_toml(&text);
                // the settings password entry moves as a whole (its MAC is computed on save)
                m.auth = if self.auth != base.auth { self.auth.clone() } else { d.auth.clone() };
                m
            }
            None => self.file_view(),
        };
        merged.load_issues.clear();
        merged.tampered = self.tampered;
        merged.save_to_with(p, unlocked)?;
        for e in &self.env_off {
            merged.env_off.push(e.clone());
            merged.env_switch_off(e.key);
        }
        Ok(merged)
    }

    /// Saves. Refused when the protected values differ from the file on disk and `unlocked` is
    /// None (the settings password was not given) while a password is set; see `settings_auth`.
    pub fn save_to_with(&self, p: &Path, unlocked: Option<&crate::settings_auth::Unlocked>) -> Result<(), String> {
        crate::settings_auth::authorize(self, p, unlocked)?;
        let sealed = crate::settings_auth::with_mac(self, p, unlocked)?;
        sealed.write_file(p)
    }

    /// Applies the entropy source switches (call after loading or changing settings).
    pub fn apply_entropy(&self) {
        crate::entropy::apply_disabled(&self.entropy_disabled);
        if !self.mouse_entropy {
            crate::entropy::set_mouse_enabled(false);
        }
    }

    pub fn save_to(&self, p: &Path) -> Result<(), String> {
        self.save_to_with(p, None)
    }

    pub(crate) fn write_file(&self, p: &Path) -> Result<(), String> {
        let dir = p.parent().ok_or("no folder")?;
        std::fs::create_dir_all(dir).map_err(|x| x.to_string())?;
        let _ = shield_platform::platform().restrict_file_permissions(dir);
        let tmp = dir.join(format!("settings.{}.{}.tmp", std::process::id(), crate::entropy::rand_hex()?));
        let r = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = crate::sysinfo::create_private_file(&tmp)?;
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
    pub fn save_unlocked(&self, u: &crate::settings_auth::Unlocked) -> Result<(), String> {
        self.save_to_with(&settings_path(), Some(u))
    }

    /// Language to use (System = the OS UI language).
    pub fn effective_lang(&self) -> crate::i18n::Lang {
        match self.lang {
            LangPref::Ko => crate::i18n::Lang::Ko,
            LangPref::En => crate::i18n::Lang::En,
            LangPref::System => crate::i18n::system_lang(),
        }
    }
}

/// Largest settings file that is read (a bigger one is treated as damaged).
const MAX_FILE: usize = 64 * 1024;

/// The `schema = N` line of a settings file (2.x files say 1; they had no settings password).
fn file_schema(text: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == "schema").then(|| v.trim().parse().ok()).flatten()
    })
}

/// Every `ui_*` key (a `ui_` row with another name comes from a newer version: not damage).
pub(crate) const UI_KEYS: &[&str] = &[
    "ui_remember_window_pos",
    "ui_win_enc",
    "ui_win_mgr",
    "ui_choose_dest",
    "ui_bundle",
    "ui_wipe_free_after",
    "ui_include_streams",
    "ui_full_rekey",
    "ui_enc_passes",
    "ui_disk_trim_after_wipe",
    "ui_mgr_passes",
];

/// `key = value` rows of a settings text, in order.
fn rows_of(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect()
}

/// `text` with the row `k` set to `v` (added at the end when missing).
fn set_row(text: &str, k: &str, v: &str) -> String {
    let mut found = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| match l.split_once('=') {
            Some((lk, _)) if lk.trim() == k && !l.trim_start().starts_with('#') => {
                found = true;
                format!("{k} = {v}")
            }
            _ => l.to_string(),
        })
        .collect();
    if !found {
        out.push(format!("{k} = {v}"));
    }
    out.join("\n") + "\n"
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

/// Folder for settings, the staging journal and lock files (Windows `%LOCALAPPDATA%\Shield`, Linux
/// `$XDG_CONFIG_HOME/shield`; 2.x on Linux wrongly used `$HOME/Shield`).
pub fn data_dir() -> PathBuf {
    if let Some(p) = portable_dir() {
        return p;
    }
    shield_platform::platform().config_dir()
}

pub fn settings_path() -> PathBuf {
    data_dir().join(FILE)
}

/// "Delete settings file" button: the defaults apply from the next start.
/// Also the recovery for a forgotten settings password: every setting returns to its default and
/// the password is gone. Containers are not affected (their keys never depend on settings).
pub fn delete_file() -> Result<(), String> {
    let p = settings_path();
    crate::settings_auth::forget_key(&p);
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(x) => Err(x.to_string()),
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
