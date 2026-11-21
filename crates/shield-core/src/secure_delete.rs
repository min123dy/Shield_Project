//! Secure delete ("완전삭제") of any file or folder (3.1.0 final; design: docs/10).
//!
//! Flow, the same for the window, the console and the shell verbs:
//! 1. [`scan`] fixes the plan: every selected item made absolute and resolved, refused when it is
//!    protected ([`Guard`]: system folders, drive roots / mount points, the user profile root,
//!    the running program, Shield's data folder, special files), every entry below a folder listed
//!    without following links or crossing mount points, with its identity (volume + file index /
//!    device + inode), size and time.
//! 2. [`Confirmation`] is the only way to a [`ConfirmedWipePlan`]: warning -> limits (with an
//!    acknowledgement) -> a 6-character code from the OS-seeded generator, typed by the user, not
//!    accepted before [`CODE_WAIT`], replaced after every wrong answer, all of it aborted after
//!    [`MAX_FAILS`] wrong answers. A selection of only `.shd` containers skips the limits step.
//!    Scripts use [`confirm_with_token`] (the token printed by a dry run of the same plan).
//!    Then [`permit`]: the settings password, when the settings ask for it (docs/10 2-5).
//! 3. [`execute`] takes the confirmed plan and the permit (nothing else): each entry is opened again without
//!    following links, compared with the plan (a replaced object is skipped and reported), then
//!    overwritten (3 or 7 passes, 1 MiB buffer, flushed and synced after each pass), its extra
//!    streams too, truncated, renamed a few times inside its folder and deleted through the
//!    checked handle. Folders are removed from the inside out. Flash volumes are TRIMmed at the end.
//!
//! What this can't do is said in every warning: SSD/NVMe wear levelling, snapshots (VSS, btrfs,
//! ZFS, LVM), copy-on-write file systems, cloud and network folders, backups and recycle-bin copies
//! may keep old data. Hard links: overwriting changes the data of every name of the file.
//!
//! No path is written to any log or file: plans and reports live in memory only.

use crate::i18n::{t, tf};
use crate::progress::*;
use crate::settings::Settings;
use crate::sysinfo::{delete_checked, final_path, open_no_follow, path_key, rename_noreplace};
use crate::wipe::{self, Passes};
use sha3::{Digest, Sha3_256};
use shield_platform::{fs as pfs, EntryInfo, EntryKind, FileId, WipeNote};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

/// Most entries (files, folders, links) one plan may hold; more is refused (split the job).
pub const MAX_ITEMS: usize = 200_000;
/// Entries named in the first warning (the rest are counted).
pub const LIST_MAX: usize = 20;
/// From this total size or ...
pub const BIG_BYTES: u64 = 1 << 30;
/// ... this many entries (or any folder) the first warning gets an extra emphasis line.
pub const BIG_COUNT: usize = 100;
/// Length of the confirmation code.
pub const CODE_LEN: usize = 6;
/// Code alphabet: no 0/O, 1/I/L (easily confused).
pub const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// Wrong codes before the whole confirmation is aborted.
pub const MAX_FAILS: u32 = 3;
/// A code is accepted only this long after it was shown (no reflex double clicks / Enter).
pub const CODE_WAIT: Duration = Duration::from_secs(3);
/// Random renames before an object is deleted (the old name does not stay in the folder index
/// as the last name of the deleted entry).
pub const RENAMES: usize = 3;

/// Error code of a refused plan or confirmation (console exit code `REFUSED`).
pub const C_REFUSED: &str = "E_WIPE_REFUSED";

fn refused(text: String) -> String {
    format!("{text} [{C_REFUSED}]")
}

/// A refusal (`scan`, `confirm_with_token`): protected target, failed confirmation, wrong token.
pub fn is_refusal(msg: &str) -> bool {
    crate::i18n::has_code(msg, C_REFUSED)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File,
    Dir,
    /// Symbolic link or junction: only the link itself is removed.
    Link,
}

/// One object to remove.
#[derive(Clone, Debug)]
pub struct Entry {
    pub path: PathBuf,
    pub kind: Kind,
    pub id: FileId,
    pub size: u64,
    pub mtime: Option<SystemTime>,
}

/// One selected item, as given and as resolved.
#[derive(Clone, Debug)]
pub struct Target {
    pub given: PathBuf,
    /// Absolute and (for files and folders) resolved path: what is really removed.
    pub path: PathBuf,
    pub kind: Kind,
}

/// Why something found while listing a folder is not touched (the folder then stays).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Left {
    MountPoint,
    Special,
    OtherReparse,
}

/// The fixed list of what will be removed. Only `scan` makes one.
#[derive(Debug)]
pub struct Plan {
    targets: Vec<Target>,
    /// Execution order: everything inside a folder comes before the folder.
    entries: Vec<Entry>,
    left: Vec<(PathBuf, Left)>,
    files: u64,
    dirs: u64,
    links: u64,
    bytes: u64,
    hardlinked: u64,
    notes: BTreeSet<WipeNote>,
    exposure: wipe::Exposure,
    passes: Passes,
}

impl Plan {
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Found but left alone (mount points, special files, other reparse points).
    pub fn left(&self) -> &[(PathBuf, Left)] {
        &self.left
    }
    pub fn files(&self) -> u64 {
        self.files
    }
    pub fn dirs(&self) -> u64 {
        self.dirs
    }
    pub fn links(&self) -> u64 {
        self.links
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    /// Files with more than one name (their data changes under every name).
    pub fn hardlinked(&self) -> u64 {
        self.hardlinked
    }
    pub fn passes(&self) -> Passes {
        self.passes
    }
    pub fn notes(&self) -> &BTreeSet<WipeNote> {
        &self.notes
    }
    pub fn exposure(&self) -> &wipe::Exposure {
        &self.exposure
    }
    /// Every selected item is a Shield container (`.shd` file): the confirmation has no limits step.
    pub fn only_containers(&self) -> bool {
        self.targets.iter().all(|t| t.kind == Kind::File && t.path.extension().is_some_and(|x| x.eq_ignore_ascii_case("shd")))
    }
    /// The first warning gets the "large job" emphasis.
    pub fn is_big(&self) -> bool {
        self.dirs > 0 || self.bytes >= BIG_BYTES || self.entries.len() >= BIG_COUNT
    }
    /// The selection this plan was made from (to notice a changed list).
    pub fn same_selection(&self, inputs: &[PathBuf]) -> bool {
        self.targets.len() == inputs.len() && self.targets.iter().zip(inputs).all(|(t, i)| &t.given == i)
    }

    /// Binding of the plan (console `--confirm-token`): SHA3-256 over the pass count and every
    /// entry's kind, path, identity, size and time. Any change of the selection or of what is
    /// on disk gives another token.
    pub fn token(&self) -> String {
        let mut h = Sha3_256::new();
        h.update(b"SHIELD-WIPE-PLAN-v1\n");
        h.update([self.passes.count() as u8]);
        for e in &self.entries {
            h.update([e.kind as u8]);
            h.update(path_key(&e.path).as_bytes());
            h.update([0]);
            h.update(e.id.vol.to_le_bytes());
            h.update(e.id.idx.to_le_bytes());
            h.update(e.size.to_le_bytes());
            let ns = e.mtime.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
            h.update(ns.to_le_bytes());
        }
        h.finalize().iter().take(16).map(|b| format!("{b:02x}")).collect()
    }

    /// Lines of the first warning: up to `LIST_MAX` resolved paths, then "and N more".
    pub fn target_lines(&self) -> Vec<String> {
        let mut v = Vec::new();
        for tg in self.targets.iter().take(LIST_MAX) {
            let what = match tg.kind {
                Kind::Link => t("sd.k_link"),
                Kind::Dir => t("sd.k_dir"),
                Kind::File => t("sd.k_file"),
            };
            v.push(format!("{what}  {}", crate::ui_fmt::path_shown(&tg.path)));
            if tg.kind == Kind::Link {
                v.push(format!("    {}", t("sd.link_only")));
            }
        }
        if self.targets.len() > LIST_MAX {
            v.push(tf("sd.more", &[&(self.targets.len() - LIST_MAX)]));
        }
        v
    }

    /// "N files, M folders, K links, X in total".
    pub fn summary_line(&self) -> String {
        tf("sd.counts", &[&self.files, &self.dirs, &self.links, &crate::ui_fmt::human(self.bytes)])
    }

    /// The limits shown in the second warning (always) plus what was detected for this plan.
    pub fn limit_lines(&self) -> Vec<String> {
        let mut v = vec![t("sd.lim_not_shield").to_string(), t("sd.lim_storage").to_string(), t("sd.lim_copies").to_string()];
        if self.hardlinked > 0 {
            v.push(tf("sd.lim_hardlinks", &[&self.hardlinked]));
        } else {
            v.push(t("sd.lim_hardlinks_none").to_string());
        }
        for n in &self.notes {
            v.push(note_text(n));
        }
        v.extend(self.exposure.snapshot_lines.iter().cloned());
        if self.exposure.not_guaranteed {
            v.push(t("dlg.shred_flash").to_string());
        }
        if !self.left.is_empty() {
            v.push(tf("sd.lim_left", &[&self.left.len()]));
        }
        v
    }
}

/// Text of a detected storage note.
pub fn note_text(n: &WipeNote) -> String {
    match n {
        WipeNote::Compressed => t("sd.n_compressed").into(),
        WipeNote::Sparse => t("sd.n_sparse").into(),
        WipeNote::Encrypted => t("sd.n_efs").into(),
        WipeNote::Cloud => t("sd.n_cloud").into(),
        WipeNote::Network => t("sd.n_network").into(),
        WipeNote::CopyOnWrite(fs) => tf("sd.n_cow", &[fs]),
        WipeNote::RamBacked => t("sd.n_ram").into(),
    }
}

// ------------------------------------------------------------------ protection (2-4)

/// Normalised comparison key of a path: resolved when it exists, `\\?\` removed, case-folded on
/// Windows, no trailing separator.
fn key_of(p: &Path) -> PathBuf {
    let c = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = c.to_string_lossy().into_owned();
    let s = s.strip_prefix(r"\\?\UNC\").map(|r| format!(r"\\{r}")).or_else(|| s.strip_prefix(r"\\?\").map(String::from)).unwrap_or(s);
    PathBuf::from(path_key(Path::new(&s)))
}

/// What secure delete refuses, whatever the confirmation says.
pub struct Guard {
    exact: Vec<PathBuf>,
    subtree: Vec<PathBuf>,
    /// Must not be removed nor be inside a removed folder (running program, data folder ...).
    keep: Vec<PathBuf>,
}

impl Guard {
    /// The OS list (`shield_platform::fs::protected`) plus Shield's own files.
    pub fn system() -> Guard {
        let p = pfs::protected();
        let mut keep = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            keep.push(exe);
        }
        if let Some(a) = std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_absolute()) {
            keep.push(a);
        }
        if let Ok(d) = crate::settings::data_dir() {
            keep.push(d);
        }
        if let Some(d) = crate::settings::portable_dir() {
            keep.push(d);
        }
        Guard::with(p.exact, p.subtree, keep)
    }

    pub fn with(exact: Vec<PathBuf>, subtree: Vec<PathBuf>, keep: Vec<PathBuf>) -> Guard {
        let k = |v: Vec<PathBuf>| v.iter().map(|p| key_of(p)).collect();
        Guard { exact: k(exact), subtree: k(subtree), keep: k(keep) }
    }

    /// Ok, or why `p` (absolute; resolved unless it is a link) must not be removed.
    pub fn check(&self, p: &Path, is_link: bool) -> Result<(), String> {
        let k = if is_link { PathBuf::from(path_key(p)) } else { key_of(p) };
        let has = |outer: &Path, inner: &Path| inner.starts_with(outer);
        if !is_link && pfs::is_mount_point(p) {
            return Err(t("sd.r_mount").into());
        }
        if k.parent().is_none() || k.as_os_str().len() <= 3 {
            return Err(t("sd.r_mount").into());
        }
        if let Some(s) = self.subtree.iter().find(|s| has(s, &k) || has(&k, s)) {
            return Err(tf("sd.r_system", &[&s.display()]));
        }
        if let Some(s) = self.exact.iter().find(|s| has(&k, s)) {
            return Err(tf("sd.r_system", &[&s.display()]));
        }
        // Protect both directions: a selected ancestor cannot contain Shield's data folder,
        // and a directly selected descendant cannot remove one of Shield's own files.
        if self.keep.iter().any(|s| has(&k, s) || has(s, &k)) {
            return Err(t("sd.r_shield").into());
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ scan

fn absolute(p: &Path) -> Result<PathBuf, String> {
    if p.as_os_str().is_empty() {
        return Err(t("sd.nothing").into());
    }
    std::path::absolute(p).map_err(|x| tf("sd.r_path", &[&crate::ui_fmt::path_shown(p), &x]))
}

fn kind_of(k: EntryKind) -> Option<Kind> {
    match k {
        EntryKind::File => Some(Kind::File),
        EntryKind::Dir => Some(Kind::Dir),
        EntryKind::Link => Some(Kind::Link),
        EntryKind::Other => None,
    }
}

fn mtime_of(p: &Path) -> Option<SystemTime> {
    fs::symlink_metadata(p).ok()?.modified().ok()
}

/// Listing state. No guard check per child: `Guard::check` refuses protected targets and any
/// selected ancestor or descendant of a protected path before a directory is traversed.
struct Scan {
    plan: Plan,
    mounts: Vec<PathBuf>,
    vols: BTreeSet<u64>,
}

impl Scan {
    fn push(&mut self, path: PathBuf, kind: Kind, info: &EntryInfo) -> R<()> {
        if self.plan.entries.len() >= MAX_ITEMS {
            return Err(refused(tf("sd.r_too_many", &[&MAX_ITEMS])));
        }
        match kind {
            Kind::File => {
                self.plan.files += 1;
                self.plan.bytes = self.plan.bytes.saturating_add(info.size);
                if info.id.nlink > 1 {
                    self.plan.hardlinked += 1;
                }
            }
            Kind::Dir => self.plan.dirs += 1,
            Kind::Link => self.plan.links += 1,
        }
        if kind != Kind::Link {
            let vol = self.vols.insert(info.id.vol);
            self.plan.notes.extend(pfs::wipe_notes(&path, info, vol));
        }
        let mtime = if kind == Kind::File { mtime_of(&path) } else { None };
        self.plan.entries.push(Entry { path, kind, id: info.id, size: info.size, mtime });
        Ok(())
    }

    /// Lists the held folder `dir` (at `p`) depth first; children are pushed before the folder.
    fn walk(&mut self, p: &Path, dir: &File, info: &EntryInfo) -> R<()> {
        let names = crate::sysinfo::list_dir_held(dir, p).map_err(|x| tf("sd.r_list", &[&crate::ui_fmt::path_shown(p), &x]))?;
        for n in names {
            check_cancel()?;
            let cp = p.join(&n);
            // looked up relative to the held folder (Linux fstatat), never through a swapped path
            let ci = pfs::entry_info_at(dir, &n, &cp).map_err(|x| tf("sd.r_list", &[&crate::ui_fmt::path_shown(&cp), &x]))?;
            match kind_of(ci.kind) {
                None => self.plan.left.push((cp, if ci.kind == EntryKind::Other && pfs::is_reparse_other(&ci) { Left::OtherReparse } else { Left::Special })),
                Some(Kind::Link) => self.push(cp, Kind::Link, &ci)?,
                Some(Kind::File) => self.push(cp, Kind::File, &ci)?,
                Some(Kind::Dir) => {
                    if ci.id.vol != info.id.vol || self.mounts.iter().any(|m| m == &cp) {
                        self.plan.left.push((cp, Left::MountPoint));
                        continue;
                    }
                    let sub = crate::sysinfo::open_dir_at(dir, &n, &cp).map_err(|x| tf("sd.r_list", &[&crate::ui_fmt::path_shown(&cp), &x]))?;
                    let si = pfs::entry_info_of(&sub).map_err(|x| tf("sd.r_list", &[&crate::ui_fmt::path_shown(&cp), &x]))?;
                    if (si.id.vol, si.id.idx) != (ci.id.vol, ci.id.idx) {
                        return Err(tf("man.moved_while_listing", &[&crate::ui_fmt::path_shown(&cp), &"folder"]));
                    }
                    self.walk(&cp, &sub, &si)?;
                    drop(sub);
                    self.push(cp, Kind::Dir, &si)?;
                }
            }
        }
        Ok(())
    }
}

/// Fixes the plan for `inputs` (see the module docs). Errors: an item that is missing, protected
/// (coded `C_REFUSED`), a special file, or a list over `MAX_ITEMS`.
pub fn scan(inputs: &[PathBuf], passes: Passes) -> R<Plan> {
    scan_with(inputs, passes, &Guard::system())
}

pub fn scan_with(inputs: &[PathBuf], passes: Passes, guard: &Guard) -> R<Plan> {
    if inputs.is_empty() {
        return Err(t("sd.nothing").into());
    }
    let plan = Plan {
        targets: vec![],
        entries: vec![],
        left: vec![],
        files: 0,
        dirs: 0,
        links: 0,
        bytes: 0,
        hardlinked: 0,
        notes: BTreeSet::new(),
        exposure: wipe::Exposure::default(),
        passes,
    };
    let mut s = Scan { plan, mounts: pfs::mount_points(), vols: BTreeSet::new() };
    // resolve every item first: duplicates and items inside another selected folder are refused
    let mut resolved: Vec<(PathBuf, PathBuf, EntryInfo)> = Vec::new();
    for given in inputs {
        check_cancel()?;
        let abs = absolute(given)?;
        let shown = crate::ui_fmt::path_shown(&abs);
        let info = pfs::entry_info(&abs).map_err(|x| tf("sd.r_missing", &[&shown, &x]))?;
        let kind = kind_of(info.kind).ok_or_else(|| refused(tf("sd.r_special", &[&shown])))?;
        // a link itself is removed, not its target: its folder is resolved (S-11: a linked folder
        // on the way, `~/x/name` with `~/x -> /usr/lib`, must be checked and shown as
        // `/usr/lib/name`, the entry that really goes), its own name is kept
        let real = if kind == Kind::Link { link_path(&abs).map_err(|x| tf("sd.r_missing", &[&shown, &x]))? } else { fs::canonicalize(&abs).map_err(|x| tf("sd.r_missing", &[&shown, &x]))? };
        let real = strip_verbatim(&real);
        if kind == Kind::Link {
            // the resolved name must still be the same link (nothing swapped meanwhile)
            let again = pfs::entry_info(&real).map_err(|x| tf("sd.r_missing", &[&shown, &x]))?;
            if again.kind != EntryKind::Link || !same(&again.id, &info.id) {
                return Err(tf("man.moved_while_listing", &[&shown, &"link"]));
            }
        }
        guard.check(&real, kind == Kind::Link).map_err(|why| refused(tf("sd.refused", &[&crate::ui_fmt::path_shown(&real), &why])))?;
        let k = PathBuf::from(path_key(&real));
        if let Some((_, other, _)) = resolved.iter().find(|(_, o, _)| {
            let ok = PathBuf::from(path_key(o));
            k.starts_with(&ok) || ok.starts_with(&k)
        }) {
            return Err(refused(tf("sd.r_overlap", &[&crate::ui_fmt::path_shown(&real), &crate::ui_fmt::path_shown(other)])));
        }
        resolved.push((given.clone(), real, info));
    }
    for (given, real, info) in resolved {
        check_cancel()?;
        let kind = kind_of(info.kind).unwrap_or(Kind::File);
        s.plan.targets.push(Target { given, path: real.clone(), kind });
        match kind {
            Kind::Dir => {
                let held = crate::sysinfo::open_dir_held(&real).map_err(|x| tf("sd.r_list", &[&crate::ui_fmt::path_shown(&real), &x]))?;
                let hi = pfs::entry_info_of(&held).map_err(|x| x.to_string())?;
                if (hi.id.vol, hi.id.idx) != (info.id.vol, info.id.idx) {
                    return Err(tf("man.moved_while_listing", &[&crate::ui_fmt::path_shown(&real), &"folder"]));
                }
                s.walk(&real, &held, &hi)?;
                drop(held);
                s.push(real, Kind::Dir, &hi)?;
            }
            k => s.push(real, k, &info)?,
        }
    }
    let tops: Vec<&Path> = s.plan.targets.iter().map(|t| t.path.as_path()).collect();
    s.plan.exposure = wipe::exposure(&tops);
    Ok(s.plan)
}

/// The real location of the link `abs` (absolute): its folder resolved, its own name kept.
fn link_path(abs: &Path) -> std::io::Result<PathBuf> {
    let (Some(dir), Some(name)) = (abs.parent(), abs.file_name()) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no folder"));
    };
    Ok(fs::canonicalize(dir)?.join(name))
}

/// `\\?\C:\x` -> `C:\x` (canonicalize on Windows), so paths are shown and compared as typed.
fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(r) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{r}"));
    }
    match s.strip_prefix(r"\\?\") {
        Some(r) if r.as_bytes().get(1) == Some(&b':') => PathBuf::from(r),
        _ => p.to_path_buf(),
    }
}

// ------------------------------------------------------------------ confirmation (2-2, 2-3)

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// What will be removed (list, real paths, counts, size, "can't be recovered").
    Warning,
    /// What overwriting can't guarantee; needs the acknowledgement.
    Limits,
    /// Type the code.
    Code,
    Done,
    Aborted,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    Accepted,
    /// Wrong: a new code is shown; this many tries are left.
    Wrong(u32),
    /// Before `CODE_WAIT`: nothing counted, the code stays.
    TooEarly,
    /// The last try was wrong: everything is aborted (start again from the first step).
    Aborted,
    /// Not at the code step.
    NotNow,
}

/// The confirmation of one plan. Each plan gets a new one; nothing carries over between plans
/// or runs (the code and the answers live only in this value).
pub struct Confirmation {
    plan: Plan,
    step: Step,
    code: Option<(String, Instant)>,
    fails: u32,
}

impl Confirmation {
    pub fn new(plan: Plan) -> Confirmation {
        Confirmation { plan, step: Step::Warning, code: None, fails: 0 }
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn step(&self) -> Step {
        self.step
    }
    /// 2 for containers only, else 3.
    pub fn steps_total(&self) -> usize {
        if self.plan.only_containers() {
            2
        } else {
            3
        }
    }
    /// 1-based number of the current step (for "step 2 of 3").
    pub fn step_no(&self) -> usize {
        match (self.step, self.plan.only_containers()) {
            (Step::Warning, _) => 1,
            (Step::Limits, _) => 2,
            (Step::Code, true) => 2,
            _ => self.steps_total(),
        }
    }

    fn new_code(&mut self, now: Instant) -> Result<(), String> {
        let mut s = String::with_capacity(CODE_LEN);
        for _ in 0..CODE_LEN {
            let i = crate::entropy::rand_upto(CODE_ALPHABET.len() as u64 - 1)? as usize;
            s.push(CODE_ALPHABET[i] as char);
        }
        self.code = Some((s, now));
        Ok(())
    }

    /// First step accepted ("I understand, continue").
    pub fn accept_warning(&mut self, now: Instant) -> Result<(), String> {
        if self.step != Step::Warning {
            return Ok(());
        }
        if self.plan.only_containers() {
            self.step = Step::Code;
            self.new_code(now)?;
        } else {
            self.step = Step::Limits;
        }
        Ok(())
    }

    /// Second step: only with the acknowledgement ticked.
    pub fn accept_limits(&mut self, acknowledged: bool, now: Instant) -> Result<(), String> {
        if self.step == Step::Limits && acknowledged {
            self.step = Step::Code;
            self.new_code(now)?;
        }
        Ok(())
    }

    pub fn cancel(&mut self) {
        self.step = Step::Aborted;
        self.code = None;
    }

    /// The code to show (only at the code step).
    pub fn code(&self) -> Option<&str> {
        self.code.as_ref().filter(|_| self.step == Step::Code).map(|(c, _)| c.as_str())
    }

    /// Time until the code can be submitted (zero when it can).
    pub fn wait_left(&self, now: Instant) -> Duration {
        match &self.code {
            Some((_, shown)) => CODE_WAIT.saturating_sub(now.saturating_duration_since(*shown)),
            None => CODE_WAIT,
        }
    }

    pub fn tries_left(&self) -> u32 {
        MAX_FAILS.saturating_sub(self.fails)
    }

    /// The typed code (spaces ignored, letters in any case).
    pub fn submit(&mut self, input: &str, now: Instant) -> Result<Answer, String> {
        if self.step != Step::Code {
            return Ok(Answer::NotNow);
        }
        if !self.wait_left(now).is_zero() {
            return Ok(Answer::TooEarly);
        }
        let typed: String = input.chars().filter(|c| !c.is_whitespace()).flat_map(char::to_uppercase).collect();
        let want = self.code.as_ref().map(|(c, _)| c.as_bytes()).unwrap_or_default();
        if !want.is_empty() && crate::password::ct_eq(typed.as_bytes(), want) {
            self.step = Step::Done;
            self.code = None;
            return Ok(Answer::Accepted);
        }
        self.fails += 1;
        if self.fails >= MAX_FAILS {
            self.cancel();
            return Ok(Answer::Aborted);
        }
        self.new_code(now)?;
        Ok(Answer::Wrong(self.tries_left()))
    }

    /// The confirmed plan, only after every step was passed; otherwise the confirmation back.
    pub fn finish(self) -> Result<ConfirmedWipePlan, Box<Confirmation>> {
        if self.step == Step::Done {
            Ok(ConfirmedWipePlan { plan: self.plan, _seal: Seal })
        } else {
            Err(Box::new(self))
        }
    }
}

/// Non-interactive confirmation (console scripts): the token of a dry run of the very same plan
/// and the explicit `--i-understand-irreversible`. A different token (anything changed since the
/// dry run) is refused.
pub fn confirm_with_token(plan: Plan, token: &str, understood: bool) -> Result<ConfirmedWipePlan, String> {
    if !understood {
        return Err(refused(t("sd.r_not_understood").into()));
    }
    let want = plan.token();
    if !crate::password::ct_eq(token.trim().to_ascii_lowercase().as_bytes(), want.as_bytes()) {
        return Err(refused(t("sd.r_token").into()));
    }
    Ok(ConfirmedWipePlan { plan, _seal: Seal })
}

/// Private marker: a `ConfirmedWipePlan` can only be built in this module.
#[derive(Debug)]
struct Seal;

/// A plan whose confirmation was completed. It has no public constructor and no public fields:
/// it comes only from [`Confirmation::finish`] or [`confirm_with_token`], and [`execute`] takes
/// nothing else, so no front end can delete without the confirmation.
///
/// ```compile_fail
/// // a plan can't be marked as confirmed from outside
/// fn forge(p: shield_core::secure_delete::Plan) -> shield_core::secure_delete::ConfirmedWipePlan {
///     shield_core::secure_delete::ConfirmedWipePlan { plan: p, _seal: todo!() }
/// }
/// ```
///
/// ```compile_fail
/// // execute does not take an unconfirmed plan
/// fn run(p: shield_core::secure_delete::Plan) {
///     shield_core::secure_delete::execute(p);
/// }
/// ```
#[derive(Debug)]
pub struct ConfirmedWipePlan {
    plan: Plan,
    _seal: Seal,
}

impl ConfirmedWipePlan {
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
}

// ------------------------------------------------------------------ settings password (3.1.0 final+)

/// Error code of a missing or wrong settings password for secure delete (also a refusal:
/// console exit code `REFUSED`).
pub const C_SET_PW: &str = "E_WIPE_SET_PW";

/// The settings that decide whether a run needs the settings password: `current` (what this
/// window or command loaded) and `disk` (the file now; another window may have switched it on or
/// changed the password). The stricter one wins; with both asking, the file's password counts.
fn gate_settings<'a>(current: &'a Settings, disk: &'a Settings) -> Option<&'a Settings> {
    let asks = |s: &Settings| s.wipe_needs_pw && s.auth.is_some();
    match (asks(current), asks(disk)) {
        (_, true) => Some(disk),
        (true, false) => Some(current),
        _ => None,
    }
}

/// True when secure delete must ask for the settings password (Settings > Security: a settings
/// password is set and "ask for it before secure delete" is on, here or in the file now).
pub fn settings_password_needed(current: &Settings) -> bool {
    gate_settings(current, &Settings::load()).is_some()
}

/// Proof for [`execute`] that the settings password was checked for this run, or that the
/// settings do not ask for it. Like [`ConfirmedWipePlan`] it can only be made in this module
/// ([`permit`]) and is used up by `execute`, so every run needs a new one.
///
/// ```compile_fail
/// fn forge() -> shield_core::secure_delete::WipePermit {
///     shield_core::secure_delete::WipePermit { _seal: todo!() }
/// }
/// ```
#[derive(Debug)]
pub struct WipePermit {
    _seal: Seal,
}

/// Checks the settings password for one secure delete run (call it right before `execute`, after
/// the confirmation). `pw`: the settings password as typed (None when the settings do not ask
/// for it). Runs Argon2id (and the retry delay after wrong passwords) when a password is needed:
/// call it off the UI thread. A missing or wrong password is a refusal coded [`C_SET_PW`].
pub fn permit(current: &Settings, pw: Option<&[u8]>) -> Result<WipePermit, String> {
    permit_with(current, &Settings::load(), pw)
}

/// `permit` with the file's settings given (tests).
pub fn permit_with(current: &Settings, disk: &Settings, pw: Option<&[u8]>) -> Result<WipePermit, String> {
    let Some(s) = gate_settings(current, disk) else { return Ok(WipePermit { _seal: Seal }) };
    let pw = pw.filter(|p| !p.is_empty()).ok_or_else(|| format!("{} [{C_SET_PW}] [{C_REFUSED}]", t("sd.pw_missing")))?;
    // the unlock (and its MAC key) is dropped at once: only "the password was right" is kept
    crate::settings_auth::unlock(s, pw).map(drop).map_err(|e| format!("{e} [{C_SET_PW}] [{C_REFUSED}]"))?;
    Ok(WipePermit { _seal: Seal })
}

// ------------------------------------------------------------------ execution (2-5)

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Overwritten (files) and removed.
    Done,
    /// Something happened to the data but not everything: overwritten but not deleted, stopped
    /// after some passes (cancel), streams not overwritten ...
    Partial(String),
    /// Not touched: changed or replaced since the confirmation, missing, in use, cancelled before.
    Skipped(String),
    /// An error before anything was overwritten.
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct ItemResult {
    pub path: PathBuf,
    pub kind: Kind,
    pub outcome: Outcome,
}

#[derive(Debug, Default)]
pub struct Report {
    pub results: Vec<ItemResult>,
    /// Found while listing and left alone (from the plan).
    pub left: Vec<(PathBuf, Left)>,
    pub cancelled: bool,
    /// " · TRIM ..." fragments.
    pub trim: String,
    pub passes: usize,
    /// Extra streams overwritten.
    pub streams: u64,
}

impl Report {
    pub fn count(&self, f: fn(&Outcome) -> bool) -> usize {
        self.results.iter().filter(|r| f(&r.outcome)).count()
    }
    pub fn done(&self) -> usize {
        self.count(|o| *o == Outcome::Done)
    }
    pub fn partial(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Partial(_)))
    }
    pub fn skipped(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Skipped(_)))
    }
    pub fn failed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Failed(_)))
    }
    /// Everything listed was removed (nothing partial, skipped, failed or left).
    pub fn all_ok(&self) -> bool {
        !self.cancelled && self.done() == self.results.len() && self.left.is_empty()
    }
    /// One line: counts, passes, TRIM. Never just "done" when something did not work.
    pub fn summary(&self) -> String {
        let head = if self.all_ok() { tf("sd.res_ok", &[&self.done(), &self.passes]) } else { tf("sd.res_problems", &[&self.done(), &self.partial(), &self.skipped(), &self.failed(), &self.left.len()]) };
        let mut s = head;
        if self.cancelled {
            s += t("sd.res_cancelled");
        }
        if self.streams > 0 {
            s += &tf("man.streams_shredded", &[&self.streams]);
        }
        s + &self.trim
    }
    /// One line per entry that was not fully removed (at most `max`, then "and N more").
    pub fn problem_lines(&self, max: usize) -> Vec<String> {
        let mut v = Vec::new();
        let mut n = 0usize;
        for r in &self.results {
            let (tag, why) = match &r.outcome {
                Outcome::Done => continue,
                Outcome::Partial(w) => (t("sd.o_partial"), w.as_str()),
                Outcome::Skipped(w) => (t("sd.o_skipped"), w.as_str()),
                Outcome::Failed(w) => (t("sd.o_failed"), w.as_str()),
            };
            n += 1;
            if v.len() < max {
                v.push(format!("[{tag}] {} - {why}", crate::ui_fmt::path_shown(&r.path)));
            }
        }
        for (p, why) in &self.left {
            n += 1;
            if v.len() < max {
                let w = match why {
                    Left::MountPoint => t("sd.l_mount"),
                    Left::Special => t("sd.l_special"),
                    Left::OtherReparse => t("sd.l_reparse"),
                };
                v.push(format!("[{}] {} - {w}", t("sd.o_left"), crate::ui_fmt::path_shown(p)));
            }
        }
        if n > v.len() {
            v.push(tf("sd.more", &[&(n - v.len())]));
        }
        v
    }
}

fn same(a: &FileId, b: &FileId) -> bool {
    (a.vol, a.idx) == (b.vol, b.idx)
}

/// The object behind `f` is still where the plan says (no folder on the way was swapped).
fn still_there(f: &File, e: &Entry) -> bool {
    match final_path(f) {
        Ok(real) => path_key(&strip_verbatim(&real)) == path_key(&e.path),
        Err(_) => false,
    }
}

/// Renames `path` (in its folder) `RENAMES` times to random names, checking after each rename that
/// the object is still `id`, and returns the final name. A mismatch renames back and stops.
fn hide_name(path: &Path, id: &FileId, dir: bool) -> Result<PathBuf, String> {
    let mut cur = path.to_path_buf();
    for _ in 0..RENAMES {
        let next = path.with_file_name(crate::entropy::rand_hex()?);
        rename_noreplace(&cur, &next).map_err(|x| x.to_string())?;
        let now = pfs::entry_info(&next).map_err(|x| x.to_string())?;
        if !same(&now.id, id) || (now.kind == EntryKind::Dir) != dir {
            let _ = rename_noreplace(&next, &cur);
            return Err(t("sd.s_changed").into());
        }
        cur = next;
    }
    Ok(cur)
}

pub(crate) use crate::wipe::Sink;

/// All passes of `passes` over `len` bytes through the shared overwrite loop
/// (`wipe::overwrite_with`, the same one the shredding of originals uses). Stops after a finished
/// pass when the job was cancelled. Returns the number of complete passes; a write error fails.
pub(crate) fn overwrite_passes(f: &mut dyn Sink, len: u64, passes: Passes) -> Result<usize, String> {
    wipe::overwrite_with(f, 0, len, passes.patterns(), true, true)
}

fn open_for_wipe(e: &Entry) -> Result<File, Outcome> {
    use std::io::ErrorKind as K;
    let skip = |w: &str| Outcome::Skipped(w.to_string());
    match pfs::open_exclusive(&e.path) {
        Ok(f) => Ok(f),
        Err(x) if x.kind() == K::NotFound => Err(skip(t("sd.s_missing"))),
        Err(x) if x.kind() == K::PermissionDenied => {
            // read-only: the identity is checked on a read handle before the attribute changes
            let ro = pfs::open_attrs(&e.path).map_err(|x| Outcome::Failed(tf("sd.f_readonly", &[&x])))?;
            let i = pfs::entry_info_of(&ro).map_err(|x| Outcome::Failed(x.to_string()))?;
            if !same(&i.id, &e.id) || i.kind != EntryKind::File || !still_there(&ro, e) {
                return Err(skip(t("sd.s_changed")));
            }
            pfs::clear_readonly(&ro).map_err(|x| Outcome::Failed(tf("sd.f_readonly", &[&x])))?;
            drop(ro);
            pfs::open_exclusive(&e.path).map_err(|x| Outcome::Failed(tf("sd.f_open", &[&x])))
        }
        Err(x) if x.raw_os_error() == Some(32) || x.kind() == K::ResourceBusy => Err(skip(t("sd.s_in_use"))),
        Err(x) => Err(Outcome::Failed(tf("sd.f_open", &[&x]))),
    }
}

fn wipe_file(e: &Entry, passes: Passes, streams: &mut u64) -> Outcome {
    let mut f = match open_for_wipe(e) {
        Ok(f) => f,
        Err(o) => return o,
    };
    let i = match pfs::entry_info_of(&f) {
        Ok(i) => i,
        Err(x) => return Outcome::Failed(x.to_string()),
    };
    let mtime = f.metadata().ok().and_then(|m| m.modified().ok());
    if !same(&i.id, &e.id) || i.kind != EntryKind::File || i.size != e.size || mtime != e.mtime || !still_there(&f, e) {
        return Outcome::Skipped(t("sd.s_changed").into());
    }
    // extra streams (NTFS ADS / Linux user xattrs) first: writing them changes the file's time
    let stream_err = match crate::ads::overwrite_streams(&e.path, passes) {
        Ok(n) => {
            *streams += n;
            None
        }
        Err(x) => Some(x),
    };
    let done = match overwrite_passes(&mut f, e.size, passes) {
        Ok(n) => n,
        Err(x) => return Outcome::Partial(tf("sd.p_write", &[&x])),
    };
    if done < passes.count() {
        return Outcome::Partial(tf("sd.p_cancelled", &[&done, &passes.count()]));
    }
    if let Err(x) = f.set_len(0).and_then(|_| f.sync_all()) {
        return Outcome::Partial(tf("sd.p_not_deleted", &[&x]));
    }
    drop(f);
    let last = match hide_name(&e.path, &e.id, false) {
        Ok(p) => p,
        Err(x) => return Outcome::Partial(tf("sd.p_not_deleted", &[&x])),
    };
    let r = open_no_follow(&last, true).and_then(|g| {
        let gi = pfs::entry_info_of(&g)?;
        if !same(&gi.id, &e.id) {
            return Err(std::io::Error::other(t("sd.s_changed")));
        }
        delete_checked(g, &last)
    });
    match (r, stream_err) {
        (Err(x), _) => Outcome::Partial(tf("sd.p_not_deleted", &[&x])),
        (Ok(()), Some(x)) => Outcome::Partial(tf("sd.p_streams", &[&x])),
        (Ok(()), None) => Outcome::Done,
    }
}

fn remove_link(e: &Entry) -> Outcome {
    match pfs::entry_info(&e.path) {
        Ok(i) if same(&i.id, &e.id) && i.kind == EntryKind::Link => match fs::remove_file(&e.path).or_else(|_| fs::remove_dir(&e.path)) {
            Ok(()) => Outcome::Done,
            Err(x) => Outcome::Failed(x.to_string()),
        },
        Ok(_) => Outcome::Skipped(t("sd.s_changed").into()),
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => Outcome::Skipped(t("sd.s_missing").into()),
        Err(x) => Outcome::Failed(x.to_string()),
    }
}

fn remove_dir(e: &Entry) -> Outcome {
    match pfs::entry_info(&e.path) {
        Ok(i) if same(&i.id, &e.id) && i.kind == EntryKind::Dir => {}
        Ok(_) => return Outcome::Skipped(t("sd.s_changed").into()),
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => return Outcome::Skipped(t("sd.s_missing").into()),
        Err(x) => return Outcome::Failed(x.to_string()),
    }
    // a folder that still has something in it (a skipped entry) stays, under its own name
    match fs::read_dir(&e.path).map(|mut r| r.next().is_none()) {
        Ok(true) => {}
        Ok(false) => return Outcome::Skipped(t("sd.s_not_empty").into()),
        Err(x) => return Outcome::Failed(x.to_string()),
    }
    let last = match hide_name(&e.path, &e.id, true) {
        Ok(p) => p,
        Err(x) => return Outcome::Failed(x),
    };
    match fs::remove_dir(&last) {
        Ok(()) => Outcome::Done,
        Err(x) => Outcome::Partial(tf("sd.p_dir_renamed", &[&x])),
    }
}

/// Runs a confirmed plan (see the module docs) with the settings-password [`permit`] of this run.
/// Never stops at the first problem: every entry gets an outcome. Cancelling stops between files
/// at once and inside a file after the current pass.
pub fn execute(c: ConfirmedWipePlan, _permit: WipePermit) -> Report {
    let plan = c.plan;
    let passes = plan.passes;
    let mut rep = Report { left: plan.left.clone(), passes: passes.count(), ..Default::default() };
    set_stage(ST_WIPE);
    progress_start(plan.bytes.saturating_mul(passes.count() as u64));
    // containers being wiped can't be opened by another Shield task meanwhile
    let mut locks = Vec::new();
    for e in plan.entries.iter().filter(|e| e.kind == Kind::File && crate::sysinfo::is_shd(&e.path)) {
        match crate::lock::lock_path_for(&e.path).and_then(|lp| crate::lock::acquire(&lp, crate::lock::Mode::Exclusive, Duration::ZERO)) {
            Ok(l) => locks.push((e.path.clone(), Some(l))),
            Err(_) => locks.push((e.path.clone(), None)),
        }
    }
    let busy = |p: &Path| locks.iter().any(|(lp, l)| lp == p && l.is_none());
    for e in &plan.entries {
        if cancelled() {
            rep.cancelled = true;
            rep.results.push(ItemResult { path: e.path.clone(), kind: e.kind, outcome: Outcome::Skipped(t("sd.s_cancelled").into()) });
            continue;
        }
        let outcome = match e.kind {
            Kind::File if busy(&e.path) => Outcome::Skipped(t("sd.s_in_use").into()),
            Kind::File => wipe_file(e, passes, &mut rep.streams),
            Kind::Link => remove_link(e),
            Kind::Dir => remove_dir(e),
        };
        if cancelled() {
            // the cancel came during this entry: it stopped after a finished pass (or was done)
            rep.cancelled = true;
        }
        rep.results.push(ItemResult { path: e.path.clone(), kind: e.kind, outcome });
    }
    drop(locks);
    if !rep.cancelled {
        let tops: Vec<&Path> = plan.targets.iter().map(|t| t.path.as_path()).collect();
        rep.trim = wipe::trim_after_shred(&tops);
    }
    set_stage(0);
    rep
}

#[cfg(test)]
#[path = "secure_delete_tests.rs"]
mod tests;
