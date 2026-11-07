//! Commands without containers: keyfile, verify, update, entropy, version.

use crate::buildinfo::{self, SelfCheck};
use crate::cred::Ctx;
use crate::i18n::{t, tf};
use crate::out::code;
use crate::update::{self, Check};
use serde_json::json;
use shield_platform::Source;
use std::path::PathBuf;

type R = Result<(), String>;

pub fn keyfile(cx: &mut Ctx) -> R {
    let path = PathBuf::from(&cx.a.items[0]);
    let kib = match cx.a.val("size") {
        None => crate::keyfile::KF_DEFAULT_KIB,
        Some(s) => s.parse().map_err(|_| tf("kf.size_range", &[&crate::keyfile::KF_MAX_KIB, &s]))?,
    };
    crate::keyfile::generate_keyfile(&path, kib)?;
    cx.o.result(&tf("cli.keyfile_done", &[&path.display(), &kib]), json!({ "keyfile": path.display().to_string(), "kib": kib }));
    Ok(())
}

/// `shield verify <file> <sig> [--key key.asc]`: OpenPGP signature check (release key by default).
/// Returns the exit code (4 when the signature is not good).
pub fn verify(cx: &mut Ctx) -> Result<i32, String> {
    let (file, sig) = (PathBuf::from(&cx.a.items[0]), PathBuf::from(&cx.a.items[1]));
    let own;
    let cert = match cx.a.val("key") {
        Some(k) => {
            let bytes = std::fs::read(k).map_err(|e| tf("sig.read", &[&e]))?;
            own = crate::sigverify::Cert::parse(&bytes)?;
            &own
        }
        None => buildinfo::release_key().ok_or_else(|| t("upd.no_key").to_string())?,
    };
    match cert.verify_file(&file, &sig) {
        Ok(v) => {
            let created = v.created.map(|c| crate::ui_fmt::date(Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(c.max(0) as u64)))).unwrap_or_default();
            cx.o.result(&tf("cli.verify_ok", &[&v.fingerprint, &v.signer, &created]), json!({ "verified": true, "fingerprint": v.fingerprint, "signer": v.signer, "created": v.created }));
            Ok(code::OK)
        }
        Err(e) => {
            cx.o.error(&tf("cli.verify_bad", &[&e]), code::VERIFY);
            Ok(code::VERIFY)
        }
    }
}

/// `shield update [--check]`: manual check; downloading and installing are asked separately.
pub fn update(cx: &mut Ctx) -> R {
    let r = match update::check()? {
        Check::UpToDate(v) => {
            cx.o.result(&tf("upd.up_to_date", &[&v]), json!({ "update": false, "current": v.to_string() }));
            return Ok(());
        }
        Check::Available(r) => r,
    };
    let j = json!({ "update": true, "current": update::Version::current().to_string(), "available": r.version.to_string(), "page": r.page });
    if cx.a.has("check") || r.files.is_none() {
        let text = format!("{}\n{}", tf("upd.available", &[&r.version]), r.page);
        cx.o.result(&text, j);
        return Ok(());
    }
    if !cx.o.confirm(&[tf("upd.available", &[&r.version])], &tf("upd.ask_download", &[&r.version, &update::Version::current()]))? {
        return Err(t("upd.cancelled").into());
    }
    let d = crate::out::with_progress(&cx.o, || {
        crate::progress::progress_start(0);
        update::download(
            &r,
            &|d, n| {
                crate::progress::PROG_TOTAL.store(n, std::sync::atomic::Ordering::Relaxed);
                crate::progress::PROG_DONE.store(d, std::sync::atomic::Ordering::Relaxed);
                crate::progress::STAGE.store(crate::progress::ST_SCAN, std::sync::atomic::Ordering::Relaxed);
            },
            &crate::progress::cancelled,
        )
    })?;
    cx.o.info(&tf("upd.verified", &[&d.version, &d.signer.fingerprint]));
    if !cx.o.confirm(&[t("upd.install_note").into()], &tf("upd.ask_install", &[&d.version]))? {
        let _ = std::fs::remove_dir_all(&d.dir);
        return Err(t("upd.cancelled").into());
    }
    match update::install(d)? {
        update::Installed::ExitNow => cx.o.result(t("cli.installer_started"), j),
        update::Installed::Done => cx.o.result(t("upd.installed"), j),
    }
    Ok(())
}

fn source_name(s: Source) -> &'static str {
    use Source::*;
    t(match s {
        OsCsprng => "ent.os",
        OsAux => "ent.os_aux",
        HwRng => "ent.hwrng",
        Timers => "ent.timers",
        CpuJitter => "ent.cpu_jitter",
        Memory => "ent.memory",
        Process => "ent.process",
        Ids => "ent.ids",
        SystemTimes => "ent.system_times",
        Disk => "ent.disk",
        Network => "ent.network",
        Processes => "ent.processes",
        PerfData => "ent.perfdata",
        ProcFs => "ent.procfs",
        Sensors => "ent.sensors",
        WindowState => "ent.window_state",
        InputTiming => "ent.input_timing",
        Mouse => "ent.mouse",
    })
}

/// `shield entropy [--enable c] [--disable c]`: status (Normal / Weak only, never values) and the
/// switches. Changing them needs the settings password like in the window.
pub fn entropy(cx: &mut Ctx) -> R {
    use crate::entropy::SourceStatus as St;
    let (on, off) = (cx.a.vals("enable").to_vec(), cx.a.vals("disable").to_vec());
    if !on.is_empty() || !off.is_empty() {
        for c in on.iter().chain(&off) {
            match Source::from_code(c) {
                None => return Err(tf("cli.unknown_source", &[c])),
                Some(Source::OsCsprng) if off.contains(c) => return Err(t("cli.os_required").into()),
                _ => {}
            }
        }
        let mut s = cx.set.clone();
        s.entropy_disabled.retain(|c| !on.contains(c));
        for c in off.iter().filter(|c| *c != "os") {
            if !s.entropy_disabled.contains(c) {
                s.entropy_disabled.push(c.clone());
            }
        }
        if s.auth.is_none() {
            return Err(t("set.pw_setup_needed").into());
        }
        let mut b = crate::secret::read(t("cli.set_pw_prompt"), crate::secret::Mode::Hidden)?;
        let u = crate::settings_auth::unlock(&cx.set, &b.take()?)?;
        s.save_unlocked(&u)?;
        s.apply_entropy();
        cx.set = s;
    }
    crate::entropy::slow_poll();
    let mut rows = vec![];
    let mut text = vec![t("ent.title").to_string()];
    for (src, st) in crate::entropy::status() {
        if st == St::Unavailable {
            continue;
        }
        let label = match st {
            St::Normal => t("ent.normal"),
            St::Weak => t("ent.weak"),
            St::Waiting => t("ent.waiting"),
            _ => t("ent.off"),
        };
        text.push(format!("  {:<13} {:<20} {}", src.code(), label, source_name(src)));
        rows.push(json!({ "source": src.code(), "status": format!("{st:?}").to_lowercase() }));
    }
    text.push(t("cli.entropy_note").into());
    cx.o.result(&text.join("\n"), json!({ "sources": rows }));
    Ok(())
}

pub fn version(cx: &mut Ctx) -> R {
    let v = buildinfo::VERSION;
    let repo = buildinfo::repo_url().unwrap_or_else(|| "-".into());
    let fpr = buildinfo::fingerprint().unwrap_or_else(|| "-".into());
    let (integrity, ok) = match buildinfo::self_check() {
        SelfCheck::Verified(v) => (tf("upd.self_ok", &[&v.fingerprint]), Some(true)),
        SelfCheck::NoSignature => (t("upd.self_nosig").to_string(), None),
        SelfCheck::NoKey => (t("upd.no_key").to_string(), None),
        SelfCheck::Invalid(e) => (tf("upd.self_bad", &[&e]), Some(false)),
    };
    let text = format!("Shield {v}\n{repo}\n{}\n{integrity}", tf("upd.fingerprint", &[&fpr]));
    cx.o.result(&text, json!({ "version": v, "repo": repo, "fingerprint": fpr, "integrity": ok }));
    if ok == Some(false) {
        return Err(tf("upd.self_bad", &[&""]));
    }
    Ok(())
}
