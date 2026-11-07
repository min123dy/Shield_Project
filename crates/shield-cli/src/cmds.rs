//! Container commands. Each one asks for the credentials itself (never cached between
//! commands) and asks before anything is overwritten or deleted, with the same snapshot / storage
//! warnings as the windows (3.0 §2). `--yes` answers the questions; the warnings still print.

use crate::compress::Strength;
use crate::container;
use crate::cred::Ctx;
use crate::engine::{self, DecOpts, Opts, StreamPolicy};
use crate::i18n::{t, tf};
use crate::outname::{bundle_output, default_output};
use crate::wipe::{self, Passes};
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

type R = Result<(), String>;

fn passes(cx: &Ctx) -> Result<Passes, String> {
    match cx.a.val("passes") {
        None => Ok(cx.set.shred_passes),
        Some("3") => Ok(Passes::Three),
        Some("7") => Ok(Passes::Seven),
        Some(x) => Err(tf("cli.bad_passes", &[&x])),
    }
}

fn strength(cx: &Ctx) -> Result<Strength, String> {
    match cx.a.val("strength") {
        None | Some("auto") => Ok(Strength::Auto),
        Some("fast") => Ok(Strength::Fast),
        Some("balanced") => Ok(Strength::Balanced),
        Some("max") => Ok(Strength::Max),
        Some(x) => Err(tf("cli.bad_strength", &[&x])),
    }
}

fn paths(v: &[String]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![];
    for p in v.iter().map(PathBuf::from) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Snapshot / storage warnings, then the question. Asked every time something is overwritten.
fn confirm_shred(cx: &Ctx, targets: &[&Path], p: Option<Passes>) -> R {
    let ex = wipe::exposure(targets);
    let mut lines = ex.snapshot_lines;
    if ex.not_guaranteed {
        lines.push(t("dlg.shred_flash").into());
    }
    if let Some(p) = p {
        lines.push(tf("cli.passes_used", &[&if p == Passes::Three { 3 } else { 7 }]));
    }
    lines.push(t("v.passes_hint").into());
    if cx.o.confirm(&lines, t("dlg.shred_body"))? {
        Ok(())
    } else {
        Err(crate::progress::cancelled_msg())
    }
}

fn run<T>(cx: &Ctx, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    crate::out::with_progress(&cx.o, f)
}

pub fn encrypt(cx: &mut Ctx) -> R {
    let items = paths(&cx.a.items);
    if let Some(m) = items.iter().find(|p| std::fs::symlink_metadata(p).is_err()) {
        return Err(tf("multi.missing", &[&m.display()]));
    }
    let separate = cx.a.has("separate") && items.len() > 1;
    let outs: Vec<PathBuf> = match (cx.a.val("output"), separate) {
        (Some(o), false) => vec![PathBuf::from(o)],
        (Some(dir), true) => items.iter().map(|i| crate::outname::free_output(Path::new(dir), &i.file_name().unwrap_or_default().to_string_lossy())).collect::<Option<_>>().ok_or(t("eng.no_name"))?,
        (None, true) => items.iter().map(|i| default_output(i, cx.set.naming)).collect::<Option<_>>().ok_or(t("eng.no_name"))?,
        (None, false) if items.len() == 1 => vec![default_output(&items[0], cx.set.naming).ok_or(t("eng.no_name"))?],
        (None, false) => vec![bundle_output(&items).ok_or(t("eng.no_name"))?],
    };
    let shred = cx.a.has("shred");
    let p = passes(cx)?;
    let mut o = Opts {
        shred_src: shred,
        passes: p,
        wipe_free_after: cx.a.has("wipe-free"),
        strength: strength(cx)?,
        keyfiles: vec![],
        streams: if cx.a.has("include-streams") { StreamPolicy::Include } else { StreamPolicy::Ask },
    };
    if shred {
        confirm_shred(cx, &items.iter().map(PathBuf::as_path).collect::<Vec<_>>(), Some(p))?;
    }
    let s = cx.create(false)?;
    o.keyfiles = s.keyfiles.clone();
    let mut done = vec![];
    let jobs: Vec<(Vec<PathBuf>, PathBuf)> = if separate { items.iter().cloned().map(|i| vec![i]).zip(outs).collect() } else { vec![(items.clone(), outs[0].clone())] };
    for (src, dst) in jobs {
        let r = run(cx, || if src.len() == 1 { engine::do_encrypt(&src[0], &dst, &s.cred(), &o) } else { engine::do_encrypt_many(&src, &dst, &s.cred(), &o) });
        match r {
            Ok(m) => {
                cx.o.info(&m);
                done.push(dst.display().to_string());
            }
            Err(e) if crate::i18n::has_code(&e, engine::C_ADS) => return Err(format!("{e}\n{}", t("cli.ads_hint"))),
            Err(e) => return Err(if done.is_empty() { e } else { format!("{e}\n{}", tf("multi.done", &[&done.len(), &items.len()])) }),
        }
    }
    cx.o.result(&tf("cli.encrypted", &[&done.join(", ")]), json!({ "containers": done }));
    Ok(())
}

pub fn decrypt(cx: &mut Ctx) -> R {
    let src = PathBuf::from(&cx.a.items[0]);
    let outdir = cx.a.val("output").map(PathBuf::from).unwrap_or_else(|| engine::parent_dir(&src));
    let s = cx.existing()?;
    let m = run(cx, || engine::do_decrypt(&src, &outdir, &s.cred(), DecOpts { strict_motw: cx.set.strict_motw }))?;
    cx.o.result(&m, json!({ "output": outdir.display().to_string() }));
    Ok(())
}

pub fn list(cx: &mut Ctx) -> R {
    let src = PathBuf::from(&cx.a.items[0]);
    let s = cx.existing()?;
    let (entries, total) = run(cx, || container::open(&src, s.cred()).map(|o| (o.entries, o.total)))?;
    if cx.o.json {
        let e: Vec<_> = entries
            .iter()
            .map(|e| json!({ "name": e.name.as_str(), "dir": e.is_dir, "size": e.size, "mtime": e.mtime.and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()) }))
            .collect();
        cx.o.result("", json!({ "entries": e, "total": total }));
    } else {
        for e in &entries {
            let size = if e.is_dir { "-".to_string() } else { crate::ui_fmt::human(e.size) };
            // the listing is the result: printed also with --quiet
            println!("{size:>10}  {}{}", e.name.as_str(), if e.is_dir { "/" } else { "" });
        }
        cx.o.info(&tf("cli.list_total", &[&entries.len(), &crate::ui_fmt::human(total)]));
    }
    Ok(())
}

pub fn add(cx: &mut Ctx) -> R {
    let target = PathBuf::from(&cx.a.items[0]);
    let adds = paths(&cx.a.items[1..]);
    if let Some(m) = adds.iter().find(|p| std::fs::symlink_metadata(p).is_err()) {
        return Err(tf("multi.missing", &[&m.display()]));
    }
    let prefix = cx.a.val("into").unwrap_or("").trim_matches(['/', '\\']).replace('\\', "/");
    let p = passes(cx)?;
    let shred = cx.a.has("shred");
    let mut targets = vec![target.as_path()];
    if shred {
        targets.extend(adds.iter().map(PathBuf::as_path));
    }
    confirm_shred(cx, &targets, Some(p))?;
    let s = cx.existing()?;
    let mut o = run(cx, || container::open(&target, s.cred()))?;
    let clash = container::conflicts(&o, &adds, &prefix);
    if !clash.is_empty() && !cx.a.has("overwrite") {
        return Err(tf("cli.conflicts", &[&clash.join(", ")]));
    }
    let ao = container::AddOpts { overwrite: cx.a.has("overwrite"), shred_src: shred, passes: p, strength: strength(cx)?, keyfiles: s.keyfiles.clone() };
    let m = run(cx, || container::add_files(&mut o, s.cred(), &adds, &prefix, &ao))?;
    cx.o.result(&m, json!({ "container": target.display().to_string(), "added": adds.len() }));
    Ok(())
}

pub fn remove(cx: &mut Ctx) -> R {
    let target = PathBuf::from(&cx.a.items[0]);
    let want: Vec<String> = cx.a.items[1..].iter().map(|n| n.trim_matches(['/', '\\']).replace('\\', "/")).collect();
    let p = passes(cx)?;
    confirm_shred(cx, &[target.as_path()], Some(p))?;
    let s = cx.existing()?;
    let mut o = run(cx, || container::open(&target, s.cred()))?;
    let have: HashSet<&str> = o.entries.iter().map(|e| e.name.as_str()).collect();
    if let Some(m) = want.iter().find(|w| !have.contains(w.as_str())) {
        return Err(tf("cli.not_in_container", &[m]));
    }
    let sel: HashSet<String> = want.into_iter().collect();
    let st = strength(cx)?;
    let m = run(cx, || container::remove_entries(&mut o, s.cred(), &sel, st, p))?;
    cx.o.result(&m, json!({ "container": target.display().to_string(), "removed": sel.len() }));
    Ok(())
}

pub fn change_password(cx: &mut Ctx) -> R {
    let target = PathBuf::from(&cx.a.items[0]);
    let old = cx.existing()?;
    let new = cx.create(true)?;
    let m = run(cx, || crate::rekey::do_change_password(&target, &old.cred(), &new.cred()))?;
    cx.o.result(&m, json!({ "container": target.display().to_string() }));
    Ok(())
}

pub fn rekey(cx: &mut Ctx) -> R {
    let target = PathBuf::from(&cx.a.items[0]);
    let p = passes(cx)?;
    confirm_shred(cx, &[target.as_path()], Some(p))?;
    let old = cx.existing()?;
    let new = cx.create(true)?;
    let m = run(cx, || crate::rekey::do_full_rekey(&target, &old.cred(), &new.cred(), p))?;
    cx.o.result(&m, json!({ "container": target.display().to_string() }));
    Ok(())
}
