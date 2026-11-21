//! `shield wipe` - secure delete of files and folders (3.1.0 final; design: docs/10).
//!
//! On a terminal: the same three steps as the window (warning with the resolved paths, limits
//! with an acknowledgement, a 6-character code typed after 3 seconds; 3 wrong codes abort).
//! Without a terminal (scripts): only with `--confirm-token <token>` from a `--dry-run` of the very
//! same plan plus `--i-understand-irreversible`; the warnings are printed to standard error
//! anyway. `--yes` never answers any of this (it is ignored with a notice). Folders need `-r`.
//! When the settings ask for it (a settings password and Settings > Security > Secure delete on),
//! the settings password is typed on the terminal right before deleting, in both modes; without a
//! terminal the run is refused (no argument, environment or pipe can give it).
//!
//! Exit codes: 0 everything removed, 7 (PARTIAL) something was not (fully) removed, 8 (REFUSED)
//! protected item / failed or missing confirmation / wrong token, 5 cancelled, 2 usage.

use crate::cred::Ctx;
use crate::i18n::{t, tf};
use crate::out::{code, with_progress};
use crate::secure_delete::{self as sd, Answer, Confirmation, Plan, Step};
use crate::ui_fmt::path_shown;
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Instant;

fn line(s: &str) {
    eprintln!("  {s}");
}

/// The first warning (also printed by `--dry-run` and before a token run).
fn print_warning(p: &Plan) {
    eprintln!("{} {}", t("cli.warning"), t("sd.w_irreversible"));
    line(&p.summary_line());
    if p.is_big() {
        line(t("sd.w_big"));
    }
    for l in p.target_lines() {
        line(&l);
    }
}

fn print_limits(p: &Plan) {
    eprintln!("{}", t("sd.l_title"));
    for l in p.limit_lines() {
        line(&format!("- {l}"));
    }
}

fn ask(q: &str) -> Result<String, String> {
    eprint!("{q} ");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).map_err(|e| e.to_string())?;
    if crate::progress::cancelled() {
        return Err(crate::progress::cancelled_msg());
    }
    Ok(s)
}

/// The three steps on a terminal. Ok(None): the user said no (cancelled).
fn interactive(plan: Plan) -> Result<Option<sd::ConfirmedWipePlan>, String> {
    let mut c = Confirmation::new(plan);
    let total = c.steps_total();
    eprintln!("{}", tf("sd.step_title", &[&1, &total]));
    print_warning(c.plan());
    if !crate::out::is_yes(&ask(&format!("{} {}", t("sd.w_go"), t("cli.yes_no")))?) {
        return Ok(None);
    }
    c.accept_warning(Instant::now())?;
    if c.step() == Step::Limits {
        eprintln!("{}", tf("sd.step_title", &[&2, &total]));
        print_limits(c.plan());
        if !crate::out::is_yes(&ask(&format!("{} {}", t("sd.l_ack"), t("cli.yes_no")))?) {
            return Ok(None);
        }
        c.accept_limits(true, Instant::now())?;
    }
    eprintln!("{}", tf("sd.step_title", &[&total, &total]));
    loop {
        let Some(code) = c.code().map(str::to_string) else { return Err(sd_refused(t("sd.cancelled"))) };
        eprintln!("{}", t("sd.c_title"));
        eprintln!("    {code}");
        eprintln!("{}", tf("sd.c_tries", &[&c.tries_left()]));
        let typed = ask(t("sd.c_field"))?;
        match c.submit(&typed, Instant::now())? {
            Answer::Accepted => break,
            Answer::TooEarly => eprintln!("{}", t("sd.c_early")),
            Answer::Wrong(n) => eprintln!("{}", tf("sd.c_wrong", &[&n])),
            Answer::Aborted => return Err(sd_refused(&tf("sd.c_aborted", &[&sd::MAX_FAILS]))),
            Answer::NotNow => return Err(sd_refused(t("sd.cancelled"))),
        }
    }
    c.finish().map(Some).map_err(|_| sd_refused(t("sd.cancelled")))
}

/// The settings password for this run (`secure_delete::permit`): asked on the terminal when the
/// settings want it, at most `MAX_FAILS` tries.
fn settings_permit(cx: &Ctx) -> Result<sd::WipePermit, String> {
    if !sd::settings_password_needed(&cx.set) {
        return sd::permit(&cx.set, None);
    }
    if !std::io::stdin().is_terminal() {
        return Err(sd_refused(t("cli.wipe_set_pw_tty")));
    }
    eprintln!("{}", t("sd.pw_title"));
    for left in (0..sd::MAX_FAILS).rev() {
        let mut b = crate::secret::read(t("cli.set_pw_prompt"), crate::secret::Mode::Hidden)?;
        let pw = b.take()?;
        match sd::permit(&cx.set, Some(&pw)) {
            Ok(p) => return Ok(p),
            Err(e) if left > 0 && crate::i18n::has_code(&e, crate::settings_auth::C_WRONG_PW) => eprintln!("{}", tf("sd.pw_wrong", &[&left])),
            Err(e) if crate::i18n::has_code(&e, crate::settings_auth::C_WRONG_PW) => return Err(sd_refused(&tf("sd.pw_aborted", &[&sd::MAX_FAILS]))),
            Err(e) => return Err(e),
        }
    }
    Err(sd_refused(t("sd.cancelled")))
}

/// A refusal message with the code that maps to exit code 8.
fn sd_refused(text: &str) -> String {
    format!("{text} [{}]", sd::C_REFUSED)
}

pub fn wipe(cx: &mut Ctx) -> Result<i32, String> {
    let passes = crate::cmds::passes(cx)?;
    let mut items: Vec<PathBuf> = Vec::new();
    for i in &cx.a.items {
        let p = PathBuf::from(i);
        if !items.contains(&p) {
            items.push(p);
        }
    }
    // like rm: a folder (not a link to one) only with -r
    if !cx.a.has("recursive") {
        if let Some(d) = items.iter().find(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())) {
            cx.o.error(&tf("cli.wipe_needs_r", &[&path_shown(d)]), code::USAGE);
            return Ok(code::USAGE);
        }
    }
    let dry = cx.a.has("dry-run");
    if cx.a.has("yes") && !dry {
        eprintln!("{} {}", t("cli.warning"), t("cli.wipe_yes_ignored"));
    }
    let plan = with_progress(&cx.o, || sd::scan(&items, passes))?;
    let token = plan.token();
    let needs_pw = sd::settings_password_needed(&cx.set);
    if dry {
        print_warning(&plan);
        print_limits(&plan);
        if needs_pw {
            eprintln!("{}", t("cli.wipe_set_pw_note"));
        }
        let targets: Vec<String> = plan.targets().iter().map(|x| x.path.display().to_string()).collect();
        cx.o.result(
            &tf("cli.wipe_dry", &[&token]),
            json!({ "dry_run": true, "token": token, "files": plan.files(), "folders": plan.dirs(), "links": plan.links(), "bytes": plan.bytes(), "passes": plan.passes().count(), "settings_password": needs_pw, "targets": targets }),
        );
        return Ok(code::OK);
    }
    let tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let confirmed = match cx.a.val("confirm-token") {
        Some(tok) => {
            // scripts: the warnings go to standard error before and again right before deleting
            print_warning(&plan);
            print_limits(&plan);
            let c = sd::confirm_with_token(plan, tok, cx.a.has("i-understand-irreversible"))?;
            eprintln!("{} {}", t("cli.warning"), t("sd.w_irreversible"));
            c
        }
        None if tty => match interactive(plan)? {
            Some(c) => c,
            None => return Err(crate::progress::cancelled_msg()),
        },
        None => {
            print_warning(&plan);
            print_limits(&plan);
            return Err(sd_refused(t("cli.wipe_needs_token")));
        }
    };
    let permit = settings_permit(cx)?;
    let rep = with_progress(&cx.o, || sd::execute(confirmed, permit));
    let problems = rep.problem_lines(50);
    if !cx.o.json {
        for l in &problems {
            eprintln!("  {l}");
        }
    }
    let exit = if rep.all_ok() {
        code::OK
    } else if rep.cancelled {
        code::CANCELLED
    } else {
        code::PARTIAL
    };
    let j = json!({ "removed": rep.done(), "partial": rep.partial(), "skipped": rep.skipped(), "failed": rep.failed(), "left": rep.left.len(), "cancelled": rep.cancelled, "passes": rep.passes, "problems": problems, "exit": exit });
    if exit == code::OK {
        cx.o.result(&rep.summary(), j);
    } else if cx.o.json {
        println!("{}", json!({ "ok": false, "error": rep.summary(), "details": j, "exit": exit }));
    } else {
        eprintln!("{} {}", t("cli.error"), rep.summary());
    }
    Ok(exit)
}
