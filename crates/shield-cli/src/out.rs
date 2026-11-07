//! Console output: plain text, `--quiet` (errors only) or `--json` (one object per result, on
//! standard output). Nothing secret is ever printed: no passwords, key material or key file
//! contents. Progress goes to standard error, only when it is a terminal.

use crate::i18n::t;
use crate::progress::{stage_short, PROG_DONE, PROG_TOTAL, STAGE};
use serde_json::{json, Value};
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Exit codes (also listed in `shield help`).
pub mod code {
    pub const OK: i32 = 0;
    pub const FAILED: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const CREDENTIALS: i32 = 3;
    pub const VERIFY: i32 = 4;
    pub const CANCELLED: i32 = 5;
    pub const BUSY: i32 = 6;
}

#[derive(Clone, Copy, Default)]
pub struct Out {
    pub quiet: bool,
    pub json: bool,
    pub yes: bool,
}

impl Out {
    /// Informational line (not in quiet / json mode).
    pub fn info(&self, s: &str) {
        if !self.quiet && !self.json {
            println!("{s}");
        }
    }
    /// Final result: text, or the JSON object with `"ok": true` added.
    pub fn result(&self, text: &str, mut j: Value) {
        if self.json {
            if let Value::Object(m) = &mut j {
                m.insert("ok".into(), Value::Bool(true));
                m.entry("message").or_insert_with(|| Value::String(text.to_string()));
            }
            println!("{j}");
        } else if !self.quiet {
            println!("{text}");
        }
    }
    pub fn error(&self, msg: &str, exit: i32) {
        if self.json {
            println!("{}", json!({ "ok": false, "error": strip_code(msg), "exit": exit }));
        } else {
            eprintln!("{} {}", t("cli.error"), strip_code(msg));
        }
    }

    /// y/N question on the terminal. `--yes` answers yes; without a terminal the answer is no
    /// (the caller then reports that `--yes` is needed).
    pub fn confirm(&self, lines: &[String], question: &str) -> Result<bool, String> {
        for l in lines {
            eprintln!("  {l}");
        }
        if self.yes {
            return Ok(true);
        }
        if !std::io::stdin().is_terminal() {
            return Err(t("cli.needs_yes").into());
        }
        eprint!("{question} {} ", t("cli.yes_no"));
        let _ = std::io::stderr().flush();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).map_err(|e| e.to_string())?;
        Ok(is_yes(&s))
    }
}

pub fn is_yes(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "y" | "yes" | "예" | "네" | "ㅇ")
}

/// Messages from the engine may end with a machine code (" [E_xxx]"); users see the text.
pub fn strip_code(msg: &str) -> &str {
    match msg.rsplit_once(" [") {
        Some((text, c)) if c.starts_with("E_") && c.ends_with(']') && c[..c.len() - 1].bytes().all(|b| b.is_ascii_uppercase() || b == b'_') => text,
        _ => msg,
    }
}

/// Exit code for an engine error.
pub fn exit_for(msg: &str) -> i32 {
    use crate::i18n::has_code;
    if has_code(msg, crate::container::C_OPEN_BAD) {
        code::CREDENTIALS
    } else if crate::progress::is_cancel(msg) {
        code::CANCELLED
    } else if has_code(msg, crate::lock::C_BUSY) {
        code::BUSY
    } else {
        code::FAILED
    }
}

/// Progress line on standard error while `f` runs (stage and percent only).
pub fn with_progress<T>(o: &Out, f: impl FnOnce() -> T) -> T {
    let show = !o.quiet && !o.json && std::io::stderr().is_terminal();
    let stop = Arc::new(AtomicBool::new(false));
    let h = show.then(|| {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut last = String::new();
            while !stop.load(Ordering::Relaxed) {
                let (d, n) = (PROG_DONE.load(Ordering::Relaxed), PROG_TOTAL.load(Ordering::Relaxed));
                let st = STAGE.load(Ordering::Relaxed);
                let line = match (st, n) {
                    (0, _) => String::new(),
                    (s, 0) => stage_short(s).to_string(),
                    (s, n) => format!("{} {:>3}%", stage_short(s), d.min(n) * 100 / n),
                };
                if line != last {
                    eprint!("\r\x1b[2K{line}");
                    let _ = std::io::stderr().flush();
                    last = line;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            if !last.is_empty() {
                eprint!("\r\x1b[2K");
            }
        })
    });
    let r = f();
    stop.store(true, Ordering::Relaxed);
    if let Some(h) = h {
        let _ = h.join();
    }
    STAGE.store(0, Ordering::Relaxed);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_and_answers() {
        assert_eq!(strip_code("wrong password [E_OPEN_BAD]"), "wrong password");
        assert_eq!(strip_code("plain [note]"), "plain [note]");
        assert_eq!(exit_for(&crate::container::open_bad()), code::CREDENTIALS);
        assert_eq!(exit_for(&crate::progress::cancelled_msg()), code::CANCELLED);
        assert_eq!(exit_for("disk full"), code::FAILED);
        assert!(is_yes(" Y\n") && is_yes("예") && !is_yes("") && !is_yes("no"));
    }
}
