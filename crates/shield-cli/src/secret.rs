//! Secret input for the console (3.0 §6). Passwords are read key by key into a locked,
//! zeroized `SecretBuf`; they never pass through a line buffer of the standard library.
//!
//! * hidden (default): nothing is echoed, not even the length;
//! * `--reveal`: the input is shown on the alternate screen, which is cleared together with the
//!   scrollback when Enter (or Esc) is pressed;
//! * `--password` (off by default): needs Settings > Command line and `--allow-arg-secrets`, and
//!   prints a warning every time. Environment variables, files and pipes are not accepted.

use crate::harden::SecretBuf;
use crate::i18n::t;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::{cursor, execute, terminal};
use std::io::{IsTerminal, Write};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Hidden,
    Reveal,
}

/// Raw mode (and the alternate screen) are undone on every exit path, also on errors.
struct Term {
    alt: bool,
}

impl Term {
    fn start(alt: bool) -> Result<Term, String> {
        if alt {
            execute!(std::io::stderr(), terminal::EnterAlternateScreen).map_err(|e| e.to_string())?;
        }
        let t = Term { alt };
        terminal::enable_raw_mode().map_err(|e| e.to_string())?;
        Ok(t)
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let mut e = std::io::stderr();
        if self.alt {
            // the shown secret disappears from the screen and from the scrollback
            let _ = execute!(e, terminal::Clear(terminal::ClearType::All), terminal::Clear(terminal::ClearType::Purge), terminal::LeaveAlternateScreen);
            let _ = execute!(e, terminal::Clear(terminal::ClearType::Purge));
        }
        let _ = writeln!(e);
    }
}

/// What a key does to the input (separate from the terminal so it can be tested).
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Continue,
    Done,
    Cancel,
}

pub fn apply_key(buf: &mut SecretBuf, code: KeyCode, mods: KeyModifiers) -> Step {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Enter => Step::Done,
        KeyCode::Esc => Step::Cancel,
        KeyCode::Char('c') | KeyCode::Char('d') if ctrl => Step::Cancel,
        KeyCode::Char('u') if ctrl => {
            buf.clear();
            Step::Continue
        }
        KeyCode::Backspace => {
            buf.pop();
            Step::Continue
        }
        KeyCode::Char(c) if !ctrl => {
            let mut s = [0u8; 4];
            buf.push_str(c.encode_utf8(&mut s));
            zeroize::Zeroize::zeroize(&mut s);
            Step::Continue
        }
        _ => Step::Continue,
    }
}

/// Reads one secret from the terminal. Refuses when standard input is not a terminal.
pub fn read(prompt: &str, mode: Mode) -> Result<SecretBuf, String> {
    if !std::io::stdin().is_terminal() {
        return Err(t("cli.no_tty").into());
    }
    let mut buf = SecretBuf::new();
    let mut err = std::io::stderr();
    let term = Term::start(mode == Mode::Reveal)?;
    let draw = |e: &mut std::io::Stderr, b: &SecretBuf| {
        if mode == Mode::Reveal {
            let _ = execute!(e, cursor::MoveToColumn(0), terminal::Clear(terminal::ClearType::CurrentLine));
            let _ = write!(e, "{} {prompt} {}", t("cli.reveal_note"), b.as_str());
        } else {
            let _ = write!(e, "{prompt} ");
        }
        let _ = e.flush();
    };
    draw(&mut err, &buf);
    let step = loop {
        match event::read().map_err(|e| e.to_string())? {
            Event::Key(k) if k.kind != KeyEventKind::Release => {
                let s = apply_key(&mut buf, k.code, k.modifiers);
                if s != Step::Continue {
                    break s;
                }
                if mode == Mode::Reveal {
                    draw(&mut err, &buf);
                }
            }
            // pasted text arrives as one event when the terminal supports it
            Event::Paste(mut s) => {
                buf.push_str(&s);
                buf.pasted = true;
                zeroize::Zeroize::zeroize(&mut s);
                if mode == Mode::Reveal {
                    draw(&mut err, &buf);
                }
            }
            _ => {}
        }
    };
    drop(term);
    match step {
        Step::Done => Ok(buf),
        _ => Err(crate::progress::cancelled_msg()),
    }
}

/// `--password` / `--new-password`: allowed only when both switches are on; warns every time.
pub fn from_arg(v: &mut String, allowed_in_settings: bool, allowed_now: bool) -> Result<SecretBuf, String> {
    let r = if !allowed_in_settings {
        Err(t("cli.arg_secrets_off").to_string())
    } else if !allowed_now {
        Err(t("cli.arg_secrets_flag").to_string())
    } else {
        eprintln!("{}", t("cli.arg_warn"));
        let mut b = SecretBuf::new();
        b.push_str(v);
        Ok(b)
    };
    zeroize::Zeroize::zeroize(v);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_edit_the_buffer() {
        let mut b = SecretBuf::new();
        let none = KeyModifiers::NONE;
        for c in "pass word".chars() {
            assert_eq!(apply_key(&mut b, KeyCode::Char(c), none), Step::Continue);
        }
        apply_key(&mut b, KeyCode::Backspace, none);
        assert_eq!(b.as_str(), "pass wor");
        apply_key(&mut b, KeyCode::Char('u'), KeyModifiers::CONTROL);
        assert!(b.is_empty(), "Ctrl+U clears");
        apply_key(&mut b, KeyCode::Char('한'), KeyModifiers::SHIFT);
        assert_eq!(b.as_str(), "한");
        assert_eq!(apply_key(&mut b, KeyCode::Char('c'), KeyModifiers::CONTROL), Step::Cancel);
        assert_eq!(apply_key(&mut b, KeyCode::Esc, none), Step::Cancel);
        assert_eq!(apply_key(&mut b, KeyCode::Enter, none), Step::Done);
        assert_eq!(b.as_str(), "한", "control keys add nothing");
    }

    #[test]
    fn argument_secrets_need_both_switches_and_are_wiped() {
        let mut v = "from argv".to_string();
        assert!(from_arg(&mut v, false, true).is_err());
        assert!(v.is_empty(), "wiped even when refused");
        let mut v = "from argv".to_string();
        assert!(from_arg(&mut v, true, false).is_err());
        let mut v = "from argv".to_string();
        assert_eq!(from_arg(&mut v, true, true).unwrap().as_str(), "from argv");
        assert!(v.is_empty());
    }
}
