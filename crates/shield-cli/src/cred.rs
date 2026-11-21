//! Credentials from the console: password (prompt, sensitive view or the guarded argument mode),
//! key files (`-k`, repeatable) and PIM. The same checks as the encryption window apply to new
//! credentials (minimum length, confirmation, weak-password and key-file-only confirmations).

use crate::args::Args;
use crate::crypto::Cred;
use crate::engine::check_new_password;
#[cfg(test)]
use crate::engine::DEFAULT_PIM;
use crate::format::MAX_PIM;
use crate::harden::SecretBuf;
use crate::i18n::{t, tf};
use crate::out::Out;
use crate::secret::{self, Mode};
use crate::settings::Settings;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Everything needed to build `Cred` values (one per operation, as the engine consumes them).
pub struct Secret {
    pw: Zeroizing<Vec<u8>>,
    kf: Option<Zeroizing<[u8; 64]>>,
    pub pim: u32,
    pub keyfiles: Vec<PathBuf>,
}

impl Secret {
    pub fn cred(&self) -> Cred {
        Cred { pw: self.pw.clone(), kf: self.kf.clone(), pim: self.pim }
    }
}

pub struct Ctx {
    pub o: Out,
    pub set: Settings,
    pub a: Args,
}

impl Ctx {
    fn mode(&self) -> Mode {
        if self.a.has("reveal") {
            Mode::Reveal
        } else {
            Mode::Hidden
        }
    }

    /// The password argument (`--password` / `--new-password`), removed from the arguments and
    /// wiped, or a prompt.
    fn password(&mut self, opt: &str, prompt: &str) -> Result<SecretBuf, String> {
        if let Some(mut vals) = self.a.opts.remove(opt) {
            let mut v = vals.pop().unwrap_or_default();
            for x in vals.iter_mut() {
                zeroize::Zeroize::zeroize(x);
            }
            return secret::from_arg(&mut v, self.set.allow_arg_secrets, self.a.has("allow-arg-secrets"));
        }
        secret::read(prompt, self.mode())
    }

    fn pim(&self, opt: &str) -> Result<u32, String> {
        match self.a.val(opt) {
            None => Ok(self.set.default_pim),
            Some(s) => s.parse::<u32>().ok().filter(|p| *p <= MAX_PIM).ok_or_else(|| tf("cli.bad_pim", &[&MAX_PIM, &s])),
        }
    }

    fn keyfiles(&self, opt: &str) -> Vec<PathBuf> {
        self.a.vals(opt).iter().map(PathBuf::from).collect()
    }

    /// Credentials of an existing container.
    pub fn existing(&mut self) -> Result<Secret, String> {
        let pim = self.pim("pim")?;
        let keyfiles = self.keyfiles("keyfile");
        let kf = crate::keyfile::keyfile_opt(&keyfiles)?;
        let mut b = self.password("password", t("cli.pw_prompt"))?;
        if b.is_empty() && kf.is_none() {
            return Err(t("p.need_cred").into());
        }
        Ok(Secret { pw: b.take()?, kf, pim, keyfiles })
    }

    /// New credentials (`new` = the `--new-...` options of change-password / rekey).
    pub fn create(&mut self, new: bool) -> Result<Secret, String> {
        let (o_pw, o_pim, o_kf) = if new { ("new-password", "new-pim", "new-keyfile") } else { ("password", "pim", "keyfile") };
        let pim = self.pim(o_pim)?;
        let keyfiles = self.keyfiles(o_kf);
        let from_arg = self.a.has(o_pw);
        let mut b = self.password(o_pw, t(if new { "cli.pw_new_prompt" } else { "cli.pw_prompt" }))?;
        if !from_arg {
            let mut b2 = secret::read(t("cli.pw_again_prompt"), self.mode())?;
            if !b.ct_eq(&b2) {
                return Err(t(if new { "p.new_confirm" } else { "p.confirm" }).into());
            }
            b2.clear();
        }
        check_new(&self.o, &b, pim, !keyfiles.is_empty(), new, self.a.has("allow-weak"))?;
        let kf = crate::keyfile::keyfile_opt(&keyfiles)?;
        Ok(Secret { pw: b.take()?, kf, pim, keyfiles })
    }
}

/// The same check as the windows (`password::check_new`): a block is an error. Warnings (weak
/// password, key file only) are always printed and then need the "use it anyway" answer on a
/// terminal or `--allow-weak` (3.1.0 final, review E). `--yes` does not answer this: a script
/// that says yes to everything must not create a container with a weak password by accident;
/// without a terminal and without `--allow-weak` it is refused. The confirmation field was
/// compared by the caller already.
pub fn check_new(o: &Out, b: &SecretBuf, pim: u32, has_kf: bool, new: bool, allow_weak: bool) -> Result<(), String> {
    let c = check_new_password(b.as_str(), None, b.overflow, pim, has_kf);
    if let Some(first) = c.blocks.into_iter().next() {
        return Err(if first == t("pw.b_empty") { t(if new { "p.need_new_cred" } else { "p.need_cred" }).into() } else { first });
    }
    if c.warnings.is_empty() {
        return Ok(());
    }
    if allow_weak {
        for w in &c.warnings {
            eprintln!("{} {w}", t("cli.warning"));
        }
        eprintln!("{}", t("cli.weak_allowed"));
        return Ok(());
    }
    if !o.ask_tty(&c.warnings, t("cli.use_weak"), t("cli.weak_needs_flag"))? {
        return Err(crate::progress::cancelled_msg());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn buf(s: &str) -> SecretBuf {
        let mut b = SecretBuf::new();
        b.push_str(s);
        b
    }
    #[test]
    fn new_credentials_follow_the_window_rules() {
        let yes = Out { yes: true, ..Default::default() };
        let no = Out::default();
        let tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        assert!(check_new(&yes, &buf(""), DEFAULT_PIM, false, false, true).is_err(), "nothing given: a block, --allow-weak does not help");
        assert!(check_new(&no, &buf("short"), DEFAULT_PIM, false, false, true).is_ok(), "short: a warning, accepted with --allow-weak");
        assert!(check_new(&no, &buf("Zk#9vQ!x2Lp$7"), 0, false, false, true).is_err(), "below the default PIM: 20 characters needed (a block)");
        assert!(check_new(&no, &buf(""), DEFAULT_PIM, true, false, true).is_ok(), "key file only, accepted with --allow-weak");
        assert!(check_new(&no, &buf("correct horse battery staple 9"), DEFAULT_PIM, false, true, false).is_ok(), "no warning: nothing to allow");
        if !tty {
            // review E: --yes alone never accepts a weak password; without a terminal it is refused
            let e = check_new(&yes, &buf("short"), DEFAULT_PIM, false, false, false).unwrap_err();
            assert_eq!(e, t("cli.weak_needs_flag"));
            assert!(check_new(&no, &buf("password1234"), DEFAULT_PIM, false, false, false).is_err());
            assert!(check_new(&yes, &buf(""), DEFAULT_PIM, true, false, false).is_err(), "key file only needs --allow-weak too");
        }
    }
}
