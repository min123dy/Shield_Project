//! Jobs of the encryption window (worker threads; the UI only polls).

use crate::crypto::Cred;
use crate::enc_app::{bundle_output, default_output, EncApp};
use crate::engine::*;
use crate::i18n::{t, tf};
use crate::keyfile::keyfile_opt;
use crate::progress::*;
use crate::wipe;
use std::path::PathBuf;

impl EncApp {
    fn enc_opts(&self) -> Opts {
        Opts {
            shred_src: self.sh.set.shred_default,
            passes: self.passes,
            wipe_free_after: self.sh.set.ui.wipe_free_after,
            strength: self.sh.set.strength,
            keyfiles: self.keyfiles.clone(),
            streams: if self.sh.set.ui.include_streams { StreamPolicy::Include } else { StreamPolicy::Ask },
        }
    }

    /// Where the container(s) go: one path per job (bundled or a single item) or one per item.
    fn outputs(&self) -> Option<Vec<(Vec<PathBuf>, PathBuf)>> {
        let items = &self.items;
        let together = items.len() == 1 || self.sh.set.ui.bundle;
        let auto = if items.len() == 1 { default_output(&items[0], self.sh.set.naming) } else { bundle_output(items) };
        if together {
            let dst = if self.sh.set.ui.choose_dest || auto.is_none() {
                let name = auto.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "Shield.shd".into());
                let mut d = rfd::FileDialog::new().set_title(t("dlg.save_shd")).set_file_name(name);
                if let Some(p) = items[0].parent() {
                    d = d.set_directory(p);
                }
                d.save_file()?
            } else {
                auto?
            };
            return Some(vec![(items.clone(), dst)]);
        }
        let dir = if self.sh.set.ui.choose_dest { Some(rfd::FileDialog::new().set_title(t("dlg.out_folder")).pick_folder()?) } else { None };
        items
            .iter()
            .map(|p| {
                let out = match &dir {
                    Some(d) => default_output(&d.join(p.file_name()?), self.sh.set.naming),
                    None => default_output(p, self.sh.set.naming),
                };
                Some((vec![p.clone()], out?))
            })
            .collect()
    }

    pub fn start_encrypt(&mut self) {
        if self.items.is_empty() {
            return;
        }
        let Some(jobs) = self.outputs() else { return };
        let pw = match self.pw.take() {
            Ok(p) => p,
            Err(x) => return self.sh.msg(false, x),
        };
        self.pw2.clear();
        let opts = self.enc_opts();
        let kfs = self.keyfiles.clone();
        let pim = self.pim_of(self.custom_pim, self.pim);
        let mut stages = vec![ST_SCAN];
        if opts.shred_src {
            stages.push(ST_ADS);
        }
        stages.extend([ST_COMPRESS, ST_ENCRYPT, ST_VERIFY]);
        if opts.shred_src {
            stages.push(ST_SHRED);
            if opts.wipe_free_after {
                stages.push(ST_WIPE_FREE);
            }
            stages.push(ST_TRIM);
        }
        self.kf_only_ack = false;
        self.spawn(t("job.encrypt"), stages, move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            if jobs.len() == 1 {
                return do_encrypt_many(&jobs[0].0, &jobs[0].1, &c, &opts);
            }
            // one container per item: go on after a failure, report every item
            let (mut ok, mut fails) = (0usize, Vec::new());
            for (srcs, dst) in &jobs {
                match do_encrypt_many(srcs, dst, &c, &opts) {
                    Ok(_) => ok += 1,
                    Err(e) => fails.push(format!("{}: {e}", srcs[0].display())),
                }
            }
            let head = tf("multi.done", &[&ok, &jobs.len()]);
            if fails.is_empty() { Ok(head) } else { Err(format!("{head}\n{}", fails.join("\n"))) }
        });
    }

    pub fn start_decrypt(&mut self) {
        if !self.decrypt_problems().is_empty() {
            return;
        }
        let Some(src) = self.selected.clone() else { return };
        let outdir = if self.sh.set.ui.choose_dest { rfd::FileDialog::new().set_title(t("dlg.out_folder")).pick_folder() } else { Some(parent_dir(&src)) };
        let Some(outdir) = outdir else { return };
        let pw = match self.pw.take() {
            Ok(p) => p,
            Err(x) => return self.sh.msg(false, x),
        };
        let kfs = self.keyfiles.clone();
        let pim = self.pim_of(self.custom_pim, self.pim);
        let d = DecOpts { strict_motw: self.sh.set.strict_motw };
        self.spawn(t("job.decrypt"), vec![ST_DECRYPT, ST_EXTRACT], move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            do_decrypt(&src, &outdir, &c, d)
        });
    }

    pub fn start_rekey(&mut self) {
        let Some(src) = self.selected.clone() else { return };
        let (old_pw, new_pw) = match (self.pw.take(), self.new_pw.take()) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(x), _) | (_, Err(x)) => return self.sh.msg(false, x),
        };
        self.new_pw2.clear();
        let (okf, nkf) = (self.keyfiles.clone(), self.new_keyfiles.clone());
        let (opim, npim) = (self.pim_of(self.custom_pim, self.pim), self.pim_of(self.new_custom_pim, self.new_pim));
        let (full, passes) = (self.sh.set.ui.full_rekey, self.passes);
        self.new_kf_only_ack = false;
        let (title, stages) = if full {
            (t("job.full_rekey"), vec![ST_DECRYPT, ST_ENCRYPT, ST_VERIFY, ST_REPLACE, ST_SHRED, ST_TRIM])
        } else {
            (t("job.change_pw"), vec![ST_REWRAP])
        };
        self.spawn(title, stages, move || {
            crate::keyfile::check_overlap(&nkf, &[&src])?;
            let old = Cred { pw: old_pw, kf: keyfile_opt(&okf)?, pim: opim };
            let new = Cred { pw: new_pw, kf: keyfile_opt(&nkf)?, pim: npim };
            if full { do_full_rekey(&src, &old, &new, passes) } else { do_change_password(&src, &old, &new) }
        });
    }

    pub fn start_trim(&mut self) {
        let Some(d) = self.disk_drive.clone() else {
            return self.sh.msg(false, t("p.pick_drive"));
        };
        self.spawn("TRIM", vec![ST_TRIM], move || {
            set_stage(ST_TRIM);
            match wipe::trim(&d) {
                (true, m) => Ok(m),
                (false, m) => Err(m),
            }
        });
    }

    pub fn start_wipe_free(&mut self) {
        let Some(d) = self.disk_drive.clone() else {
            return self.sh.msg(false, t("p.pick_drive"));
        };
        let trim = self.sh.set.ui.disk_trim_after_wipe;
        let mut stages = vec![ST_WIPE_FREE];
        if trim {
            stages.push(ST_TRIM);
        }
        self.spawn(t("job.wipe_free"), stages, move || {
            set_stage(ST_WIPE_FREE);
            let mut m = wipe::wipe_free_space(&d)?;
            if trim {
                set_stage(ST_TRIM);
                m += &format!(" \u{00B7} {}", wipe::trim(&d).1);
            }
            Ok(m)
        });
    }
}
