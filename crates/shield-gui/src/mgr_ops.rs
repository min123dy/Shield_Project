//! Operations on the open container (check, extract, add, remove): they wait for fresh
//! credentials, and adding / removing always confirm with the pass count (3.0 §2).

use crate::container::{self, AddOpts, BodyCheck};
use crate::crypto::Cred;
use crate::engine::DecOpts;
use crate::i18n::t;
use crate::keyfile::keyfile_opt;
use crate::mgr_app::{Confirm, MgrApp, Op, Out};
use crate::progress::*;
use std::path::{Path, PathBuf};

impl MgrApp {
    /// Runs the operation that was waiting for the credentials.
    pub fn run_op(&mut self) {
        let Some(op) = self.op.take() else { return };
        let Some(mut o) = self.open.take() else { return };
        let (pw, kfs, pim) = match self.take_cred() {
            Ok(c) => c,
            Err(x) => {
                self.open = Some(o);
                self.op = Some(op);
                return self.sh.msg(false, x);
            }
        };
        let strict = self.sh.set.strict_motw;
        let (title, stages) = match &op {
            Op::Check => (t("job.check"), vec![ST_CHECK]),
            Op::ExtractSelected { .. } => (t("job.extract_sel"), vec![ST_EXTRACT]),
            Op::ExtractAll { .. } => (t("job.extract_all"), vec![ST_DECRYPT, ST_EXTRACT]),
            Op::Add { .. } => (t("job.add"), vec![ST_SCAN, ST_DECRYPT, ST_REBUILD, ST_ENCRYPT, ST_VERIFY, ST_REPLACE]),
            Op::Remove { .. } => (t("job.remove"), vec![ST_DECRYPT, ST_REBUILD, ST_ENCRYPT, ST_VERIFY, ST_REPLACE]),
        };
        let ao = AddOpts { overwrite: false, shred_src: self.shred_added, strength: self.sh.set.strength, keyfiles: kfs.clone(), passes: self.passes };
        let prefix = self.inner.clone();
        self.shred_added = false;
        self.spawn(title, stages, move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            let res = match op {
                Op::Check => {
                    let r = container::verify_body(&o, c);
                    o.body = if r.is_ok() { BodyCheck::Ok } else { BodyCheck::Failed };
                    r
                }
                Op::ExtractSelected { sel, base, dir } => container::extract_selected(&o, c, &sel, &base, &dir, DecOpts { strict_motw: strict }),
                Op::ExtractAll { dir } => crate::engine::do_decrypt(&o.path, &dir, &c, DecOpts { strict_motw: strict }),
                Op::Add { paths, overwrite } => container::add_files(&mut o, c, &paths, &prefix, &AddOpts { overwrite, ..ao }),
                Op::Remove { sel } => container::remove_entries(&mut o, c, &sel, ao.strength, ao.passes),
            };
            Ok(Out { opened: Some(o), res })
        });
    }

    /// Asks before overwriting same-name entries or shredding the added originals.
    pub fn request_add(&mut self, paths: Vec<PathBuf>) {
        let Some(o) = &self.open else { return };
        if paths.is_empty() {
            return;
        }
        let clash = container::conflicts(o, &paths, &self.inner);
        let mut on: Vec<&Path> = vec![o.path.as_path()];
        if self.shred_added {
            on.extend(paths.iter().map(PathBuf::as_path));
        }
        let exposure = exposure_lines(&on);
        self.confirm = Some(Confirm::Add { paths, clash, exposure });
    }

    pub fn request_remove(&mut self) {
        if self.csel.is_empty() {
            return self.sh.msg(false, t("m.pick_entries"));
        }
        let sel = self.csel.clone();
        let exposure = self.open.as_ref().map(|o| exposure_lines(&[o.path.as_path()])).unwrap_or_default();
        self.confirm = Some(Confirm::Remove { sel, exposure });
    }
}

/// Snapshot / storage lines for the confirmation (nothing is deleted here).
fn exposure_lines(paths: &[&Path]) -> Vec<String> {
    let ex = crate::wipe::exposure(paths);
    let mut l = ex.snapshot_lines;
    if ex.not_guaranteed {
        l.push(t("dlg.shred_flash").into());
    }
    l
}
