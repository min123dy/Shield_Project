//! Simple per-source health tests in the spirit of NIST SP 800-90B §4.4 (not a certified
//! implementation, and not an entropy estimate):
//!
//! * repetition: the same sample digest several times in a row;
//! * stuck: every number of a sample equal (a counter or sensor that does not move);
//! * monotonic only: a sample whose numbers all step by the same amount (a plain counter).
//!
//! A source that fails is marked Weak and its samples are left out of the pool until it delivered
//! enough good samples again. Only Normal / Weak is ever shown, never values.

use shield_platform::Sample;

/// Consecutive identical samples that make a source Weak (90B uses a cutoff C from the claimed
/// min-entropy; this conservative fixed cutoff suits the small, slow sample streams here).
pub const REPEAT_CUTOFF: u32 = 3;
/// Good samples in a row a Weak source needs to become Normal again.
pub const RECOVER_AFTER: u32 = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Ok,
    Repeated,
    Stuck,
    Monotonic,
}

#[derive(Clone, Debug, Default)]
pub struct Health {
    last: Option<u64>,
    repeats: u32,
    good_run: u32,
    pub weak: bool,
    pub samples: u64,
    pub rejected: u64,
}

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, x| (h ^ *x as u64).wrapping_mul(0x0100_0000_01b3))
}

fn digest(s: &Sample<'_>) -> u64 {
    match s {
        Sample::Bytes(b) => fnv(b),
        Sample::Nums(n) => n.iter().fold(0x9E37_79B9_7F4A_7C15u64, |h, x| (h ^ x).wrapping_mul(0x0100_0000_01b3).rotate_left(29)),
    }
}

pub fn shape(s: &Sample<'_>) -> Verdict {
    let Sample::Nums(n) = s else { return Verdict::Ok };
    if n.len() >= 2 && n.iter().all(|x| *x == n[0]) {
        return Verdict::Stuck;
    }
    if n.len() >= 4 {
        let d = n[1].wrapping_sub(n[0]);
        if n.windows(2).all(|w| w[1].wrapping_sub(w[0]) == d) {
            return Verdict::Monotonic;
        }
    }
    Verdict::Ok
}

impl Health {
    /// Judges one sample; true when it may go into the pool.
    pub fn check(&mut self, s: &Sample<'_>) -> bool {
        self.samples += 1;
        let d = digest(s);
        let v = if self.last == Some(d) {
            self.repeats += 1;
            if self.repeats + 1 >= REPEAT_CUTOFF {
                Verdict::Repeated
            } else {
                Verdict::Ok
            }
        } else {
            self.repeats = 0;
            shape(s)
        };
        self.last = Some(d);
        if v == Verdict::Ok {
            self.good_run += 1;
            if self.weak && self.good_run >= RECOVER_AFTER {
                self.weak = false;
            }
        } else {
            self.good_run = 0;
            self.weak = true;
            self.rejected += 1;
        }
        !self.weak
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repetition_marks_weak_and_recovery_needs_a_good_run() {
        let mut h = Health::default();
        assert!(h.check(&Sample::Nums(&[1, 7, 3])));
        assert!(h.check(&Sample::Nums(&[1, 7, 3])), "one repeat is tolerated");
        assert!(!h.check(&Sample::Nums(&[1, 7, 3])), "third identical sample: weak");
        assert!(h.weak);
        for i in 0..RECOVER_AFTER as u64 - 1 {
            assert!(!h.check(&Sample::Nums(&[i, 99 - i, i * 7 + 1])));
        }
        assert!(h.check(&Sample::Nums(&[500, 3, 77])), "recovered");
    }
    #[test]
    fn stuck_and_counter_like_samples_are_rejected() {
        assert_eq!(shape(&Sample::Nums(&[5, 5, 5])), Verdict::Stuck);
        assert_eq!(shape(&Sample::Nums(&[10, 20, 30, 40])), Verdict::Monotonic);
        assert_eq!(shape(&Sample::Nums(&[10, 21, 30, 40])), Verdict::Ok);
        assert_eq!(shape(&Sample::Bytes(&[0, 0, 0])), Verdict::Ok, "bytes are only hashed");
        let mut h = Health::default();
        assert!(!h.check(&Sample::Nums(&[0, 0])));
    }
}
