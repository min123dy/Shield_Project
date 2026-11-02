//! Randomness. The OS CSPRNG is always the primary source; mouse movement (Settings > Security,
//! on by default) is hashed into a pool on top of it, so the output is never weaker than the OS
//! RNG even if the mouse input were predictable or absent. The pool is an auxiliary input only:
//! nothing waits for it, and no key, salt or key file depends on how much was collected.
//!
//! Key-grade values (DEK, salts, nonces, SecTemp keys, key files) come from `fill_random`:
//! SHAKE256(label | 64 fresh OS bytes | pool | counter) is squeezed straight into the caller's
//! buffer; the sponge state is zeroized on drop (sha3 "zeroize" feature). OS RNG failures are
//! returned as errors (no panic, nothing is generated). Bulk overwrite data for shredding uses a
//! separate ChaCha20 stream (`bulk_rng`) for speed; that data is not secret.
//!
//! Mouse credit is a conservative *score*, not an entropy estimate: a sample only counts when the
//! movement direction or speed changes noticeably, at most 1 point per sample, nothing for timing.

use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_512, Shake256,
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

/// Score shown in Settings as "collected" (display only; nothing is gated on it).
pub const DISPLAY_BITS: u64 = 1024;

static MOUSE_ON: AtomicBool = AtomicBool::new(true);

/// Settings > Security > mouse entropy. Turning it off also wipes what was collected.
pub fn set_mouse_enabled(on: bool) {
    MOUSE_ON.store(on, Ordering::Relaxed);
    if !on {
        clear_pool();
    }
}
pub fn mouse_enabled() -> bool {
    MOUSE_ON.load(Ordering::Relaxed)
}

struct Pool {
    h: [u8; 64],
    last: Option<(f32, f32)>,
    last_d: (f32, f32),
    draws: u64,
}

static POOL: Mutex<Pool> = Mutex::new(Pool { h: [0u8; 64], last: None, last_d: (0.0, 0.0), draws: 0 });
static T0: OnceLock<Instant> = OnceLock::new();
/// Raw mouse events mixed into the pool.
pub static SAMPLES: AtomicU64 = AtomicU64::new(0);
/// Conservative score (see module docs).
pub static CREDIT: AtomicU64 = AtomicU64::new(0);



fn mix_into(h: &mut [u8; 64], data: &[u8]) {
    let mut s = Sha3_512::new();
    Digest::update(&mut s, b"SHIELD-POOL-v2");
    Digest::update(&mut s, &h[..]);
    Digest::update(&mut s, data);
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&s.finalize());
    h.copy_from_slice(&*out);
}

/// Hash one pointer position (+ high resolution timestamp) into the pool.
pub fn mix_mouse(x: f32, y: f32, t: f64) {
    if !mouse_enabled() {
        return;
    }
    let ns = T0.get_or_init(Instant::now).elapsed().as_nanos() as u64;
    let mut p = POOL.lock().unwrap_or_else(|x| x.into_inner());
    let credit = match p.last {
        Some((lx, ly)) if lx == x && ly == y => return,
        Some((lx, ly)) => {
            let d = (x - lx, y - ly);
            let dd = (d.0 - p.last_d.0).abs() + (d.1 - p.last_d.1).abs();
            p.last_d = d;
            u64::from(dd >= 1.0) // straight, constant-speed movement earns nothing
        }
        None => 0,
    };
    p.last = Some((x, y));
    let n = SAMPLES.fetch_add(1, Ordering::Relaxed);
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&x.to_bits().to_le_bytes());
    b[4..8].copy_from_slice(&y.to_bits().to_le_bytes());
    b[8..16].copy_from_slice(&t.to_bits().to_le_bytes());
    b[16..24].copy_from_slice(&ns.to_le_bytes());
    b[24..].copy_from_slice(&n.to_le_bytes());
    mix_into(&mut p.h, &b);
    b.zeroize();
    if credit > 0 {
        CREDIT.fetch_add(credit, Ordering::Relaxed);
    }
}

pub fn credited_bits() -> u64 {
    CREDIT.load(Ordering::Relaxed)
}


/// Wipes the mouse pool (on exit and after the idle timeout). The score restarts from zero.
pub fn clear_pool() {
    let mut p = POOL.lock().unwrap_or_else(|x| x.into_inner());
    p.h.zeroize();
    p.last = None;
    p.last_d = (0.0, 0.0);
    CREDIT.store(0, Ordering::Relaxed);
    SAMPLES.store(0, Ordering::Relaxed);
}

/// Fresh OS randomness; an error instead of a panic when the OS RNG fails.
pub fn os_random(buf: &mut [u8]) -> Result<(), String> {
    OsRng.try_fill_bytes(buf).map_err(|_| crate::i18n::t("err.rng").to_string())
}

/// Key-grade randomness (see module docs).
pub fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    let mut os = Zeroizing::new([0u8; 64]);
    os_random(&mut *os)?;
    let mut p = POOL.lock().unwrap_or_else(|x| x.into_inner());
    p.draws = p.draws.wrapping_add(1);
    let mut x = Shake256::default();
    x.update(b"SHIELD-RNG-v3");
    x.update(&*os);
    x.update(&p.h);
    x.update(&p.draws.to_le_bytes());
    let mut rd = x.finalize_xof();
    rd.read(buf);
    let mut next = Zeroizing::new([0u8; 64]);
    rd.read(&mut *next);
    drop(rd);
    mix_into(&mut p.h, &*next); // the pool moves on after every draw
    Ok(())
}

/// Non-secret bulk stream for overwrite passes (fast). Seeded from `fill_random`.
pub fn bulk_rng() -> Result<ChaCha20Rng, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    fill_random(&mut *seed)?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

/// Uniform integer in 0..=max (rejection sampling, no modulo bias).
pub fn rand_upto(max: u64) -> Result<u64, String> {
    if max == u64::MAX {
        let mut b = [0u8; 8];
        fill_random(&mut b)?;
        return Ok(u64::from_le_bytes(b));
    }
    let n = max + 1;
    let zone = u64::MAX - (u64::MAX % n) - 1;
    loop {
        let mut b = [0u8; 8];
        fill_random(&mut b)?;
        let v = u64::from_le_bytes(b);
        if v <= zone {
            return Ok(v % n);
        }
    }
}

pub fn rand_hex() -> Result<String, String> {
    let mut r = [0u8; 12];
    fill_random(&mut r)?;
    Ok(r.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn random_values_differ_and_bounds_hold() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
        for _ in 0..200 {
            assert!(rand_upto(10).unwrap() <= 10);
        }
        assert_eq!(rand_upto(0).unwrap(), 0);
    }
    #[test]
    fn key_material_never_waits_for_the_mouse() {
        // with the mouse source off and nothing collected, key-grade randomness still works
        set_mouse_enabled(false);
        mix_mouse(1.0, 2.0, 3.0);
        assert_eq!(credited_bits(), 0);
        let mut k = [0u8; 64];
        fill_random(&mut k).unwrap();
        assert!(k.iter().any(|&b| b != 0));
        set_mouse_enabled(true);
    }
}
