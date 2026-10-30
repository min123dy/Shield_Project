//! Randomness. The OS CSPRNG is always the primary source; mouse movement is hashed into a pool
//! on top of it, so the output is never weaker than OsRng even if the mouse input were predictable.
//!
//! Mouse credit is deliberately conservative: a sample only counts when the movement direction or
//! speed changes noticeably (second difference of the position >= 1 px), at most 1 bit per sample,
//! and nothing for timing. Key files are generated only after `TARGET_BITS` have been credited,
//! i.e. at least 1024 irregular samples (Shield 1.0 accepted any 256 raw samples).

use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha512};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::Instant,
};
use zeroize::Zeroizing;

/// Credited mouse entropy required before a key file can be generated.
pub const TARGET_BITS: u64 = 1024;

struct Pool {
    h: [u8; 64],
    last: Option<(f32, f32)>,
    last_d: (f32, f32),
}

static POOL: Mutex<Pool> = Mutex::new(Pool { h: [0u8; 64], last: None, last_d: (0.0, 0.0) });
static T0: OnceLock<Instant> = OnceLock::new();
/// Raw mouse events mixed into the pool.
pub static SAMPLES: AtomicU64 = AtomicU64::new(0);
/// Conservatively credited bits (see module docs).
pub static CREDIT: AtomicU64 = AtomicU64::new(0);

fn mix_into(h: &mut [u8; 64], data: &[u8]) {
    let mut s = Sha512::new();
    s.update(&h[..]);
    s.update(data);
    h.copy_from_slice(s.finalize().as_slice());
}

/// Hash one pointer position (+ high resolution timestamp) into the pool.
pub fn mix_mouse(x: f32, y: f32, t: f64) {
    let ns = T0.get_or_init(Instant::now).elapsed().as_nanos() as u64;
    let mut p = POOL.lock().unwrap_or_else(|x| x.into_inner());
    let credit = match p.last {
        Some((lx, ly)) if lx == x && ly == y => return, // no movement, nothing new
        Some((lx, ly)) => {
            let d = (x - lx, y - ly);
            let dd = (d.0 - p.last_d.0).abs() + (d.1 - p.last_d.1).abs();
            p.last_d = d;
            // straight, constant-speed movement is predictable and earns nothing
            u64::from(dd >= 1.0)
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
    if credit > 0 {
        CREDIT.fetch_add(credit, Ordering::Relaxed);
    }
}

pub fn credited_bits() -> u64 {
    CREDIT.load(Ordering::Relaxed)
}
pub fn entropy_ready() -> bool {
    credited_bits() >= TARGET_BITS
}

/// ChaCha20 seeded with H(fresh OS entropy || mouse pool); never weaker than OsRng.
pub fn fill_random(buf: &mut [u8]) {
    let mut os = Zeroizing::new([0u8; 64]);
    OsRng.fill_bytes(&mut *os);
    let mut p = POOL.lock().unwrap_or_else(|x| x.into_inner());
    let mut h = Sha512::new();
    h.update(b"SHIELD-RNG-v2");
    h.update(&*os);
    h.update(p.h);
    let mut d = Zeroizing::new([0u8; 64]);
    d.copy_from_slice(h.finalize().as_slice());
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&d[..32]);
    mix_into(&mut p.h, &d[32..]); // forward secrecy: the pool moves on after every draw
    drop(p);
    ChaCha20Rng::from_seed(*seed).fill_bytes(buf);
}

pub fn rand_hex() -> String {
    let mut r = [0u8; 8];
    fill_random(&mut r);
    r.iter().map(|b| format!("{b:02x}")).collect()
}
