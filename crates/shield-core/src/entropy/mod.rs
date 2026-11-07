//! Randomness (pool v4, Shield 3.0).
//!
//! * The OS CSPRNG (getrandom / BCryptGenRandom via `rand::OsRng`) is the base of every output and
//!   can't be switched off. If it fails, nothing is generated and the operation stops.
//! * Extra sources (`shield_platform::Source`: timers, CPU jitter, memory / process / system
//!   statistics, RDRAND/RDSEED, /proc, sensors, and in the GUI window state, input timing and
//!   pointer positions) are *mixed in only*. They never produce a key alone and nothing waits for
//!   them; a failing source is ignored.
//! * Each sample is absorbed as SHA3-512("SHIELD-POOL-v4" | pool | source code | time | counter |
//!   data): the source code is the domain separator, the monotonic time and the counter make two
//!   equal samples distinct. Health tests (health.rs) leave out a source that repeats, is stuck or
//!   only counts; only Normal / Weak is shown.
//! * Output = HKDF-SHA3-512(salt "SHIELD-RNG-v4", ikm = 64 fresh OS bytes | pool | draw counter),
//!   expanded into the caller's buffer; then the pool is remixed with a further expansion, so a
//!   later pool compromise does not reveal earlier outputs. All intermediate buffers are zeroized.
//! * The pool is never written to disk, logs or the network; there is no Debug output of it.
//!
//! VeraCrypt's Random.c was read for ideas (which OS values are worth polling) only; no code was
//! taken (TrueCrypt License 3.0 / Apache 2.0 terms; see docs/06 section 4, license review).

mod health;

use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_512};
use shield_platform::{platform, EntropyCtx, Os, Poll, Sample, Source};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

/// Score shown as "collected" (guidance only: not an entropy guarantee, nothing is gated on it).
pub const DISPLAY_BITS: u64 = 1024;
const FAST_EVERY: Duration = Duration::from_millis(100);
const SLOW_EVERY: Duration = Duration::from_secs(600);

struct Pool {
    h: [u8; 64],
    absorbed: u64,
    draws: u64,
    last: Option<(f32, f32)>,
    last_d: (f32, f32),
    last_input: u64,
    health: Vec<(Source, health::Health)>,
    fast_at: Option<Instant>,
    slow_at: Option<Instant>,
}

static POOL: Mutex<Pool> = Mutex::new(Pool {
    h: [0u8; 64],
    absorbed: 0,
    draws: 0,
    last: None,
    last_d: (0.0, 0.0),
    last_input: 0,
    health: Vec::new(),
    fast_at: None,
    slow_at: None,
});
static T0: OnceLock<Instant> = OnceLock::new();
/// Disabled sources, one bit per `Source::ALL` index. OsCsprng's bit is ignored.
static DISABLED: AtomicU64 = AtomicU64::new(0);
/// GUI process: window state, input timing and pointer sources may be read. Off by default, so a
/// console program never collects them unless the GUI turned it on.
static GUI: AtomicBool = AtomicBool::new(false);
static SLOW_RUNNING: AtomicBool = AtomicBool::new(false);
/// Pointer events mixed in (GUI).
pub static SAMPLES: AtomicU64 = AtomicU64::new(0);
/// Conservative pointer score (see `mix_mouse`).
pub static CREDIT: AtomicU64 = AtomicU64::new(0);

fn bit(s: Source) -> u64 {
    1 << Source::ALL.iter().position(|x| *x == s).unwrap_or(0)
}

fn now_ns() -> u64 {
    T0.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

fn lock() -> std::sync::MutexGuard<'static, Pool> {
    POOL.lock().unwrap_or_else(|x| x.into_inner())
}

/// GUI programs call this once; console commands never do (§1: no window / input sources there).
pub fn set_gui(on: bool) {
    GUI.store(on, Ordering::Relaxed);
}

pub fn is_enabled(s: Source) -> bool {
    s == Source::OsCsprng || DISABLED.load(Ordering::Relaxed) & bit(s) == 0
}

/// Settings / `shield entropy`: switches a source. The OS CSPRNG can't be switched off.
pub fn set_enabled(s: Source, on: bool) {
    if s == Source::OsCsprng {
        return;
    }
    if on {
        DISABLED.fetch_and(!bit(s), Ordering::Relaxed);
    } else {
        DISABLED.fetch_or(bit(s), Ordering::Relaxed);
        if s == Source::Mouse {
            CREDIT.store(0, Ordering::Relaxed);
        }
    }
}

/// Applies a stored list of disabled source codes (unknown codes are ignored).
pub fn apply_disabled(codes: &[String]) {
    DISABLED.store(0, Ordering::Relaxed);
    for c in codes {
        if let Some(s) = Source::from_code(c) {
            set_enabled(s, false);
        }
    }
}

pub fn set_mouse_enabled(on: bool) {
    set_enabled(Source::Mouse, on);
}
pub fn mouse_enabled() -> bool {
    is_enabled(Source::Mouse) && GUI.load(Ordering::Relaxed)
}

fn wanted(s: Source) -> bool {
    is_enabled(s) && (GUI.load(Ordering::Relaxed) || !s.gui_only())
}

/// SHA3-512 chaining with the source code as domain separator.
fn absorb(p: &mut Pool, src: Source, data: &[u8]) {
    p.absorbed = p.absorbed.wrapping_add(1);
    let mut s = Sha3_512::new();
    s.update(b"SHIELD-POOL-v4");
    s.update(p.h);
    let code = src.code().as_bytes();
    s.update([code.len() as u8]);
    s.update(code);
    s.update(now_ns().to_le_bytes());
    s.update(p.absorbed.to_le_bytes());
    s.update((data.len() as u64).to_le_bytes());
    s.update(data);
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&s.finalize());
    p.h.copy_from_slice(&*out);
}

fn sample_bytes(s: &Sample<'_>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(match s {
        Sample::Bytes(b) => b.to_vec(),
        Sample::Nums(n) => n.iter().flat_map(|x| x.to_le_bytes()).collect(),
    })
}

/// Health check, then absorb (or drop) one sample.
fn take(p: &mut Pool, src: Source, s: Sample<'_>) {
    if !wanted(src) {
        return;
    }
    let ok = match p.health.iter_mut().find(|(x, _)| *x == src) {
        Some((_, h)) => h.check(&s),
        None => {
            let mut h = health::Health::default();
            let ok = h.check(&s);
            p.health.push((src, h));
            ok
        }
    };
    if ok {
        let b = sample_bytes(&s);
        absorb(p, src, &b);
    }
}

fn poll_into(p: &mut Pool, kind: Poll) {
    let enabled = |s: Source| wanted(s);
    let ctx = EntropyCtx { gui: GUI.load(Ordering::Relaxed), enabled: &enabled };
    platform().entropy_extra(kind, &ctx, &mut |src, s| take(p, src, s));
}

/// Expensive statistics (process lists, /proc, perf data, sensors). Runs at start-up from a
/// background thread (`start_background`) and again every 10 minutes when randomness is drawn.
pub fn slow_poll() {
    let mut p = lock();
    poll_into(&mut p, Poll::Slow);
    p.slow_at = Some(Instant::now());
}

/// Starts one background slow poll (non-blocking; a failure is simply ignored).
pub fn start_background() {
    if SLOW_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = std::thread::Builder::new().name("entropy-poll".into()).spawn(|| {
        slow_poll();
        SLOW_RUNNING.store(false, Ordering::Release);
    });
}

/// Hashes one pointer position (+ timestamps) into the pool (GUI, own window only). The credit
/// is a conservative score: only a noticeable change of direction or speed counts, at most 1.
pub fn mix_mouse(x: f32, y: f32, t: f64) {
    if !mouse_enabled() {
        return;
    }
    let mut p = lock();
    let credit = match p.last {
        Some((lx, ly)) if lx == x && ly == y => return,
        Some((lx, ly)) => {
            let d = (x - lx, y - ly);
            let dd = (d.0 - p.last_d.0).abs() + (d.1 - p.last_d.1).abs();
            p.last_d = d;
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
    b[16..24].copy_from_slice(&now_ns().to_le_bytes());
    b[24..].copy_from_slice(&n.to_le_bytes());
    absorb(&mut p, Source::Mouse, &b);
    b.zeroize();
    CREDIT.fetch_add(credit, Ordering::Relaxed);
}

/// Key / pointer event timing inside Shield's window: only the time since the previous event is
/// used (never which key). GUI only.
pub fn mix_input_timing() {
    if !wanted(Source::InputTiming) {
        return;
    }
    let mut p = lock();
    let t = now_ns();
    let d = t.wrapping_sub(p.last_input);
    p.last_input = t;
    let c = shield_platform::cpu::cycle_counter().unwrap_or(0);
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&d.to_le_bytes());
    b[8..].copy_from_slice(&c.to_le_bytes());
    absorb(&mut p, Source::InputTiming, &b);
    b.zeroize();
}

pub fn credited_bits() -> u64 {
    if mouse_enabled() {
        CREDIT.load(Ordering::Relaxed)
    } else {
        0
    }
}

/// Wipes the pool (on exit and after the idle timeout). Health state restarts too.
pub fn clear_pool() {
    let mut p = lock();
    p.h.zeroize();
    p.last = None;
    p.last_d = (0.0, 0.0);
    p.health.clear();
    p.fast_at = None;
    p.slow_at = None;
    CREDIT.store(0, Ordering::Relaxed);
    SAMPLES.store(0, Ordering::Relaxed);
}

/// What the UI and `shield entropy` may show about a source (never values).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceStatus {
    /// Not available on this OS (or in console programs for GUI-only sources).
    Unavailable,
    Disabled,
    /// Enabled, no sample yet.
    Waiting,
    Normal,
    Weak,
}

pub fn status() -> Vec<(Source, SourceStatus)> {
    let os = platform().os();
    let gui = GUI.load(Ordering::Relaxed);
    let p = lock();
    Source::ALL
        .into_iter()
        .map(|s| {
            let st = if !s.exists_on(os) || (s.gui_only() && !gui) || (s == Source::HwRng && !hw_rng_present()) {
                SourceStatus::Unavailable
            } else if s == Source::OsCsprng {
                SourceStatus::Normal
            } else if !is_enabled(s) {
                SourceStatus::Disabled
            } else if s == Source::Mouse || s == Source::InputTiming {
                if SAMPLES.load(Ordering::Relaxed) > 0 || p.last_input != 0 { SourceStatus::Normal } else { SourceStatus::Waiting }
            } else {
                match p.health.iter().find(|(x, _)| *x == s) {
                    None => SourceStatus::Waiting,
                    Some((_, h)) if h.weak => SourceStatus::Weak,
                    Some(_) => SourceStatus::Normal,
                }
            };
            (s, st)
        })
        .collect()
}

fn hw_rng_present() -> bool {
    !shield_platform::cpu::hw_random(1).is_empty()
}

/// Fresh OS randomness; an error instead of a panic when the OS RNG fails.
pub fn os_random(buf: &mut [u8]) -> Result<(), String> {
    OsRng.try_fill_bytes(buf).map_err(|_| crate::i18n::t("err.rng").to_string())
}

/// Key-grade randomness (see module docs).
pub fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    let mut ikm = Zeroizing::new([0u8; 64 + 64 + 8]);
    os_random(&mut ikm[..64])?; // the base: stop if it fails
    let mut p = lock();
    let now = Instant::now();
    if p.fast_at.is_none_or(|t| now.duration_since(t) >= FAST_EVERY) {
        p.fast_at = Some(now);
        poll_into(&mut p, Poll::Fast);
    }
    if p.slow_at.is_none_or(|t| now.duration_since(t) >= SLOW_EVERY) {
        p.slow_at = Some(now); // also keeps concurrent draws from starting several polls
        start_background();
    }
    p.draws = p.draws.wrapping_add(1);
    ikm[64..128].copy_from_slice(&p.h);
    ikm[128..].copy_from_slice(&p.draws.to_le_bytes());
    let hk = Hkdf::<Sha3_512>::new(Some(b"SHIELD-RNG-v4"), &ikm[..]);
    // HKDF can expand 255 * 64 bytes per info string: longer buffers use numbered blocks
    for (i, block) in buf.chunks_mut(8192).enumerate() {
        let mut info = *b"SHIELD-RNG-v4 out ........";
        info[18..].copy_from_slice(&(i as u64).to_le_bytes());
        hk.expand(&info, block).map_err(|_| crate::i18n::t("err.rng").to_string())?;
    }
    let mut next = Zeroizing::new([0u8; 64]);
    hk.expand(b"SHIELD-RNG-v4 remix", &mut next[..]).map_err(|_| crate::i18n::t("err.rng").to_string())?;
    absorb(&mut p, Source::OsCsprng, &next[..]); // the pool moves on after every draw
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

/// True on the OSes whose sources include window state (for the settings page).
pub fn has_window_state() -> bool {
    platform().os() == Os::Windows
}

#[cfg(test)]
mod tests;
