//! Architecture-specific counters and the CPU random number instructions (x86 RDTSC / RDRAND /
//! RDSEED, arm64 CNTVCT_EL0). Shared by every OS module. The hardware generator is never trusted on
//! its own: its output is only mixed into the pool.

/// Cycle / virtual counter, or None on an architecture without a user-readable one.
#[inline]
pub fn cycle_counter() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDTSC is available on every x86_64 CPU and has no side effects.
        Some(unsafe { core::arch::x86_64::_rdtsc() })
    }
    #[cfg(target_arch = "aarch64")]
    {
        let v: u64;
        // SAFETY: CNTVCT_EL0 is readable from EL0 on Linux and Windows on Arm.
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
        Some(v)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

/// Up to `n` values from RDSEED (preferred) or RDRAND. Empty when the CPU has neither.
pub fn hw_random(n: usize) -> Vec<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut out = Vec::with_capacity(n);
        let seed = std::arch::is_x86_feature_detected!("rdseed");
        let rand = std::arch::is_x86_feature_detected!("rdrand");
        for _ in 0..n {
            let mut v = 0u64;
            // SAFETY: the instructions are used only after CPUID reported them.
            let ok = unsafe {
                (seed && rdseed(&mut v)) || (rand && rdrand(&mut v))
            };
            if ok {
                out.push(v);
            }
        }
        out
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = n;
        Vec::new()
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdseed")]
unsafe fn rdseed(v: &mut u64) -> bool {
    for _ in 0..10 {
        if core::arch::x86_64::_rdseed64_step(v) == 1 {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand(v: &mut u64) -> bool {
    for _ in 0..10 {
        if core::arch::x86_64::_rdrand64_step(v) == 1 {
            return true;
        }
    }
    false
}

/// Timer jitter: `n` differences between consecutive reads of `clock` while a small memory walk
/// and a thread yield disturb the timing (jitterentropy idea: cache misses and scheduling). Only
/// the differences are returned; the caller hashes them.
pub fn jitter(n: usize, clock: &dyn Fn() -> u64) -> Vec<u64> {
    let mut mem = vec![0u8; 64 * 1024];
    let mut out = Vec::with_capacity(n);
    let mut prev = clock();
    let mut idx = 0usize;
    for i in 0..n {
        // walk with a stride that defeats the prefetcher a little
        for _ in 0..64 {
            idx = (idx + 4099) % mem.len();
            mem[idx] = mem[idx].wrapping_add(i as u8 ^ 0x5a);
        }
        if i % 16 == 0 {
            std::thread::yield_now();
        }
        let now = clock();
        out.push(now.wrapping_sub(prev));
        prev = now;
    }
    std::hint::black_box(&mem);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn jitter_returns_differences() {
        let t0 = std::time::Instant::now();
        let d = super::jitter(64, &|| t0.elapsed().as_nanos() as u64);
        assert_eq!(d.len(), 64);
    }
    #[test]
    fn hw_random_is_bounded() {
        assert!(super::hw_random(4).len() <= 4);
    }
}
