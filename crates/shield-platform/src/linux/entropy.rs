//! Linux additional entropy sources (design 3.0 §1 i–o). No /dev/input, no global pointer
//! position (Wayland gives none and Shield does not ask X11 for it): pointer and key timing come
//! from Shield's own window only and are fed by the GUI through the core.
//! /proc lists contribute numbers only (pids), never command names or paths.

use crate::{cpu, EntropyCtx, Poll, Sample, Source};
use std::{
    fs,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
};

type Sink<'a> = &'a mut dyn FnMut(Source, Sample<'_>);

static AUX_SENT: AtomicBool = AtomicBool::new(false);

fn words<T>(v: &T) -> Vec<u64> {
    let n = core::mem::size_of::<T>();
    let b = unsafe { std::slice::from_raw_parts(v as *const T as *const u8, n) };
    b.chunks(8).map(|c| c.iter().enumerate().fold(0u64, |a, (i, x)| a | (*x as u64) << (8 * i))).collect()
}

fn clock(id: libc::clockid_t) -> u64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(id, &mut t) };
    (t.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(t.tv_nsec as u64)
}

fn mono_raw() -> u64 {
    clock(libc::CLOCK_MONOTONIC_RAW)
}

fn best_clock() -> &'static dyn Fn() -> u64 {
    if cpu::cycle_counter().is_some() {
        &|| cpu::cycle_counter().unwrap_or(0)
    } else {
        &mono_raw
    }
}

/// Reads at most 256 KiB of a /proc or /sys file.
fn read_small(p: &str, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    match fs::File::open(p) {
        Ok(f) => f.take(256 * 1024).read_to_end(buf).is_ok() && !buf.is_empty(),
        Err(_) => false,
    }
}

fn files(src: Source, list: &[&str], sink: Sink<'_>) {
    let mut all = Vec::new();
    let mut b = Vec::new();
    for p in list {
        if read_small(p, &mut b) {
            all.extend_from_slice(&(b.len() as u64).to_le_bytes());
            all.extend_from_slice(&b);
        }
    }
    if !all.is_empty() {
        sink(src, Sample::Bytes(&all));
    }
    all.fill(0);
    b.fill(0);
}

pub fn collect(poll: Poll, ctx: &EntropyCtx<'_>, sink: Sink<'_>) {
    fast(ctx, sink);
    if poll == Poll::Slow {
        slow(ctx, sink);
    }
}

fn fast(ctx: &EntropyCtx<'_>, sink: Sink<'_>) {
    if ctx.wants(Source::OsAux) && !AUX_SENT.swap(true, Ordering::Relaxed) {
        // AT_RANDOM: 16 bytes the kernel put on the initial stack (constant per process: sent once)
        let p = unsafe { libc::getauxval(libc::AT_RANDOM) } as *const u8;
        if !p.is_null() {
            let b = unsafe { std::slice::from_raw_parts(p, 16) };
            sink(Source::OsAux, Sample::Bytes(b));
        }
    }
    if ctx.wants(Source::Timers) {
        let mut v = cpu::jitter(48, best_clock());
        for id in [libc::CLOCK_REALTIME, libc::CLOCK_MONOTONIC, libc::CLOCK_MONOTONIC_RAW, libc::CLOCK_BOOTTIME, libc::CLOCK_PROCESS_CPUTIME_ID, libc::CLOCK_THREAD_CPUTIME_ID] {
            v.push(clock(id));
        }
        v.push(cpu::cycle_counter().unwrap_or(0));
        sink(Source::Timers, Sample::Nums(&v));
    }
    if ctx.wants(Source::Process) {
        let mut v = Vec::new();
        unsafe {
            let mut t: libc::tms = core::mem::zeroed();
            v.push(libc::times(&mut t) as u64);
            v.extend(words(&t));
            for who in [libc::RUSAGE_SELF, libc::RUSAGE_THREAD] {
                let mut r: libc::rusage = core::mem::zeroed();
                if libc::getrusage(who, &mut r) == 0 {
                    v.extend(words(&r));
                }
            }
        }
        sink(Source::Process, Sample::Nums(&v));
    }
    if ctx.wants(Source::Memory) {
        let mut s: libc::sysinfo = unsafe { core::mem::zeroed() };
        if unsafe { libc::sysinfo(&mut s) } == 0 {
            sink(Source::Memory, Sample::Nums(&words(&s)));
        }
    }
    if ctx.wants(Source::Ids) {
        let local = 0u8;
        let heap = Box::new(0u64);
        let v = [
            std::process::id() as u64,
            unsafe { libc::getppid() } as u64,
            unsafe { libc::syscall(libc::SYS_gettid) } as u64,
            &local as *const u8 as u64,
            &*heap as *const u64 as u64,
            collect as *const () as usize as u64,
            unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as u64,
        ];
        sink(Source::Ids, Sample::Nums(&v));
    }
    if ctx.wants(Source::Disk) {
        let mut v = Vec::new();
        for d in ["/", "/tmp"] {
            let c = std::ffi::CString::new(d).unwrap_or_default();
            let mut s: libc::statvfs = unsafe { core::mem::zeroed() };
            if unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0 {
                v.extend([s.f_bfree as u64, s.f_bavail as u64, s.f_ffree as u64]);
            }
        }
        sink(Source::Disk, Sample::Nums(&v));
    }
    if ctx.wants(Source::HwRng) {
        let v = cpu::hw_random(4);
        if !v.is_empty() {
            sink(Source::HwRng, Sample::Nums(&v));
        }
    }
}

fn slow(ctx: &EntropyCtx<'_>, sink: Sink<'_>) {
    if ctx.wants(Source::CpuJitter) {
        sink(Source::CpuJitter, Sample::Nums(&cpu::jitter(1024, best_clock())));
    }
    if ctx.wants(Source::SystemTimes) {
        files(Source::SystemTimes, &["/proc/stat", "/proc/schedstat", "/proc/loadavg", "/proc/uptime"], sink);
    }
    if ctx.wants(Source::Memory) {
        files(Source::Memory, &["/proc/meminfo", "/proc/vmstat"], sink);
    }
    if ctx.wants(Source::Disk) {
        files(Source::Disk, &["/proc/diskstats"], sink);
    }
    if ctx.wants(Source::Network) {
        files(Source::Network, &["/proc/net/dev", "/proc/net/snmp"], sink);
    }
    if ctx.wants(Source::ProcFs) {
        files(
            Source::ProcFs,
            &["/proc/interrupts", "/proc/softirqs", "/proc/self/stat", "/proc/self/statm", "/proc/self/io", "/proc/pressure/cpu", "/proc/pressure/io", "/proc/pressure/memory"],
            sink,
        );
    }
    if ctx.wants(Source::Processes) {
        let v: Vec<u64> = fs::read_dir("/proc").map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok()).take(65_536).collect()).unwrap_or_default();
        if !v.is_empty() {
            sink(Source::Processes, Sample::Nums(&v));
        }
    }
    if ctx.wants(Source::Sensors) {
        sensors(sink);
    }
}

/// Thermal zones and hwmon inputs (temperatures, fans, voltages, currents, power).
fn sensors(sink: Sink<'_>) {
    let mut v = Vec::new();
    let mut b = Vec::new();
    let mut read_num = |p: &std::path::Path, v: &mut Vec<u64>| {
        if let Some(s) = p.to_str() {
            if read_small(s, &mut b) {
                if let Ok(n) = String::from_utf8_lossy(&b).trim().parse::<i64>() {
                    v.push(n as u64);
                }
            }
        }
    };
    if let Ok(rd) = fs::read_dir("/sys/class/thermal") {
        for e in rd.flatten().take(64) {
            read_num(&e.path().join("temp"), &mut v);
        }
    }
    if let Ok(rd) = fs::read_dir("/sys/class/hwmon") {
        for e in rd.flatten().take(32) {
            if let Ok(inner) = fs::read_dir(e.path()) {
                for f in inner.flatten().take(128) {
                    let n = f.file_name();
                    let n = n.to_string_lossy();
                    if n.ends_with("_input") && ["temp", "fan", "in", "curr", "power"].iter().any(|k| n.starts_with(k)) {
                        read_num(&f.path(), &mut v);
                    }
                }
            }
        }
    }
    if !v.is_empty() {
        sink(Source::Sensors, Sample::Nums(&v));
    }
}
