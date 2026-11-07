//! Windows additional entropy sources (design 3.0 §1). Ideas only were taken from VeraCrypt's
//! FastPoll / SlowPoll (which values are worth reading); this is a new implementation.
//!
//! Rules: values are handed to the core sink right away and never stored or logged here; window /
//! focus / clipboard-owner state is read only for the GUI (`ctx.gui`), the clipboard *contents*
//! never; process lists contribute numbers (ids, counts, sizes) only, never names or paths.

use crate::{cpu, EntropyCtx, Poll, Sample, Source};
use windows_sys::Win32::Foundation::{FILETIME, POINT, RECT};

type Sink<'a> = &'a mut dyn FnMut(Source, Sample<'_>);

/// A plain-old-data struct as 32-bit words (the struct was zero-initialised before the call, so
/// padding is defined).
fn words<T>(v: &T) -> Vec<u64> {
    let n = core::mem::size_of::<T>();
    let b = unsafe { std::slice::from_raw_parts(v as *const T as *const u8, n) };
    b.chunks(4).map(|c| c.iter().enumerate().fold(0u64, |a, (i, x)| a | (*x as u64) << (8 * i))).collect()
}

fn ft(f: FILETIME) -> u64 {
    (f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64
}

fn qpc() -> u64 {
    let mut v = 0i64;
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut v) };
    v as u64
}

pub fn collect(poll: Poll, ctx: &EntropyCtx<'_>, sink: Sink<'_>) {
    match poll {
        Poll::Fast => fast(ctx, sink),
        Poll::Slow => {
            fast(ctx, sink);
            slow(ctx, sink);
        }
    }
}

fn fast(ctx: &EntropyCtx<'_>, sink: Sink<'_>) {
    use windows_sys::Win32::System::SystemInformation::*;
    use windows_sys::Win32::System::Threading::*;
    if ctx.wants(Source::Timers) {
        let clock: &dyn Fn() -> u64 = match cpu::cycle_counter() {
            Some(_) => &|| cpu::cycle_counter().unwrap_or(0),
            None => &qpc,
        };
        let mut v = cpu::jitter(48, clock);
        let (mut adj, mut inc, mut dis) = (0u32, 0u32, 0i32);
        let mut f = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        unsafe {
            GetSystemTimeAsFileTime(&mut f);
            GetSystemTimeAdjustment(&mut adj, &mut inc, &mut dis);
            v.extend([qpc(), GetTickCount64(), ft(f), adj as u64, inc as u64, dis as u64]);
        }
        sink(Source::Timers, Sample::Nums(&v));
    }
    if ctx.wants(Source::Memory) {
        let mut m: MEMORYSTATUSEX = unsafe { core::mem::zeroed() };
        m.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut m) } != 0 {
            sink(Source::Memory, Sample::Nums(&words(&m)));
        }
    }
    if ctx.wants(Source::Process) {
        use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut a, mut b, mut c, mut d) = (z, z, z, z);
        let mut v = Vec::new();
        unsafe {
            if GetProcessTimes(GetCurrentProcess(), &mut a, &mut b, &mut c, &mut d) != 0 {
                v.extend([ft(a), ft(c), ft(d)]);
            }
            if GetThreadTimes(GetCurrentThread(), &mut a, &mut b, &mut c, &mut d) != 0 {
                v.extend([ft(a), ft(c), ft(d)]);
            }
            let mut pm: PROCESS_MEMORY_COUNTERS = core::mem::zeroed();
            pm.cb = core::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pm, pm.cb) != 0 {
                v.extend(words(&pm));
            }
        }
        sink(Source::Process, Sample::Nums(&v));
    }
    if ctx.wants(Source::Ids) {
        let local = 0u8;
        let heap = unsafe { windows_sys::Win32::System::Memory::GetProcessHeap() } as u64;
        let v = [GetCurrentProcessId as *const () as usize as u64, unsafe { GetCurrentProcessId() } as u64, unsafe { GetCurrentThreadId() } as u64, heap, &local as *const u8 as u64, collect as *const () as usize as u64];
        sink(Source::Ids, Sample::Nums(&v));
    }
    if ctx.wants(Source::SystemTimes) {
        use windows_sys::Win32::System::ProcessStatus::{K32GetPerformanceInfo, PERFORMANCE_INFORMATION};
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut i, mut k, mut u) = (z, z, z);
        let mut v = Vec::new();
        unsafe {
            if GetSystemTimes(&mut i, &mut k, &mut u) != 0 {
                v.extend([ft(i), ft(k), ft(u)]);
            }
            let mut pi: PERFORMANCE_INFORMATION = core::mem::zeroed();
            pi.cb = core::mem::size_of::<PERFORMANCE_INFORMATION>() as u32;
            if K32GetPerformanceInfo(&mut pi, pi.cb) != 0 {
                v.extend(words(&pi));
            }
        }
        sink(Source::SystemTimes, Sample::Nums(&v));
    }
    if ctx.wants(Source::Disk) {
        let mut v = Vec::new();
        for d in [super::fs::system_dir(), Some(std::env::temp_dir())].into_iter().flatten() {
            use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
            let w = super::fs::wide(&d);
            let (mut a, mut b, mut c) = (0u64, 0u64, 0u64);
            if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut a, &mut b, &mut c) } != 0 {
                v.extend([a, b, c]);
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
    if ctx.wants(Source::OsAux) {
        use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
        let mut b = [0u8; 32];
        if unsafe { BCryptGenRandom(core::ptr::null_mut(), b.as_mut_ptr(), b.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) } == 0 {
            sink(Source::OsAux, Sample::Bytes(&b));
        }
        b.fill(0);
    }
    if ctx.wants(Source::WindowState) {
        window_state(sink);
    }
}

/// a) caret, foreground / focus / capture / desktop / active window handles, clipboard OWNER handles
/// (never the clipboard contents), message position / time, input state, queue status, last
/// input tick, cursor position and the foreground window rectangle.
fn window_state(sink: Sink<'_>) {
    use windows_sys::Win32::System::DataExchange::{GetClipboardOwner, GetOpenClipboardWindow};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetActiveWindow, GetCapture, GetFocus, GetLastInputInfo, LASTINPUTINFO};
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    let mut v = Vec::with_capacity(24);
    unsafe {
        let mut p = POINT { x: 0, y: 0 };
        if GetCursorPos(&mut p) != 0 {
            v.extend([p.x as u64, p.y as u64]);
        }
        if GetCaretPos(&mut p) != 0 {
            v.extend([p.x as u64, p.y as u64]);
        }
        let fg = GetForegroundWindow();
        v.extend([fg as u64, GetFocus() as u64, GetCapture() as u64, GetDesktopWindow() as u64, GetActiveWindow() as u64]);
        v.extend([GetClipboardOwner() as u64, GetOpenClipboardWindow() as u64]);
        v.extend([GetMessagePos() as u64, GetMessageTime() as u64, GetInputState() as u64, GetQueueStatus(QS_ALLINPUT) as u64]);
        let mut li = LASTINPUTINFO { cbSize: core::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        if GetLastInputInfo(&mut li) != 0 {
            v.push(li.dwTime as u64);
        }
        let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        if fg != 0 && GetWindowRect(fg, &mut r) != 0 {
            v.extend([r.left as u64, r.top as u64, r.right as u64, r.bottom as u64]);
        }
    }
    sink(Source::WindowState, Sample::Nums(&v));
}

fn slow(ctx: &EntropyCtx<'_>, sink: Sink<'_>) {
    if ctx.wants(Source::CpuJitter) {
        let clock: &dyn Fn() -> u64 = match cpu::cycle_counter() {
            Some(_) => &|| cpu::cycle_counter().unwrap_or(0),
            None => &qpc,
        };
        sink(Source::CpuJitter, Sample::Nums(&cpu::jitter(1024, clock)));
    }
    if ctx.wants(Source::Processes) {
        toolhelp(sink);
    }
    if ctx.wants(Source::Network) {
        network(sink);
    }
    if ctx.wants(Source::PerfData) {
        perf_data(sink);
    }
}

/// f) ToolHelp: process / thread numbers system-wide, module bases / sizes and heap ids of this
/// process. Process names (szExeFile) are skipped.
fn toolhelp(sink: Sink<'_>) {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let mut v: Vec<u64> = Vec::with_capacity(4096);
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        if h != INVALID_HANDLE_VALUE {
            let mut p: PROCESSENTRY32W = core::mem::zeroed();
            p.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(h, &mut p) != 0;
            while ok && v.len() < 60_000 {
                v.extend([p.th32ProcessID as u64, p.th32ParentProcessID as u64, p.cntThreads as u64, p.pcPriClassBase as u64]);
                ok = Process32NextW(h, &mut p) != 0;
            }
            p.szExeFile.fill(0);
            let mut t: THREADENTRY32 = core::mem::zeroed();
            t.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
            let mut ok = Thread32First(h, &mut t) != 0;
            while ok && v.len() < 120_000 {
                v.extend([t.th32ThreadID as u64, t.th32OwnerProcessID as u64, t.tpBasePri as u64]);
                ok = Thread32Next(h, &mut t) != 0;
            }
            CloseHandle(h);
        }
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPHEAPLIST, 0);
        if h != INVALID_HANDLE_VALUE {
            let mut m: MODULEENTRY32W = core::mem::zeroed();
            m.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;
            let mut ok = Module32FirstW(h, &mut m) != 0;
            while ok {
                v.extend([m.modBaseAddr as u64, m.modBaseSize as u64, m.GlblcntUsage as u64]);
                ok = Module32NextW(h, &mut m) != 0;
            }
            m.szModule.fill(0);
            m.szExePath.fill(0);
            let mut hl: HEAPLIST32 = core::mem::zeroed();
            hl.dwSize = core::mem::size_of::<HEAPLIST32>();
            let mut ok = Heap32ListFirst(h, &mut hl) != 0;
            while ok {
                v.extend([hl.th32HeapID as u64, hl.dwFlags as u64]);
                ok = Heap32ListNext(h, &mut hl) != 0;
            }
            CloseHandle(h);
        }
    }
    if !v.is_empty() {
        sink(Source::Processes, Sample::Nums(&v));
    }
}

/// g) Interface byte / packet counters (GetIfTable2) and IP statistics (GetIpStatistics).
fn network(sink: Sink<'_>) {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    let mut v = Vec::new();
    unsafe {
        let mut t: *mut MIB_IF_TABLE2 = core::ptr::null_mut();
        if GetIfTable2(&mut t) == 0 && !t.is_null() {
            let n = (*t).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*t).Table.as_ptr(), n.min(256));
            for r in rows {
                v.extend([r.InOctets, r.OutOctets, r.InUcastPkts, r.OutUcastPkts, r.InNUcastPkts, r.OutNUcastPkts, r.InDiscards, r.InErrors]);
            }
            FreeMibTable(t as _);
        }
        let mut s: MIB_IPSTATS_LH = core::mem::zeroed();
        if GetIpStatistics(&mut s) == 0 {
            v.extend(words(&s));
        }
    }
    if !v.is_empty() {
        sink(Source::Network, Sample::Nums(&v));
    }
}

/// h) HKEY_PERFORMANCE_DATA: System (2), Memory (4), Processor (238) and PhysicalDisk (234) counter
/// objects (CPU use, disk I/O). Hashed as one block; at most 8 MiB.
fn perf_data(sink: Sink<'_>) {
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegQueryValueExW, HKEY_PERFORMANCE_DATA};
    const ERROR_MORE_DATA: u32 = 234;
    let name = super::fs::wstr("2 4 238 234");
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let mut len = buf.len() as u32;
        let rc = unsafe { RegQueryValueExW(HKEY_PERFORMANCE_DATA, name.as_ptr(), core::ptr::null_mut(), core::ptr::null_mut(), buf.as_mut_ptr(), &mut len) };
        if rc == ERROR_MORE_DATA && buf.len() < 8 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc == 0 {
            sink(Source::PerfData, Sample::Bytes(&buf[..len as usize]));
        }
        break;
    }
    buf.fill(0);
    unsafe { RegCloseKey(HKEY_PERFORMANCE_DATA) };
}
