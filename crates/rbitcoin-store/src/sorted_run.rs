//! Worker cap from free RAM. Used by `tx.head` rebuild and scripthash extract.
//!
//! The sorted-run codec is gone. Tip materialize does not write `scripthash.runs`.
//! Store open unlinks leftover names in that directory except `SEAL`.

/// Cap workers at 1 per `per_worker` free bytes (floor 1, clamp 1..=256 vs CPUs).
pub fn workers_for_free_ram(cpus: usize, free_bytes: u64, per_worker: u64) -> usize {
    let cpus = cpus.clamp(1, 256);
    if per_worker == 0 {
        return 1;
    }
    let ram_cap = (free_bytes / per_worker) as usize;
    cpus.min(ram_cap.clamp(1, 256))
}

/// `MemAvailable` from `/proc/meminfo`, capped by this process's cgroup v2
/// headroom. `/proc/meminfo` reports the whole host even under `MemoryMax=`
/// or a container limit.
///
/// Headroom is `min(memory.max, memory.high)` minus the working set
/// (`memory.current` less reclaimable `inactive_file`), at the cgroup named
/// in `/proc/self/cgroup` and at each ancestor up to `cgroup_root`. The
/// smallest wins. A level with neither limit set is skipped.
#[cfg(any(debug_assertions, target_os = "linux"))]
#[doc(hidden)]
pub fn mem_available_under_cgroup(
    meminfo: &str,
    proc_self_cgroup: &str,
    cgroup_root: &std::path::Path,
) -> Option<u64> {
    let host = mem_available_from_meminfo(meminfo)?;
    let Some(leaf) = proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
    else {
        return Some(host);
    };
    let leaf_dir = cgroup_root.join(leaf);
    Some(
        leaf_dir
            .ancestors()
            .take_while(|dir| dir.starts_with(cgroup_root))
            .filter_map(cgroup_headroom)
            .fold(host, u64::min),
    )
}

#[cfg(any(debug_assertions, target_os = "linux"))]
fn cgroup_headroom(dir: &std::path::Path) -> Option<u64> {
    let read_u64 = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    };
    let limit = ["memory.max", "memory.high"]
        .into_iter()
        .filter_map(read_u64)
        .min()?;
    let inactive_file = std::fs::read_to_string(dir.join("memory.stat"))
        .ok()
        .and_then(|stat| {
            stat.lines()
                .find_map(|line| line.strip_prefix("inactive_file "))
                .and_then(|n| n.trim().parse::<u64>().ok())
        })
        .unwrap_or(0);
    let working_set = read_u64("memory.current")
        .unwrap_or(0)
        .saturating_sub(inactive_file);
    Some(limit.saturating_sub(working_set))
}

/// `MemAvailable` from `/proc/meminfo` text (kB → bytes).
#[cfg(any(debug_assertions, target_os = "linux"))]
fn mem_available_from_meminfo(text: &str) -> Option<u64> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("MemAvailable:") else {
            continue;
        };
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        return Some(kb.saturating_mul(1024));
    }
    None
}

/// Darwin reclaimable pages (`free_count + inactive_count`) × page size.
/// Speculative pages are already inside `free_count`.
#[cfg(any(debug_assertions, target_os = "macos"))]
#[doc(hidden)]
pub fn mem_available_from_darwin_vm(
    page_size: u64,
    free_count: u64,
    inactive_count: u64,
) -> Option<u64> {
    if page_size == 0 {
        return None;
    }
    Some(
        free_count
            .saturating_add(inactive_count)
            .saturating_mul(page_size),
    )
}

#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn mem_available_from_darwin_host() -> Option<u64> {
    let page_size = {
        // SAFETY: `sysconf` reads the process page size. It takes no pointer.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if n <= 0 {
            return None;
        }
        n as u64
    };
    // SAFETY: the zeroed struct is the `host_statistics64` out-buffer filled below.
    let mut vm = unsafe { std::mem::zeroed::<libc::vm_statistics64>() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    // SAFETY: `vm` and `count` are locals. `mach_host_self` is this process.
    let kr = unsafe {
        // SAFETY: process host port; HOST_VM_INFO64 writes into this stack vm_statistics64.
        #[allow(deprecated)]
        let host = libc::mach_host_self();
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            &mut vm as *mut _ as libc::host_info64_t,
            &mut count,
        )
    };
    if kr != libc::KERN_SUCCESS {
        return None;
    }
    mem_available_from_darwin_vm(
        page_size,
        u64::from(vm.free_count),
        u64::from(vm.inactive_count),
    )
}

#[cfg(windows)]
#[repr(C)]
#[allow(dead_code)]
#[doc(hidden)]
pub struct MemoryStatusEx {
    pub dw_length: u32,
    pub dw_memory_load: u32,
    pub ull_total_phys: u64,
    pub ull_avail_phys: u64,
    pub ull_total_page_file: u64,
    pub ull_avail_page_file: u64,
    pub ull_total_virtual: u64,
    pub ull_avail_virtual: u64,
    pub ull_avail_extended_virtual: u64,
}

#[cfg(windows)]
extern "system" {
    fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
}

#[cfg(windows)]
#[doc(hidden)]
pub fn mem_available_from_windows_host() -> Option<u64> {
    let mut st = MemoryStatusEx {
        dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
        dw_memory_load: 0,
        ull_total_phys: 0,
        ull_avail_phys: 0,
        ull_total_page_file: 0,
        ull_avail_page_file: 0,
        ull_total_virtual: 0,
        ull_avail_virtual: 0,
        ull_avail_extended_virtual: 0,
    };
    // SAFETY: dw_length is size_of Self; the API fills the remaining fields.
    if unsafe { GlobalMemoryStatusEx(&mut st) } == 0 {
        return None;
    }
    Some(st.ull_avail_phys)
}

/// Host memory available for new allocations.
///
/// Linux: `MemAvailable`, capped by the cgroup v2 memory headroom
/// ([`mem_available_under_cgroup`]). Darwin: free+inactive pages. Windows:
/// `ullAvailPhys`. Other OS: `None` (worker cap falls back to 1).
pub fn host_mem_available_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        let self_cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        mem_available_under_cgroup(
            &meminfo,
            &self_cgroup,
            std::path::Path::new("/sys/fs/cgroup"),
        )
    }
    #[cfg(target_os = "macos")]
    {
        mem_available_from_darwin_host()
    }
    #[cfg(windows)]
    {
        return mem_available_from_windows_host();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

/// [`host_mem_available_bytes`] as a log label (`"12.3"` GiB, or `"?"` when unknown).
pub fn free_gib_label() -> String {
    host_mem_available_bytes()
        .map(|b| format!("{:.1}", b as f64 / (1u64 << 30) as f64))
        .unwrap_or_else(|| "?".into())
}

pub fn logical_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 256)
}
