use rbitcoin_store::sorted_run::*;

#[test]
fn workers_for_free_ram_1gib_head_is_not_sh_1_5gib() {
    const HEAD: u64 = rbitcoin_store::tx_table::TX_HEAD_REBUILD_WORKER_FREE_RAM_BYTES;
    assert_eq!(workers_for_free_ram(8, 0, HEAD), 1);
    assert_eq!(workers_for_free_ram(8, HEAD.saturating_sub(1), HEAD), 1);
    assert_eq!(workers_for_free_ram(8, HEAD, HEAD), 1);
    assert_eq!(workers_for_free_ram(8, 2 * HEAD, HEAD), 2);
    assert_eq!(workers_for_free_ram(8, 3 * HEAD, HEAD), 3);
    assert_eq!(workers_for_free_ram(4, 20 * HEAD, HEAD), 4);
    assert_eq!(workers_for_free_ram(8, 3 * (1 << 30) / 2, HEAD), 1);
    assert_eq!(workers_for_free_ram(8, 2 * (1 << 30), HEAD), 2);
}

const GIB: u64 = 1 << 30;
const MEMINFO_9_5_GIB: &str = "MemTotal: 16777216 kB\nMemAvailable: 9961472 kB\n";

fn cgroup_level(root: &std::path::Path, rel: &str, files: &[(&str, String)]) {
    let dir = root.join(rel);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, body) in files {
        std::fs::write(dir.join(name), body).unwrap();
    }
}

#[test]
fn cgroup_limit_caps_free_ram() {
    let root = rbitcoin_store::testutil::TempDir::labeled("cgroup").unwrap();
    let svc = "system.slice/rbitcoin.service";
    let self_cgroup = format!("0::/{svc}\n");
    cgroup_level(root.path(), "", &[]);
    cgroup_level(
        root.path(),
        "system.slice",
        &[
            ("memory.max", "max\n".into()),
            ("memory.high", "max\n".into()),
            ("memory.current", format!("{}\n", 2 * GIB)),
        ],
    );
    cgroup_level(
        root.path(),
        svc,
        &[
            ("memory.max", format!("{}\n", 7 * GIB)),
            ("memory.high", "max\n".into()),
            ("memory.current", format!("{}\n", GIB)),
            ("memory.stat", "anon 1\ninactive_file 0\n".into()),
        ],
    );
    assert_eq!(
        mem_available_under_cgroup(MEMINFO_9_5_GIB, &self_cgroup, root.path()),
        Some(6 * GIB),
        "MemoryMax=7G with 1 GiB used leaves 6 GiB, not the host's 9.5"
    );

    cgroup_level(
        root.path(),
        svc,
        &[
            ("memory.current", format!("{}\n", 6 * GIB)),
            (
                "memory.stat",
                format!("anon 1\ninactive_file {}\n", 2 * GIB),
            ),
        ],
    );
    assert_eq!(
        mem_available_under_cgroup(MEMINFO_9_5_GIB, &self_cgroup, root.path()),
        Some(3 * GIB),
        "inactive page cache is reclaimable"
    );

    cgroup_level(
        root.path(),
        "system.slice",
        &[
            ("memory.high", format!("{}\n", 4 * GIB)),
            ("memory.current", format!("{}\n", 3 * GIB)),
        ],
    );
    assert_eq!(
        mem_available_under_cgroup(MEMINFO_9_5_GIB, &self_cgroup, root.path()),
        Some(GIB),
        "a tighter ancestor memory.high wins"
    );

    cgroup_level(
        root.path(),
        "system.slice",
        &[("memory.current", format!("{}\n", 5 * GIB))],
    );
    assert_eq!(
        mem_available_under_cgroup(MEMINFO_9_5_GIB, &self_cgroup, root.path()),
        Some(0),
        "over the limit leaves nothing"
    );
}

#[test]
fn cgroup_without_limit_keeps_host_free_ram() {
    let root = rbitcoin_store::testutil::TempDir::labeled("cgroup").unwrap();
    cgroup_level(
        root.path(),
        "user.slice",
        &[
            ("memory.max", "max\n".into()),
            ("memory.current", format!("{}\n", 50 * GIB)),
        ],
    );
    let host = Some(9_961_472 * 1024);
    assert_eq!(
        mem_available_under_cgroup(MEMINFO_9_5_GIB, "0::/user.slice\n", root.path()),
        host
    );
    assert_eq!(
        mem_available_under_cgroup(MEMINFO_9_5_GIB, "0::/gone.slice\n", root.path()),
        host
    );
    assert_eq!(
        mem_available_under_cgroup(MEMINFO_9_5_GIB, "4:memory:/user.slice\n", root.path()),
        host,
        "cgroup v1 only"
    );
    assert_eq!(
        mem_available_under_cgroup("MemTotal: 1 kB\n", "0::/user.slice\n", root.path()),
        None
    );
}

#[test]
fn darwin_vm_pages_count_as_free_ram() {
    assert_eq!(mem_available_from_darwin_vm(0, 10, 10), None);
    assert_eq!(mem_available_from_darwin_vm(4096, 0, 0), Some(0));
    assert_eq!(mem_available_from_darwin_vm(4096, 1, 0), Some(4096));
    assert_eq!(mem_available_from_darwin_vm(16384, 2, 2), Some(4 * 16384));
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn host_mem_available_bytes_is_some_on_linux_macos_windows() {
    let n = host_mem_available_bytes().expect("Linux MemAvailable / Darwin vm / Windows AvailPhys");
    let w = workers_for_free_ram(logical_cpus(), n, 2 << 30);
    assert!((1..=256).contains(&w));
    assert!(w <= logical_cpus());
    let label = free_gib_label();
    assert!(label == "?" || label.parse::<f64>().is_ok(), "{label}");
}
