/// The callgraph shim is a drop-in replacement for `libfuzzer-sys` that provides:
/// - A `fuzz_target!` macro for replaying seed inputs
/// - A Rust-defined `main` symbol so we do not need generated C code
/// - SanitizerCoverage callbacks (`trace-pc-guard`, `pcs_init`) that record
///   (prev_guard, cur_guard) transitions for call graph extraction
///
/// The shim crate is written to a temp directory at `cargo fuzz callgraph` time
/// and patched in via `--config 'patch.crates-io.libfuzzer-sys.path=...'`.

/// Cargo.toml template for the shim crate.
/// The version is filled in dynamically to match the locked libfuzzer-sys version.
pub fn cargo_toml(version: &str) -> String {
    format!(
        r#"[package]
name = "libfuzzer-sys"
version = "{version}"
edition = "2021"

[dependencies]
arbitrary = {{ version = "1", features = ["derive"] }}

[features]
default = []
"#
    )
}

/// lib.rs content for the shim crate.
pub const LIB_RS: &str = r#"
// Re-export arbitrary so `use libfuzzer_sys::arbitrary` works (matches real libfuzzer-sys)
pub use arbitrary;

/// Drop-in replacement for libfuzzer-sys's fuzz_target! macro.
/// Defines `LLVMFuzzerTestOneInput` (same as real libfuzzer-sys) so our replay
/// entry point can feed corpus inputs through the target.
#[macro_export]
macro_rules! fuzz_target {
    (|$data:ident| $body:expr) => {
        $crate::fuzz_target!(init: (), |$data: &[u8]| -> () { $body });
    };

    (|$data:ident: &[u8]| $body:expr) => {
        $crate::fuzz_target!(init: (), |$data: &[u8]| -> () { $body });
    };

    (|$data:ident: &[u8]| -> $rty:ty $body:block) => {
        $crate::fuzz_target!(init: (), |$data: &[u8]| -> $rty { $body });
    };

    (init: $init:expr, |$data:ident| $body:expr) => {
        $crate::fuzz_target!(init: $init, |$data: &[u8]| -> () { $body });
    };

    (init: $init:expr, |$data:ident: &[u8]| $body:expr) => {
        $crate::fuzz_target!(init: $init, |$data: &[u8]| -> () { $body });
    };

    (init: $init:expr, |$data:ident: &[u8]| -> $rty:ty $body:block) => {
        const _: () = {
            static INIT: ::std::sync::Once = ::std::sync::Once::new();

            #[inline]
            fn __callgraph_init() {
                INIT.call_once(|| {
                    $init;
                });
            }

            #[export_name = "LLVMFuzzerTestOneInput"]
            fn __fuzz_target_impl(data_ptr: *const u8, size: usize) -> i32 {
                __callgraph_init();
                let $data: &[u8] = unsafe { ::std::slice::from_raw_parts(data_ptr, size) };
                let _result: $rty = { $body };
                0
            }
        };
    };

    (|$data:ident: $dty:ty| $body:block) => {
        // Typed (Arbitrary) target. We deserialize from raw bytes using
        // Arbitrary, matching what the real libfuzzer-sys macro does.
        // The body is wrapped in a closure so bare `return;` returns from
        // the user's closure, not from the outer i32-returning function.
        #[export_name = "LLVMFuzzerTestOneInput"]
        fn __fuzz_target_impl(data_ptr: *const u8, size: usize) -> i32 {
            let bytes: &[u8] = unsafe { ::std::slice::from_raw_parts(data_ptr, size) };
            use ::arbitrary::{Arbitrary, Unstructured};
            let mut unstructured = Unstructured::new(bytes);
            if let Ok($data) = <$dty as Arbitrary>::arbitrary(&mut unstructured) {
                (|| $body)();
            }
            0
        }
    };
}

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    __callgraph_rust_main()
}

/// Rust entry point for replay.
///
/// Arguments before `--` are treated as seed file paths. Arguments after `--`
/// remain visible in `std::env::args*()` to the fuzz target but are not opened
/// as files by the shim.
pub fn __callgraph_rust_main() -> i32 {
    __callgraph_shim::init();

    let args: Vec<::std::ffi::OsString> = ::std::env::args_os().collect();
    let split_at = args[1..]
        .iter()
        .position(|arg| arg == "--")
        .map(|idx| idx + 1)
        .unwrap_or(args.len());

    let seed_args = &args[1..split_at];
    if seed_args.is_empty() {
        eprintln!("Usage: {} <seed_file> [seed_file ...] [-- target_args...]", args[0].to_string_lossy());
        return 1;
    }

    for path in seed_args {
        if let Ok(data) = ::std::fs::read(path) {
            __callgraph_shim::reset_prev();
            __callgraph_shim::set_tracking(true);
            unsafe { LLVMFuzzerTestOneInput(data.as_ptr(), data.len()); }
            __callgraph_shim::set_tracking(false);
        }
    }

    let out_file = ::std::env::var("CALLGRAPH_EDGES_FILE")
        .unwrap_or_else(|_| String::from("callgraph_edges.json"));
    __callgraph_shim::dump_edges(&out_file);

    0
}

/// SanitizerCoverage shim for call graph edge collection.
pub mod __callgraph_shim {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::ptr;
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
    use std::sync::OnceLock;

    const MAX_PC_SPANS: usize = 256;

    #[derive(Clone, Copy)]
    struct PcSpan {
        begin: *const [usize; 2],
        count: usize,
    }

    static EDGE_KEYS: OnceLock<Box<[AtomicU64]>> = OnceLock::new();
    static EDGE_COUNTS: OnceLock<Box<[AtomicU64]>> = OnceLock::new();
    static DROPPED_EDGES: AtomicU64 = AtomicU64::new(0);
    static DROPPED_PC_SPANS: AtomicU64 = AtomicU64::new(0);
    static TRACKING_ENABLED: AtomicU8 = AtomicU8::new(0);

    static mut PREV_GUARD: u32 = 0;
    static mut GUARD_COUNT: u32 = 0;
    static mut PC_SPAN_COUNT: usize = 0;
    static mut PC_SPANS: [PcSpan; MAX_PC_SPANS] = [PcSpan {
        begin: ptr::null(),
        count: 0,
    }; MAX_PC_SPANS];

    pub fn init() {
        let guard_count = unsafe { GUARD_COUNT as usize }.max(1);
        let slots = guard_count
            .saturating_mul(8)
            .next_power_of_two()
            .clamp(1 << 12, 1 << 20);

        let _ = EDGE_KEYS.set(
            (0..slots)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        let _ = EDGE_COUNTS.set(
            (0..slots)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        DROPPED_EDGES.store(0, Ordering::Relaxed);
        DROPPED_PC_SPANS.store(0, Ordering::Relaxed);
        TRACKING_ENABLED.store(0, Ordering::Relaxed);
        unsafe {
            PREV_GUARD = 0;
        }
    }

    pub fn reset_prev() {
        unsafe {
            PREV_GUARD = 0;
        }
    }

    pub fn set_tracking(enabled: bool) {
        TRACKING_ENABLED.store(u8::from(enabled), Ordering::Release);
    }

    /// Called by LLVM to provide the PC table for one module.
    #[no_mangle]
    pub extern "C" fn __sanitizer_cov_pcs_init(
        pcs_beg: *const [usize; 2],
        pcs_end: *const [usize; 2],
    ) {
        let count = unsafe { pcs_end.offset_from(pcs_beg) as usize };
        unsafe {
            if PC_SPAN_COUNT < MAX_PC_SPANS {
                PC_SPANS[PC_SPAN_COUNT] = PcSpan {
                    begin: pcs_beg,
                    count,
                };
                PC_SPAN_COUNT += 1;
            } else {
                DROPPED_PC_SPANS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Assign sequential IDs to guards.
    #[no_mangle]
    pub extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, stop: *mut u32) {
        if start == stop || unsafe { *start != 0 } {
            return;
        }
        let mut x = start;
        while x < stop {
            unsafe {
                GUARD_COUNT += 1;
                *x = GUARD_COUNT;
                x = x.add(1);
            }
        }
    }

    /// Called at every instrumented basic block. Records (prev, cur) guard transitions.
    #[no_mangle]
    pub extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
        if TRACKING_ENABLED.load(Ordering::Acquire) == 0 {
            return;
        }

        let cur = unsafe { *guard };
        if cur == 0 {
            return;
        }

        let prev = unsafe { PREV_GUARD };
        if prev != 0 && prev != cur {
            if let (Some(keys), Some(counts)) = (EDGE_KEYS.get(), EDGE_COUNTS.get()) {
                // Keep the callback allocation-free and lock-free. A heavier
                // runtime here can deadlock or recurse under sancov replay.
                let key = ((prev as u64) << 32) | (cur as u64);
                let mask = keys.len() - 1;
                let mut idx = (key.wrapping_mul(0x9E37_79B1_85EB_CA87) as usize) & mask;
                let mut inserted = false;

                for _ in 0..keys.len() {
                    let slot = &keys[idx];
                    let existing = slot.load(Ordering::Acquire);
                    if existing == 0 {
                        match slot.compare_exchange(
                            0,
                            key,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => {
                                counts[idx].store(1, Ordering::Release);
                                inserted = true;
                                break;
                            }
                            Err(found) if found == key => {
                                counts[idx].fetch_add(1, Ordering::Relaxed);
                                inserted = true;
                                break;
                            }
                            Err(_) => {}
                        }
                    } else if existing == key {
                        counts[idx].fetch_add(1, Ordering::Relaxed);
                        inserted = true;
                        break;
                    }
                    idx = (idx + 1) & mask;
                }

                if !inserted {
                    DROPPED_EDGES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        unsafe {
            PREV_GUARD = cur;
        }
    }

    fn current_exe() -> Option<PathBuf> {
        std::env::current_exe().ok()
    }

    #[cfg(target_os = "linux")]
    fn current_binary_load_base() -> Option<u64> {
        let exe = current_exe()?;
        let maps = fs::read_to_string("/proc/self/maps").ok()?;
        parse_linux_load_base(&maps, &exe)
    }

    #[cfg(not(target_os = "linux"))]
    fn current_binary_load_base() -> Option<u64> {
        Some(0)
    }

    #[cfg(target_os = "linux")]
    fn parse_linux_load_base(maps: &str, exe: &std::path::Path) -> Option<u64> {
        let exe = exe.to_string_lossy();
        let mut base = None;

        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next()?;
            let _perms = fields.next()?;
            let offset = fields.next()?;
            let _dev = fields.next()?;
            let _inode = fields.next()?;
            let path = fields.next();

            let Some(path) = path else {
                continue;
            };

            let path = path.strip_suffix(" (deleted)").unwrap_or(path);
            if path != exe {
                continue;
            }

            let (start, _) = range.split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let offset = u64::from_str_radix(offset, 16).ok()?;
            let candidate = start.checked_sub(offset)?;
            base = Some(base.map_or(candidate, |current: u64| current.min(candidate)));
        }

        base
    }

    fn collect_pc_table() -> Vec<(u32, u64)> {
        let mut table = Vec::new();
        let base = current_binary_load_base().unwrap_or(0);
        let mut guard_id = 1u32;

        unsafe {
            let spans = ptr::addr_of!(PC_SPANS) as *const PcSpan;
            for span_idx in 0..PC_SPAN_COUNT {
                let span = &*spans.add(span_idx);
                for idx in 0..span.count {
                    let entry = &*span.begin.add(idx);
                    let runtime_pc = entry[0] as u64;
                    let normalized_pc = runtime_pc.checked_sub(base).unwrap_or(runtime_pc);
                    table.push((guard_id, normalized_pc));
                    guard_id += 1;
                }
            }
        }

        table
    }

    fn collect_edge_snapshot() -> Vec<(u32, u32, u64)> {
        let mut edges = Vec::new();

        if let (Some(keys), Some(counts)) = (EDGE_KEYS.get(), EDGE_COUNTS.get()) {
            for (key, count) in keys.iter().zip(counts.iter()) {
                let encoded = key.load(Ordering::Acquire);
                let hits = count.load(Ordering::Acquire);
                if encoded == 0 || hits == 0 {
                    continue;
                }

                edges.push(((encoded >> 32) as u32, encoded as u32, hits));
            }
        }

        edges
    }

    /// Dump edges as JSON.
    ///
    /// Format:
    ///   {
    ///     "edges":[{"prev":1,"cur":2,"count":3}],
    ///     "pcs":[{"guard_id":1,"pc":4096}]
    ///   }
    ///
    /// The PC values are normalized against the binary load base, so they remain
    /// stable even when the replay binary is PIE and ASLR is enabled.
    pub fn dump_edges(path: &str) {
        reset_prev();
        let edges = collect_edge_snapshot();
        let pc_table = collect_pc_table();
        let mut f = std::fs::File::create(path).expect("failed to create edges file");
        write!(f, "{{\"edges\":[").unwrap();
        for (idx, (prev, cur, hits)) in edges.iter().enumerate() {
            write!(
                f,
                "{{\"prev\":{},\"cur\":{},\"count\":{}}}{}",
                prev,
                cur,
                hits,
                if idx + 1 == edges.len() { "" } else { "," }
            )
            .unwrap();
        }
        write!(f, "],\"pcs\":[").unwrap();
        for (idx, (guard_id, pc)) in pc_table.iter().enumerate() {
            write!(
                f,
                "{{\"guard_id\":{},\"pc\":{}}}{}",
                guard_id,
                pc,
                if idx + 1 == pc_table.len() { "" } else { "," }
            )
            .unwrap();
        }
        write!(f, "]}}").unwrap();
        f.flush().unwrap();

        let dropped_edges = DROPPED_EDGES.load(Ordering::Relaxed);
        if dropped_edges != 0 {
            eprintln!(
                "Warning: dropped {} call graph edges because the edge table filled up",
                dropped_edges
            );
        }

        let dropped_spans = DROPPED_PC_SPANS.load(Ordering::Relaxed);
        if dropped_spans != 0 {
            eprintln!(
                "Warning: dropped {} sanitizer PC spans because the shim span table filled up",
                dropped_spans
            );
        }
    }
}
"#;

#[cfg(test)]
mod tests {
    use super::{cargo_toml, LIB_RS};
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;

    #[test]
    fn shim_cargo_toml_is_pure_rust() {
        let manifest = cargo_toml("0.4.99");
        assert!(manifest.contains("name = \"libfuzzer-sys\""));
        assert!(!manifest.contains("build ="));
        assert!(!manifest.contains("[build-dependencies]"));
    }

    #[test]
    fn shim_runtime_exports_rust_main_and_normalizes_pcs() {
        assert!(LIB_RS.contains("pub extern \"C\" fn main() -> i32"));
        assert!(LIB_RS.contains("/proc/self/maps"));
        assert!(LIB_RS.contains("runtime_pc.checked_sub(base)"));
        assert!(!LIB_RS.contains("thread_local!"));
        assert!(!LIB_RS.contains("main.c"));
    }

    #[test]
    fn generated_shim_crate_compiles() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("Cargo.toml"), cargo_toml("0.4.99")).unwrap();
        fs::write(dir.path().join("src/lib.rs"), LIB_RS).unwrap();

        let status = Command::new("cargo")
            .arg("check")
            .arg("--manifest-path")
            .arg(dir.path().join("Cargo.toml"))
            .status()
            .unwrap();

        assert!(status.success());
    }
}
