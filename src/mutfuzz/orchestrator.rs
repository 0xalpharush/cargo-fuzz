use anyhow::{bail, Context, Result};
use rand::SeedableRng;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use std::{env, ffi, fs};

use crate::mutfuzz::disassemble;
use crate::mutfuzz::mutate;
use crate::options;
use crate::options::Sanitizer;

/// Guard that restores the original binary on drop.
/// This ensures the binary is always restored, even on panic or Ctrl-C.
struct BinaryGuard {
    path: PathBuf,
    original: Vec<u8>,
    needs_restore: bool,
}

impl BinaryGuard {
    fn new(path: PathBuf, original: Vec<u8>) -> Self {
        Self {
            path,
            original,
            needs_restore: false,
        }
    }

    fn mark_mutated(&mut self) {
        self.needs_restore = true;
    }

    fn restore(&mut self) -> Result<()> {
        if self.needs_restore {
            // Write to temp file first, then rename (atomic on same filesystem)
            let tmp_path = self.path.with_extension("mutfuzz_restore_tmp");
            fs::write(&tmp_path, &self.original).context("failed to write restore file")?;
            fs::rename(&tmp_path, &self.path).context("failed to rename restore file")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755))
                    .context("failed to set executable permissions")?;
            }
            self.needs_restore = false;
        }
        Ok(())
    }
}

impl Drop for BinaryGuard {
    fn drop(&mut self) {
        if self.needs_restore {
            // Best-effort restore on drop
            let _ = fs::write(&self.path, &self.original);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755));
            }
        }
    }
}

/// Get the path to the compiled fuzz binary.
pub fn get_fuzz_bin_path(
    fuzz_dir: &Path,
    build: &options::BuildOptions,
    target: &str,
) -> Result<PathBuf> {
    let profile_subdir = if build.dev { "debug" } else { "release" };

    // The fuzz binary is at fuzz/target/<triple>/<profile>/<target>
    let target_dir = if let Some(ref td) = build.target_dir {
        PathBuf::from(td)
    } else {
        fuzz_dir.join("target")
    };

    let bin_path = target_dir
        .join(&build.triple)
        .join(profile_subdir)
        .join(target);

    if !bin_path.exists() {
        bail!(
            "fuzz binary not found at {}. Did the build succeed?",
            bin_path.display()
        );
    }

    Ok(bin_path)
}

/// Build sanitizer environment variables matching what cargo() sets up.
fn sanitizer_env_vars(build: &options::BuildOptions) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    match build.sanitizer {
        Sanitizer::Address => {
            let mut asan_opts = env::var("ASAN_OPTIONS").unwrap_or_default();
            if !asan_opts.is_empty() {
                asan_opts.push(':');
            }
            asan_opts.push_str("detect_odr_violation=0");
            vars.push(("ASAN_OPTIONS".to_string(), asan_opts));
        }
        Sanitizer::Thread => {
            let mut tsan_opts = env::var("TSAN_OPTIONS").unwrap_or_default();
            if !tsan_opts.is_empty() {
                tsan_opts.push(':');
            }
            tsan_opts.push_str("report_signal_unsafe=0");
            vars.push(("TSAN_OPTIONS".to_string(), tsan_opts));
        }
        _ => {}
    }
    vars
}

/// Run the mutant-guided fuzzing orchestration loop.
pub fn run(
    _fuzz_dir: &Path,
    artifacts_dir: &Path,
    corpus_dir: &Path,
    bin_path: &Path,
    opts: &options::MutFuzz,
) -> Result<()> {
    // Platform check
    if !opts.build.triple.contains("x86_64") {
        bail!(
            "mutfuzz only supports x86_64 targets (got triple: {}). \
             Binary mutation of conditional jumps is architecture-specific.",
            opts.build.triple
        );
    }

    eprintln!("Reading binary: {}", bin_path.display());
    let original_bytes = fs::read(bin_path)
        .with_context(|| format!("failed to read binary at {}", bin_path.display()))?;
    eprintln!("Binary size: {} bytes", original_bytes.len());

    // Parse only/avoid patterns
    let only_mutate: Vec<String> = opts
        .only_mutate
        .as_deref()
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_default();
    let avoid_mutating: Vec<String> = opts
        .avoid_mutating
        .as_deref()
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_default();

    eprintln!("Disassembling binary...");
    let disasm = disassemble::get_jumps(&original_bytes, &only_mutate, &avoid_mutating)?;
    eprintln!(
        "Found {} mutable jumps in {} functions",
        disasm.jumps.len(),
        disasm.function_map.len()
    );

    if disasm.jumps.is_empty() {
        eprintln!(
            "WARNING: No mutable conditional jumps found. \
             Falling back to normal fuzzing for the full budget."
        );
        run_normal_fuzzing(bin_path, artifacts_dir, corpus_dir, opts, opts.budget)?;
        return Ok(());
    }

    // Print jump counts per function
    for (func, jumps) in &disasm.function_map {
        eprintln!("  {}: {} jumps", func, jumps.len());
    }

    // Set up RNG
    let mut rng: rand::rngs::StdRng = match opts.seed {
        Some(seed) => rand::rngs::StdRng::seed_from_u64(seed),
        None => rand::rngs::StdRng::from_entropy(),
    };

    let mut guard = BinaryGuard::new(bin_path.to_path_buf(), original_bytes.clone());
    let mut visited: HashMap<(usize, Vec<u8>), u32> = HashMap::new();

    let budget_secs = opts.budget;
    let mutant_budget = (budget_secs as f64 * opts.fraction_mutant) as u64;
    let start = Instant::now();

    let mut mutant_no = 0u64;
    let mut mutants_killed = 0u64;
    let mut mutants_survived = 0u64;

    eprintln!();
    eprintln!(
        "Starting mutant fuzzing: {} seconds total budget, {} seconds for mutants, {} seconds per mutant",
        budget_secs, mutant_budget, opts.time_per_mutant
    );

    // Mutant fuzzing phase
    while start.elapsed().as_secs() < mutant_budget {
        mutant_no += 1;

        let (mutated_bytes, records) = match mutate::create_mutant(
            &original_bytes,
            &disasm,
            opts.order,
            opts.avoid_repeats,
            &mut visited,
            &mut rng,
        ) {
            Some(result) => result,
            None => {
                eprintln!("Failed to generate mutant, stopping mutant phase");
                break;
            }
        };

        eprintln!();
        eprintln!(
            "[{:.1}s] Mutant #{}: {} mutation(s)",
            start.elapsed().as_secs_f64(),
            mutant_no,
            records.len()
        );
        for rec in &records {
            eprintln!(
                "  Mutating jump at offset 0x{:x} in {}",
                rec.file_offset, rec.function_name
            );
        }

        // Write mutated binary
        fs::write(bin_path, &mutated_bytes).context("failed to write mutated binary")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(bin_path, fs::Permissions::from_mode(0o755))
                .context("failed to set executable permissions on mutant")?;
        }
        guard.mark_mutated();

        // Run the mutant
        let mutant_start = Instant::now();
        let status = run_fuzz_binary(
            bin_path,
            artifacts_dir,
            corpus_dir,
            opts,
            opts.time_per_mutant,
        )?;

        let elapsed = mutant_start.elapsed().as_secs_f64();

        if !status.success() {
            mutants_killed += 1;
            eprintln!(
                "  KILLED in {:.1}s (exit: {})",
                elapsed,
                status.code().unwrap_or(-1)
            );
        } else {
            mutants_survived += 1;
            eprintln!("  survived in {:.1}s", elapsed);
        }

        // Restore original binary
        guard.restore()?;
    }

    // Normal fuzzing phase
    let elapsed = start.elapsed().as_secs();
    let remaining = budget_secs.saturating_sub(elapsed);
    if remaining > 0 && opts.fraction_mutant < 1.0 {
        eprintln!();
        eprintln!(
            "[{:.1}s] Starting normal fuzzing for {} remaining seconds",
            start.elapsed().as_secs_f64(),
            remaining
        );
        // Ensure original is restored before normal fuzzing
        guard.restore()?;
        run_normal_fuzzing(bin_path, artifacts_dir, corpus_dir, opts, remaining)?;
    }

    // Summary
    let total_mutants = mutants_killed + mutants_survived;
    eprintln!();
    eprintln!("{:=<60}", "");
    eprintln!("MutFuzz Summary");
    eprintln!("{:-<60}", "");
    eprintln!("Total mutants tested:  {}", total_mutants);
    eprintln!("Mutants killed:        {}", mutants_killed);
    eprintln!("Mutants survived:      {}", mutants_survived);
    if total_mutants > 0 {
        eprintln!(
            "Mutation score:        {:.1}%",
            (mutants_killed as f64 / total_mutants as f64) * 100.0
        );
    }
    eprintln!(
        "Total time:            {:.1}s",
        start.elapsed().as_secs_f64()
    );
    eprintln!("{:=<60}", "");

    Ok(())
}

/// Spawn the fuzz binary directly (not via cargo) with libFuzzer arguments.
fn run_fuzz_binary(
    bin_path: &Path,
    artifacts_dir: &Path,
    corpus_dir: &Path,
    opts: &options::MutFuzz,
    max_time: u64,
) -> Result<std::process::ExitStatus> {
    let mut cmd = Command::new(bin_path);

    // Set sanitizer env vars
    for (key, val) in sanitizer_env_vars(&opts.build) {
        cmd.env(&key, &val);
    }

    // libFuzzer arguments
    let mut artifact_arg = ffi::OsString::from("-artifact_prefix=");
    artifact_arg.push(artifacts_dir);
    cmd.arg(&artifact_arg);
    cmd.arg(format!("-max_total_time={}", max_time));
    cmd.arg(corpus_dir);

    // Pass through user args
    for arg in &opts.args {
        cmd.arg(arg);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn fuzz binary: {:?}", cmd))?;

    // Enforce max_time out of band in case the mutant breaks libFuzzer's
    // own control loop (e.g. a flipped branch in its shutdown path).
    let deadline = Duration::from_secs(max_time + 10);
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if start.elapsed() > deadline {
                    eprintln!(
                        "  Mutant exceeded time limit ({}s), killing",
                        max_time
                    );
                    let _ = child.kill();
                    return child
                        .wait()
                        .with_context(|| "failed to wait after killing hung mutant");
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(e).context("failed to wait on fuzz binary"),
        }
    }
}

/// Run normal (non-mutant) fuzzing by spawning the binary directly.
fn run_normal_fuzzing(
    bin_path: &Path,
    artifacts_dir: &Path,
    corpus_dir: &Path,
    opts: &options::MutFuzz,
    max_time: u64,
) -> Result<()> {
    let mut cmd = Command::new(bin_path);

    for (key, val) in sanitizer_env_vars(&opts.build) {
        cmd.env(&key, &val);
    }

    let mut artifact_arg = ffi::OsString::from("-artifact_prefix=");
    artifact_arg.push(artifacts_dir);
    cmd.arg(&artifact_arg);
    cmd.arg(format!("-max_total_time={}", max_time));
    cmd.arg(corpus_dir);

    if opts.jobs > 1 {
        cmd.arg(format!("-fork={}", opts.jobs));
    }

    for arg in &opts.args {
        cmd.arg(arg);
    }

    let status = cmd
        .status()
        .with_context(|| format!("failed to run normal fuzzing: {:?}", cmd))?;

    if !status.success() {
        // Non-zero exit from libFuzzer usually means a crash was found, which is expected
        eprintln!("Normal fuzzing phase exited with: {}", status);
    }

    Ok(())
}
