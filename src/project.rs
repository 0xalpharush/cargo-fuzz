use crate::options::{self, BuildMode, BuildOptions, Sanitizer};
use crate::rustc_version::RustVersion;
use crate::utils::default_target;
use addr2line::Loader;
use anyhow::{anyhow, bail, Context, Result};
use cargo_metadata::MetadataCommand;
use petgraph::graph::UnGraph;
use petgraph::visit::EdgeRef;
use rayon::prelude::*;
use rustc_demangle::demangle;
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{
    env, ffi, fs,
    process::{Command, Stdio},
    time::{self, SystemTime, UNIX_EPOCH},
};

const DEFAULT_FUZZ_DIR: &str = "fuzz";
const SYMBOL_CACHE_VERSION: u64 = 2;

pub struct FuzzProject {
    /// The project with fuzz targets
    fuzz_dir: PathBuf,
    targets: Vec<String>,
}

impl FuzzProject {
    /// Creates a new instance.
    //
    /// Find an existing `cargo fuzz` project by starting at the current
    /// directory and walking up the filesystem.
    ///
    /// If `fuzz_dir_opt` is `None`, returns a new instance with the default fuzz project
    /// path.
    pub fn new(fuzz_dir_opt: Option<PathBuf>) -> Result<Self> {
        let mut project = Self::manage_initial_instance(fuzz_dir_opt)?;
        let manifest = project.manifest()?;
        if !is_fuzz_manifest(&manifest) {
            bail!(
                "manifest `{}` does not look like a cargo-fuzz manifest. \
                 Add following lines to override:\n\
                 [package.metadata]\n\
                 cargo-fuzz = true",
                project.manifest_path().display()
            );
        }
        project.targets = collect_targets(&manifest);
        Ok(project)
    }

    /// Creates the fuzz project structure and returns a new instance.
    ///
    /// This will not clone libfuzzer-sys.
    /// Similar to `FuzzProject::new`, the fuzz directory will depend on `fuzz_dir_opt`.
    pub fn init(init: &options::Init, fuzz_dir_opt: Option<PathBuf>) -> Result<Self> {
        let project = Self::manage_initial_instance(fuzz_dir_opt)?;
        let fuzz_project = project.fuzz_dir();
        let manifest = Manifest::parse()?;

        // TODO: check if the project is already initialized
        fs::create_dir(fuzz_project)
            .with_context(|| format!("failed to create directory {}", fuzz_project.display()))?;

        let fuzz_targets_dir = fuzz_project.join(crate::FUZZ_TARGETS_DIR);
        fs::create_dir(&fuzz_targets_dir).with_context(|| {
            format!("failed to create directory {}", fuzz_targets_dir.display())
        })?;

        let cargo_toml = fuzz_project.join("Cargo.toml");
        let mut cargo = fs::File::create(&cargo_toml)
            .with_context(|| format!("failed to create {}", cargo_toml.display()))?;
        cargo
            .write_fmt(toml_template!(
                manifest.crate_name,
                manifest.edition,
                init.fuzz_engine,
                init.fuzzing_workspace
            ))
            .with_context(|| format!("failed to write to {}", cargo_toml.display()))?;

        let gitignore = fuzz_project.join(".gitignore");
        let mut ignore = fs::File::create(&gitignore)
            .with_context(|| format!("failed to create {}", gitignore.display()))?;
        ignore
            .write_fmt(gitignore_template!())
            .with_context(|| format!("failed to write to {}", gitignore.display()))?;

        project
            .create_target_template(&init.target, &manifest)
            .with_context(|| {
                format!(
                    "could not create template file for target {:?}",
                    init.target
                )
            })?;
        Ok(project)
    }

    pub fn list_targets(&self) -> Result<()> {
        for bin in &self.targets {
            println!("{}", bin);
        }
        Ok(())
    }

    /// Create a new fuzz target.
    pub fn add_target(&self, add: &options::Add, manifest: &Manifest) -> Result<()> {
        // Create corpus and artifact directories for the newly added target
        self.corpus_for(&add.target)?;
        self.artifacts_for(&add.target)?;
        self.create_target_template(&add.target, manifest)
            .with_context(|| format!("could not add target {:?}", add.target))
    }

    /// Add a new fuzz target script with a given name
    fn create_target_template(&self, target: &str, manifest: &Manifest) -> Result<()> {
        let target_path = self.target_path(target);

        // If the user manually created a fuzz project, but hasn't created any
        // targets yet, the `fuzz_targets` directory might not exist yet,
        // despite a `fuzz/Cargo.toml` manifest with the `metadata.cargo-fuzz`
        // key present. Make sure it does exist.
        fs::create_dir_all(self.fuzz_targets_dir())
            .context("ensuring that `fuzz_targets` directory exists failed")?;

        let mut script = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target_path)
            .with_context(|| format!("could not create target script file at {:?}", target_path))?;
        script.write_fmt(target_template!(manifest.edition))?;

        let mut cargo = fs::OpenOptions::new()
            .append(true)
            .open(self.manifest_path())?;
        Ok(cargo.write_fmt(toml_bin_template!(target))?)
    }

    fn cargo(&self, subcommand: &str, build: &BuildOptions) -> Result<Command> {
        let mut cmd = Command::new("cargo");
        cmd.arg(subcommand)
            .arg("--manifest-path")
            .arg(self.manifest_path())
            // --target=<TARGET> won't pass rustflags to build scripts
            .arg("--target")
            .arg(&build.triple);
        // we default to release mode unless debug mode is explicitly requested
        if !build.dev {
            // Note: setting `debug` doesn't only affect `-Cdebuginfo`. It also
            // affects how cargo uses `-Cstrip` and `-Csplit-debuginfo`.
            cmd.args([
                "--release",
                "--config",
                "profile.release.debug=\"line-tables-only\"",
            ]);
        }
        if build.verbose {
            cmd.arg("--verbose");
        }
        if build.no_default_features {
            cmd.arg("--no-default-features");
        }
        if build.all_features {
            cmd.arg("--all-features");
        }
        if let Some(ref features) = build.features {
            cmd.arg("--features").arg(features);
        }
        for flag in &build.unstable_flags {
            cmd.arg("-Z").arg(flag);
        }

        if (matches!(build.sanitizer, Sanitizer::Memory) || build.build_std || build.careful_mode)
            && !build.coverage
        {
            cmd.arg("-Z").arg("build-std");
        }

        let mut rustflags = String::new();
        rustflags.push_str(" -Cpasses=sancov-module");
        rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-level=4");
        rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-inline-8bit-counters");
        rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-pc-table");

        if !build.no_trace_compares {
            rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-trace-compares");
        }

        if build.trace_div {
            rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-trace-divs");
        }

        if build.trace_gep {
            rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-trace-geps");
        }

        if !build.no_cfg_fuzzing {
            rustflags.push_str(" --cfg fuzzing");
        }

        match build.strip_dead_code {
            // No flag, --strip-dead-code, or --strip-dead-code=true: do nothing, because rustc
            // strips dead code by default.
            None | Some(None) | Some(Some(true)) => {}

            // --strip-dead-code=false: explicitly include dead code.
            Some(Some(false)) => rustflags.push_str(" -Clink-dead-code"),
        }

        match build.disable_branch_folding {
            // No flag, --disable_branch_folding, or --disable-branch-folding=true: disable.
            None | Some(None) | Some(Some(true)) => {
                rustflags.push_str(" -Cllvm-args=-simplifycfg-branch-fold-threshold=0");
            }
            // --disable-branch-folding=false: do nothing.
            Some(Some(false)) => {}
        }

        if build.coverage {
            rustflags.push_str(" -Cinstrument-coverage");
        }

        if !matches!(build.sanitizer, Sanitizer::None) {
            // Select the appropriate sanitizer flag for the given rustc version
            let rust_version = RustVersion::discover()?;
            let sanitizer_flag = match rust_version.has_sanitizers_on_stable() {
                true => "-Csanitizer",
                false => "-Zsanitizer",
            };

            // Set rustc CLI arguments for the chosen sanitizer
            match build.sanitizer {
                Sanitizer::None => {} // needs no flags
                Sanitizer::Memory => {
                    // Memory sanitizer requires more flags to function than others:
                    // https://doc.rust-lang.org/unstable-book/compiler-flags/sanitizer.html#memorysanitizer
                    rustflags.push_str(&format!(
                        " {sanitizer_flag}=memory -Zsanitizer-memory-track-origins"
                    ))
                }
                _ => rustflags.push_str(&format!(" {sanitizer_flag}={}", build.sanitizer)),
            }

            // Not all sanitizers are stabilized on all platforms.
            // It is infeasible to keep up this code to date with the list.
            // So we just set `-Zunstable-options` required for some sanitizers
            // whenever we're on nightly on a recent enough compiler,
            // and let the compiler show an error message
            // if the user tries to enable a sanitizer not supported on their stable compiler.
            if rust_version.nightly && rust_version.has_sanitizers_on_stable() {
                rustflags.push_str(" -Zunstable-options")
            }
        }

        if build.careful_mode {
            rustflags.push_str(" -Zextra-const-ub-checks -Zstrict-init-checks --cfg careful");
        }
        if build.triple.contains("-linux-") {
            rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-stack-depth");
        }
        if !build.release || build.debug_assertions || build.careful_mode {
            rustflags.push_str(" -Cdebug-assertions");
        }
        if build.triple.contains("-msvc") && !build.no_include_main_msvc {
            // This forces the MSVC linker (which runs on Windows systems) to
            // find the entry point (i.e. the `main` function) within the
            // LibFuzzer `.rlib` file produced during the build.
            //
            // The `--no-include-main-msvc` argument disables the addition of
            // this linker argument. In certain situations, a user may not want
            // this argument included as part of the MSVC invocation.
            //
            // For example, if the user is attempting to build and fuzz a
            // Windows DLL (shared library), adding `/include:main` will force
            // the DLL to compile with an external reference to `main`.
            // DLLs/shared libraries are designed to be built as a separate
            // object file, intentionally left *without* knowledge of the entry
            // point. So, forcing a DLL to include `main` will cause linking to
            // fail. Using `--no-include-main-msvc` will allow the DLL to be
            // built without issue.
            rustflags.push_str(" -Clink-arg=/include:main");
        }

        if let Some(codegen_units) = build.codegen_units {
            rustflags.push_str(&format!(" -Ccodegen-units={}", codegen_units));
        }

        if !build.dev {
            // If release mode is enabled and the user hasn't chosen their own
            // codegen-units value then we force 1 CGU to be used in rustc.
            // This will result in slower compilations but it looks like the sancov
            // passes otherwise add `notEligibleToImport` annotations to functions
            // in LLVM IR, meaning that *nothing* can get imported with ThinLTO.
            // This means that in release mode, where ThinLTO is critical for
            // performance, we're taking a huge hit relative to actual release mode.
            // Local tests have once showed this to be a ~3x faster runtime where
            // otherwise functions like `Vec::as_ptr` aren't inlined.
            if build.codegen_units.is_none() {
                rustflags.push_str(" -Ccodegen-units=1");
            }
        }

        // If the user specified RUSTFLAGS, append that to the RUSTFLAGS
        // entries we are generating ourselves. That way the user's will
        // override ours.
        if let Ok(other_flags) = env::var("RUSTFLAGS") {
            rustflags.push(' ');
            rustflags.push_str(&other_flags);
        }
        cmd.env("RUSTFLAGS", rustflags);

        // For asan and tsan we have default options. Merge them to the given
        // options, so users can still provide their own options to e.g. disable
        // the leak sanitizer.  Options are colon-separated.
        match build.sanitizer {
            Sanitizer::Address => {
                let mut asan_opts = env::var("ASAN_OPTIONS").unwrap_or_default();
                if !asan_opts.is_empty() {
                    asan_opts.push(':');
                }
                asan_opts.push_str("detect_odr_violation=0");
                cmd.env("ASAN_OPTIONS", asan_opts);
            }

            Sanitizer::Thread => {
                let mut tsan_opts = env::var("TSAN_OPTIONS").unwrap_or_default();
                if !tsan_opts.is_empty() {
                    tsan_opts.push(':');
                }
                tsan_opts.push_str("report_signal_unsafe=0");
                cmd.env("TSAN_OPTIONS", tsan_opts);
            }

            _ => {}
        }

        Ok(cmd)
    }

    fn cargo_run(&self, build: &options::BuildOptions, fuzz_target: &str) -> Result<Command> {
        let mut cmd = self.cargo("run", build)?;
        cmd.arg("--bin").arg(fuzz_target);

        if let Some(target_dir) = &build.target_dir {
            cmd.arg("--target-dir").arg(target_dir);
        }

        let mut artifact_arg = ffi::OsString::from("-artifact_prefix=");
        artifact_arg.push(self.artifacts_for(fuzz_target)?);
        cmd.arg("--").arg(artifact_arg);

        Ok(cmd)
    }

    // note: never returns Ok(None) if build.coverage is true
    fn target_dir(&self, build: &options::BuildOptions) -> Result<Option<PathBuf>> {
        // Use the user-provided target directory, if provided. Otherwise if building for coverage,
        // use the coverage directory
        if let Some(target_dir) = build.target_dir.as_ref() {
            Ok(Some(PathBuf::from(target_dir)))
        } else if build.coverage {
            // To ensure that fuzzing and coverage-output generation can run in parallel, we
            // produce a separate binary for the coverage command.
            let current_dir = env::current_dir()?;
            Ok(Some(
                current_dir
                    .join("target")
                    .join(default_target())
                    .join("coverage"),
            ))
        } else {
            Ok(None)
        }
    }

    pub fn exec_build(
        &self,
        mode: options::BuildMode,
        build: &options::BuildOptions,
        fuzz_target: Option<&str>,
    ) -> Result<()> {
        let cargo_subcommand = match mode {
            options::BuildMode::Build => "build",
            options::BuildMode::Check => "check",
        };
        let mut cmd = self.cargo(cargo_subcommand, build)?;

        if let Some(fuzz_target) = fuzz_target {
            cmd.arg("--bin").arg(fuzz_target);
        } else {
            cmd.arg("--bins");
        }

        if let Some(target_dir) = self.target_dir(build)? {
            cmd.arg("--target-dir").arg(target_dir);
        }

        let status = cmd
            .status()
            .with_context(|| format!("failed to execute: {:?}", cmd))?;
        if !status.success() {
            bail!("failed to build fuzz script: {:?}", cmd);
        }

        Ok(())
    }

    fn get_artifacts_since(
        &self,
        target: &str,
        since: &time::SystemTime,
    ) -> Result<HashSet<PathBuf>> {
        let mut artifacts = HashSet::new();

        let artifacts_dir = self.artifacts_for(target)?;

        for entry in fs::read_dir(&artifacts_dir).with_context(|| {
            format!(
                "failed to read directory entries of {}",
                artifacts_dir.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read directory entry inside {}",
                    artifacts_dir.display()
                )
            })?;

            let metadata = entry
                .metadata()
                .context("failed to read artifact metadata")?;
            let modified = metadata
                .modified()
                .context("failed to get artifact modification time")?;
            if !metadata.is_file() || modified <= *since {
                continue;
            }

            artifacts.insert(entry.path());
        }

        Ok(artifacts)
    }

    fn run_fuzz_target_debug_formatter(
        &self,
        build: &BuildOptions,
        target: &str,
        artifact: &Path,
    ) -> Result<String> {
        let debug_output = tempfile::NamedTempFile::new().context("failed to create temp file")?;

        let mut cmd = self.cargo_run(build, target)?;
        cmd.stdin(Stdio::null());
        cmd.env("RUST_LIBFUZZER_DEBUG_PATH", debug_output.path());
        cmd.arg(artifact);

        let output = cmd
            .output()
            .with_context(|| format!("failed to run command: {:?}", cmd))?;

        if !output.status.success() {
            bail!(
                "Fuzz target '{target}' exited with failure when attempting to \
                 debug formatting an interesting input that we discovered!\n\n\
                 Artifact: {artifact}\n\n\
                 Command: {cmd:?}\n\n\
                 Status: {status}\n\n\
                 === stdout ===\n\
                 {stdout}\n\n\
                 === stderr ===\n\
                 {stderr}",
                target = target,
                status = output.status,
                cmd = cmd,
                artifact = artifact.display(),
                stdout = String::from_utf8_lossy(&output.stdout),
                stderr = String::from_utf8_lossy(&output.stderr),
            );
        }

        let debug = fs::read_to_string(&debug_output).context("failed to read temp file")?;
        Ok(debug)
    }

    /// Prints the debug output of an input test case
    pub fn debug_fmt_input(&self, debugfmt: &options::Fmt) -> Result<()> {
        if !debugfmt.input.exists() {
            bail!(
                "Input test case does not exist: {}",
                debugfmt.input.display()
            );
        }

        let debug = self
            .run_fuzz_target_debug_formatter(&debugfmt.build, &debugfmt.target, &debugfmt.input)
            .with_context(|| {
                format!(
                    "failed to run `cargo fuzz fmt` on input: {}",
                    debugfmt.input.display()
                )
            })?;

        eprintln!("\nOutput of `std::fmt::Debug`:\n");
        for l in debug.lines() {
            eprintln!("{}", l);
        }

        Ok(())
    }

    /// Fuzz a given fuzz target
    pub fn exec_fuzz(&self, run: &options::Run) -> Result<()> {
        self.exec_build(BuildMode::Build, &run.build, Some(&run.target))?;
        let mut cmd = self.cargo_run(&run.build, &run.target)?;

        for arg in &run.args {
            cmd.arg(arg);
        }

        if !run.corpus.is_empty() {
            for corpus in &run.corpus {
                cmd.arg(corpus);
            }
        } else {
            cmd.arg(self.corpus_for(&run.target)?);
        }

        if run.jobs != 1 {
            cmd.arg(format!("-fork={}", run.jobs));
        }

        // When libfuzzer finds failing inputs, those inputs will end up in the
        // artifacts directory. To easily filter old artifacts from new ones,
        // get the current time, and then later we only consider files modified
        // after now.
        let before_fuzzing = time::SystemTime::now();

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn command: {:?}", cmd))?;
        let status = child
            .wait()
            .with_context(|| format!("failed to wait on child process for command: {:?}", cmd))?;
        if status.success() {
            return Ok(());
        }

        // Get and print the `Debug` formatting of any new artifacts, along with
        // tips about how to reproduce failures and/or minimize test cases.

        let new_artifacts = self.get_artifacts_since(&run.target, &before_fuzzing)?;

        for artifact in new_artifacts {
            // To make the artifact a little easier to read, strip the current
            // directory prefix when possible.
            let artifact = strip_current_dir_prefix(&artifact);

            eprintln!("\n{:─<80}", "");
            eprintln!("\nFailing input:\n\n\t{}\n", artifact.display());

            // Note: ignore errors when running the debug formatter. This most
            // likely just means that we're dealing with a fuzz target that uses
            // an older version of the libfuzzer crate, and doesn't support
            // `RUST_LIBFUZZER_DEBUG_PATH`.
            if let Ok(debug) =
                self.run_fuzz_target_debug_formatter(&run.build, &run.target, artifact)
            {
                eprintln!("Output of `std::fmt::Debug`:\n");
                for l in debug.lines() {
                    eprintln!("\t{}", l);
                }
                eprintln!();
            }

            let fuzz_dir = if self.fuzz_dir_is_default_path() {
                String::new()
            } else {
                format!(" --fuzz-dir {}", self.fuzz_dir().display())
            };

            eprintln!(
                "Reproduce with:\n\n\tcargo fuzz run{fuzz_dir}{options} {target} {artifact}\n",
                fuzz_dir = &fuzz_dir,
                options = &run.build,
                target = &run.target,
                artifact = artifact.display()
            );
            eprintln!(
                "Minimize test case with:\n\n\tcargo fuzz tmin{fuzz_dir}{options} {target} {artifact}\n",
                fuzz_dir = &fuzz_dir,
                options = &run.build,
                target = &run.target,
                artifact = artifact.display()
            );
        }

        eprintln!("{:─<80}\n", "");
        bail!("Fuzz target exited with {}", status)
    }

    pub fn exec_tmin(&self, tmin: &options::Tmin) -> Result<()> {
        self.exec_build(BuildMode::Build, &tmin.build, Some(&tmin.target))?;
        let mut cmd = self.cargo_run(&tmin.build, &tmin.target)?;
        cmd.arg("-minimize_crash=1")
            .arg(format!("-runs={}", tmin.runs))
            .arg(&tmin.test_case);

        for arg in &tmin.args {
            cmd.arg(arg);
        }

        let before_tmin = time::SystemTime::now();

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn command: {:?}", cmd))?;
        let status = child
            .wait()
            .with_context(|| format!("failed to wait on child process for command: {:?}", cmd))?;
        if !status.success() {
            eprintln!("\n{:─<80}\n", "");
            return Err(anyhow!("Command `{:?}` exited with {}", cmd, status)).with_context(|| {
                "Test case minimization failed.\n\
                 \n\
                 Usually this isn't a hard error, and just means that libfuzzer\n\
                 doesn't know how to minimize the test case any further while\n\
                 still reproducing the original crash.\n\
                 \n\
                 See the logs above for details."
            });
        }

        // Find and display the most recently modified artifact, which is
        // presumably the result of minification. Yeah, this is a little hacky,
        // but it seems to work. I don't want to parse libfuzzer's stderr output
        // and hope it never changes.
        let minimized_artifact = self
            .get_artifacts_since(&tmin.target, &before_tmin)?
            .into_iter()
            .max_by_key(|a| {
                a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(time::SystemTime::UNIX_EPOCH)
            });

        if let Some(artifact) = minimized_artifact {
            let artifact = strip_current_dir_prefix(&artifact);

            eprintln!("\n{:─<80}\n", "");
            eprintln!("Minimized artifact:\n\n\t{}\n", artifact.display());

            // Note: ignore errors when running the debug formatter. This most
            // likely just means that we're dealing with a fuzz target that uses
            // an older version of the libfuzzer crate, and doesn't support
            // `RUST_LIBFUZZER_DEBUG_PATH`.
            if let Ok(debug) =
                self.run_fuzz_target_debug_formatter(&tmin.build, &tmin.target, artifact)
            {
                eprintln!("Output of `std::fmt::Debug`:\n");
                for l in debug.lines() {
                    eprintln!("\t{}", l);
                }
                eprintln!();
            }

            let fuzz_dir = if self.fuzz_dir_is_default_path() {
                String::new()
            } else {
                format!(" --fuzz-dir {}", self.fuzz_dir().display())
            };

            eprintln!(
                "Reproduce with:\n\n\tcargo fuzz run{fuzz_dir}{options} {target} {artifact}\n",
                fuzz_dir = &fuzz_dir,
                options = &tmin.build,
                target = &tmin.target,
                artifact = artifact.display()
            );
        }

        Ok(())
    }

    /// Run mutant-guided fuzzing
    pub fn exec_mutfuzz(&self, opts: &options::MutFuzz) -> Result<()> {
        use crate::mutfuzz::orchestrator;

        // Build the fuzz target first
        self.exec_build(BuildMode::Build, &opts.build, Some(&opts.target))?;

        // Locate the compiled binary
        let bin_path = orchestrator::get_fuzz_bin_path(self.fuzz_dir(), &opts.build, &opts.target)?;

        // Set up corpus and artifacts directories
        let corpus_dir = if !opts.corpus.is_empty() {
            std::path::PathBuf::from(&opts.corpus[0])
        } else {
            self.corpus_for(&opts.target)?
        };
        let artifacts_dir = self.artifacts_for(&opts.target)?;

        orchestrator::run(
            self.fuzz_dir(),
            &artifacts_dir,
            &corpus_dir,
            &bin_path,
            opts,
        )
    }

    pub fn exec_cmin(&self, cmin: &options::Cmin) -> Result<()> {
        self.exec_build(BuildMode::Build, &cmin.build, Some(&cmin.target))?;
        let mut cmd = self.cargo_run(&cmin.build, &cmin.target)?;

        for arg in &cmin.args {
            cmd.arg(arg);
        }

        let corpus = if let Some(corpus) = cmin.corpus.clone() {
            corpus
        } else {
            self.corpus_for(&cmin.target)?
        };
        let corpus = corpus
            .to_str()
            .ok_or_else(|| anyhow!("corpus must be valid unicode"))?
            .to_owned();

        let tmp = tempfile::TempDir::new_in(self.fuzz_dir())?;
        let tmp_corpus = tmp.path().join("corpus");
        fs::create_dir(&tmp_corpus)?;

        cmd.arg("-merge=1").arg(&tmp_corpus).arg(&corpus);

        // Spawn cmd in child process instead of exec-ing it
        let status = cmd
            .status()
            .with_context(|| format!("could not execute command: {:?}", cmd))?;
        if status.success() {
            // move corpus directory into tmp to auto delete it
            fs::rename(&corpus, tmp.path().join("old"))?;
            fs::rename(tmp.path().join("corpus"), corpus)?;
        } else {
            println!("Failed to minimize corpus: {}", status);
        }

        Ok(())
    }

    /// Produce coverage information for a given corpus
    pub fn exec_coverage(self, coverage: &options::Coverage) -> Result<()> {
        // Build project with source-based coverage generation enabled.
        self.exec_build(BuildMode::Build, &coverage.build, Some(&coverage.target))?;

        // Retrieve corpus directories.
        let corpora = if coverage.corpus.is_empty() {
            vec![self.corpus_for(&coverage.target)?]
        } else {
            coverage
                .corpus
                .iter()
                .map(|name| Path::new(name).to_path_buf())
                .collect()
        };

        // Collect the (non-directory) readable input files from the corpora.
        let files_and_dirs = corpora.iter().flat_map(fs::read_dir).flatten().flatten();
        let mut readable_input_files = files_and_dirs
            .filter(|file| match file.file_type() {
                Ok(ft) => ft.is_file(),
                _ => false,
            })
            .peekable();
        if readable_input_files.peek().is_none() {
            bail!(
                "The corpus does not contain program-input files. \
                 Coverage information requires existing input files. \
                 Try running the fuzzer first (`cargo fuzz run ...`) to generate a corpus, \
                 or provide a nonempty corpus directory."
            )
        }

        let (coverage_out_raw_dir, coverage_out_file) = self.coverage_for(&coverage.target)?;

        let mut all_input_files: Vec<PathBuf> = corpora
            .iter()
            .flat_map(|corpus_dir| {
                fs::read_dir(corpus_dir)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                    .map(|entry| entry.path())
            })
            .collect();
        all_input_files.sort();

        if all_input_files.is_empty() {
            bail!("No input files found in corpus directories");
        }

        const MIN_BATCH_SIZE: usize = 100;
        let num_files = all_input_files.len();
        let requested_workers = usize::from(coverage.jobs);

        let effective_workers = if num_files < MIN_BATCH_SIZE {
            1
        } else {
            (num_files / MIN_BATCH_SIZE).min(requested_workers)
        };

        let batch_size = num_files.div_ceil(effective_workers);

        eprintln!(
            "Processing {} input files using {} workers (batch size: ~{})",
            num_files, effective_workers, batch_size
        );

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(effective_workers)
            .build()
            .context("Failed to create thread pool")?;

        let result = pool.install(|| {
            all_input_files
                .par_chunks(batch_size)
                .enumerate()
                .try_for_each(|(batch_idx, file_batch)| -> Result<()> {
                    eprintln!(
                        "Worker {}: Generating coverage for {} files",
                        batch_idx,
                        file_batch.len()
                    );

                    let mut cmd = self.coverage_cmd_with_files(
                        coverage,
                        &coverage_out_raw_dir,
                        file_batch,
                        batch_idx,
                    )?;

                    let status_result = cmd.status();

                    match status_result {
                        Err(e) if e.kind() == std::io::ErrorKind::ArgumentListTooLong => {
                            eprintln!(
                                "Worker {}: Argument list too long, falling back to temp directory",
                                batch_idx
                            );
                            let (mut cmd, _temp_corpus, _dummy_corpus) = self
                                .coverage_cmd_with_dir(
                                    coverage,
                                    &coverage_out_raw_dir,
                                    file_batch,
                                    batch_idx,
                                )?;
                            let status = cmd
                                .status()
                                .with_context(|| format!("Failed to run command: {:?}", cmd))?;
                            if !status.success() {
                                return Err(anyhow!(
                                    "Command exited with failure status {}: {:?}",
                                    status,
                                    cmd
                                ))
                                .context("Failed to generate coverage data");
                            }
                        }
                        Err(e) => return Err(e).context("Failed to run coverage command"),
                        Ok(status) => {
                            if !status.success() {
                                return Err(anyhow!(
                                    "Command exited with failure status {}: {:?}",
                                    status,
                                    cmd
                                ))
                                .context("Failed to generate coverage data");
                            }
                        }
                    }

                    Ok(())
                })
        });

        result?;

        let mut profdata_bin_path = coverage.llvm_path.clone().unwrap_or(rustlib()?);
        profdata_bin_path.push(format!("llvm-profdata{}", env::consts::EXE_SUFFIX));
        self.merge_coverage(
            &profdata_bin_path,
            &coverage_out_raw_dir,
            &coverage_out_file,
        )?;

        Ok(())
    }

    fn get_coverage_bin_path(&self, coverage: &options::Coverage) -> Result<PathBuf> {
        let profile_subdir = if coverage.build.dev {
            "debug"
        } else {
            "release"
        };

        let target_dir = self
            .target_dir(&coverage.build)?
            .expect("target dir for coverage command should never be None");

        Ok(target_dir
            .join(&coverage.build.triple)
            .join(profile_subdir)
            .join(&coverage.target))
    }

    fn coverage_cmd_with_dir(
        &self,
        coverage: &options::Coverage,
        coverage_dir: &Path,
        files: &[PathBuf],
        batch_id: usize,
    ) -> Result<(Command, tempfile::TempDir, tempfile::TempDir)> {
        let temp_corpus = tempfile::tempdir()?;
        let temp_corpus_path = temp_corpus.path();

        for file in files {
            if let Some(file_name) = file.file_name() {
                let dest = temp_corpus_path.join(file_name);
                fs::hard_link(file, &dest)
                    .or_else(|_| fs::copy(file, &dest).map(|_| ()))
                    .with_context(|| {
                        format!(
                            "Failed to link or copy {} to temp directory",
                            file.display()
                        )
                    })?;
            }
        }

        let bin_path = self.get_coverage_bin_path(coverage)?;
        let mut cmd = Command::new(bin_path);

        cmd.env(
            "LLVM_PROFILE_FILE",
            coverage_dir.join(format!("batch-{}.profraw", batch_id)),
        );

        cmd.arg("-merge=1");
        let dummy_merged_corpus = tempfile::tempdir()?;
        cmd.arg(dummy_merged_corpus.path());
        cmd.arg(temp_corpus_path);

        for arg in &coverage.args {
            cmd.arg(arg);
        }

        Ok((cmd, temp_corpus, dummy_merged_corpus))
    }

    fn coverage_cmd_with_files(
        &self,
        coverage: &options::Coverage,
        coverage_dir: &Path,
        files: &[PathBuf],
        batch_id: usize,
    ) -> Result<Command> {
        let bin_path = self.get_coverage_bin_path(coverage)?;
        let mut cmd = Command::new(bin_path);

        cmd.env(
            "LLVM_PROFILE_FILE",
            coverage_dir.join(format!("batch-{}.profraw", batch_id)),
        );

        for arg in &coverage.args {
            cmd.arg(arg);
        }

        for file in files {
            cmd.arg(file);
        }

        Ok(cmd)
    }

    fn merge_coverage(
        &self,
        profdata_bin_path: &Path,
        profdata_raw_path: &Path,
        profdata_out_path: &Path,
    ) -> Result<()> {
        let mut merge_cmd = Command::new(profdata_bin_path);
        merge_cmd.arg("merge").arg("-sparse");
        merge_cmd.arg(profdata_raw_path);
        merge_cmd.arg("-o").arg(profdata_out_path);

        eprintln!("Merging raw coverage data...");
        let status = merge_cmd
            .status()
            .with_context(|| format!("Failed to run command: {:?}", merge_cmd))
            .with_context(|| "Merging raw coverage files failed.\n\
                              \n\
                              Do you have LLVM coverage tools installed?\n\
                              https://doc.rust-lang.org/rustc/instrument-coverage.html#installing-llvm-coverage-tools")?;
        if !status.success() {
            Err(anyhow!(
                "Command exited with failure status {}: {:?}",
                status,
                merge_cmd
            ))
            .context("Merging raw coverage files failed")?;
        }

        if profdata_out_path.exists() {
            eprintln!("Coverage data merged and saved in {:?}.", profdata_out_path);
            Ok(())
        } else {
            bail!("Coverage data could not be merged.")
        }
    }

    pub(crate) fn fuzz_dir(&self) -> &Path {
        &self.fuzz_dir
    }

    fn manifest_path(&self) -> PathBuf {
        self.fuzz_dir().join("Cargo.toml")
    }

    /// Returns paths to the `coverage/<target>/raw` directory and `coverage/<target>/coverage.profdata` file.
    fn coverage_for(&self, target: &str) -> Result<(PathBuf, PathBuf)> {
        let mut coverage_data = self.fuzz_dir().to_owned();
        coverage_data.push("coverage");
        coverage_data.push(target);
        let mut coverage_raw = coverage_data.clone();
        coverage_data.push("coverage.profdata");
        coverage_raw.push("raw");
        fs::create_dir_all(&coverage_raw).with_context(|| {
            format!("could not make a coverage directory at {:?}", coverage_raw)
        })?;
        Ok((coverage_raw, coverage_data))
    }

    fn corpus_for(&self, target: &str) -> Result<PathBuf> {
        let mut p = self.fuzz_dir().to_owned();
        p.push("corpus");
        p.push(target);
        fs::create_dir_all(&p)
            .with_context(|| format!("could not make a corpus directory at {:?}", p))?;
        Ok(p)
    }

    fn artifacts_for(&self, target: &str) -> Result<PathBuf> {
        let mut p = self.fuzz_dir().to_owned();
        p.push("artifacts");
        p.push(target);

        // This adds a trailing slash, which is necessary for libFuzzer, because
        // it does simple string concatenation when joining paths.
        p.push("");

        fs::create_dir_all(&p)
            .with_context(|| format!("could not make a artifact directory at {:?}", p))?;

        Ok(p)
    }

    fn fuzz_targets_dir(&self) -> PathBuf {
        let mut root = self.fuzz_dir().to_owned();
        if root.join(crate::FUZZ_TARGETS_DIR_OLD).exists() {
            println!(
                "warning: The `fuzz/fuzzers/` directory has renamed to `fuzz/fuzz_targets/`. \
                 Please rename the directory as such. This will become a hard error in the \
                 future."
            );
            root.push(crate::FUZZ_TARGETS_DIR_OLD);
        } else {
            root.push(crate::FUZZ_TARGETS_DIR);
        }
        root
    }

    fn target_path(&self, target: &str) -> PathBuf {
        let mut root = self.fuzz_targets_dir();
        root.push(target);
        root.set_extension("rs");
        root
    }

    fn manifest(&self) -> Result<toml::Value> {
        let filename = self.manifest_path();
        let mut file = fs::File::open(&filename)
            .with_context(|| format!("could not read the manifest file: {}", filename.display()))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        toml::from_slice(&data).with_context(|| {
            format!(
                "could not decode the manifest file at {}",
                filename.display()
            )
        })
    }

    // If `fuzz_dir_opt` is `None`, returns a new instance with the default fuzz project
    // path. Otherwise, returns a new instance with the inner content of `fuzz_dir_opt`.
    fn manage_initial_instance(fuzz_dir_opt: Option<PathBuf>) -> Result<Self> {
        let fuzz_dir = if let Some(el) = fuzz_dir_opt {
            el
        } else {
            find_package()?.join(DEFAULT_FUZZ_DIR)
        };
        Ok(FuzzProject {
            fuzz_dir,
            targets: Vec::new(),
        })
    }

    fn fuzz_dir_is_default_path(&self) -> bool {
        self.fuzz_dir.ends_with(DEFAULT_FUZZ_DIR)
    }

    /// Detect a compatible libfuzzer-sys version from cargo metadata without
    /// resolving dependencies or scraping the lockfile.
    /// Detect the exact locked version of libfuzzer-sys from the fuzz project's
    /// Cargo.lock. The shim must match this version exactly for the patch to work.
    fn detect_libfuzzer_version(&self) -> Result<String> {
        // Try Cargo.lock first — the exact resolved version is what matters for patch
        let lockfile_path = self.fuzz_dir().join("Cargo.lock");
        if lockfile_path.exists() {
            let content = fs::read_to_string(&lockfile_path)?;
            if let Ok(lock) = toml::from_str::<toml::Value>(&content) {
                if let Some(packages) = lock.get("package").and_then(toml::Value::as_array) {
                    for pkg in packages {
                        let name = pkg.get("name").and_then(toml::Value::as_str);
                        let version = pkg.get("version").and_then(toml::Value::as_str);
                        if name == Some("libfuzzer-sys") {
                            if let Some(v) = version {
                                return Ok(v.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Fallback: parse dependency requirement from Cargo.toml metadata
        let metadata = MetadataCommand::new()
            .manifest_path(self.manifest_path())
            .no_deps()
            .exec()
            .context("failed to load cargo metadata for fuzz project")?;

        if let Some(req) = metadata
            .packages
            .iter()
            .find(|pkg| pkg.manifest_path.as_std_path() == self.manifest_path())
            .and_then(|pkg| {
                pkg.dependencies
                    .iter()
                    .find(|dep| dep.name == "libfuzzer-sys")
                    .map(|dep| dep.req.to_string())
            })
        {
            if let Some(version) = version_from_dependency_req(&req) {
                return Ok(version);
            }
        }

        Ok("0.4.0".to_string())
    }

    /// Write the callgraph shim crate to a temp directory and return its path.
    /// The shim is a drop-in replacement for `libfuzzer-sys` that provides the same
    /// `fuzz_target!` macro but replaces libFuzzer with trace-pc-guard edge collection.
    fn write_callgraph_shim(&self) -> Result<tempfile::TempDir> {
        use crate::callgraph_shim;

        let version = self.detect_libfuzzer_version()?;
        let shim_dir =
            tempfile::tempdir().context("failed to create temp directory for callgraph shim")?;
        let shim_path = shim_dir.path();

        fs::create_dir_all(shim_path.join("src"))?;
        fs::write(
            shim_path.join("Cargo.toml"),
            callgraph_shim::cargo_toml(&version),
        )?;
        fs::write(shim_path.join("src").join("lib.rs"), callgraph_shim::LIB_RS)?;
        Ok(shim_dir)
    }

    /// Build a cargo command with callgraph-specific RUSTFLAGS and the shim patched in.
    fn cargo_callgraph(&self, build: &BuildOptions, shim_path: &Path) -> Result<Command> {
        let mut cmd = Command::new("cargo");
        cmd.arg("build")
            .arg("--manifest-path")
            .arg(self.manifest_path());

        if !build.dev {
            cmd.arg("--release");
            // Use full debug info (not just line-tables-only) so addr2line can
            // resolve function names, not just source locations.
            cmd.env("CARGO_PROFILE_RELEASE_DEBUG", "2");
        }

        cmd.arg("--target").arg(&build.triple);

        if build.verbose {
            cmd.arg("-v");
        }

        if build.no_default_features {
            cmd.arg("--no-default-features");
        }

        if build.all_features {
            cmd.arg("--all-features");
        }

        if let Some(ref features) = build.features {
            cmd.arg("--features").arg(features);
        }

        // Patch libfuzzer-sys to our shim crate
        let patch_config = format!(
            "patch.crates-io.libfuzzer-sys.path='{}'",
            shim_path.display()
        );
        cmd.arg("--config").arg(&patch_config);

        // Callgraph-specific RUSTFLAGS: trace-pc-guard + pc-table for edge collection,
        // instrument-coverage for profraw data, NO inline-8bit-counters (that's for libFuzzer).
        let mut rustflags = String::new();
        rustflags.push_str(" -Cpasses=sancov-module");
        rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-level=3");
        rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-trace-pc-guard");
        rustflags.push_str(" -Cllvm-args=-sanitizer-coverage-pc-table");
        rustflags.push_str(" -Cinstrument-coverage");

        if !build.no_cfg_fuzzing {
            rustflags.push_str(" --cfg fuzzing");
        }

        // No sanitizer for profiling builds — we just want coverage + call edges.

        // Merge user RUSTFLAGS if present
        if let Ok(other) = env::var("RUSTFLAGS") {
            rustflags.push(' ');
            rustflags.push_str(&other);
        }

        cmd.env("RUSTFLAGS", rustflags);

        Ok(cmd)
    }

    /// Returns paths to the callgraph output directories and DOT file.
    /// profraw_dir: for .profraw files (fed to llvm-profdata merge)
    /// edges_dir: for .bin edge files (our custom format)
    fn callgraph_for(&self, target: &str) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let mut callgraph_dir = self.fuzz_dir().to_owned();
        callgraph_dir.push("callgraph");
        callgraph_dir.push(target);
        let profraw_dir = callgraph_dir.join("raw");
        let edges_dir = callgraph_dir.join("edges");
        fs::create_dir_all(&profraw_dir).with_context(|| {
            format!("could not create callgraph directory at {:?}", profraw_dir)
        })?;
        fs::create_dir_all(&edges_dir)
            .with_context(|| format!("could not create edges directory at {:?}", edges_dir))?;
        let dot_file = callgraph_dir.join("callgraph.dot");
        Ok((profraw_dir, edges_dir, dot_file))
    }

    /// Execute callgraph collection: build profiling binary with shim patched in,
    /// replay corpus, symbolize PCs, and emit a DOT call graph.
    pub fn exec_callgraph(&self, cg: &options::Callgraph) -> Result<()> {
        let target = &cg.target;

        // 1. Write the shim crate to a temp directory
        let shim_dir = self.write_callgraph_shim()?;
        eprintln!("Building callgraph binary for '{}'...", target);

        // 2. Build the original fuzz target with our shim patched in
        let mut cmd = self.cargo_callgraph(&cg.build, shim_dir.path())?;
        cmd.arg("--bin").arg(target);

        // Use a separate target-dir so we don't conflict with normal fuzz builds.
        // Respect CARGO_TARGET_DIR if set (e.g. in tests), otherwise use default.
        let base_target_dir = if let Some(ref td) = cg.build.target_dir {
            PathBuf::from(td)
        } else if let Ok(td) = env::var("CARGO_TARGET_DIR") {
            PathBuf::from(td)
        } else {
            env::current_dir()?.join("target")
        };
        let callgraph_target_dir = base_target_dir.join(default_target()).join("callgraph");
        cmd.arg("--target-dir").arg(&callgraph_target_dir);

        let status = cmd
            .status()
            .with_context(|| format!("failed to execute: {:?}", cmd))?;
        if !status.success() {
            bail!("failed to build callgraph binary: {:?}", cmd);
        }

        // 3. Locate the built binary
        let profile_subdir = if cg.build.dev { "debug" } else { "release" };
        let bin_path = callgraph_target_dir
            .join(&cg.build.triple)
            .join(profile_subdir)
            .join(target);

        if !bin_path.exists() {
            bail!("callgraph binary not found at {:?}", bin_path);
        }

        // 4. Collect corpus files
        let corpora = if cg.corpus.is_empty() {
            vec![self.corpus_for(target)?]
        } else {
            cg.corpus.iter().map(|s| PathBuf::from(s)).collect()
        };

        let all_input_files: Vec<PathBuf> = corpora
            .iter()
            .flat_map(|corpus_dir| {
                fs::read_dir(corpus_dir)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                    .map(|entry| entry.path())
            })
            .collect();

        if all_input_files.is_empty() {
            bail!(
                "No input files found in corpus directories. \
                 Run the fuzzer first (`cargo fuzz run {}`) to generate a corpus.",
                target
            );
        }

        let (profraw_dir, edges_dir, dot_file) = self.callgraph_for(target)?;
        clear_directory(&profraw_dir)?;
        clear_directory(&edges_dir)?;

        let num_files = all_input_files.len();
        let effective_workers = usize::from(cg.jobs).min(num_files).max(1);
        let seed_jobs: Vec<_> = all_input_files
            .into_iter()
            .enumerate()
            .map(|(index, seed_path)| SeedReplayJob {
                artifact_stem: seed_artifact_stem(index, &seed_path),
                seed_path,
            })
            .collect();

        eprintln!(
            "Replaying {} corpus files using {} workers (per-seed tracing)...",
            num_files, effective_workers
        );

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(effective_workers)
            .build()
            .context("Failed to create thread pool")?;

        let result = pool.install(|| {
            seed_jobs.par_iter().try_for_each(|job| -> Result<()> {
                let edges_file = edges_dir.join(format!("{}.json", job.artifact_stem));
                let profraw_file = profraw_dir.join(format!("{}.profraw", job.artifact_stem));

                let mut cmd = Command::new(&bin_path);
                cmd.env("CALLGRAPH_EDGES_FILE", &edges_file);
                cmd.env("LLVM_PROFILE_FILE", &profraw_file);
                cmd.arg(&job.seed_path);

                cmd.arg("--");

                for arg in &cg.args {
                    cmd.arg(arg);
                }

                let status = cmd
                    .status()
                    .with_context(|| format!("Failed to run callgraph binary: {:?}", cmd))?;

                if !status.success() {
                    eprintln!(
                        "Warning: Seed {:?} exited with status {}",
                        job.seed_path, status
                    );
                }

                Ok(())
            })
        });

        result?;

        // 6. Merge profraw files
        let mut profdata_bin_path = cg.llvm_path.clone().unwrap_or(rustlib()?);
        profdata_bin_path.push(format!("llvm-profdata{}", env::consts::EXE_SUFFIX));
        let profdata_out = profraw_dir.parent().unwrap().join("coverage.profdata");
        self.merge_coverage(&profdata_bin_path, &profraw_dir, &profdata_out)?;

        // 7. Read per-seed edge files, collect unique PCs, symbolize, and emit outputs.
        eprintln!("Processing call graph edges...");
        let seed_traces = load_seed_traces(&seed_jobs, &edges_dir)?;
        let (edges, pc_table) = merge_seed_traces(&seed_traces);

        if edges.is_empty() {
            bail!("No call graph edges collected. The corpus may be too small or the target too simple.");
        }

        let symbol_cache_path = dot_file.with_file_name("symbol-cache.json");
        let pc_to_func = symbolize_pcs(&bin_path, &pc_table, &symbol_cache_path)?;

        // Build function-level call graph
        let func_edges = aggregate_function_edges(&edges, &pc_table, &pc_to_func);
        let seed_summaries = summarize_seed_traces(&seed_traces, &pc_to_func);

        let cov_export_path = if let Some(ref llvm_path) = cg.llvm_path {
            llvm_path.join(format!("llvm-cov{}", env::consts::EXE_SUFFIX))
        } else {
            let mut rustlib_path = rustlib()?;
            rustlib_path.push(format!("llvm-cov{}", env::consts::EXE_SUFFIX));
            if rustlib_path.exists() {
                rustlib_path
            } else {
                PathBuf::from(format!("llvm-cov{}", env::consts::EXE_SUFFIX))
            }
        };
        let coverage_by_function =
            export_function_coverage(&cov_export_path, &bin_path, &profdata_out)?;
        let callgraph_json = dot_file.with_file_name("callgraph.json");
        write_callgraph_json(&callgraph_json, &func_edges, &coverage_by_function)?;
        let seed_hits_json = dot_file.with_file_name("seed_hits.json");
        write_seed_hits_json(&seed_hits_json, &seed_summaries)?;
        let workspace_root = self
            .fuzz_dir()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(env::current_dir()?);
        let partition_dir = dot_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("partitions");
        write_partition_outputs(
            &partition_dir,
            &cg.partitioner,
            usize::from(cg.partitions),
            &func_edges,
            &coverage_by_function,
            &seed_summaries,
            &workspace_root,
        )?;

        // Write DOT file
        write_dot_callgraph(&dot_file, &func_edges)?;

        eprintln!("Call graph written to {:?}", dot_file);
        eprintln!("Call graph metadata written to {:?}", callgraph_json);
        eprintln!("Per-seed call graph data written to {:?}", seed_hits_json);
        eprintln!("Partition outputs written to {:?}", partition_dir);
        eprintln!("Coverage data at {:?}", profdata_out);
        eprintln!(
            "Visualize with: dot -Tsvg {} -o callgraph.svg",
            dot_file.display()
        );

        Ok(())
    }
}

fn clear_directory(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("could not create directory at {:?}", dir))?;
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("failed to remove directory {:?}", path))?;
        } else {
            fs::remove_file(&path).with_context(|| format!("failed to remove file {:?}", path))?;
        }
    }

    Ok(())
}

fn seed_artifact_stem(index: usize, seed_path: &Path) -> String {
    let file_name = seed_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("seed");
    let sanitized: String = file_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    format!("seed-{index:05}-{sanitized}")
}

fn version_from_dependency_req(req: &str) -> Option<String> {
    let mut components = Vec::new();
    let mut current = String::new();

    for ch in req.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            components.push(current.parse::<u64>().ok()?);
            current.clear();
            if components.len() == 3 {
                break;
            }
        }
    }

    if !current.is_empty() && components.len() < 3 {
        components.push(current.parse::<u64>().ok()?);
    }

    if components.is_empty() {
        return None;
    }

    while components.len() < 3 {
        components.push(0);
    }

    Some(format!(
        "{}.{}.{}",
        components[0], components[1], components[2]
    ))
}

fn read_edge_file(path: &Path) -> Result<(HashMap<(u32, u32), u64>, HashMap<u32, u64>)> {
    let data = fs::read(path).with_context(|| format!("failed to read edge file {:?}", path))?;
    let json: Value =
        serde_json::from_slice(&data).with_context(|| format!("invalid edge json {:?}", path))?;
    let mut edges = HashMap::new();
    let mut pcs = HashMap::new();

    if let Some(items) = json.get("edges").and_then(Value::as_array) {
        for item in items {
            let prev = item
                .get("prev")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok());
            let cur = item
                .get("cur")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok());
            let count = item.get("count").and_then(Value::as_u64);
            if let (Some(prev), Some(cur), Some(count)) = (prev, cur, count) {
                *edges.entry((prev, cur)).or_insert(0) += count;
            }
        }
    }

    if let Some(items) = json.get("pcs").and_then(Value::as_array) {
        for item in items {
            let guard_id = item
                .get("guard_id")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok());
            let pc = item.get("pc").and_then(Value::as_u64);
            if let (Some(guard_id), Some(pc)) = (guard_id, pc) {
                pcs.entry(guard_id).or_insert(pc);
            }
        }
    }

    Ok((edges, pcs))
}

fn load_seed_traces(seed_jobs: &[SeedReplayJob], edges_dir: &Path) -> Result<Vec<SeedTrace>> {
    let mut traces = Vec::with_capacity(seed_jobs.len());

    for job in seed_jobs {
        let edges_file = edges_dir.join(format!("{}.json", job.artifact_stem));
        if !edges_file.exists() {
            eprintln!(
                "Warning: missing edge file for seed {:?} at {:?}",
                job.seed_path, edges_file
            );
            continue;
        }

        let (edges, pc_table) = read_edge_file(&edges_file)?;
        traces.push(SeedTrace {
            seed_path: job.seed_path.clone(),
            artifact_stem: job.artifact_stem.clone(),
            edges,
            pc_table,
        });
    }

    Ok(traces)
}

fn merge_seed_traces(seed_traces: &[SeedTrace]) -> (HashMap<(u32, u32), u64>, HashMap<u32, u64>) {
    let mut all_edges = HashMap::new();
    let mut all_pcs = HashMap::new();

    for trace in seed_traces {
        for (&edge, &count) in &trace.edges {
            *all_edges.entry(edge).or_insert(0) += count;
        }
        for (&guard_id, &pc) in &trace.pc_table {
            all_pcs.entry(guard_id).or_insert(pc);
        }
    }

    (all_edges, all_pcs)
}

fn summarize_seed_traces(
    seed_traces: &[SeedTrace],
    pc_to_func: &HashMap<u64, String>,
) -> Vec<SeedTraceSummary> {
    seed_traces
        .iter()
        .map(|trace| {
            let func_edges = aggregate_function_edges(&trace.edges, &trace.pc_table, pc_to_func);
            let mut function_hits = BTreeMap::new();
            let mut edge_hits: Vec<_> = func_edges.into_iter().collect();
            edge_hits.sort_by(|a, b| a.0.cmp(&b.0));

            for ((caller, callee), count) in &edge_hits {
                *function_hits.entry(caller.clone()).or_insert(0) += *count;
                *function_hits.entry(callee.clone()).or_insert(0) += *count;
            }

            SeedTraceSummary {
                seed_path: trace.seed_path.clone(),
                artifact_stem: trace.artifact_stem.clone(),
                function_hits,
                edge_hits,
            }
        })
        .collect()
}

/// Symbolize a set of normalized PCs using addr2line.
/// Returns a map from PC -> function name.
/// The shim normalizes runtime PCs against the replay binary's load base
/// before writing them, so PIE/ASLR do not affect symbolization here.
fn load_symbol_cache(path: &Path, binary_path: &Path) -> Result<HashMap<u64, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let data = fs::read(path).with_context(|| format!("failed to read symbol cache {:?}", path))?;
    let json: Value = serde_json::from_slice(&data)
        .with_context(|| format!("invalid symbol cache json {:?}", path))?;
    let metadata = fs::metadata(binary_path)
        .with_context(|| format!("failed to stat callgraph binary {:?}", binary_path))?;
    let mtime_ns = metadata
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let size = metadata.len();

    if json.get("version").and_then(Value::as_u64) != Some(SYMBOL_CACHE_VERSION)
        || json
            .get("binary_size")
            .and_then(Value::as_u64)
            .zip(json.get("binary_mtime_ns").and_then(Value::as_u64))
            != Some((size, mtime_ns))
    {
        return Ok(HashMap::new());
    }

    let mut cache = HashMap::new();
    for entry in json
        .get("symbols")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(pc) = entry.get("pc").and_then(Value::as_u64) else {
            continue;
        };
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        cache.insert(pc, name.to_string());
    }
    Ok(cache)
}

fn write_symbol_cache(
    path: &Path,
    binary_path: &Path,
    pc_to_func: &HashMap<u64, String>,
) -> Result<()> {
    let metadata = fs::metadata(binary_path)
        .with_context(|| format!("failed to stat callgraph binary {:?}", binary_path))?;
    let mtime_ns = metadata
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let size = metadata.len();

    let mut entries: Vec<_> = pc_to_func.iter().collect();
    entries.sort_by_key(|(pc, _)| **pc);

    let mut f = fs::File::create(path)
        .with_context(|| format!("failed to create symbol cache at {:?}", path))?;
    writeln!(f, "{{")?;
    writeln!(f, "  \"version\":{},", SYMBOL_CACHE_VERSION)?;
    writeln!(f, "  \"binary_size\":{},", size)?;
    writeln!(f, "  \"binary_mtime_ns\":{},", mtime_ns)?;
    writeln!(f, "  \"symbols\": [")?;
    for (idx, (pc, name)) in entries.iter().enumerate() {
        writeln!(
            f,
            "    {{\"pc\":{},\"name\":\"{}\"}}{}",
            pc,
            json_escape(name),
            if idx + 1 == entries.len() { "" } else { "," }
        )?;
    }
    writeln!(f, "  ]")?;
    writeln!(f, "}}")?;
    Ok(())
}

fn symbolize_pc_batch(loader: &Loader, pcs: &[u64]) -> Result<HashMap<u64, String>> {
    if pcs.is_empty() {
        return Ok(HashMap::new());
    }

    // Prefer the symbol table entry because it preserves mangled linkage names
    // with clone suffixes and other uniqueness markers. Fall back to DWARF when
    // no symbol-table name is available for a PC.
    let mut pc_to_func = HashMap::with_capacity(pcs.len());

    for &pc in pcs {
        let mut frames = loader
            .find_frames(pc)
            .map_err(|err| anyhow!("failed to resolve DWARF frames for PC 0x{pc:x}: {err}"))?;
        let mut raw_name: Option<String> = None;
        while let Some(frame) = frames
            .next()
            .map_err(|err| anyhow!("failed to iterate DWARF frames for PC 0x{pc:x}: {err}"))?
        {
            if let Some(function) = frame.function {
                raw_name = Some(
                    function
                        .raw_name()
                        .map_err(|err| {
                            anyhow!("failed to decode function name for PC 0x{pc:x}: {err}")
                        })?
                        .into_owned(),
                );
            }
        }

        let func_name = if let Some(name) = raw_name {
            format!("{:#}", demangle(&name))
        } else if let Some(symbol) = loader
            .find_symbol(pc)
            .filter(|name| !name.is_empty() && !name.starts_with("__covrec_"))
        {
            format!("{:#}", demangle(symbol))
        } else {
            format!("unknown_0x{:x}", pc)
        };

        pc_to_func.insert(pc, func_name);
    }

    Ok(pc_to_func)
}

fn symbolize_pcs(
    binary_path: &Path,
    pc_table: &HashMap<u32, u64>,
    cache_path: &Path,
) -> Result<HashMap<u64, String>> {
    let unique_pcs: Vec<u64> = {
        let mut pcs: Vec<u64> = pc_table.values().copied().collect();
        pcs.sort();
        pcs.dedup();
        pcs
    };

    if unique_pcs.is_empty() {
        return Ok(HashMap::new());
    }

    let mut pc_to_func = load_symbol_cache(cache_path, binary_path)?;
    let missing_pcs: Vec<u64> = unique_pcs
        .iter()
        .copied()
        .filter(|pc| !pc_to_func.contains_key(pc))
        .collect();

    if !missing_pcs.is_empty() {
        eprintln!(
            "Symbolizing {} unique PCs ({} cached)...",
            missing_pcs.len(),
            unique_pcs.len().saturating_sub(missing_pcs.len())
        );
        let loader = Loader::new(binary_path)
            .map_err(|err| anyhow!("failed to load addr2line data from {:?}: {err}", binary_path))?;
        pc_to_func.extend(symbolize_pc_batch(&loader, &missing_pcs)?);
        write_symbol_cache(cache_path, binary_path, &pc_to_func)?;
    } else {
        eprintln!("Symbolization cache hit for {} PCs.", unique_pcs.len());
    }

    pc_to_func.retain(|pc, _| unique_pcs.binary_search(pc).is_ok());
    Ok(pc_to_func)
}

/// Aggregate guard-level edges into function-level edges.
/// Returns: map from (caller_func, callee_func) -> total hit count
fn aggregate_function_edges(
    edges: &HashMap<(u32, u32), u64>,
    pc_table: &HashMap<u32, u64>,
    pc_to_func: &HashMap<u64, String>,
) -> HashMap<(String, String), u64> {
    let mut func_edges: HashMap<(String, String), u64> = HashMap::new();

    let resolve = |guard_id: u32| -> String {
        pc_table
            .get(&guard_id)
            .and_then(|pc| pc_to_func.get(pc))
            .cloned()
            .unwrap_or_else(|| format!("guard_{}", guard_id))
    };

    for (&(prev, cur), &count) in edges {
        let caller = resolve(prev);
        let callee = resolve(cur);

        // Only keep edges between different functions (same-function transitions
        // are just intra-procedural control flow, not call edges)
        if caller != callee {
            *func_edges.entry((caller, callee)).or_insert(0) += count;
        }
    }

    func_edges
}

#[derive(Clone, Debug, Default)]
struct FunctionCoverage {
    count: u64,
    region_total: u64,
    region_covered: u64,
    line_total: u64,
    line_covered: u64,
    file: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct CoverageState {
    line_covered: u64,
    no_gain_cycles: u64,
}

#[derive(Clone, Debug)]
struct SeedReplayJob {
    seed_path: PathBuf,
    artifact_stem: String,
}

#[derive(Clone, Debug)]
struct SeedTrace {
    seed_path: PathBuf,
    artifact_stem: String,
    edges: HashMap<(u32, u32), u64>,
    pc_table: HashMap<u32, u64>,
}

#[derive(Clone, Debug)]
struct SeedTraceSummary {
    seed_path: PathBuf,
    artifact_stem: String,
    function_hits: BTreeMap<String, u64>,
    edge_hits: Vec<((String, String), u64)>,
}

#[derive(Clone, Debug)]
struct PartitionNode {
    name: String,
    weight: u64,
}

#[derive(Clone, Debug)]
struct PartitionPlan {
    algorithm: &'static str,
    partitions: Vec<Vec<String>>,
    loads: Vec<u64>,
    seed_assignments: Vec<Vec<PathBuf>>,
    partition_edges: Vec<Vec<(String, String)>>,
}

const SHARED_SEED_FRACTION_THRESHOLD: f64 = 0.8;

fn normalize_coverage_function_name(raw_name: &str) -> String {
    // Use {:#} to get the full demangled path without crate hash disambiguators.
    // This must match the naming used by symbolize_pcs() so call graph nodes and
    // coverage entries use the same keys.
    format!("{:#}", demangle(raw_name))
}

fn export_function_coverage(
    llvm_cov_path: &Path,
    binary_path: &Path,
    profdata_path: &Path,
) -> Result<HashMap<String, FunctionCoverage>> {
    let output = Command::new(llvm_cov_path)
        .arg("export")
        .arg(binary_path)
        .arg(format!("-instr-profile={}", profdata_path.display()))
        .output()
        .with_context(|| format!("failed to run llvm-cov at {:?}", llvm_cov_path))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("llvm-cov export failed: {}", stderr);
    }

    parse_llvm_cov_export(&output.stdout)
}

fn parse_llvm_cov_export(bytes: &[u8]) -> Result<HashMap<String, FunctionCoverage>> {
    let json: Value = serde_json::from_slice(bytes).context("failed to parse llvm-cov JSON")?;
    let mut coverage = HashMap::new();

    let functions = json
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("functions"))
        .filter_map(Value::as_array)
        .flatten();

    for func in functions {
        let raw_name = func.get("name").and_then(Value::as_str).unwrap_or_default();
        let name = normalize_coverage_function_name(raw_name);
        if name.is_empty() {
            continue;
        }

        let count = func.get("count").and_then(Value::as_u64).unwrap_or(0);
        let file = func
            .get("filenames")
            .and_then(Value::as_array)
            .and_then(|files| files.first())
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let mut region_total = 0u64;
        let mut region_covered = 0u64;
        let mut covered_lines = HashSet::new();
        let mut total_lines = HashSet::new();
        if let Some(regions) = func.get("regions").and_then(Value::as_array) {
            for region in regions {
                let Some(items) = region.as_array() else {
                    continue;
                };
                if items.len() < 5 {
                    continue;
                }
                let execution_count = items[4].as_u64().unwrap_or(0);
                region_total += 1;
                if execution_count > 0 {
                    region_covered += 1;
                }

                let start_line = items.first().and_then(Value::as_u64).unwrap_or(0);
                let end_line = items.get(2).and_then(Value::as_u64).unwrap_or(start_line);
                if start_line == 0 {
                    continue;
                }
                let last_line = end_line.max(start_line);
                for line in start_line..=last_line {
                    total_lines.insert(line);
                    if execution_count > 0 {
                        covered_lines.insert(line);
                    }
                }
            }
        }

        let entry = coverage
            .entry(name)
            .or_insert_with(FunctionCoverage::default);
        entry.count = entry.count.max(count);
        entry.region_total = entry.region_total.max(region_total);
        entry.region_covered = entry.region_covered.max(region_covered);
        entry.line_total = entry.line_total.max(total_lines.len() as u64);
        entry.line_covered = entry.line_covered.max(covered_lines.len() as u64);
        if entry.file.is_none() {
            entry.file = file;
        }
    }

    Ok(coverage)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn write_callgraph_json(
    path: &Path,
    func_edges: &HashMap<(String, String), u64>,
    coverage_by_function: &HashMap<String, FunctionCoverage>,
) -> Result<()> {
    let mut nodes: BTreeMap<String, FunctionCoverage> = BTreeMap::new();
    for (caller, callee) in func_edges.keys() {
        nodes.entry(caller.clone()).or_insert_with(|| {
            coverage_by_function
                .get(caller)
                .cloned()
                .unwrap_or_default()
        });
        nodes.entry(callee.clone()).or_insert_with(|| {
            coverage_by_function
                .get(callee)
                .cloned()
                .unwrap_or_default()
        });
    }

    let mut edges: Vec<_> = func_edges.iter().collect();
    edges.sort_by(|a, b| a.0.cmp(b.0));

    let mut f = fs::File::create(path)
        .with_context(|| format!("failed to create callgraph json at {:?}", path))?;
    writeln!(f, "{{")?;
    writeln!(f, "  \"nodes\": [")?;
    for (idx, (name, cov)) in nodes.iter().enumerate() {
        let file = cov
            .file
            .as_deref()
            .map(json_escape)
            .map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| String::from("null"));
        let coverage_ratio = if cov.region_total == 0 {
            0.0
        } else {
            cov.region_covered as f64 / cov.region_total as f64
        };
        writeln!(
            f,
            "    {{\"name\":\"{}\",\"count\":{},\"region_total\":{},\"region_covered\":{},\"coverage_ratio\":{:.6},\"file\":{}}}{}",
            json_escape(name),
            cov.count,
            cov.region_total,
            cov.region_covered,
            coverage_ratio,
            file,
            if idx + 1 == nodes.len() { "" } else { "," }
        )?;
    }
    writeln!(f, "  ],")?;
    writeln!(f, "  \"edges\": [")?;
    for (idx, ((caller, callee), count)) in edges.iter().enumerate() {
        writeln!(
            f,
            "    {{\"caller\":\"{}\",\"callee\":\"{}\",\"count\":{}}}{}",
            json_escape(caller),
            json_escape(callee),
            count,
            if idx + 1 == edges.len() { "" } else { "," }
        )?;
    }
    writeln!(f, "  ]")?;
    writeln!(f, "}}")?;
    Ok(())
}

fn write_seed_hits_json(path: &Path, seed_summaries: &[SeedTraceSummary]) -> Result<()> {
    let mut function_ids = BTreeMap::new();
    for summary in seed_summaries {
        for name in summary.function_hits.keys() {
            let next_id = function_ids.len();
            function_ids.entry(name.clone()).or_insert(next_id);
        }
        for ((caller, callee), _) in &summary.edge_hits {
            let next_id = function_ids.len();
            function_ids.entry(caller.clone()).or_insert(next_id);
            let next_id = function_ids.len();
            function_ids.entry(callee.clone()).or_insert(next_id);
        }
    }

    let mut f = fs::File::create(path)
        .with_context(|| format!("failed to create seed hits json at {:?}", path))?;
    writeln!(f, "{{")?;
    writeln!(f, "  \"functions\": [")?;
    for (idx, (name, id)) in function_ids.iter().enumerate() {
        writeln!(
            f,
            "    {{\"id\":{},\"name\":\"{}\"}}{}",
            id,
            json_escape(name),
            if idx + 1 == function_ids.len() {
                ""
            } else {
                ","
            }
        )?;
    }
    writeln!(f, "  ],")?;
    writeln!(f, "  \"seeds\": [")?;
    for (idx, summary) in seed_summaries.iter().enumerate() {
        writeln!(
            f,
            "    {{\"seed\":\"{}\",\"artifact\":\"{}\",\"function_ids\":[",
            json_escape(&summary.seed_path.display().to_string()),
            json_escape(&summary.artifact_stem),
        )?;

        for (func_idx, name) in summary.function_hits.keys().enumerate() {
            writeln!(
                f,
                "      {}{}",
                function_ids[name],
                if func_idx + 1 == summary.function_hits.len() {
                    ""
                } else {
                    ","
                }
            )?;
        }

        writeln!(f, "    ],\"edges\":[")?;
        for (edge_idx, ((caller, callee), count)) in summary.edge_hits.iter().enumerate() {
            writeln!(
                f,
                "      {{\"caller_id\":{},\"callee_id\":{},\"count\":{}}}{}",
                function_ids[caller],
                function_ids[callee],
                count,
                if edge_idx + 1 == summary.edge_hits.len() {
                    ""
                } else {
                    ","
                }
            )?;
        }

        writeln!(
            f,
            "    ]}}{}",
            if idx + 1 == seed_summaries.len() {
                ""
            } else {
                ","
            }
        )?;
    }
    writeln!(f, "  ]")?;
    writeln!(f, "}}")?;
    Ok(())
}

fn is_partitionable_source(file: Option<&str>, workspace_root: &Path) -> bool {
    let Some(file) = file else {
        return false;
    };
    let path = Path::new(file);
    if path.is_absolute() {
        path.starts_with(workspace_root)
    } else {
        true
    }
}

fn display_source_path(file: &str, workspace_root: &Path) -> String {
    let path = Path::new(file);
    if path.is_absolute() {
        if let Ok(stripped) = path.strip_prefix(workspace_root) {
            return stripped.display().to_string();
        }
    }
    file.to_string()
}

fn owned_functions(
    coverage_by_function: &HashMap<String, FunctionCoverage>,
    workspace_root: &Path,
) -> HashSet<String> {
    coverage_by_function
        .iter()
        .filter_map(|(name, cov)| {
            is_partitionable_source(cov.file.as_deref(), workspace_root).then_some(name.clone())
        })
        .collect()
}

fn is_shared_source(file: Option<&str>, workspace_root: &Path) -> bool {
    let Some(file) = file else {
        return false;
    };

    let displayed = display_source_path(file, workspace_root);
    displayed == "src/main.rs"
        || displayed.starts_with("fuzz/")
        || displayed.starts_with("fuzz_targets/")
}

fn function_seed_hits(seed_summaries: &[SeedTraceSummary]) -> HashMap<String, u64> {
    let mut hits_by_function = HashMap::new();
    for summary in seed_summaries {
        for name in summary.function_hits.keys() {
            *hits_by_function.entry(name.clone()).or_insert(0) += 1;
        }
    }
    hits_by_function
}

fn shared_functions(
    seed_summaries: &[SeedTraceSummary],
    coverage_by_function: &HashMap<String, FunctionCoverage>,
    workspace_root: &Path,
) -> HashSet<String> {
    let owned = owned_functions(coverage_by_function, workspace_root);
    let hits_by_function = function_seed_hits(seed_summaries);
    let seed_count = seed_summaries.len().max(1) as f64;

    coverage_by_function
        .iter()
        .filter_map(|(name, cov)| {
            if !owned.contains(name) {
                return None;
            }

            let shared_by_source = is_shared_source(cov.file.as_deref(), workspace_root);
            let shared_by_frequency = hits_by_function
                .get(name)
                .map(|hits| ((*hits as f64) / seed_count) >= SHARED_SEED_FRACTION_THRESHOLD)
                .unwrap_or(false);

            (shared_by_source || shared_by_frequency).then_some(name.clone())
        })
        .collect()
}

fn entry_roots(func_edges: &HashMap<(String, String), u64>) -> HashSet<String> {
    let mut all_nodes = HashSet::new();
    let mut has_predecessor = HashSet::new();
    for (caller, callee) in func_edges.keys() {
        all_nodes.insert(caller.clone());
        all_nodes.insert(callee.clone());
        has_predecessor.insert(callee.clone());
    }

    let roots: HashSet<_> = all_nodes
        .iter()
        .filter(|name| !has_predecessor.contains(*name))
        .cloned()
        .collect();
    if !roots.is_empty() {
        return roots;
    }

    all_nodes
        .into_iter()
        .filter(|name| {
            name.ends_with("::main")
                || name == "main"
                || name.contains("LLVMFuzzerTestOneInput")
                || name.contains("__fuzz_target_impl")
                || name.contains("__callgraph_rust_main")
        })
        .collect()
}

fn load_coverage_state(path: &Path) -> Result<HashMap<String, CoverageState>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let data =
        fs::read(path).with_context(|| format!("failed to read coverage state {:?}", path))?;
    let json: Value = serde_json::from_slice(&data)
        .with_context(|| format!("invalid coverage state {:?}", path))?;
    let mut state = HashMap::new();
    for entry in json
        .get("functions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        state.insert(
            name.to_string(),
            CoverageState {
                line_covered: entry
                    .get("line_covered")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                no_gain_cycles: entry
                    .get("no_gain_cycles")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            },
        );
    }
    Ok(state)
}

fn build_coverage_state(
    coverage_by_function: &HashMap<String, FunctionCoverage>,
    previous_state: &HashMap<String, CoverageState>,
) -> HashMap<String, CoverageState> {
    coverage_by_function
        .iter()
        .map(|(name, cov)| {
            let prev = previous_state.get(name).cloned().unwrap_or_default();
            let gained = cov.line_covered > prev.line_covered;
            (
                name.clone(),
                CoverageState {
                    line_covered: cov.line_covered,
                    no_gain_cycles: if gained {
                        0
                    } else {
                        prev.no_gain_cycles.saturating_add(1)
                    },
                },
            )
        })
        .collect()
}

fn write_coverage_state(path: &Path, state: &HashMap<String, CoverageState>) -> Result<()> {
    let mut entries: Vec<_> = state.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut f = fs::File::create(path)
        .with_context(|| format!("failed to create coverage state at {:?}", path))?;
    writeln!(f, "{{")?;
    writeln!(f, "  \"functions\": [")?;
    for (idx, (name, entry)) in entries.iter().enumerate() {
        writeln!(
            f,
            "    {{\"name\":\"{}\",\"line_covered\":{},\"no_gain_cycles\":{}}}{}",
            json_escape(name),
            entry.line_covered,
            entry.no_gain_cycles,
            if idx + 1 == entries.len() { "" } else { "," }
        )?;
    }
    writeln!(f, "  ]")?;
    writeln!(f, "}}")?;
    Ok(())
}

fn min_max_normalize(values: &HashMap<String, f64>) -> HashMap<String, f64> {
    if values.is_empty() {
        return HashMap::new();
    }
    let min = values.values().copied().fold(f64::INFINITY, f64::min);
    let max = values.values().copied().fold(f64::NEG_INFINITY, f64::max);
    if (max - min).abs() < f64::EPSILON {
        return values
            .keys()
            .map(|name| (name.clone(), 0.0))
            .collect::<HashMap<_, _>>();
    }
    values
        .iter()
        .map(|(name, value)| (name.clone(), (value - min) / (max - min)))
        .collect()
}

fn entropy_weights(metrics: &[HashMap<String, f64>]) -> Vec<f64> {
    let epsilon = 1e-12;
    if metrics.is_empty() {
        return Vec::new();
    }
    let node_count = metrics[0].len().max(1) as f64;
    let mut gains = Vec::with_capacity(metrics.len());
    for metric in metrics {
        let sum = metric.values().copied().sum::<f64>() + epsilon;
        let entropy = metric.values().copied().fold(0.0, |acc, value| {
            let p = value / sum;
            if p <= 0.0 {
                acc
            } else {
                acc - p * (p + epsilon).ln()
            }
        }) / node_count.ln().max(1.0);
        gains.push((1.0 - entropy).max(0.0));
    }
    let total_gain = gains.iter().copied().sum::<f64>() + epsilon;
    gains.into_iter().map(|gain| gain / total_gain).collect()
}

fn katz_centrality(
    predecessors: &HashMap<String, Vec<String>>,
    nodes: &[String],
) -> HashMap<String, f64> {
    if nodes.is_empty() {
        return HashMap::new();
    }

    let max_in_degree = predecessors.values().map(Vec::len).max().unwrap_or(0) as f64;
    let alpha = 0.5 / (max_in_degree + 1.0);
    let beta = 1.0;
    let mut scores = nodes
        .iter()
        .map(|name| (name.clone(), 1.0))
        .collect::<HashMap<_, _>>();

    for _ in 0..100 {
        let mut delta = 0.0f64;
        let mut next = HashMap::with_capacity(nodes.len());
        for node in nodes {
            let influence = predecessors
                .get(node)
                .into_iter()
                .flatten()
                .map(|pred| scores.get(pred).copied().unwrap_or(0.0))
                .sum::<f64>();
            let score = beta + alpha * influence;
            delta = delta.max((score - scores.get(node).copied().unwrap_or(0.0)).abs());
            next.insert(node.clone(), score);
        }
        scores = next;
        if delta < 1e-9 {
            break;
        }
    }

    scores
}

fn build_partition_graph(
    func_edges: &HashMap<(String, String), u64>,
    seed_summaries: &[SeedTraceSummary],
    coverage_by_function: &HashMap<String, FunctionCoverage>,
    previous_state: &HashMap<String, CoverageState>,
    current_state: &HashMap<String, CoverageState>,
    workspace_root: &Path,
) -> UnGraph<PartitionNode, u64> {
    let shared = shared_functions(seed_summaries, coverage_by_function, workspace_root);

    let mut edge_weight_sum: HashMap<String, u64> = HashMap::new();
    for ((caller, callee), count) in func_edges {
        *edge_weight_sum.entry(caller.clone()).or_insert(0) += *count;
        *edge_weight_sum.entry(callee.clone()).or_insert(0) += *count;
    }

    let mut names: Vec<_> = edge_weight_sum.keys().cloned().collect();
    names.sort();

    let mut graph = UnGraph::<PartitionNode, u64>::new_undirected();
    let mut function_nodes = HashMap::new();
    let mut predecessors: HashMap<String, Vec<String>> = HashMap::new();

    for name in names {
        let Some(cov) = coverage_by_function.get(&name) else {
            continue;
        };
        if !is_partitionable_source(cov.file.as_deref(), workspace_root) {
            continue;
        }
        if shared.contains(&name) {
            continue;
        }

        let idx = graph.add_node(PartitionNode {
            name: name.clone(),
            weight: 1,
        });
        function_nodes.insert(name.clone(), idx);
    }

    for ((caller, callee), count) in func_edges {
        let Some(&caller_idx) = function_nodes.get(caller) else {
            continue;
        };
        let Some(&callee_idx) = function_nodes.get(callee) else {
            continue;
        };

        if let Some(edge_idx) = graph.find_edge(caller_idx, callee_idx) {
            if let Some(weight) = graph.edge_weight_mut(edge_idx) {
                *weight += *count;
            }
        } else {
            graph.add_edge(caller_idx, callee_idx, *count);
        }
        predecessors
            .entry(callee.clone())
            .or_default()
            .push(caller.clone());
    }

    for summary in seed_summaries {
        let mut hit_nodes: Vec<_> = summary
            .function_hits
            .keys()
            .filter_map(|name| function_nodes.get(name).copied())
            .collect();
        hit_nodes.sort_by_key(|idx| idx.index());
        hit_nodes.dedup_by_key(|idx| idx.index());

        for left in 0..hit_nodes.len() {
            for right in left + 1..hit_nodes.len() {
                let lhs = hit_nodes[left];
                let rhs = hit_nodes[right];
                if let Some(edge_idx) = graph.find_edge(lhs, rhs) {
                    if let Some(weight) = graph.edge_weight_mut(edge_idx) {
                        *weight += 1;
                    }
                } else {
                    graph.add_edge(lhs, rhs, 1);
                }
            }
        }
    }

    let function_names: Vec<String> = function_nodes.keys().cloned().collect();
    let katz = katz_centrality(&predecessors, &function_names);
    let mut residual = HashMap::new();
    let mut recent_gain = HashMap::new();
    let mut difficulty_penalty = HashMap::new();
    for name in function_nodes.keys() {
        let cov = coverage_by_function.get(name).cloned().unwrap_or_default();
        let prev_state = previous_state.get(name).cloned().unwrap_or_default();
        let state = current_state.get(name).cloned().unwrap_or_default();
        let prev = prev_state
            .line_covered
            .min(cov.line_total.max(cov.line_covered));
        residual.insert(
            name.clone(),
            cov.line_total.saturating_sub(cov.line_covered) as f64,
        );
        recent_gain.insert(name.clone(), cov.line_covered.saturating_sub(prev) as f64);
        difficulty_penalty.insert(name.clone(), (-0.3 * state.no_gain_cycles as f64).exp());
    }

    let normalized_residual = min_max_normalize(&residual);
    let normalized_gain = min_max_normalize(&recent_gain);
    let normalized_penalty = min_max_normalize(&difficulty_penalty);
    let normalized_katz = min_max_normalize(&katz);
    let weights = entropy_weights(&[
        normalized_residual.clone(),
        normalized_gain.clone(),
        normalized_penalty.clone(),
        normalized_katz.clone(),
    ]);

    for node_idx in graph.node_indices() {
        let name = graph[node_idx].name.clone();
        let score = weights.first().copied().unwrap_or(0.25)
            * normalized_residual.get(&name).copied().unwrap_or(0.0)
            + weights.get(1).copied().unwrap_or(0.25)
                * normalized_gain.get(&name).copied().unwrap_or(0.0)
            + weights.get(2).copied().unwrap_or(0.25)
                * normalized_penalty.get(&name).copied().unwrap_or(0.0)
            + weights.get(3).copied().unwrap_or(0.25)
                * normalized_katz.get(&name).copied().unwrap_or(0.0);
        graph[node_idx].weight = (score.mul_add(1_000_000.0, 1.0)).round() as u64;
    }

    graph
}

fn partitioner_name(partitioner: &options::Partitioner) -> &'static str {
    match partitioner {
        options::Partitioner::Ldg => "ldg",
        options::Partitioner::Fennel => "fennel",
        options::Partitioner::Hrdf => "hrdf",
        options::Partitioner::Random => "random",
    }
}

fn random_partition(name: &str, partition_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    (hasher.finish() as usize) % partition_count
}

fn partition_graph_vertices(
    graph: &UnGraph<PartitionNode, u64>,
    partition_count: usize,
    partitioner: &options::Partitioner,
) -> PartitionPlan {
    let partition_count = partition_count.max(1);
    let algorithm = partitioner_name(partitioner);
    let mut partitions = vec![Vec::new(); partition_count];
    let mut loads = vec![0u64; partition_count];
    let total_weight = graph
        .node_indices()
        .map(|idx| graph[idx].weight)
        .sum::<u64>()
        .max(1);
    let total_edge_weight = graph.edge_weights().copied().sum::<u64>().max(1);
    let capacity = total_weight.div_ceil(partition_count as u64).max(1);
    let gamma = 1.5f64;
    let alpha = (total_edge_weight as f64) * (partition_count as f64).powf(gamma - 1.0)
        / (total_weight as f64).powf(gamma);

    let mut nodes: Vec<_> = graph.node_indices().collect();
    nodes.sort_by(|&left, &right| {
        graph[right]
            .weight
            .cmp(&graph[left].weight)
            .then_with(|| graph[left].name.cmp(&graph[right].name))
    });

    let mut assigned = vec![None; graph.node_count()];

    for node_idx in nodes {
        let node = &graph[node_idx];
        let chosen_partition = if matches!(partitioner, options::Partitioner::Random) {
            random_partition(&node.name, partition_count)
        } else {
            let mut best_partition = 0usize;
            let mut best_score = f64::NEG_INFINITY;

            for partition_idx in 0..partition_count {
                let affinity = graph
                    .edges(node_idx)
                    .filter_map(|edge| {
                        let neighbor = edge.target();
                        (assigned[neighbor.index()] == Some(partition_idx))
                            .then_some(*edge.weight() as f64)
                    })
                    .sum::<f64>();

                let score = match partitioner {
                    options::Partitioner::Ldg => {
                        let balance =
                            (1.0 - (loads[partition_idx] as f64 / capacity as f64)).max(0.0);
                        affinity * balance
                    }
                    options::Partitioner::Fennel => {
                        affinity
                            - alpha
                                * (((loads[partition_idx] + node.weight) as f64).powf(gamma)
                                    - (loads[partition_idx] as f64).powf(gamma))
                    }
                    options::Partitioner::Hrdf | options::Partitioner::Random => unreachable!(),
                };

                if score > best_score
                    || ((score - best_score).abs() < f64::EPSILON
                        && (loads[partition_idx], partition_idx)
                            < (loads[best_partition], best_partition))
                {
                    best_score = score;
                    best_partition = partition_idx;
                }
            }

            best_partition
        };

        partitions[chosen_partition].push(node.name.clone());
        loads[chosen_partition] += node.weight;
        assigned[node_idx.index()] = Some(chosen_partition);
    }

    PartitionPlan {
        algorithm,
        partitions,
        loads,
        seed_assignments: vec![Vec::new(); partition_count],
        partition_edges: vec![Vec::new(); partition_count],
    }
}

fn partition_graph_edges_hrdf(
    graph: &UnGraph<PartitionNode, u64>,
    partition_count: usize,
) -> PartitionPlan {
    let partition_count = partition_count.max(1);
    let mut partitions = vec![Vec::new(); partition_count];
    let mut partition_edges = vec![Vec::new(); partition_count];
    let mut loads = vec![0u64; partition_count];
    let mut membership = vec![HashSet::<usize>::new(); graph.node_count()];
    let lambda = 2.0f64;

    let mut edges: Vec<_> = graph.edge_references().collect();
    edges.sort_by(|left, right| {
        right.weight().cmp(left.weight()).then_with(|| {
            let left_endpoints = (
                graph[left.source()].name.as_str(),
                graph[left.target()].name.as_str(),
            );
            let right_endpoints = (
                graph[right.source()].name.as_str(),
                graph[right.target()].name.as_str(),
            );
            left_endpoints.cmp(&right_endpoints)
        })
    });

    for edge in edges {
        let source = edge.source();
        let target = edge.target();
        let source_name = graph[source].name.clone();
        let target_name = graph[target].name.clone();
        let source_weight = graph[source].weight;
        let target_weight = graph[target].weight;
        let edge_score_total = (source_weight + target_weight).max(1) as f64;

        let max_load = loads.iter().copied().max().unwrap_or(0) as f64;
        let min_load = loads.iter().copied().min().unwrap_or(0) as f64;
        let mut best_partition = 0usize;
        let mut best_score = f64::NEG_INFINITY;

        for partition_idx in 0..partition_count {
            let source_present = membership[source.index()].contains(&partition_idx);
            let target_present = membership[target.index()].contains(&partition_idx);
            let locality = if source_present {
                1.0 + (source_weight as f64 / edge_score_total)
            } else {
                0.0
            } + if target_present {
                1.0 + (target_weight as f64 / edge_score_total)
            } else {
                0.0
            };

            let balance = if (max_load - min_load).abs() < f64::EPSILON {
                1.0
            } else {
                (max_load - loads[partition_idx] as f64) / (max_load - min_load + 1e-9)
            };
            let score = locality + lambda * balance;

            if score > best_score
                || ((score - best_score).abs() < f64::EPSILON
                    && (loads[partition_idx], partition_idx)
                        < (loads[best_partition], best_partition))
            {
                best_score = score;
                best_partition = partition_idx;
            }
        }

        if membership[source.index()].insert(best_partition) {
            partitions[best_partition].push(source_name.clone());
            loads[best_partition] += source_weight;
        }
        if membership[target.index()].insert(best_partition) {
            partitions[best_partition].push(target_name.clone());
            loads[best_partition] += target_weight;
        }

        let edge_pair = if source_name <= target_name {
            (source_name, target_name)
        } else {
            (target_name, source_name)
        };
        partition_edges[best_partition].push(edge_pair);
    }

    let mut isolated: Vec<_> = graph
        .node_indices()
        .filter(|&node_idx| graph.edges(node_idx).next().is_none())
        .collect();
    isolated.sort_by(|&left, &right| graph[left].name.cmp(&graph[right].name));
    for node_idx in isolated {
        let best_partition = loads
            .iter()
            .enumerate()
            .min_by_key(|(partition_idx, load)| (*load, *partition_idx))
            .map(|(partition_idx, _)| partition_idx)
            .unwrap_or(0);
        if membership[node_idx.index()].insert(best_partition) {
            partitions[best_partition].push(graph[node_idx].name.clone());
            loads[best_partition] += graph[node_idx].weight;
        }
    }

    for functions in &mut partitions {
        functions.sort();
        functions.dedup();
    }
    for edges in &mut partition_edges {
        edges.sort();
        edges.dedup();
    }

    PartitionPlan {
        algorithm: "hrdf",
        partitions,
        loads,
        seed_assignments: vec![Vec::new(); partition_count],
        partition_edges,
    }
}

fn partition_graph(
    graph: &UnGraph<PartitionNode, u64>,
    partition_count: usize,
    partitioner: &options::Partitioner,
) -> PartitionPlan {
    match partitioner {
        options::Partitioner::Hrdf => partition_graph_edges_hrdf(graph, partition_count),
        options::Partitioner::Ldg | options::Partitioner::Fennel | options::Partitioner::Random => {
            partition_graph_vertices(graph, partition_count, partitioner)
        }
    }
}

fn compact_partition_plan(mut plan: PartitionPlan) -> PartitionPlan {
    let mut partitions = Vec::new();
    let mut loads = Vec::new();
    let mut seed_assignments = Vec::new();
    let mut partition_edges = Vec::new();

    for (((functions, load), seeds), edges) in plan
        .partitions
        .into_iter()
        .zip(plan.loads.into_iter())
        .zip(plan.seed_assignments.into_iter())
        .zip(plan.partition_edges.into_iter())
    {
        if functions.is_empty() {
            continue;
        }
        partitions.push(functions);
        loads.push(load);
        seed_assignments.push(seeds);
        partition_edges.push(edges);
    }

    if partitions.is_empty() {
        partitions.push(Vec::new());
        loads.push(0);
        seed_assignments.push(Vec::new());
        partition_edges.push(Vec::new());
    }

    plan.partitions = partitions;
    plan.loads = loads;
    plan.seed_assignments = seed_assignments;
    plan.partition_edges = partition_edges;
    plan
}

fn assign_seeds_to_partitions(
    plan: &mut PartitionPlan,
    seed_summaries: &[SeedTraceSummary],
    seed_hits: &HashMap<String, u64>,
) {
    if plan.partition_edges.iter().any(|edges| !edges.is_empty()) {
        let mut edge_to_partitions: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
        for (partition_idx, edges) in plan.partition_edges.iter().enumerate() {
            for (left, right) in edges {
                edge_to_partitions
                    .entry((left.as_str(), right.as_str()))
                    .or_default()
                    .push(partition_idx);
            }
        }

        for summary in seed_summaries {
            let mut scores = vec![0f64; plan.partitions.len()];
            for ((caller, callee), count) in &summary.edge_hits {
                let key = if caller <= callee {
                    (caller.as_str(), callee.as_str())
                } else {
                    (callee.as_str(), caller.as_str())
                };
                if let Some(partitions) = edge_to_partitions.get(&key) {
                    let frequency = seed_hits.get(caller).copied().unwrap_or(1).max(1) as f64
                        + seed_hits.get(callee).copied().unwrap_or(1).max(1) as f64;
                    let increment = *count as f64 / frequency.max(1.0);
                    for &partition_idx in partitions {
                        scores[partition_idx] += increment;
                    }
                }
            }

            let best_partition = scores
                .iter()
                .enumerate()
                .max_by(|(left_idx, left_score), (right_idx, right_score)| {
                    left_score
                        .partial_cmp(right_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            std::cmp::Reverse(plan.seed_assignments[*left_idx].len())
                                .cmp(&std::cmp::Reverse(plan.seed_assignments[*right_idx].len()))
                        })
                })
                .map(|(partition_idx, _)| partition_idx)
                .unwrap_or(0);
            plan.seed_assignments[best_partition].push(summary.seed_path.clone());
        }
        return;
    }

    let mut function_to_partition = HashMap::new();
    for (partition_idx, functions) in plan.partitions.iter().enumerate() {
        for name in functions {
            function_to_partition.insert(name.as_str(), partition_idx);
        }
    }

    for summary in seed_summaries {
        let mut scores = vec![0f64; plan.partitions.len()];
        for name in summary.function_hits.keys() {
            if let Some(&partition_idx) = function_to_partition.get(name.as_str()) {
                let frequency = seed_hits.get(name).copied().unwrap_or(1).max(1) as f64;
                scores[partition_idx] += 1.0 / frequency;
            }
        }

        let best_partition = scores
            .iter()
            .enumerate()
            .max_by(|(left_idx, left_score), (right_idx, right_score)| {
                left_score
                    .partial_cmp(right_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        std::cmp::Reverse(plan.seed_assignments[*left_idx].len())
                            .cmp(&std::cmp::Reverse(plan.seed_assignments[*right_idx].len()))
                    })
            })
            .map(|(partition_idx, _)| partition_idx)
            .unwrap_or(0);
        plan.seed_assignments[best_partition].push(summary.seed_path.clone());
    }
}

fn shortest_predecessor_path(
    target: &str,
    predecessors: &HashMap<String, Vec<String>>,
    roots: &HashSet<String>,
    blocked_owned: &HashSet<String>,
) -> Vec<String> {
    let mut queue = VecDeque::from([target.to_string()]);
    let mut visited = HashSet::from([target.to_string()]);
    let mut next_on_path: HashMap<String, String> = HashMap::new();
    let mut found_root = roots.contains(target).then(|| target.to_string());

    while found_root.is_none() {
        let Some(current) = queue.pop_front() else {
            break;
        };
        if let Some(preds) = predecessors.get(&current) {
            for pred in preds {
                if blocked_owned.contains(pred) || !visited.insert(pred.clone()) {
                    continue;
                }
                next_on_path.insert(pred.clone(), current.clone());
                if roots.contains(pred) {
                    found_root = Some(pred.clone());
                    break;
                }
                queue.push_back(pred.clone());
            }
        }
    }

    let Some(mut current) = found_root else {
        return vec![target.to_string()];
    };

    let mut path = vec![current.clone()];
    while current != target {
        let Some(next) = next_on_path.get(&current) else {
            break;
        };
        current = next.clone();
        path.push(current.clone());
    }
    path
}

fn expand_partition_tasks(
    partitions: &[Vec<String>],
    func_edges: &HashMap<(String, String), u64>,
    coverage_by_function: &HashMap<String, FunctionCoverage>,
    workspace_root: &Path,
    shared: &HashSet<String>,
) -> Vec<Vec<String>> {
    let owned_functions = owned_functions(coverage_by_function, workspace_root);
    let roots = entry_roots(func_edges);

    let mut predecessors: HashMap<String, Vec<String>> = HashMap::new();
    let mut successors: HashMap<String, Vec<String>> = HashMap::new();
    for (caller, callee) in func_edges.keys() {
        predecessors
            .entry(callee.clone())
            .or_default()
            .push(caller.clone());
        successors
            .entry(caller.clone())
            .or_default()
            .push(callee.clone());
    }

    partitions
        .iter()
        .map(|base_functions| {
            let base_set: HashSet<String> = base_functions.iter().cloned().collect();
            let blocked_owned: HashSet<String> = owned_functions
                .iter()
                .filter(|name| !base_set.contains(*name) && !shared.contains(*name))
                .cloned()
                .collect();

            let mut expanded = base_set.clone();

            for name in base_functions {
                for path_node in
                    shortest_predecessor_path(name, &predecessors, &roots, &blocked_owned)
                {
                    if owned_functions.contains(&path_node) || shared.contains(&path_node) {
                        expanded.insert(path_node);
                    }
                }
            }

            let mut visited: HashSet<String> = base_set.clone();
            let mut queue: VecDeque<String> = base_functions.iter().cloned().collect();
            while let Some(current) = queue.pop_front() {
                for neighbor in predecessors
                    .get(&current)
                    .into_iter()
                    .flatten()
                    .chain(successors.get(&current).into_iter().flatten())
                {
                    if blocked_owned.contains(neighbor) || !visited.insert(neighbor.clone()) {
                        continue;
                    }
                    if owned_functions.contains(neighbor) || shared.contains(neighbor) {
                        expanded.insert(neighbor.clone());
                    }
                    queue.push_back(neighbor.clone());
                }
            }

            let mut functions: Vec<_> = expanded.into_iter().collect();
            functions.sort();
            functions
        })
        .collect()
}

fn write_partitions_json(
    path: &Path,
    plan: &PartitionPlan,
    expanded_tasks: &[Vec<String>],
    shared: &HashSet<String>,
    coverage_by_function: &HashMap<String, FunctionCoverage>,
    workspace_root: &Path,
) -> Result<()> {
    let mut function_ids = BTreeMap::new();
    for functions in expanded_tasks {
        for name in functions {
            let next_id = function_ids.len();
            function_ids.entry(name.clone()).or_insert(next_id);
        }
    }
    for name in shared {
        let next_id = function_ids.len();
        function_ids.entry(name.clone()).or_insert(next_id);
    }

    let mut f = fs::File::create(path)
        .with_context(|| format!("failed to create partition json at {:?}", path))?;
    writeln!(f, "{{")?;
    writeln!(f, "  \"partitioner\":\"{}\",", json_escape(plan.algorithm))?;
    writeln!(f, "  \"functions\": [")?;
    for (idx, (name, id)) in function_ids.iter().enumerate() {
        let source = coverage_by_function
            .get(name)
            .and_then(|cov| cov.file.as_deref())
            .map(|file| display_source_path(file, workspace_root))
            .unwrap_or_else(|| String::from("<unknown>"));
        writeln!(
            f,
            "    {{\"id\":{},\"name\":\"{}\",\"source\":\"{}\"}}{}",
            id,
            json_escape(name),
            json_escape(&source),
            if idx + 1 == function_ids.len() {
                ""
            } else {
                ","
            }
        )?;
    }
    writeln!(f, "  ],")?;
    writeln!(f, "  \"shared_function_ids\": [")?;
    let mut sorted_shared: Vec<_> = shared.iter().collect();
    sorted_shared.sort();
    for (idx, name) in sorted_shared.iter().enumerate() {
        writeln!(
            f,
            "    {}{}",
            function_ids[*name],
            if idx + 1 == sorted_shared.len() {
                ""
            } else {
                ","
            }
        )?;
    }
    writeln!(f, "  ],")?;
    writeln!(f, "  \"partitions\": [")?;

    for (idx, functions) in plan.partitions.iter().enumerate() {
        writeln!(
            f,
            "    {{\"id\":{},\"load\":{},\"partition_functions\":[",
            idx + 1,
            plan.loads[idx]
        )?;

        for (func_idx, name) in functions.iter().enumerate() {
            let source = coverage_by_function
                .get(name)
                .and_then(|cov| cov.file.as_deref())
                .map(|file| display_source_path(file, workspace_root))
                .unwrap_or_else(|| String::from("<unknown>"));
            writeln!(
                f,
                "      {{\"name\":\"{}\",\"source\":\"{}\"}}{}",
                json_escape(name),
                json_escape(&source),
                if func_idx + 1 == functions.len() {
                    ""
                } else {
                    ","
                }
            )?;
        }

        writeln!(f, "    ],\"task_function_ids\":[")?;
        for (func_idx, name) in expanded_tasks[idx].iter().enumerate() {
            writeln!(
                f,
                "      {}{}",
                function_ids[name],
                if func_idx + 1 == expanded_tasks[idx].len() {
                    ""
                } else {
                    ","
                }
            )?;
        }

        writeln!(f, "    ],\"partition_edges\":[")?;
        for (edge_idx, (caller, callee)) in plan.partition_edges[idx].iter().enumerate() {
            writeln!(
                f,
                "      {{\"caller\":\"{}\",\"callee\":\"{}\"}}{}",
                json_escape(caller),
                json_escape(callee),
                if edge_idx + 1 == plan.partition_edges[idx].len() {
                    ""
                } else {
                    ","
                }
            )?;
        }

        writeln!(f, "    ],\"seeds\":[")?;
        for (seed_idx, seed_path) in plan.seed_assignments[idx].iter().enumerate() {
            writeln!(
                f,
                "      \"{}\"{}",
                json_escape(&seed_path.display().to_string()),
                if seed_idx + 1 == plan.seed_assignments[idx].len() {
                    ""
                } else {
                    ","
                }
            )?;
        }

        writeln!(
            f,
            "    ]}}{}",
            if idx + 1 == plan.partitions.len() {
                ""
            } else {
                ","
            }
        )?;
    }

    writeln!(f, "  ]")?;
    writeln!(f, "}}")?;
    Ok(())
}

fn write_partition_outputs(
    partition_dir: &Path,
    partitioner: &options::Partitioner,
    requested_partitions: usize,
    func_edges: &HashMap<(String, String), u64>,
    coverage_by_function: &HashMap<String, FunctionCoverage>,
    seed_summaries: &[SeedTraceSummary],
    workspace_root: &Path,
) -> Result<()> {
    clear_directory(partition_dir)?;

    let shared = shared_functions(seed_summaries, coverage_by_function, workspace_root);
    let seed_hits = function_seed_hits(seed_summaries);
    let state_path = partition_dir
        .parent()
        .unwrap_or(partition_dir)
        .join("coverage-state.json");
    let previous_state = load_coverage_state(&state_path)?;
    let current_state = build_coverage_state(coverage_by_function, &previous_state);
    let graph = build_partition_graph(
        func_edges,
        seed_summaries,
        coverage_by_function,
        &previous_state,
        &current_state,
        workspace_root,
    );
    let partition_count = requested_partitions.min(graph.node_count().max(1));
    let mut plan = if graph.node_count() == 0 {
        PartitionPlan {
            algorithm: partitioner_name(partitioner),
            partitions: vec![Vec::new(); partition_count.max(1)],
            loads: vec![0; partition_count.max(1)],
            seed_assignments: vec![Vec::new(); partition_count.max(1)],
            partition_edges: vec![Vec::new(); partition_count.max(1)],
        }
    } else {
        partition_graph(&graph, partition_count, partitioner)
    };
    plan = compact_partition_plan(plan);
    assign_seeds_to_partitions(&mut plan, seed_summaries, &seed_hits);
    let expanded_tasks = expand_partition_tasks(
        &plan.partitions,
        func_edges,
        coverage_by_function,
        workspace_root,
        &shared,
    );

    for (idx, task_functions) in expanded_tasks.iter().enumerate() {
        // Skip partitions with no seeds — these contain functions that exist
        // in the call graph but were never exercised by any corpus input.
        // They're still recorded in partitions.json for visibility.
        if plan.seed_assignments[idx].is_empty() {
            continue;
        }

        // Task files contain the expanded closure used for selective
        // instrumentation, including shared setup/trunk functions.
        let task_path = partition_dir.join(format!("task_{}.txt", idx + 1));
        let mut task_file = fs::File::create(&task_path)
            .with_context(|| format!("failed to create task file at {:?}", task_path))?;
        for name in task_functions {
            let source = coverage_by_function
                .get(name)
                .and_then(|cov| cov.file.as_deref())
                .map(|file| display_source_path(file, workspace_root))
                .unwrap_or_else(|| String::from("<unknown>"));
            writeln!(task_file, "{}:{}", source, name)?;
        }

        let seeds_path = partition_dir.join(format!("seeds_{}.txt", idx + 1));
        let mut seeds_file = fs::File::create(&seeds_path)
            .with_context(|| format!("failed to create seed file at {:?}", seeds_path))?;
        for seed_path in &plan.seed_assignments[idx] {
            writeln!(seeds_file, "{}", seed_path.display())?;
        }

        let task_dot = partition_dir.join(format!("task_{}.dot", idx + 1));
        let task_edges = select_function_edges(func_edges, task_functions);
        write_dot_graph(&task_dot, task_functions.clone(), &task_edges)?;
    }

    let partitions_json = partition_dir.join("partitions.json");
    write_partitions_json(
        &partitions_json,
        &plan,
        &expanded_tasks,
        &shared,
        coverage_by_function,
        workspace_root,
    )?;
    write_coverage_state(&state_path, &current_state)?;
    Ok(())
}

#[cfg(test)]
mod callgraph_tests {
    use super::{
        build_partition_graph, compact_partition_plan, expand_partition_tasks,
        normalize_coverage_function_name, parse_llvm_cov_export, partition_graph, shared_functions,
        version_from_dependency_req, CoverageState, FunctionCoverage, PartitionPlan,
        SeedTraceSummary,
    };
    use crate::options::Partitioner;
    use petgraph::graph::UnGraph;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::path::Path;

    #[test]
    fn parses_function_coverage_from_llvm_cov_export() {
        let json = br#"{
          "data": [{
            "functions": [
              {
                "name": "_RNvCs9jzkiEjFDR0_18run_with_callgraph6stage1",
                "count": 7,
                "filenames": ["src/lib.rs"],
                "regions": [
                  [1, 1, 1, 10, 7, 0, 0, 0],
                  [2, 1, 2, 10, 0, 0, 0, 0]
                ]
              }
            ]
          }]
        }"#;

        let parsed = parse_llvm_cov_export(json).unwrap();
        let stage1 = parsed.get("run_with_callgraph::stage1").unwrap();
        assert_eq!(stage1.count, 7);
        assert_eq!(stage1.region_total, 2);
        assert_eq!(stage1.region_covered, 1);
        assert_eq!(stage1.line_total, 2);
        assert_eq!(stage1.line_covered, 1);
        assert_eq!(stage1.file.as_deref(), Some("src/lib.rs"));
    }

    #[test]
    fn normalizes_full_demangled_path_without_hashes() {
        assert_eq!(
            normalize_coverage_function_name("_RNvCs9jzkiEjFDR0_18run_with_callgraph6stage2"),
            "run_with_callgraph::stage2"
        );
        assert_eq!(normalize_coverage_function_name("plain_name"), "plain_name");
    }

    #[test]
    fn derives_concrete_version_from_dependency_req() {
        assert_eq!(
            version_from_dependency_req("^0.4").as_deref(),
            Some("0.4.0")
        );
        assert_eq!(
            version_from_dependency_req(">=0.4.12, <0.5").as_deref(),
            Some("0.4.12")
        );
        assert_eq!(
            version_from_dependency_req("0.15.3").as_deref(),
            Some("0.15.3")
        );
    }

    #[test]
    fn builds_partition_graph_from_owned_nodes_only() {
        let mut func_edges = HashMap::new();
        func_edges.insert((String::from("stage1"), String::from("stage2")), 3);
        func_edges.insert((String::from("stage2"), String::from("memchr_naive")), 2);

        let mut coverage = HashMap::new();
        coverage.insert(
            String::from("stage1"),
            FunctionCoverage {
                count: 3,
                region_total: 4,
                region_covered: 4,
                line_total: 4,
                line_covered: 4,
                file: Some(String::from("/tmp/work/src/lib.rs")),
            },
        );
        coverage.insert(
            String::from("stage2"),
            FunctionCoverage {
                count: 3,
                region_total: 4,
                region_covered: 4,
                line_total: 4,
                line_covered: 4,
                file: Some(String::from("/tmp/work/src/lib.rs")),
            },
        );
        coverage.insert(
            String::from("memchr_naive"),
            FunctionCoverage {
                count: 2,
                region_total: 1,
                region_covered: 1,
                line_total: 1,
                line_covered: 1,
                file: Some(String::from(
                    "/rustc/toolchain/library/core/src/slice/memchr.rs",
                )),
            },
        );

        let graph = build_partition_graph(
            &func_edges,
            &[],
            &coverage,
            &HashMap::<String, CoverageState>::new(),
            &HashMap::<String, CoverageState>::new(),
            Path::new("/tmp/work"),
        );
        assert_eq!(graph.node_count(), 2);

        let plan = partition_graph(&graph, 2, &Partitioner::Ldg);
        assert_eq!(plan.partitions.len(), 2);
    }

    #[test]
    fn compacts_empty_partitions_before_seed_assignment() {
        let plan = compact_partition_plan(PartitionPlan {
            algorithm: "ldg",
            partitions: vec![
                vec![String::from("branch_z")],
                Vec::new(),
                vec![String::from("branch_other")],
            ],
            loads: vec![5, 0, 7],
            seed_assignments: vec![Vec::new(), Vec::new(), Vec::new()],
            partition_edges: vec![Vec::new(), Vec::new(), Vec::new()],
        });

        assert_eq!(
            plan.partitions,
            vec![
                vec![String::from("branch_z")],
                vec![String::from("branch_other")],
            ]
        );
        assert_eq!(plan.loads, vec![5, 7]);
        assert_eq!(plan.seed_assignments.len(), 2);
        assert_eq!(plan.partition_edges.len(), 2);
    }

    #[test]
    fn hrdf_replicates_boundary_nodes_instead_of_creating_islands() {
        let mut graph = UnGraph::<super::PartitionNode, u64>::new_undirected();
        let left = graph.add_node(super::PartitionNode {
            name: String::from("left"),
            weight: 10,
        });
        let hub = graph.add_node(super::PartitionNode {
            name: String::from("hub"),
            weight: 10,
        });
        let right = graph.add_node(super::PartitionNode {
            name: String::from("right"),
            weight: 10,
        });
        graph.add_edge(left, hub, 5);
        graph.add_edge(hub, right, 5);

        let plan = partition_graph(&graph, 2, &Partitioner::Hrdf);
        assert_eq!(plan.partitions.len(), 2);
        assert_eq!(plan.partition_edges.len(), 2);
        assert!(plan
            .partitions
            .iter()
            .all(|partition| partition.contains(&String::from("hub"))));
        assert!(
            plan.partition_edges.iter().all(|edges| !edges.is_empty()),
            "expected both HDRF partitions to own at least one edge: {:?}",
            plan.partition_edges
        );
    }

    #[test]
    fn expands_partition_tasks_with_shared_path_context() {
        let mut func_edges = HashMap::new();
        func_edges.insert(
            (String::from("__fuzz_target_impl"), String::from("stage1")),
            3,
        );
        func_edges.insert((String::from("stage1"), String::from("stage2")), 3);
        func_edges.insert((String::from("stage2"), String::from("memchr_naive")), 2);
        func_edges.insert((String::from("memchr_naive"), String::from("branch_z")), 2);
        func_edges.insert((String::from("stage2"), String::from("branch_other")), 1);
        func_edges.insert((String::from("branch_z"), String::from("helper_len")), 2);
        func_edges.insert((String::from("branch_z"), String::from("helper_first")), 2);
        func_edges.insert(
            (String::from("branch_other"), String::from("helper_len")),
            1,
        );

        let mut coverage = HashMap::new();
        for name in [
            "stage1",
            "stage2",
            "branch_z",
            "branch_other",
            "helper_len",
            "helper_first",
        ] {
            coverage.insert(
                String::from(name),
                FunctionCoverage {
                    count: 1,
                    region_total: 1,
                    region_covered: 1,
                    line_total: 1,
                    line_covered: 1,
                    file: Some(String::from("/tmp/work/src/lib.rs")),
                },
            );
        }
        for name in [
            "__fuzz_target_impl",
            "fuzz_helper",
            "fuzz_helper::{closure#0}",
        ] {
            coverage.insert(
                String::from(name),
                FunctionCoverage {
                    count: 1,
                    region_total: 1,
                    region_covered: 1,
                    line_total: 1,
                    line_covered: 1,
                    file: Some(String::from("/tmp/work/fuzz/fuzz_targets/demo.rs")),
                },
            );
        }
        coverage.insert(
            String::from("memchr_naive"),
            FunctionCoverage {
                count: 1,
                region_total: 1,
                region_covered: 1,
                line_total: 1,
                line_covered: 1,
                file: Some(String::from(
                    "/rustc/toolchain/library/core/src/slice/memchr.rs",
                )),
            },
        );
        let seed_summaries = vec![
            SeedTraceSummary {
                seed_path: Path::new("/tmp/work/seed-0").to_path_buf(),
                artifact_stem: String::from("seed-0"),
                function_hits: BTreeMap::from([
                    (String::from("stage1"), 1),
                    (String::from("stage2"), 1),
                    (String::from("branch_other"), 1),
                    (String::from("helper_len"), 1),
                ]),
                edge_hits: Vec::new(),
            },
            SeedTraceSummary {
                seed_path: Path::new("/tmp/work/seed-1").to_path_buf(),
                artifact_stem: String::from("seed-1"),
                function_hits: BTreeMap::from([
                    (String::from("stage1"), 1),
                    (String::from("stage2"), 1),
                    (String::from("branch_z"), 1),
                    (String::from("helper_len"), 1),
                    (String::from("helper_first"), 1),
                ]),
                edge_hits: Vec::new(),
            },
            SeedTraceSummary {
                seed_path: Path::new("/tmp/work/seed-2").to_path_buf(),
                artifact_stem: String::from("seed-2"),
                function_hits: BTreeMap::from([
                    (String::from("stage1"), 1),
                    (String::from("stage2"), 1),
                    (String::from("branch_z"), 1),
                    (String::from("helper_len"), 1),
                    (String::from("helper_first"), 1),
                ]),
                edge_hits: Vec::new(),
            },
        ];
        let shared = shared_functions(&seed_summaries, &coverage, Path::new("/tmp/work"));

        let partitions = vec![
            vec![String::from("branch_z"), String::from("helper_first")],
            vec![String::from("branch_other")],
        ];

        assert_eq!(
            shared,
            HashSet::from([
                String::from("__fuzz_target_impl"),
                String::from("fuzz_helper"),
                String::from("fuzz_helper::{closure#0}"),
                String::from("stage1"),
                String::from("stage2"),
                String::from("helper_len"),
            ])
        );

        let expanded = expand_partition_tasks(
            &partitions,
            &func_edges,
            &coverage,
            Path::new("/tmp/work"),
            &shared,
        );
        assert_eq!(
            expanded[0],
            vec![
                String::from("__fuzz_target_impl"),
                String::from("branch_z"),
                String::from("helper_first"),
                String::from("helper_len"),
                String::from("stage1"),
                String::from("stage2"),
            ]
        );
        assert_eq!(
            expanded[1],
            vec![
                String::from("__fuzz_target_impl"),
                String::from("branch_other"),
                String::from("helper_len"),
                String::from("stage1"),
                String::from("stage2"),
            ]
        );
        assert!(!expanded[0].iter().any(|name| name == "fuzz_helper"));
        assert!(!expanded[1]
            .iter()
            .any(|name| name == "fuzz_helper::{closure#0}"));
    }
}

fn select_function_edges(
    func_edges: &HashMap<(String, String), u64>,
    functions: &[String],
) -> HashMap<(String, String), u64> {
    let selected: HashSet<&str> = functions.iter().map(String::as_str).collect();
    func_edges
        .iter()
        .filter_map(|((caller, callee), count)| {
            (selected.contains(caller.as_str()) && selected.contains(callee.as_str()))
                .then_some(((caller.clone(), callee.clone()), *count))
        })
        .collect()
}

fn write_dot_graph(
    path: &Path,
    nodes: impl IntoIterator<Item = String>,
    func_edges: &HashMap<(String, String), u64>,
) -> Result<()> {
    let mut f = fs::File::create(path)
        .with_context(|| format!("failed to create DOT file at {:?}", path))?;

    writeln!(f, "digraph callgraph {{")?;
    writeln!(f, "    rankdir=LR;")?;
    writeln!(
        f,
        "    node [shape=box, style=filled, fillcolor=lightyellow];"
    )?;
    writeln!(f)?;

    let mut functions: Vec<_> = nodes.into_iter().collect();
    functions.sort();
    functions.dedup();

    // Declare nodes
    for func in &functions {
        let escaped = func.replace('\"', "\\\"");
        writeln!(f, "    \"{}\" [label=\"{}\"];", escaped, escaped)?;
    }
    writeln!(f)?;

    // Write edges sorted by count (descending) for readability
    let mut sorted_edges: Vec<_> = func_edges.iter().collect();
    sorted_edges.sort_by(|a, b| b.1.cmp(a.1));

    for ((caller, callee), count) in sorted_edges {
        let caller_escaped = caller.replace('\"', "\\\"");
        let callee_escaped = callee.replace('\"', "\\\"");
        writeln!(
            f,
            "    \"{}\" -> \"{}\" [label=\"{}\", penwidth={}];",
            caller_escaped,
            callee_escaped,
            count,
            // Scale pen width: log2(count) clamped to [1, 8]
            ((*count as f64).log2().max(1.0).min(8.0))
        )?;
    }

    writeln!(f, "}}")?;
    Ok(())
}

/// Write a DOT-format call graph.
fn write_dot_callgraph(path: &Path, func_edges: &HashMap<(String, String), u64>) -> Result<()> {
    let mut functions = HashSet::new();
    for (caller, callee) in func_edges.keys() {
        functions.insert(caller.clone());
        functions.insert(callee.clone());
    }
    write_dot_graph(path, functions, func_edges)
}

fn sysroot() -> Result<String> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("--print").arg("sysroot").output()?;
    // Note: We must trim() to remove the `\n` from the end of stdout
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn rustlib() -> Result<PathBuf> {
    let sysroot = sysroot()?;
    let mut pathbuf = PathBuf::from(sysroot);
    pathbuf.push("lib");
    pathbuf.push("rustlib");
    pathbuf.push(rustc_version::version_meta()?.host);
    pathbuf.push("bin");
    Ok(pathbuf)
}

fn collect_targets(value: &toml::Value) -> Vec<String> {
    let bins = value
        .as_table()
        .and_then(|v| v.get("bin"))
        .and_then(toml::Value::as_array);
    let mut bins = if let Some(bins) = bins {
        bins.iter()
            .map(|bin| {
                bin.as_table()
                    .and_then(|v| v.get("name"))
                    .and_then(toml::Value::as_str)
            })
            .filter_map(|name| name.map(String::from))
            .collect()
    } else {
        Vec::new()
    };
    // Always sort them, so that we have deterministic output.
    bins.sort();
    bins
}

pub struct Manifest {
    crate_name: String,
    edition: Option<String>,
}

impl Manifest {
    pub fn parse() -> Result<Self> {
        let metadata = MetadataCommand::new().no_deps().exec()?;
        let package = metadata.packages.first().with_context(|| {
            anyhow!(
                "Expected to find at least one package in {}",
                metadata.target_directory
            )
        })?;
        let crate_name = package.name.clone();
        let edition = Some(String::from(package.edition.as_str()));

        Ok(Manifest {
            crate_name,
            edition,
        })
    }
}

fn is_fuzz_manifest(value: &toml::Value) -> bool {
    let is_fuzz = value
        .as_table()
        .and_then(|v| v.get("package"))
        .and_then(toml::Value::as_table)
        .and_then(|v| v.get("metadata"))
        .and_then(toml::Value::as_table)
        .and_then(|v| v.get("cargo-fuzz"))
        .and_then(toml::Value::as_bool);
    is_fuzz == Some(true)
}

/// Returns the path for the first found non-fuzz Cargo package
fn find_package() -> Result<PathBuf> {
    let mut dir = env::current_dir()?;
    let mut data = Vec::new();
    loop {
        let manifest_path = dir.join("Cargo.toml");
        match fs::File::open(&manifest_path) {
            Err(_) => {}
            Ok(mut f) => {
                data.clear();
                f.read_to_end(&mut data)
                    .with_context(|| format!("failed to read {}", manifest_path.display()))?;
                let value: toml::Value = toml::from_slice(&data).with_context(|| {
                    format!(
                        "could not decode the manifest file at {}",
                        manifest_path.display()
                    )
                })?;
                if !is_fuzz_manifest(&value) {
                    // Not a cargo-fuzz project => must be a proper cargo project :)
                    return Ok(dir);
                }
            }
        }
        if !dir.pop() {
            break;
        }
    }
    bail!("could not find a cargo project")
}

fn strip_current_dir_prefix(path: &Path) -> &Path {
    env::current_dir()
        .ok()
        .and_then(|curdir| path.strip_prefix(curdir).ok())
        .unwrap_or(path)
}
