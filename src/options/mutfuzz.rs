use crate::{
    options::{BuildOptions, FuzzDirWrapper},
    project::FuzzProject,
    RunCommand,
};
use anyhow::Result;
use clap::Parser;

#[derive(Clone, Debug, Parser)]
pub struct MutFuzz {
    #[command(flatten)]
    pub build: BuildOptions,

    /// Name of the fuzz target
    pub target: String,

    /// Custom corpus directories or artifact files.
    pub corpus: Vec<String>,

    #[command(flatten)]
    pub fuzz_dir_wrapper: FuzzDirWrapper,

    /// Total fuzzing budget in seconds
    #[arg(long, default_value = "3600")]
    pub budget: u64,

    /// Seconds to fuzz each mutant
    #[arg(long, default_value = "300")]
    pub time_per_mutant: u64,

    /// Fraction of budget spent on mutant fuzzing (0.0-1.0)
    #[arg(long, default_value = "0.5")]
    pub fraction_mutant: f64,

    /// Number of simultaneous mutations per mutant
    #[arg(long, default_value = "1")]
    pub order: usize,

    /// Don't reuse the same mutant
    #[arg(long)]
    pub avoid_repeats: bool,

    /// Only mutate functions matching these patterns (comma-separated)
    #[arg(long)]
    pub only_mutate: Option<String>,

    /// Avoid mutating functions matching these patterns (comma-separated)
    #[arg(long)]
    pub avoid_mutating: Option<String>,

    /// RNG seed for reproducibility
    #[arg(long)]
    pub seed: Option<u64>,

    /// Number of parallel jobs for the normal fuzzing phase
    #[arg(
        short,
        long,
        default_value = "1",
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub jobs: u16,

    #[arg(last(true))]
    /// Additional libFuzzer arguments passed through to the binary
    pub args: Vec<String>,
}

impl RunCommand for MutFuzz {
    fn run_command(&mut self) -> Result<()> {
        let project = FuzzProject::new(self.fuzz_dir_wrapper.fuzz_dir.to_owned())?;
        project.exec_mutfuzz(self)
    }
}
