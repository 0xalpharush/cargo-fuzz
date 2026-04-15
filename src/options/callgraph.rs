use crate::{
    options::{BuildOptions, FuzzDirWrapper},
    project::FuzzProject,
    RunCommand,
};
use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Partitioner {
    Ldg,
    Fennel,
    Hrdf,
    Random,
}

#[derive(Clone, Debug, Parser)]
pub struct Callgraph {
    #[command(flatten)]
    pub build: BuildOptions,

    /// Name of the fuzz target
    pub target: String,

    /// Custom corpus directories or artifact files.
    pub corpus: Vec<String>,

    #[command(flatten)]
    pub fuzz_dir_wrapper: FuzzDirWrapper,

    /// Path to LLVM tools (llvm-profdata, llvm-cov)
    #[arg(long)]
    pub llvm_path: Option<PathBuf>,

    /// Number of concurrent jobs
    #[arg(
        short,
        long,
        default_value_t = u16::try_from(num_cpus::get().max(1)).unwrap_or(u16::MAX),
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub jobs: u16,

    /// Maximum number of graph partitions/tasks to emit. Actual count may be
    /// lower if the call graph has fewer function clusters than requested.
    #[arg(
        long,
        default_value_t = 8,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub partitions: u16,

    /// Graph partitioning algorithm.
    #[arg(long, value_enum, default_value_t = Partitioner::Ldg)]
    pub partitioner: Partitioner,

    #[arg(last(true))]
    /// Additional arguments passed through to the binary
    pub args: Vec<String>,
}

impl RunCommand for Callgraph {
    fn run_command(&mut self) -> Result<()> {
        let project = FuzzProject::new(self.fuzz_dir_wrapper.fuzz_dir.to_owned())?;
        project.exec_callgraph(self)
    }
}
