//! Library entrypoint for `git-dfs`. The binary in `src/main.rs` is a thin
//! shell over these modules so the same code is exercisable from integration
//! tests without spawning a subprocess.

pub mod config;
pub mod filter_process;
pub mod install;
pub mod local_reconstruct;
pub mod manifest_cache;
pub mod pktline;
pub mod pointer;
pub mod remote_manifest;
pub mod track;
