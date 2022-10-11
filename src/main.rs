mod capabilities;
mod child;
mod cli;
mod cmd_create;
mod cmd_start;
mod config;
mod container;
mod errors;
mod hostname;
mod ipc;
mod kernel;
mod mounts;
mod namespaces;
mod resources;
mod spec;
mod syscalls;
mod utils;

#[macro_use]
extern crate scan_fmt;

use errors::exit_with_retcode;

fn main() {
    exit_with_retcode(cli::run_subcommand());
}
