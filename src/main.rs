mod child;
mod cli;
mod config;
mod container;
mod errors;
mod hostname;
mod ipc;
mod kernel;

#[macro_use]
extern crate scan_fmt;

use errors::exit_with_retcode;
use log::debug;

fn main() {
    let args = cli::parse_args();
    match args {
        Ok(args) => {
            debug!("Args: {:?}", args);
            exit_with_retcode(container::start(args));
        }
        Err(e) => {
            exit_with_retcode(Err(e));
        }
    }
}
