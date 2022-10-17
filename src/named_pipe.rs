use crate::errors::Errcode;

use log::{debug, error};
use nix::sys::stat;
use nix::sys::wait::waitpid;
use nix::unistd;
use nix::unistd::{fork, getpid, getppid, ForkResult};
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use tempdir::TempDir;

const EXEC_FIFO_FILENAME: &'static str = "exec.fifo";

pub fn create_named_pipe() -> Result<PathBuf, Errcode> {
    let tmp_dir = match TempDir::new("toycon") {
        Ok(t) => Ok(t),
        Err(_) => Err(Errcode::TempDirCreateError(0)),
    }?;
    let fifo_path = tmp_dir.path().join(EXEC_FIFO_FILENAME);

    match unistd::mkfifo(&fifo_path, stat::Mode::S_IRWXU) {
        Ok(_) => debug!("created fifo file {:?}", fifo_path),
        Err(err) => error!("Error creating fifo: {}", err),
    };

    Ok(fifo_path)
}

pub fn await_fifo_open() {}

pub fn fifo_open() {}
