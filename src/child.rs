use crate::config::ContainerOpts;
use crate::errors::Errcode;
use crate::hostname::set_container_hostname;

use log::{debug, error, info};
use nix::libc::tm;
use nix::sched::clone;
use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

// 1KiB
const STACK_SIZE: usize = 1024 * 1024;

pub fn generate_child_process(config: ContainerOpts) -> Result<Pid, Errcode> {
    let mut tmp_stack: [u8; STACK_SIZE] = [0; STACK_SIZE]; // stack for child_process

    // namespace related flags
    let mut flags = CloneFlags::empty();
    flags.insert(CloneFlags::CLONE_NEWNS); // mount namespace
    flags.insert(CloneFlags::CLONE_NEWCGROUP); // cgroup namespace
    flags.insert(CloneFlags::CLONE_NEWPID); // pid namespace
    flags.insert(CloneFlags::CLONE_NEWIPC); // ipc namespace
    flags.insert(CloneFlags::CLONE_NEWNET); // network namespace
    flags.insert(CloneFlags::CLONE_NEWUTS); // uts namespace

    // https://qiita.com/wellflat/items/7d62f2a63e9fcddb31cc
    match clone(
        Box::new(|| child(config.clone())), // args for child_process
        &mut tmp_stack,
        flags,
        Some(Signal::SIGCHLD as i32),
    ) {
        Ok(pid) => Ok(pid),
        Err(e) => {
            debug!("Clone Err: {}", e);
            Err(Errcode::ChildProcessError(0))
        }
    }
}

fn child(config: ContainerOpts) -> isize {
    match setup_container_configurations(&config) {
        Ok(_) => info!("Container set up successfully"),
        Err(e) => {
            error!("Error while configuring container: {:?}", e);
            return -1;
        }
    }

    info!(
        "Starting container with command {} and args {:?}",
        config.path.to_str().unwrap(),
        config.argv
    );

    0
}

fn setup_container_configurations(config: &ContainerOpts) -> Result<(), Errcode> {
    set_container_hostname(&config.hostname)?;
    Ok(())
}
