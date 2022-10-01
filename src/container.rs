use crate::child::generate_child_process;
use crate::cli::Args;
use crate::config::ContainerOpts;
use crate::errors::Errcode;
use crate::kernel::check_linux_version;
use crate::mounts::clean_mounts;

use log::{debug, error};
use nix::sys::wait::waitpid;
use nix::unistd::close;
use nix::unistd::Pid;
use std::os::unix::io::RawFd;

pub struct Container {
    sockets: (RawFd, RawFd),
    config: ContainerOpts,
    child_pid: Option<Pid>,
}

impl Container {
    pub fn new(args: Args) -> Result<Container, Errcode> {
        let (config, sockets) = ContainerOpts::new(args.command, args.uid, args.mount_dir)?;

        Ok(Container {
            sockets,
            config,
            child_pid: None,
        })
    }

    pub fn create(&mut self) -> Result<(), Errcode> {
        let pid = generate_child_process(self.config.clone())?;
        self.child_pid = Some(pid);

        debug!("Creation finished");
        Ok(())
    }

    pub fn clean_exit(&mut self) -> Result<(), Errcode> {
        debug!("Cleaning container");

        for socket in [self.sockets.0, self.sockets.1].iter() {
            if let Err(e) = close(*socket) {
                log::error!("Unable to close write socket: {:?}", e);
                return Err(Errcode::SocketError(3));
            }
        }

        clean_mounts(&self.config.mount_dir)?;

        Ok(())
    }
}

pub fn start(args: Args) -> Result<(), Errcode> {
    check_linux_version()?;

    let mut container = Container::new(args)?;
    if let Err(e) = container.create() {
        container.clean_exit()?;
        error!("Error while creating container: {:?}", e);
        return Err(e);
    }

    debug!("Finished, cleaning & exit");
    wait_child(container.child_pid)?;
    container.clean_exit()
}

pub fn wait_child(pid: Option<Pid>) -> Result<(), Errcode> {
    if let Some(child_pid) = pid {
        debug!("Waiting for child (pid {}) to finish", child_pid);
        if let Err(e) = waitpid(child_pid, None) {
            error!("Error while waiting for pid to finish: {:?}", e);
            return Err(Errcode::ContainerError(1));
        }
    }

    Ok(())
}
