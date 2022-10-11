use crate::child::generate_child_process;
use crate::cmd_create::CreateCmdInput;
use crate::config::ContainerOpts;
use crate::errors::Errcode;
use crate::kernel::check_linux_version;
use crate::mounts::clean_mounts;
use crate::namespaces::handle_child_uid_map;
use crate::resources::clean_cgroups;
use crate::resources::restict_resources;

use log::{debug, error};
use nix::sys::wait::waitpid;
use nix::unistd::close;
use nix::unistd::Pid;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub struct Container {
    sockets: (RawFd, RawFd),
    config: ContainerOpts,
    child_pid: Option<Pid>,
}

impl Container {
    pub fn new(args: &CreateCmdInput) -> Result<Container, Errcode> {
        let mut addpaths = vec![];
        for ap_pair in args.addpaths.iter() {
            let mut pair = ap_pair.to_str().unwrap().split(":");
            let frompath = PathBuf::from(pair.next().unwrap())
                .canonicalize()
                .expect("Cannot canonicalize path")
                .to_path_buf();
            let mntpath = PathBuf::from(pair.next().unwrap())
                .strip_prefix("/")
                .expect("Cannot strip prefix from path")
                .to_path_buf();
            addpaths.push((frompath, mntpath));
        }

        let (config, sockets) = ContainerOpts::new(
            args.command.clone(),
            args.uid,
            args.mount_dir.clone(),
            addpaths,
        )?;

        Ok(Container {
            sockets,
            config,
            child_pid: None,
        })
    }

    pub fn create(&mut self) -> Result<(), Errcode> {
        let pid = generate_child_process(self.config.clone())?;
        restict_resources(&self.config.hostname, pid)?;
        handle_child_uid_map(pid, self.sockets.0)?;
        self.child_pid = Some(pid);

        debug!("Creation finished");
        Ok(())
    }

    pub fn clean_exit(&mut self) -> Result<(), Errcode> {
        debug!("Cleaning container");

        for socket in [self.sockets.0, self.sockets.1].iter() {
            if let Err(e) = close(*socket) {
                error!("Unable to close write socket: {:?}", e);
                return Err(Errcode::SocketError(3));
            }
        }

        if let Err(e) = clean_cgroups(&self.config.hostname) {
            error!("Cgroups cleaning failed: {}", e);
            return Err(e);
        }

        clean_mounts(&self.config.mount_dir)?;

        Ok(())
    }
}

// 参孝実装
// https://github.com/opencontainers/runc/blob/526d3b33742eaf502d8bf156ca794aae58ade8c7/utils_linux.go#L312
pub fn start(args: &CreateCmdInput) -> Result<(), Errcode> {
    check_linux_version()?;

    let mut container = Container::new(args)?;
    if let Err(e) = container.create() {
        error!("Error while creating container: {:?}", e);
        container.clean_exit()?;
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
