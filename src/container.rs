use crate::cli::Args;
use crate::config::ContainerOpts;
use crate::errors::Errcode;
use crate::kernel::check_linux_version;

use nix::unistd::close;
use std::os::unix::io::RawFd;

use log::{debug, error};

pub struct Container {
    sockets: (RawFd, RawFd),
    config: ContainerOpts,
}

impl Container {
    pub fn new(args: Args) -> Result<Container, Errcode> {
        let (config, sockets) = ContainerOpts::new(args.command, args.uid, args.mount_dir)?;

        Ok(Container { sockets, config })
    }

    pub fn create(&mut self) -> Result<(), Errcode> {
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
    container.clean_exit()
}
