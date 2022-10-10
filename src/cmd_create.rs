use crate::cli::CommandDef;
use crate::container;
use crate::errors::Errcode;

use log::debug;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct CreateCmdInput {
    /// Activate debug mode
    #[structopt(short, long)]
    debug: bool,

    /// Command to execute inside the container
    #[structopt(short, long)]
    pub command: String,

    /// User ID to create inside the container
    #[structopt(short, long)]
    pub uid: u32,

    /// Directory to mount as root of the container
    #[structopt(parse(from_os_str), short = "m", long = "mount")]
    pub mount_dir: PathBuf,

    /// Mount a directory inside the container
    #[structopt(parse(from_os_str), short = "a", long = "add")]
    pub addpaths: Vec<PathBuf>,
}

impl CommandDef for CreateCmdInput {
    fn validate(&self) -> Result<(), Errcode> {
        if !self.mount_dir.exists() || !self.mount_dir.is_dir() {
            return Err(Errcode::ArgumentInvalid("mount"));
        }

        if self.command.is_empty() {
            return Err(Errcode::ArgumentInvalid("command"));
        }

        debug!("Args: {:?}", self);
        Ok(())
    }

    fn run(&self) -> Result<(), Errcode> {
        self.validate()?;
        self.setup_logger(self.debug)?;

        container::start(self)?;
        Ok(())
    }
}
