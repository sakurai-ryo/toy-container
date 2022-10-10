use crate::cmd_create;
use crate::cmd_start;
use crate::errors::Errcode;

use log::LevelFilter;
use structopt::{clap, StructOpt};

pub trait CommandDef {
    fn run(&self) -> Result<(), Errcode>;
    fn validate(&self) -> Result<(), Errcode>;
    fn setup_logger(&self, debug: bool) -> Result<(), Errcode> {
        let log_level = if debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        };
        env_logger::Builder::from_default_env()
            .format_timestamp_secs()
            .filter(None, log_level)
            .init();
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
#[structopt(setting(clap::AppSettings::ColoredHelp))]
pub struct CommandOpt {
    #[structopt(subcommand)]
    sub: SubCommands,
}

#[derive(Debug, StructOpt)]
#[structopt(about = "toycon COMMAND [OPTIONS, ...]")]
pub enum SubCommands {
    #[structopt(about = "Create container")]
    #[structopt(setting(clap::AppSettings::ColoredHelp))]
    Create(cmd_create::CreateCmdInput),

    #[structopt(about = "Run container")]
    #[structopt(setting(clap::AppSettings::ColoredHelp))]
    Run(cmd_start::RunCmdInput),
}

pub fn run_subcommand() -> Result<(), Errcode> {
    match CommandOpt::from_args().sub {
        SubCommands::Create(cmd) => cmd.run(),
        SubCommands::Run(cmd) => cmd.run(),
    }
}
