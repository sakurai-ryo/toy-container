use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Args {
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
}

pub fn parse_args() -> Args {
    let args = Args::from_args();

    match args.debug {
        true => setup_log(log::LevelFilter::Debug),
        false => setup_log(log::LevelFilter::Info),
    }

    args
}

pub fn setup_log(level: log::LevelFilter) {
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .filter(None, level)
        .init();
}
