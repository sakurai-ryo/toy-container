mod cli;
mod error;

use log::info;

fn main() {
    let args = cli::parse_args();

    info!("{:?}", args);
}
