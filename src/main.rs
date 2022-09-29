mod cli;
mod errors;

use errors::exit_with_retcode;
use log::{error, info};

fn main() {
    let args = cli::parse_args();
    match args {
        Ok(args) => {
            info!("Args: {:?}", args);
        }
        Err(e) => {
            error!("Error while parsing arguments:\n\t{}", e);
            exit_with_retcode(Err(e));
        }
    }
}
