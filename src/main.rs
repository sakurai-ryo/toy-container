mod cli;
mod errors;

use errors::exit_with_retcode;
use log::debug;

fn main() {
    let args = cli::parse_args();
    match args {
        Ok(args) => {
            debug!("Args: {:?}", args);
            exit_with_retcode(Ok(()));
        }
        Err(e) => {
            exit_with_retcode(Err(e));
        }
    }
}
