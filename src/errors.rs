use log::{debug, error};
use std::fmt;
use std::process::exit;

#[derive(Debug)]
pub enum Errcode {
    ArgumentInvalid(&'static str),
    ContainerError(u8),
    NotSupported(u8),
}

impl Errcode {
    pub fn get_retcode(&self) -> i32 {
        1
    }
}

#[allow(unreachable_patterns)]
impl fmt::Display for Errcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Errcode::ArgumentInvalid(element) => write!(f, "ArgumentInvalid: {}", element),
            _ => write!(f, "Unknown error"),
        }
    }
}

pub fn exit_with_retcode(res: Result<(), Errcode>) {
    match res {
        Ok(_) => {
            debug!("Exit without any error, returning 0");
            exit(0);
        }

        Err(e) => {
            let retcode = e.get_retcode();
            error!("Error on exit:\n\t{}\n\tReturning {}", e, retcode);
            exit(retcode);
        }
    }
}
