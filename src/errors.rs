use log::{debug, error};
use std::fmt;
use std::process::exit;

#[derive(Debug)]
pub enum Errcode {
    ArgumentInvalid(&'static str),
    ContainerError(u8),
    NotSupported(u8),
    SocketError(u8),
    ChildProcessError(u8),
    HostnameError(u8),
    RngError,
    MountsError(u8),
    NamespacesError(u8),
    SyscallsError(u8),
    CapabilitiesError(u8),
    ResourcesError(u8),
    TempDirCreateError(u8),

    // https://github.com/opencontainers/runc/blob/main/libcontainer/error.go
    ExistErrors,
    InvalidIDError,
    NotExistError,
    PausedError,
    RunningError,
    NotRunningError,
    NotPausedError,
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
            Errcode::ExistErrors => write!(f, "container with given ID already exists"),
            Errcode::InvalidIDError => write!(f, "invalid container ID format"),
            Errcode::NotExistError => write!(f, "container does not exist"),
            Errcode::PausedError => write!(f, "container paused"),
            Errcode::RunningError => write!(f, "container still running"),
            Errcode::NotRunningError => write!(f, "container not running"),
            Errcode::NotPausedError => write!(f, "container not paused"),
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
