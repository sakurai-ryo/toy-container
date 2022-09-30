use crate::errors::Errcode;
use log::debug;
use nix::sys::utsname::uname;

pub const MINIMAL_KERNEL_VERSION: f32 = 4.8;

pub fn check_linux_version() -> Result<(), Errcode> {
    let host = uname().unwrap();
    let release = host.release().to_str().unwrap();
    let machine = host.machine().to_str().unwrap();
    debug!("Linux release: {}", release);
    debug!("Machine hardware platform: {}", machine);

    if let Ok(version) = scan_fmt!(release, "{f}.{}", f32) {
        if version < MINIMAL_KERNEL_VERSION {
            return Err(Errcode::NotSupported(0));
        }
    } else {
        return Err(Errcode::ContainerError(0));
    }

    if host.machine() != "x86_64" {
        return Err(Errcode::NotSupported(1));
    }

    Ok(())
}
