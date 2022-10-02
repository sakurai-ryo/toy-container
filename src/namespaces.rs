use crate::errors::Errcode;
use crate::ipc::{recv_boolean, send_boolean};

use log::{debug, info};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::Pid;
use nix::unistd::{setgroups, setresgid, setresuid};
use nix::unistd::{Gid, Uid};
use std::fs::File;
use std::io::Write;
use std::os::unix::io::RawFd;

const USERNS_OFFSET: u64 = 10000; // uid starts with the number 10000
const USERNS_COUNT: u64 = 2000; // number of users limited to 2000

// exec by child
pub fn userns(fd: RawFd, uid: u32) -> Result<(), Errcode> {
    debug!("Setting up user namespace with UID {}", uid);

    // use new user namespace which is not shared with any previously existing process.
    let has_users = unshare(CloneFlags::CLONE_NEWUSER).is_ok();
    send_boolean(fd, has_users)?; // tells parent if support namespaces

    if recv_boolean(fd)? {
        return Err(Errcode::NamespacesError(0));
    }

    if has_users {
        info!("User namespaces set up");
    } else {
        info!("User namespaces not supported, continuing...");
    }

    debug!("Switching to uid {} / gid {}...", uid, uid);
    let gid = Gid::from_raw(uid);
    let uid = Uid::from_raw(uid);
    // set the list of groups the process is part of
    if setgroups(&[gid]).is_err() {
        return Err(Errcode::NamespacesError(1));
    }

    // https://stackoverflow.com/questions/32455684/difference-between-real-user-id-effective-user-id-and-saved-user-id/32456814#32456814
    if setresgid(gid, gid, gid).is_err() {
        return Err(Errcode::NamespacesError(2));
    }
    if setresuid(uid, uid, uid).is_err() {
        return Err(Errcode::NamespacesError(3));
    }

    Ok(())
}

pub fn handle_child_uid_map(pid: Pid, fd: RawFd) -> Result<(), Errcode> {
    // child tells parent
    if recv_boolean(fd)? {
        write_proc_uid_file(pid, "uid_map")?;
        write_proc_uid_file(pid, "gid_map")?;
    } else {
        info!("No user namespace set up from child process");
    }

    debug!("Child UID/GID map done, sending signal to child to continue...");
    send_boolean(fd, false)
}

pub fn write_proc_uid_file(pid: Pid, file_name: &str) -> Result<(), Errcode> {
    /*
    `/proc/<pid>/uidmap` file is following format
    ```
    ID-inside-ns ID-outside-ns length
    ```
    */
    let mut uid_map = match File::create(format!("/proc/{}/{}", pid.as_raw(), file_name)) {
        Ok(f) => f,
        Err(_) => return Err(Errcode::NamespacesError(5)),
    };

    match uid_map.write_all(format!("0 {} {}", USERNS_OFFSET, USERNS_COUNT).as_bytes()) {
        Ok(_) => Ok(()),
        Err(_) => Err(Errcode::NamespacesError(4)),
    }
}
