use crate::errors::Errcode;
use crate::utils::random_string;

use log::{debug, error};
use nix::mount::{mount, MsFlags};
use nix::mount::{umount2, MntFlags};
use nix::unistd::chdir;
use nix::unistd::pivot_root;
use std::fs::create_dir_all;
use std::fs::remove_dir;
use std::path::PathBuf;

pub fn setmountpoint(mount_dir: &PathBuf) -> Result<(), Errcode> {
    // $ ROOTFS=$(mktemp -d)
    // $ cp -a /bin /lib /lib64 $ROOTFS
    // $ NEW_ROOT=$ROOTFS
    // $ mkdir $NEW_ROOT/{.put_old,proc}
    // $ unshare -mpfr /bin/sh -c " \
    //   mount --bind $NEW_ROOT $NEW_ROOT && \
    //   mount -t proc proc $NEW_ROOT/proc && \
    //   pivot_root $NEW_ROOT $NEW_ROOT/.put_old && \
    //   umount -l /.put_old && \
    //   cd / && \
    //   exec /bin/sh
    // "

    debug!("Setting mount points ...");
    mount_directory(
        None,
        &PathBuf::from("/"),
        vec![MsFlags::MS_REC, MsFlags::MS_PRIVATE],
    )?;

    let new_root = PathBuf::from(format!("/tmp/crabcan.{}", random_string(12)));
    debug!(
        "Mounting temp directory {}",
        new_root.as_path().to_str().unwrap()
    );
    create_directory(&new_root)?;
    mount_directory(
        Some(&mount_dir),
        &new_root,
        vec![MsFlags::MS_BIND, MsFlags::MS_PRIVATE],
    )?;

    debug!("Pivoting root");
    let old_root_tail = format!("oldroot.{}", random_string(6));
    let put_old = new_root.join(PathBuf::from(old_root_tail.clone()));
    create_directory(&put_old)?;
    if let Err(_) = pivot_root(&new_root, &put_old) {
        return Err(Errcode::MountsError(4));
    }

    debug!("Unmounting old root");
    let old_root = PathBuf::from(format!("/{}", old_root_tail));
    if let Err(_) = chdir(&PathBuf::from("/")) {
        return Err(Errcode::MountsError(5));
    }
    unmount_path(&old_root)?;
    delete_dir(&old_root)?;

    Ok(())
}

// TODO: 実装
pub fn clean_mounts(_rootpath: &PathBuf) -> Result<(), Errcode> {
    Ok(())
}

pub fn mount_directory(
    path: Option<&PathBuf>,
    mount_point: &PathBuf,
    flags: Vec<MsFlags>,
) -> Result<(), Errcode> {
    // https://blog.amedama.jp/entry/linux-mount-namespace
    let mut ms_flags = MsFlags::empty();
    for f in flags.iter() {
        ms_flags.insert(*f);
    }

    match mount::<PathBuf, PathBuf, PathBuf, PathBuf>(path, mount_point, None, ms_flags, None) {
        Ok(_) => Ok(()),
        Err(e) => {
            if let Some(p) = path {
                error!(
                    "Cannot mount {} to {}: {}",
                    p.to_str().unwrap(),
                    mount_point.to_str().unwrap(),
                    e
                );
            } else {
                error!("Cannot remount {}: {}", mount_point.to_str().unwrap(), e);
            }
            Err(Errcode::MountsError(3))
        }
    }
}

pub fn create_directory(path: &PathBuf) -> Result<(), Errcode> {
    match create_dir_all(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Cannot create directory {}: {}", path.to_str().unwrap(), e);
            Err(Errcode::MountsError(2))
        }
    }
}

pub fn unmount_path(path: &PathBuf) -> Result<(), Errcode> {
    match umount2(path, MntFlags::MNT_DETACH) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Unable to umount {}: {}", path.to_str().unwrap(), e);
            Err(Errcode::MountsError(0))
        }
    }
}

pub fn delete_dir(path: &PathBuf) -> Result<(), Errcode> {
    match remove_dir(path.as_path()) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!(
                "Unable to delete directory {}: {}",
                path.to_str().unwrap(),
                e
            );
            Err(Errcode::MountsError(1))
        }
    }
}
