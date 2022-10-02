use crate::errors::Errcode;

use cgroups_rs::cgroup_builder::CgroupBuilder;
use cgroups_rs::hierarchies::V2;
use cgroups_rs::{CgroupPid, MaxValue};
use log::{debug, error};
use nix::unistd::Pid;
use rlimit::{setrlimit, Resource};
use std::convert::TryInto;
use std::fs::{canonicalize, remove_dir};

//                       KiB    MiB    Gib
const KMEM_LIMIT: i64 = 1024 * 1024 * 1024;
const MEM_LIMIT: i64 = KMEM_LIMIT;
const MAX_PID: MaxValue = MaxValue::Value(64);
const NOFILE_RLIMIT: u64 = 64;

pub fn restict_resources(hostname: &String, pid: Pid) -> Result<(), Errcode> {
    debug!("Restricting resources for hostname {}", hostname);

    // Cgroups
    let cgs = CgroupBuilder::new(hostname)
        // Allocate less CPU time than other processes
        .cpu()
        .shares(256)
        .done()
        // Limiting the memory usage to 1 GiB
        // The user can limit it to less than this, never increase above 1Gib
        .memory()
        .kernel_memory_limit(KMEM_LIMIT)
        .memory_hard_limit(MEM_LIMIT)
        .done()
        // This process can only create a maximum of 64 child processes
        .pid()
        .maximum_number_of_processes(MAX_PID)
        .done()
        // Give an access priority to block IO lower than the system
        .blkio()
        .weight(50)
        .done()
        .build(Box::new(V2::new()));
    debug!("cgroups info: {:?}", cgs);

    // apply the cgroups rules to the child process we just created
    let pid: u64 = pid.as_raw().try_into().unwrap();
    if let Err(e) = cgs.add_task(CgroupPid::from(pid)) {
        error!("cgroup add task error: {}", e);
        return Err(Errcode::ResourcesError(0));
    };

    // Rlimit
    // Can create only 64 file descriptors
    if setrlimit(Resource::NOFILE, NOFILE_RLIMIT, NOFILE_RLIMIT).is_err() {
        return Err(Errcode::ResourcesError(0));
    }

    Ok(())
}

pub fn clean_cgroups(hostname: &String) -> Result<(), Errcode> {
    debug!("Cleaning cgroups");

    match canonicalize(format!("/sys/fs/cgroup/{}/", hostname)) {
        Ok(p) => {
            if remove_dir(p).is_err() {
                return Err(Errcode::ResourcesError(2));
            }
        }
        Err(e) => {
            error!("Error while canonicalize path: {}", e);
            return Err(Errcode::ResourcesError(3));
        }
    }

    Ok(())
}
