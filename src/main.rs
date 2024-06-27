use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{clone, unshare, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execve, getpid, pivot_root, sethostname, Pid};

use which::which;

use std::env;
use std::ffi::CString;
use std::fs::{create_dir, create_dir_all, remove_dir, write};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

const ROOT_DIR: &str = "./root";
const CGROUP_DIR: &str = "/sys/fs/cgroup/container";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Invalid arguments");
        return;
    }

    // コンテナプロセスを作成する前に、事前にcgroupを作成する
    // コンテナプロセスはここで作成したcgroupをrootとして起動させるため
    if let Err(e) = setup_cgroup() {
        eprintln!("cgroup setting error: {:?}", e);
        return;
    }

    match clone_container_process(args) {
        Ok(pid) => {
            println!("Created Container with PID: {}", pid);
            match waitpid(pid, None) {
                Ok(status) => match status {
                    // https://github.com/nix-rust/nix/blob/1bfbb034cba446a370ba3c899a235b94fbcc2099/src/sys/wait.rs#L88
                    WaitStatus::Exited(_, status) => {
                        println!("Container process exited: {:?}", status)
                    }
                    WaitStatus::Signaled(_, status, _) => {
                        println!("Container process killed by signal: {:?}", status)
                    }
                    _ => eprintln!("Unexpected WaitStatus"),
                },
                Err(e) => eprintln!("Error waiting for child process: {:?}", e),
            }
        }
        Err(e) => {
            eprintln!("Error creating new process: {:?}", e);
        }
    }

    // コンテナ用のcgroup削除
    if let Err(e) = remove_dir(PathBuf::from(CGROUP_DIR)) {
        eprintln!("cgroup umount error: {:?}", e);
    }
}

fn clone_container_process(args: Vec<String>) -> Result<Pid, nix::Error> {
    let mut stack = vec![0; 1024 * 1024]; // 1MB
    let clone_flags = CloneFlags::CLONE_NEWUTS // UTS namespace
    | CloneFlags::CLONE_NEWPID // PID namespace
    | CloneFlags::CLONE_NEWNS // mount namespace
    | CloneFlags::CLONE_NEWIPC // IPC namespace
    | CloneFlags::CLONE_NEWNET; // network namespace

    // cloneはunsafeになったので注意
    // https://github.com/nix-rust/nix/pull/1993
    unsafe {
        clone(
            Box::new(|| container_process(args.clone())),
            &mut stack,
            clone_flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
}

fn setup_cgroup() -> Result<(), io::Error> {
    let cgroup_path = &PathBuf::from(CGROUP_DIR);

    // コンテナ用に子cgroupを作成する
    create_dir_all(PathBuf::from(cgroup_path))?;

    // メモリのハードリミットを50Mに設定する
    write(PathBuf::from(cgroup_path).join("memory.max"), "50M")?;
    Ok(())
}

fn container_process(args: Vec<String>) -> isize {
    if let Err(e) = setup_child_process() {
        eprintln!("setup_child_process failed: {:?}", e);
        return e as isize;
    }

    let command = args[1].clone();
    let command_bin_path = which(command).unwrap_or(PathBuf::from("/bin/bash"));
    let cstr_command = CString::new(command_bin_path.as_os_str().as_bytes())
        .unwrap_or(CString::new("/bin/bash").unwrap());

    let args = &args[2..];
    let cstr_args: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).unwrap_or(CString::new("").unwrap()))
        .collect();

    if let Err(e) = execve::<CString, CString>(&cstr_command, &cstr_args, &[]) {
        return e as isize;
    }
    0
}

fn setup_child_process() -> Result<(), nix::Error> {
    setup_container_cgroup()?;
    change_hostname()?;
    disable_mount_propagation()?;
    change_container_root_dir()?;
    mount_special_filesystem()?;

    Ok(())
}

fn setup_container_cgroup() -> Result<(), nix::Error> {
    // プロセスIDの書き込み、cgroupを適用する
    let child_pid = getpid().as_raw().to_string();
    write(PathBuf::from(CGROUP_DIR).join("cgroup.procs"), child_pid).map_err(|e| {
        eprintln!("write error: {:?}", e);
        match e.raw_os_error() {
            Some(errno) => nix::Error::from_raw(errno),
            None => nix::errno::Errno::UnknownErrno,
        }
    })?;

    // cgroup namespaceの適用
    unshare(CloneFlags::CLONE_NEWCGROUP)?;

    Ok(())
}

fn change_hostname() -> Result<(), nix::Error> {
    // UTS namespaceの動作確認のためhostnameを変更する
    sethostname("container")?;

    Ok(())
}

fn disable_mount_propagation() -> Result<(), nix::Error> {
    // マウントプロパゲーションの無効化
    // runcの参考箇所: https://github.com/opencontainers/runc/blob/d8a3daacbd8e30b074047c060d2eeb4f48ffa1cf/libcontainer/rootfs_linux.go#L784
    // runcの参孝コミット: https://github.com/opencontainers/runc/commit/117c92745bd098bf05a69489b7b78cac6364e1d0
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    Ok(())
}

fn change_container_root_dir() -> Result<(), nix::Error> {
    // pivot_rootを利用してプロセスのRootディレクトリを変更
    let root_dir = PathBuf::from(ROOT_DIR);
    let put_old_dir = root_dir.join(".put_old");

    // 現在のルートファイルシステムの退避先を作成
    if !put_old_dir.exists() {
        create_dir(&put_old_dir).map_err(|e| {
            eprintln!("create_dir error: {:?}", e);
            match e.raw_os_error() {
                Some(errno) => nix::Error::from_raw(errno),
                None => nix::errno::Errno::UnknownErrno,
            }
        })?;
    }

    // 新しいルートディレクトリはマウントポイントである必要があるのでbindマウントを行う
    mount(
        Some(&root_dir),
        &root_dir,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;

    pivot_root(&root_dir, &put_old_dir)?;

    // 古いルートファイルシステムの削除
    umount2("/.put_old", MntFlags::MNT_DETACH)?;
    remove_dir(put_old_dir).map_err(|e| {
        eprintln!("remove_dir error: {:?}", e);
        match e.raw_os_error() {
            Some(errno) => nix::Error::from_raw(errno),
            None => nix::errno::Errno::UnknownErrno,
        }
    })?;

    chdir("/")?;

    Ok(())
}

fn mount_special_filesystem() -> Result<(), nix::Error> {
    // procfsのマウント。man 8 mountにある通り、sourceは`proc`文字列にする
    // フラグの参考: https://github.com/opencontainers/runc/blob/main/libcontainer/SPEC.md#:~:text=Data-,/proc,-proc
    // runcが読むconfig.jsonのprocfsの箇所: https://github.com/opencontainers/runtime-spec/blob/main/config.md#:~:text=%22mounts%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B-,%22destination%22,-%3A%20%22/proc
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    // sysfsのマウント
    // マウントの参考: https://gihyo.jp/admin/serial/01/linux_containers/0038#sec1
    // runcが読むconfig.jsonのprocfsの箇所: https://github.com/opencontainers/runtime-spec/blob/main/config.md#:~:text=%22nodev%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B-,%22destination%22,-%3A%20%22/sys/fs
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    Ok(())
}
