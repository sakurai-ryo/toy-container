use crate::errors::Errcode;
use libc::TIOCSTI;
use log::debug;
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use syscallz::{Action, Context, Syscall};
use syscallz::{Cmp, Comparator};

const EPERM: u16 = 1;

pub fn setsyscalls() -> Result<(), Errcode> {
    debug!("Refusing / Filtering unwanted syscalls");

    let s_isuid: u64 = Mode::S_ISUID.bits().into();
    let s_isgid: u64 = Mode::S_ISGID.bits().into();
    let clone_new_user: u64 = CloneFlags::CLONE_NEWUSER.bits() as u64;

    // Unconditionnal syscall deny
    let syscalls_refused = [
        Syscall::keyctl,
        Syscall::add_key,
        Syscall::request_key,
        Syscall::mbind,
        Syscall::migrate_pages,
        Syscall::move_pages,
        Syscall::set_mempolicy,
        Syscall::userfaultfd,
        Syscall::perf_event_open,
    ];
    // Conditionnal syscall deny
    let syscalls_refuse_ifcomp = [
        (Syscall::chmod, 1, s_isuid),
        (Syscall::chmod, 1, s_isgid),
        (Syscall::fchmod, 1, s_isuid),
        (Syscall::fchmod, 1, s_isgid),
        (Syscall::fchmodat, 2, s_isuid),
        (Syscall::fchmodat, 2, s_isgid),
        (Syscall::unshare, 0, clone_new_user),
        (Syscall::clone, 0, clone_new_user),
        (Syscall::ioctl, 1, TIOCSTI),
    ];

    // all syscalls allow by default
    match Context::init_with_action(Action::Allow) {
        Ok(mut ctx) => {
            for sc in syscalls_refused.iter() {
                refuse_syscall(&mut ctx, sc)?;
            }
            for (sc, ind, biteq) in syscalls_refuse_ifcomp.iter() {
                refuse_if_comp(&mut ctx, *ind, sc, *biteq)?;
            }

            if ctx.load().is_err() {
                return Err(Errcode::SyscallsError(0));
            }
            Ok(())
        }
        Err(_) => Err(Errcode::SyscallsError(1)),
    }
}

fn refuse_syscall(ctx: &mut Context, sc: &Syscall) -> Result<(), Errcode> {
    match ctx.set_action_for_syscall(Action::Errno(EPERM), *sc) {
        Ok(_) => Ok(()),
        Err(_) => Err(Errcode::SyscallsError(2)),
    }
}

fn refuse_if_comp(ctx: &mut Context, ind: u32, sc: &Syscall, biteq: u64) -> Result<(), Errcode> {
    match ctx.set_rule_for_syscall(
        Action::Errno(EPERM),
        *sc,
        &[Comparator::new(ind, Cmp::MaskedEq, biteq, Some(biteq))],
    ) {
        Ok(_) => Ok(()),
        Err(_) => Err(Errcode::SyscallsError(3)),
    }
}
