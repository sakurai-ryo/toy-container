use crate::errors::Errcode;

use nix::sys::socket::{recv, send, socketpair, AddressFamily, MsgFlags, SockFlag, SockType};
use std::os::unix::io::RawFd;

pub fn generate_socket_pair() -> Result<(RawFd, RawFd), Errcode> {
    match socketpair(
        AddressFamily::Unix, // unix domain socket
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_NOSIGPIPE,
    ) {
        Ok(res) => Ok(res),
        Err(_) => Err(Errcode::SocketError(0)),
    }
}
