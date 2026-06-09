use nix::sys::socket::setsockopt;
use nix::sys::socket::sockopt::{TcpTlsRx, TcpTlsTx, TlsCryptoInfo, TcpUlp};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use nix::sys::uio;

use std::os::fd::AsRawFd;
use std::net::TcpStream;

use crate::message::record::{Record, RecordType};

use crate::error::TlsError;

pub fn to_crypto_info() {

}

pub fn set_ktls_tx(sock: &TcpStream, key: &[u8]) -> Result<(), TlsError> {
    let fd = sock.as_raw_fd();

    setsockopt(fd, TcpUlp, "tls")
        .map_err(|e| TlsError::Crypto(format!("TCP_ULP set error: {e}")))?;
    
    setsockopt(fd, TcpTlsTx, &key)
        .map_err(|e| TlsError::Crypto(format!("setsockopt tx error: {e}")))?;

    Ok(())
}

pub fn set_ktls_rx(sock: &TcpStream, key: &[u8]) -> Result<(), TlsError> {
    let fd = sock.as_raw_fd();

    setsockopt(fd, TcpUlp, "tls")
        .map_err(|e| TlsError::Crypto(format!("TCP_ULP set error: {e}")))?;

    setsockopt(fd, TcpTlsRx, &key)
        .map_err(|e| TlsError::Crypto(format!("setsockopt rx error: {e}")))?;

    Ok(())
}

pub fn sendmsg(
    sock: &TcpStream,
    record_type: RecordType,
    record: Record
) -> Result<(), TlsError> {
    let fd:  = sock.as_raw_fd();
    let iov = [nix::sys::uio::IoVec(data)];
    let cmsg = [ControlMessage::TlsRecordType(record_type)];
    
    sendmsg(fd, &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|e| TlsError::Crypto(format!("sendmsg error: {e}")))?;

    Ok(())
}