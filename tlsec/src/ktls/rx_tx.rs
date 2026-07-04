use libc::{setsockopt, SOL_TCP, TLS_TX, TLS_RX, TCP_ULP, SOL_TLS};

use super::crypto::TlsCryptoInfo;

use crate::error::*;

pub fn enable_ulp(fd: &i32) -> TlsResult<()> {
    let ulp_name = b"tls\0";

    unsafe {
        let ret = setsockopt(
            *fd,
            SOL_TCP,
            TCP_ULP,
            ulp_name.as_ptr() as *const _,
            ulp_name.len() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(TlsError::Io(format!("TCP_ULP error: {}", std::io::Error::last_os_error())));
        }
    }
    Ok(())
}

pub fn set_ktls_tx(fd: &i32, cipher: &TlsCryptoInfo) -> TlsResult<()> {
    unsafe {
        let ret = setsockopt(
            *fd,
            SOL_TLS,
            TLS_TX,
            cipher.as_ptr() as *const _,
            cipher.size() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(TlsError::Io(format!("TLS_TX error: {}", std::io::Error::last_os_error())));
        }
    }
    
    Ok(())
}

pub fn set_ktls_rx(fd: &i32, cipher: &TlsCryptoInfo) -> TlsResult<()> {
    unsafe {
        let ret = setsockopt(
            *fd,
            SOL_TLS,
            TLS_RX,
            cipher.as_ptr() as *const _,
            cipher.size() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(TlsError::Io(format!("TLS_TX error: {}", std::io::Error::last_os_error())));
        }
    }

    Ok(())
}