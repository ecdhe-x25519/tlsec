use libc::{
    cmsghdr, iovec, msghdr,
    sendmsg, recvmsg,
    SOL_TLS, TLS_SET_RECORD_TYPE, TLS_GET_RECORD_TYPE,
    CMSG_LEN, CMSG_SPACE, CMSG_DATA,
};

use std::mem;

use crate::error::*;

#[allow(dead_code)]
pub fn send_ktls_message(
    fd: &i32,
    record_type: u8,
    data: &[u8],
) -> TlsResult<usize> {
    let mut iov = iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    
    let mut cmsg_buf = [0u8; 64];
    
    unsafe {
        let cmsg_ptr = cmsg_buf.as_mut_ptr() as *mut cmsghdr;
        (*cmsg_ptr).cmsg_len = CMSG_LEN(1) as _;
        (*cmsg_ptr).cmsg_level = SOL_TLS;
        (*cmsg_ptr).cmsg_type = TLS_SET_RECORD_TYPE;
        
        let data_ptr = CMSG_DATA(cmsg_ptr) as *mut u8;
        *data_ptr = record_type;
        
        let mut msg: msghdr = mem::zeroed();
        msg.msg_iov = &mut iov as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = CMSG_SPACE(1) as _;
        
        let ret = sendmsg(*fd, &msg, 0);
        if ret < 0 {
            return Err(TlsError::Io(format!("sendmsg error: {}", std::io::Error::last_os_error())));
        }

        Ok(ret as usize)
    }
}

#[allow(dead_code)]
pub fn recv_ktls_message(
    fd: &i32,
    buf: &mut [u8],
) -> TlsResult<(usize, u8)> {
    let mut iov = iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    
    let mut cmsg_buf = [0u8; 64];
    let mut record_type: u8 = 0;
    
    unsafe {
        let mut msg: msghdr = mem::zeroed();
        msg.msg_iov = &mut iov as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_buf.len() as _;
        
        let ret = recvmsg(*fd, &mut msg, 0);
        if ret < 0 {
            return Err(TlsError::Io(format!("sendmsg error: {}", std::io::Error::last_os_error())));
        }
        
        let mut cmsg_ptr = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg_ptr.is_null() {
            if (*cmsg_ptr).cmsg_level == SOL_TLS && (*cmsg_ptr).cmsg_type == TLS_GET_RECORD_TYPE {
                let data_ptr = CMSG_DATA(cmsg_ptr) as *const u8;
                record_type = *data_ptr;
                break;
            }
            cmsg_ptr = libc::CMSG_NXTHDR(&msg, cmsg_ptr);
        }
        
        Ok((ret as usize, record_type))
    }
}