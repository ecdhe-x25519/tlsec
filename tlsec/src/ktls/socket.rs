use super::crypto::TlsCryptoInfo;
use super::msg;
use super::rx_tx;

use crate::encryption::key_schedule::ApplicationKeys;

use crate::error::*;

#[derive(Debug)]
pub struct KtlsSocket {
    fd: i32,
    client_key: TlsCryptoInfo,
    server_key: TlsCryptoInfo
}

impl KtlsSocket {
    pub fn new(
        fd: i32,
        keys: ApplicationKeys,
    ) -> Self {
        let client_key = TlsCryptoInfo::new(&keys.client);
        let server_key = TlsCryptoInfo::new(&keys.server);
        
        Self { fd, client_key, server_key }
    }

    pub fn set_ktls_tx(&self) -> TlsResult<()> {
        rx_tx::enable_ulp(&self.fd)?;
        rx_tx::set_ktls_tx(&self.fd, &self.client_key)?;
        
        Ok(())
    }

    pub fn set_ktls_rx(&self) -> TlsResult<()> {
        rx_tx::enable_ulp(&self.fd)?;
        rx_tx::set_ktls_rx(&self.fd, &self.server_key)?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn send_ktls_message(
        &self,
        record_type: u8,
        data: &[u8],
    ) -> TlsResult<usize> {
        msg::send_ktls_message(&self.fd, record_type, data)
    }

    #[allow(dead_code)]
    pub fn recv_ktls_message(
        &self,
        buf: &mut [u8]
    ) -> TlsResult<(usize, u8)> {
        msg::recv_ktls_message(&self.fd, buf)
    }
}