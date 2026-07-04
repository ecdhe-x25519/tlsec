use std::sync::Arc;

use super::super::configs::configs::*;

pub trait Side: Send + Sync + 'static {
    type Config: Send + Sync;
    type Side;
    fn common(config: Arc<Self::Config>) -> Arc<TlsCommonConfig>;
}

pub struct ServerSide;
impl Side for ServerSide {
    type Config = TlsServerConfig;
    type Side = ServerSide;
    fn common(config: Arc<Self::Config>) -> Arc<TlsCommonConfig> {
        config.common.clone()
    }
}

pub struct ClientSide;
impl Side for ClientSide {
    type Config = TlsClientConfig;
    type Side = ClientSide;
    fn common(config: Arc<Self::Config>) -> Arc<TlsCommonConfig> {
        config.common.clone()
    }
}