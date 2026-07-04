use std::sync::Arc;

use super::{
    super::{
        configs::configs::*,
    },
    
    side::*,
    state::CommonState,
};

use crate::error::*;

pub struct Context<S: Side> {
    pub common: CommonState,
    pub config: Arc<S::Config>,
    pub side: S,
}

impl Context<ClientSide> {
    pub fn new_client(config: Arc<TlsClientConfig>) -> TlsResult<Self> {
        Ok(Self {
            common: CommonState::new(&config.common.supported_params.cipher_suite[0])?,
            config,
            side: ClientSide,
        })
    }
}

impl Context<ServerSide> {
    pub fn new_server(config: Arc<TlsServerConfig>) -> TlsResult<Self> {
        Ok(Self {
            common: CommonState::new(&config.common.supported_params.cipher_suite[0])?,
            config,
            side: ServerSide,
        })
    }
}