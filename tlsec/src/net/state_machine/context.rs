use crate::net::state_machine::{configs::{ClientConfig, ServerConfig}, side::{ClientSide, ServerSide, Side}, state::CommonState};

pub struct Context<S: Side> {
    pub common: CommonState,
    pub config: S::Config,
    pub side: S,
}

impl Context<ClientSide> {
    pub fn new_client(config: ClientConfig) -> Self {
        Self {
            common: CommonState::new(),
            config,
            side: ClientSide,
        }
    }
}

impl Context<ServerSide> {
    pub fn new_server(config: ServerConfig) -> Self {
        Self {
            common: CommonState::new(),
            config,
            side: ServerSide,
        }
    }
}