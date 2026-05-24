use super::state::CommonState;

use super::*;

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

impl<S: Side> Context<S> {
    pub fn is_client(&self) -> bool {
        std::any::TypeId::of::<S>() == std::any::TypeId::of::<ClientSide>()
    }
    
    pub fn is_server(&self) -> bool {
        std::any::TypeId::of::<S>() == std::any::TypeId::of::<ServerSide>()
    }
}