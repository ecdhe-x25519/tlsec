pub mod configs;
pub mod connection;
pub mod context;
pub mod deframer;
pub mod record_layer;
pub mod state;

use configs::{ClientConfig, ServerConfig};

pub use bytes::{BytesMut, BufMut, Buf};

pub use crate::error::Error;

pub trait Side: Send + Sync + 'static {
    type Config: Send + Sync;
    fn is_client() -> bool;
}

pub struct ClientSide;

impl Side for ClientSide {
    type Config = ClientConfig;
    fn is_client() -> bool { true }
}

pub struct ServerSide;

impl Side for ServerSide {
    type Config = ServerConfig;
    fn is_client() -> bool { false }

}