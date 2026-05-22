pub mod parse;
pub mod verify;
pub mod signature;

pub use crate::error::Error;

pub struct Der(pub Vec<u8>);

impl From<Vec<u8>> for Der {
    fn from(data: Vec<u8>) -> Self {
        Der(data)
    }
}