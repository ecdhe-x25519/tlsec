use std::mem::replace;

use crate::messages::Serialize;
use crate::messages::record::RecordType;
use crate::messages::handshake::handshake::HandshakeMessage;
use crate::messages::Version::Tls12;

use crate::net::acceptor::ServerStart;
use crate::net::connector::ClientStart;

use super::state::{State, NextState};
use super::context::Context;
use super::deframer::{MessageDeframer, PlainMessage, OpaqueMessage};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::*;

struct Placeholder;
impl<S: Side> State<S> for Placeholder {
    fn handle(self: Box<Self>, _ctx: &mut Context<S>, _msg: HandshakeMessage) -> Result<NextState<S>, Error> {
        Err(Error::Handshake("invalid state"))
    }
}

pub struct TlsConnection<S: Side> {
    pub read_stream: OwnedReadHalf,
    pub write_stream: OwnedWriteHalf,
    pub state: Box<dyn State<S>>,
    pub ctx: Context<S>,
    pub deframer: MessageDeframer,
    pub read_buf: BytesMut,
    pub write_buf: BytesMut,
}

impl TlsConnection<ClientSide> {
    pub async fn new_client(
        config: ClientConfig,
        stream: TcpStream,
    ) -> Self {
        let (read_stream, write_stream) = stream.into_split();

        let ctx: Context<ClientSide> = Context::new_client(config);
        let state: Box<dyn State<ClientSide>> = Box::new(ClientStart);
        let deframer: MessageDeframer = MessageDeframer::new();

        Self {
            read_stream,
            write_stream,
            state,
            ctx,
            deframer,
            read_buf: BytesMut::with_capacity(16384),
            write_buf: BytesMut::with_capacity(16384),
        }
    }
}

impl TlsConnection<ServerSide> {
    pub async fn new_server(
        config: ServerConfig,
        stream: TcpStream,
    ) -> Self {
        let (read_stream, write_stream) = stream.into_split();

        let ctx: Context<ServerSide> = Context::new_server(config);
        let state: Box<dyn State<ServerSide>> = Box::new(ServerStart);
        let deframer: MessageDeframer = MessageDeframer::new();

        Self {
            read_stream,
            write_stream,
            state,
            ctx,
            deframer,
            read_buf: BytesMut::with_capacity(16384),
            write_buf: BytesMut::with_capacity(16384),
        }
    }
}

impl<S: Side> TlsConnection<S> {
    pub async fn read_tls(&mut self) -> Result<(), Error> {
        let n: usize = self.read_stream.read_buf(&mut self.read_buf)
            .await
            .map_err(|e| Error::Io(format!("read buf error: {e}")))?;

        if n == 0 && self.read_buf.is_empty() {
            return Ok(());
        }

        while let Some(opaque) = self.deframer.pop()? {
            let plain: PlainMessage = self.ctx.common.record_layer.decrypt_incoming(opaque)?;
            
            match plain.typ {
                RecordType::HandshakeMessage => {
                    let mut payload: BytesMut = plain.payload;
                    let handshake: HandshakeMessage = HandshakeMessage::decode(&mut payload)?;
                    
                    let current: Box<dyn State<S>> = replace(&mut self.state, Box::new(Placeholder));
                    let next: NextState<S> = current.handle(&mut self.ctx, handshake)?;
                    self.state = next.state;
                    
                    if let Some(output) = next.output {
                        let encrypted: OpaqueMessage = self.ctx.common.record_layer.encrypt_outgoing(
                            PlainMessage {
                                typ: RecordType::HandshakeMessage,
                                version: Tls12,
                                payload: output,
                            }
                        )?;
                        self.write_buf.extend_from_slice(&encrypted.into_bytes());
                    }
                }
                RecordType::ApplicationData => {
                    // TODO: save 4 app
                    // self.pending_data = Some(plain.payload);
                }
                RecordType::Alert => {
                    // TODO: handle Alert
                    return Err(Error::AlertReceived);
                }
            }
        }
        
        Ok(())
    }

    pub async fn write_tls(&mut self) -> Result<(), Error> {
        if self.write_buf.is_empty() {
            return Ok(());
        }
        
        self.write_stream.write_all(&self.write_buf)
            .await
            .map_err(|e| Error::Io(format!("write buf error: {e}")))?;

        self.write_buf.clear();
        Ok(())
    }
}