use std::mem::replace;
use std::sync::Arc;

use crate::{
    message::{
        record::*,
        handshake::messages::*,
        version::*,
    }
};

use super::{
    deframer::*,
    
    super::{
        configs::configs::*,
        general::{
            side::*,
            context::*,
            state::*,
        },
        connection::record_layer::*,
        state_machine::{
            client::*,
            server::*,
        }
    },
};

use brevno::*;

use crate::error::*;

use bytes::*;

struct Placeholder;
impl<S: Side> ConnState<S> for Placeholder {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<S>,
        _record_layer: &mut RecordLayer,
        _msg: HandshakeMessage,
    ) -> TlsResult<NextState<S>> {
        Err(TlsError::Alert(AlertDescription::UnexpectedMessage))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct TlsConnection<S: Side> {
    deframer: MessageDeframer,
    record_layer: RecordLayer,
    context: Context<S>,
    state: Box<dyn ConnState<S>>,
}

impl TlsConnection<ServerSide> {
    pub fn new_server(
        config: Arc<TlsServerConfig>,
        fd: i32,
    ) -> TlsResult<Self> {
        let group = &config.common.supported_params.named_group[0];
        let capacity: usize = config.common.bufs_capacity;

        let deframer = MessageDeframer::new(capacity);
        let record_layer = RecordLayer::new(capacity, fd, group)?;
        let state: Box<dyn ConnState<ServerSide>> = Box::new(ExpectClientHello);
        let context = Context::new_server(config)?;

        Ok(Self {
            record_layer,
            deframer,
            state,
            context,
        })
    }
}

impl TlsConnection<ClientSide> {
    pub fn new_client(
        config: Arc<TlsClientConfig>,
        fd: i32,
    ) -> TlsResult<Self> {
        let group = &config.common.supported_params.named_group[0];
        let capacity: usize = config.common.bufs_capacity;

        let deframer = MessageDeframer::new(capacity);
        let record_layer = RecordLayer::new(capacity, fd, group)?;
        let state: Box<dyn ConnState<ClientSide>> = Box::new(ExpectServerHello);
        let context = Context::new_client(config)?;

        Ok(Self {
            record_layer,
            deframer,
            state,
            context,
        })
    }
}

impl<S: Side> TlsConnection<S> {
    pub fn write_in(&mut self, data: &[u8]) -> TlsResult<()> {
        self.deframer.write(data);
        self.process_tls()
    }

    pub fn read_out(&mut self) -> BytesMut {
        self.record_layer.out_buf.split()
    }

    pub fn finished(&self) -> bool {
        self.state.finished()
    }

    fn process_tls(&mut self) -> TlsResult<()> {
        if let Some(msg) = self.deframer.pop()? {
            let plain: InnerMessage = self.record_layer.decrypt(msg)?;

            match plain.typ {
                RecordType::HandshakeMessage => {
                    let mut payload: BytesMut = plain.plaintext;
                    let handshake: HandshakeMessage = match HandshakeMessage::decode(
                        &mut payload,
                        self.context.common.negotiated.cipher_suite.as_ref()
                    ) {
                        Ok(msg) => msg,
                        Err(e) => {
                            build_alert(AlertDescription::DecodeTlsError).encode(&mut self.record_layer.out_buf);
                            return Err(e)
                        }
                    };

                    let current: Box<dyn ConnState<S>> = replace(&mut self.state, Box::new(Placeholder));

                    let next = match current.handle(&mut self.context, &mut self.record_layer, handshake) {
                        Ok(ns) => ns,
                        Err(TlsError::Alert(desc)) => {
                            build_alert(desc).encode(&mut self.record_layer.out_buf);
                            return Err(TlsError::Alert(desc));
                        }
                        Err(e) => return Err(e)
                    };

                    self.state = next.state;

                    if let Some(output) = next.output {
                        let inner = InnerMessage {
                            typ: RecordType::HandshakeMessage,
                            version: Version::Tls12,
                            plaintext: ,
                        };
                        self.record_layer.encrypt(inner)?.encode(&mut self.record_layer.out_buf);
                    }
                }
                RecordType::ApplicationData => {
                    if !self.finished() {
                        return Err(TlsError::Alert(AlertDescription::UnexpectedMessage))
                    }

                    self.write_tls(&plain.plaintext);

                    return Ok(())
                }
                RecordType::Alert => {
                    if plain.plaintext.len() == 1 {
                        let description = AlertDescription::try_from(plain.plaintext[0] as u8)?;
                        error!("Alert received");
                        return Err(TlsError::Alert(description));
                    }

                    error!("Alert error");
                    return Err(TlsError::Alert(AlertDescription::InternalTlsError))
                }
            }
        }

        Ok(())
    }

    fn write_tls(&mut self, data: &[u8]) {
        self.record_layer.out_buf.extend_from_slice(&data);
    }
}

#[cfg(test)]
mod test_tls {
    use super::*;
    use crate::{encryption::random::*, message::{handshake::{extensions::*, hello::*}, version::{SupportedVersion, Version::*}}};
    use venus::net::tcp::{acceptor::*, connector::*};

    #[tokio::test]
    pub async fn test_tls() {
        init_rng();

        let common = TcpCommonConfig::new(
            64 * 1024,
            5,
            false,
            false,
            None,
            None,
        ).unwrap();

        let config = TcpServerConfig::new(
            common,
            100,
            "127.0.0.1:4433",
        ).unwrap();

        let tls_common = TlsCommonConfig::new(
            64 * 1024,
            SupportedParams {
                version: vec![SupportedVersion::Tls13],
                cipher_suite: vec![SupportedCipherSuite::Aes128],
                named_group: vec![SupportedNamedGroup::X25519],
                compression_method: vec![SupportedCompressionMethod::Null],
                compression_algorithm: None,
                signature_scheme: vec![SupportedScheme::Ed25519],
                alpn_protocol: None,
                ec_point_format: vec![SupportedEcPointFormat::Uncompressed],
                psk_ke_mode: None,
                server_name: None
            },
            None,
            None,
            false
        );

        let tls_server_config = TlsServerConfig::new(
            tls_common,
            false,
            None
        );

        let server = TcpServer::bind(config).await.unwrap();

        let _server_handle = tokio::spawn(async move {
            loop {
                let mut conn = server.accept().await.unwrap();

                let fd = conn.fd;

                let mut tls_conn = TlsConnection::new_server(tls_server_config, fd).unwrap();

                loop {
                    let request = conn.read_frame().await.unwrap();

                    println!("request: {:?}", &request);

                    tls_conn.write_in(&request).unwrap();

                    let response = tls_conn.read_out();
                    conn.write_frame(&response).await.unwrap();

                    println!("response: {:?}", response.to_vec());
                }
            }            
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        for _ in 0..1 {
            tokio::spawn(async move {
                let common = TcpCommonConfig::new(
                    1024 * 16,
                    5 * 60,
                    true,
                    true,
                    Some(500),
                    Some(255),
                ).unwrap();

                let config = TcpClientConfig::new(
                    common,
                    "127.0.0.1:1234",
                    5,
                ).unwrap();

                let tls_common = TlsCommonConfig::new(
                    64 * 1024,
                    SupportedParams {
                        version: vec![SupportedVersion::Tls13],
                        cipher_suite: vec![SupportedCipherSuite::Aes128],
                        named_group: vec![SupportedNamedGroup::X25519],
                        compression_method: vec![SupportedCompressionMethod::Null],
                        compression_algorithm: None,
                        signature_scheme: vec![SupportedScheme::Ed25519],
                        alpn_protocol: None,
                        ec_point_format: vec![SupportedEcPointFormat::Uncompressed],
                        psk_ke_mode: None,
                        server_name: None
                    },
                    None,
                    None,
                    false
                );

                let client_hello = ClientHelloPayload {
                    legacy_version: Tls12,
                    random: {
                        let mut random = [0u8; 32];
                        ochkagen(&mut random).unwrap();
                        random
                    },
                    legacy_session_id: Bytes::new(),
                    cipher_suites: vec![CipherSuite::TlsAes128GcmSha256],
                    legacy_compression_methods: vec![CompressionMethod::Null],
                    extensions: vec![
                        Extension {
                            extension_type: ExtensionType::SupportedVersions,
                            payload: ExtensionPayload::SupportedVersions(SupportedVersionsPayload {
                                versions: vec![Tls13]
                            }),
                        },
                        Extension {
                            extension_type: ExtensionType::SupportedGroups,
                            payload: ExtensionPayload::SupportedGroups(SupportedGroupsPayload {
                                groups: vec![NamedGroup::X25519]
                            }),
                        },
                        Extension {
                            extension_type: ExtensionType::KeyShare,
                            payload: ExtensionPayload::KeyShare(KeySharePayload {
                                key_shares: vec![KeyShareEntry {
                                    group: NamedGroup::X25519,
                                    key_exchange: Bytes::new(),
                                }]
                            }),
                        },
                    ]
                };

                let tls_client_config = TlsClientConfig::new(
                    tls_common,
                    false,
                    client_hello
                );

                let client: TcpClient = TcpClient::connect(config).await.unwrap();

                let mut conn = client.handle().await.unwrap();

                let fd = conn.fd;

                let mut tls_conn = TlsConnection::new_client(tls_client_config, fd).unwrap();

                loop {
                    let request = conn.read_frame().await.unwrap();

                    println!("request: {:?}", &request);

                    tls_conn.write_in(&request).unwrap();

                    let response = tls_conn.read_out();
                    conn.write_frame(&response).await.unwrap();

                    println!("response: {:?}", response.to_vec());

                    println!("{}", tls_conn.finished());
                }
            });
        };

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }
}