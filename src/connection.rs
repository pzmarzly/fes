use rand::rngs::OsRng;
use rand::RngCore;

use crate::dh::{EncryptionKeyPair, EncryptionPubKey};
use crate::proto::{ClientSays, ServerSays, UnsignedDH, ProtocolVersion};
use crate::signature::{SigningKeyPair, SigningPubKey};
use crate::util::{Stream, StreamWrapper};
use crate::Error;

/// Established and encrypted 1:1 connection
#[derive(Debug)]
pub struct SecureConnection<T: Stream> {
    id: SigningKeyPair,
    other_id: SigningPubKey,
    stream: StreamWrapper<T>,
}

/// Established but unencrypted 1:1 connection
#[derive(Debug)]
pub struct Connection<T: Stream> {
    id: SigningKeyPair,
    stream: StreamWrapper<T>,
}

macro_rules! recv {
    ($src:ident) => {
        await!($src.stream.recv())?
    };
}

macro_rules! send {
    ($src:ident, $expression:expr) => {
        await!($src.stream.send($expression))?
    };
}

impl<T: Stream> Connection<T> {
    pub fn new(id: SigningKeyPair, stream: T) -> Self {
        Self {
            id,
            stream: StreamWrapper::new(stream),
        }
    }

    /// Treat other side of Stream as server, try to upgrade connection to encrypted one.
    ///
    /// By specifying `other`, you can make sure you are connecting to server you intended
    /// (think: certificate pinning).
    pub async fn client_side_upgrade(
        mut self,
        other_id: Option<SigningPubKey>,
        proto_version: ProtocolVersion
    ) -> Result<SecureConnection<T>, Error> {
        send!(self, ClientSays::Hello(proto_version));

        let server_id = match recv!(self) {
            ServerSays::Hello(p, real_id) => {
                if p != proto_version.reply() {
                    return Err(Error::Logic);
                }
                if let Some(expected_id) = other_id {
                        if expected_id != real_id {
                            return Err(Error::Rejected);
                        }
                }
                real_id
            }
            _ => return Err(Error::Logic),
        };

        let keys = EncryptionKeyPair::generate();
        let mut rng = OsRng::new().unwrap();
        let nonce = rng.next_u32();
        send!(self, ClientSays::DH(UnsignedDH(keys.public(), nonce)));

        let server_key = match recv!(self) {
            ServerSays::DH(unsigned, signature) => {
                if unsigned.1 != nonce || !server_id.verify(&unsigned, &signature) {
                    return Err(Error::Logic);
                }
                unsigned.0
            }
            _ => return Err(Error::Logic),
        };

        let shared = keys.dh(&server_key);
        let secure = SecureConnection {
            id: self.id,
            other_id: server_id,
            stream: self.stream,
        };

        Ok(secure)
    }

    /// Treat other side of Stream as client, try to upgrade connection to encrypted one.
    ///
    /// By specifying `accept_only`, you can whitelist clients.
    pub async fn server_side_upgrade(
        mut self,
        accept_only: Option<&[SigningPubKey]>,
        proto_version: ProtocolVersion,
    ) -> Result<SecureConnection<T>, Error> {
        match recv!(self) {
            ClientSays::Hello(p) => {
                if p != proto_version {
                    return Err(Error::Logic);
                }
            }
            _ => return Err(Error::Logic),
        }

        send!(
            self,
            ServerSays::Hello(proto_version.reply(), self.id.public())
        );

        let (client_key, nonce) = match recv!(self) {
            ClientSays::DH(UnsignedDH(pub_key, nonce)) => (pub_key, nonce),
            _ => return Err(Error::Logic),
        };

        let keys = EncryptionKeyPair::generate();
        let unsigned = UnsignedDH(keys.public(), nonce);
        let signature = self.id.sign(&unsigned);
        send!(self, ServerSays::DH(unsigned, signature));

        return Ok(SecureConnection {
            id: self.id,
            other_id: SigningPubKey {
                public_key: [0; 32],
            },
            stream: self.stream,
        });
    }
}
