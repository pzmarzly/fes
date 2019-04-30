use rand::rngs::OsRng;
use rand::RngCore;

use crate::dh::{EncryptionKeyPair, EncryptionPubKey};
use crate::proto::{ClientSays, ServerSays, UnsignedDH};
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
        other: Option<SigningPubKey>,
    ) -> Result<SecureConnection<T>, Error> {
        send!(self, ClientSays::Hello("fts 1 req".to_string()));

        let server_id = match recv!(self) {
            ServerSays::Hello(s, server_id) => {
                if s != "fts 1 res" {
                    return Err(Error::Logic);
                }
                if let Some(expected) = other {
                    if expected != server_id {
                        return Err(Error::Rejected);
                    }
                }
                server_id
            }
            _ => return Err(Error::Logic),
        };

        let keys = EncryptionKeyPair::generate();
        let mut rng = OsRng::new().unwrap();
        let nonce = rng.next_u32();
        send!(self, ClientSays::DH(UnsignedDH(keys.public(), nonce)));

        Ok(SecureConnection {
            id: self.id,
            other_id: server_id,
            stream: self.stream,
        })
    }

    /// Treat other side of Stream as client, try to upgrade connection to encrypted one.
    ///
    /// By specifying `accept_only`, you can whitelist clients.
    pub async fn server_side_upgrade(
        mut self,
        accept_only: Option<&[SigningPubKey]>,
    ) -> Result<SecureConnection<T>, Error> {
        match recv!(self) {
            ClientSays::Hello(s) => {
                if s != "fts 1 req" {
                    return Err(Error::Logic);
                }
            }
            _ => return Err(Error::Logic),
        }

        send!(
            self,
            ServerSays::Hello("fts 1 res".to_string(), self.id.public())
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
