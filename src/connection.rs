use crate::proto::{ClientSays, ServerSays};
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
        // Send request
        await!(self.stream.send(ClientSays::Hello("fts 1 req".to_string())))?;
        // Get server identity
        let server_id = match await!(self.stream.recv::<ServerSays>())? {
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
        // Generate and send ephemeral key, sign it to prove our identity
        // TODO:
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
        // Get request
        match await!(self.stream.recv::<ClientSays>())? {
            ClientSays::Hello(s) => {
                if s != "fts 1 req" {
                    return Err(Error::Logic);
                }
            }
            _ => {
                return Err(Error::Logic);
            }
        }
        // Send our identity
        await!(self.stream.send(ServerSays::Hello(
            "fts 1 res".to_string(),
            self.id.get_partial()
        )))?;
        // TODO: get client public key...
        return Ok(SecureConnection {
            id: self.id,
            other_id: SigningPubKey {
                public_key: [0; 32],
            },
            stream: self.stream,
        });
    }
}
