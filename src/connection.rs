use crate::id::{Identity, PartialIdentity};
use crate::proto::{
    ClientToServer::{self, *},
    ServerToClient::{self, *},
};
use crate::util::{Stream, StreamWrapper};
use crate::Error;

/// Established and encrypted 1:1 connection
#[derive(Debug)]
pub struct SecureConnection<T: Stream> {
    id: Identity,
    other_id: PartialIdentity,
    stream: StreamWrapper<T>,
}

/// Established but unencrypted 1:1 connection
#[derive(Debug)]
pub struct Connection<T: Stream> {
    id: Identity,
    stream: StreamWrapper<T>,
}

impl<T: Stream> Connection<T> {
    pub fn new(id: Identity, stream: T) -> Self {
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
        other: Option<PartialIdentity>,
    ) -> Result<SecureConnection<T>, Error> {
        // Send request
        await!(self.stream.send(UpgradeRequest("fts 1 req".to_string())))?;
        // Get server public key
        let server_id = match await!(self.stream.recv::<ServerToClient>())? {
            UpgradeResponse(s, server_id) => {
                if s != "fts 1 res" {
                    return Err(Error::Logic);
                }
                if let Some(expected) = other {
                    if expected != server_id {
                        return Err(Error::Id);
                    }
                }
                server_id
            }
            _ => return Err(Error::Logic),
        };
        // Send our public key, encrypted
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
        accept_only: Option<Vec<PartialIdentity>>,
    ) -> Result<SecureConnection<T>, Error> {
        // Get request
        match await!(self.stream.recv::<ClientToServer>())? {
            UpgradeRequest(s) => {
                if s != "fts 1 req" {
                    return Err(Error::Logic);
                }
            }
            _ => {
                return Err(Error::Logic);
            }
        }
        // Send our public key, unencrypted
        await!(self.stream.send(UpgradeResponse(
            "fts 1 res".to_string(),
            self.id.get_partial()
        )))?;
        // TODO: get client public key...
        return Ok(SecureConnection {
            id: self.id,
            other_id: PartialIdentity {
                public_key: Vec::new(),
            },
            stream: self.stream,
        });
    }
}
