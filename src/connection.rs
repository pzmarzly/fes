use crate::id::{Identity, PartialIdentity};
use crate::proto::{ClientToServer::*, ServerToClient::*};
use crate::util::{Stream, StreamWrapper};

#[derive(Debug)]
pub struct SecureConnection<T: Stream> {
    id: Identity,
    stream: StreamWrapper<T>,
}

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

    pub async fn client_side_upgrade(
        mut self,
        other: Option<PartialIdentity>,
    ) -> Result<SecureConnection<T>, futures::io::Error> {
        await!(self.stream.send(UpgradeRequest("fts 1".to_string())))?;
        Ok(SecureConnection {
            id: self.id,
            stream: self.stream,
        })
    }

    pub async fn server_side_upgrade(
        self,
        accept_only: Option<Vec<PartialIdentity>>,
    ) -> SecureConnection<T> {
        SecureConnection {
            id: self.id,
            stream: self.stream,
        }
    }
}
