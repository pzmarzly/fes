use protocol::Parcel;
use futures::io::{AsyncReadExt, AsyncWriteExt};

use crate::util::ParcelExt;
use crate::id::{PartialIdentity, Identity};
use crate::proto::{ClientToServer::*, ServerToClient::*};

#[derive(Debug)]
pub struct SecureConnection<T> {
    id: Identity,
    stream: T,
}

#[derive(Debug)]
pub struct Connection<T> {
    id: Identity,
    stream: T,
}

impl<T: AsyncReadExt + AsyncWriteExt + Unpin> Connection<T> {
    pub fn new(id: Identity, stream: T) -> Self {
        Self { id, stream }
    }

    pub async fn client_side_upgrade(
        mut self,
        other: Option<PartialIdentity>,
    ) -> Result<SecureConnection<T>, futures::io::Error> {
        await!(self.send(UpgradeRequest("fts 1".to_string())))?;
        Ok(SecureConnection {
            id: self.id,
            stream: self.stream,
        })
    }

    async fn send(&mut self, item: impl Parcel) -> Result<(), futures::io::Error> {
        let bytes = item.to_bytes();
        await!(self.stream.write_all(&bytes))?;
        Ok(())
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
