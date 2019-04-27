use futures::io::{AsyncReadExt, AsyncWriteExt};
use protocol::Parcel;

use crate::id::{Identity, PartialIdentity};
use crate::proto::{ClientToServer::*, ServerToClient::*};
use crate::util::ParcelExt;

pub trait Stream: AsyncReadExt + AsyncWriteExt + Unpin {}
impl<T: AsyncReadExt + AsyncWriteExt + Unpin> Stream for T {}

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

impl<T: Stream> Connection<T> {
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
        let data = item.to_bytes();
        let data_len = data.len().to_le_bytes();
        await!(self.stream.write_all(&data_len))?;
        await!(self.stream.write_all(&data))?;
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
