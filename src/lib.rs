#![feature(async_await, await_macro)]
pub mod id;

use id::*;

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

#[derive(Debug, PartialEq, Protocol)]
enum ClientToServer {
    UpgradeRequest(String),
}

#[derive(Debug, PartialEq, Protocol)]
enum ServerToClient {
    UpgradeResponse(String, PartialIdentity),
}

trait ParcelExt {
    fn to_bytes(&self) -> Vec<u8>;
}
impl<T: Parcel> ParcelExt for T {
    fn to_bytes(&self) -> Vec<u8> {
        self.raw_bytes(&protocol::Settings::default()).unwrap()
    }
}

use futures::io::{AsyncReadExt, AsyncWriteExt};
use protocol::Parcel;
use protocol_derive::Protocol;

impl<T: AsyncReadExt + AsyncWriteExt + Unpin> Connection<T> {
    pub fn new(id: Identity, stream: T) -> Self {
        Self { id, stream }
    }

    pub async fn client_side_upgrade(
        mut self,
        other: Option<PartialIdentity>,
    ) -> Result<SecureConnection<T>, futures::io::Error> {
        use ClientToServer::*;
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
