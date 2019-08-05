use crate::{
    dh::{DhKeyPair, SharedEncryptionKey},
    proto::{ClientSays, Nonce, ProtocolVersion, ServerSays, UnsignedDH},
    signature::{SigningKeyPair, SigningPubKey},
    AsyncRW, Connection, EncryptedAsyncRW, Error, ParcelExt, SecureConnection, UnencryptedAsyncRW,
};
use protocol::Parcel;

impl<T: AsyncRW> UnencryptedAsyncRW<T> {
    pub fn new(async_rw: T) -> Self {
        Self(async_rw)
    }

    pub async fn send(&mut self, item: impl Parcel) -> Result<(), Error> {
        let bytes = item.to_bytes();
        await!(self.send_bytes(&bytes))
    }

    pub async fn send_bytes<'a>(&'a mut self, data: &'a [u8]) -> Result<(), Error> {
        let data_len = (data.len() as u32).to_le_bytes();
        await!(self.0.write_all(&data_len))?;
        await!(self.0.write_all(&data))?;
        Ok(())
    }

    pub async fn recv<P: Parcel>(&mut self) -> Result<P, Error> {
        let data = await!(self.recv_bytes())?;

        Ok(P::from_bytes(&data)?)
    }

    pub async fn recv_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut data_len = [0u8; 4];
        await!(self.0.read_exact(&mut data_len))?;
        let mut data = Vec::with_capacity(u32::from_le_bytes(data_len) as usize);
        await!(self.0.read_exact(&mut data))?;
        Ok(data)
    }

    pub(crate) fn into_encrypted(
        self,
        shared: SharedEncryptionKey,
        nonce: Nonce,
    ) -> EncryptedAsyncRW<T> {
        EncryptedAsyncRW {
            unencrypted: self,
            key: shared,
            nonce: u128::from(nonce.0),
        }
    }
}

impl<T: AsyncRW> EncryptedAsyncRW<T> {}

macro_rules! recv {
    ($src:ident) => {
        await!($src.remote.recv())?
    };
}

macro_rules! send {
    ($src:ident, $expression:expr) => {
        await!($src.remote.send($expression))?
    };
}

impl<T: AsyncRW> Connection<T> {
    pub fn new(id: SigningKeyPair, remote: T) -> Self {
        Self {
            id,
            remote: UnencryptedAsyncRW::new(remote),
        }
    }

    /// Treat other side of AsyncRW as server, try to upgrade connection to encrypted one
    ///
    /// By specifying `other`, you can make sure you are connecting to server you intended
    /// (think: certificate pinning).
    pub async fn client_side_upgrade(
        mut self,
        other_id: Option<SigningPubKey>,
    ) -> Result<SecureConnection<T>, Error> {
        let proto_version = ProtocolVersion::v1();
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

        let keys = DhKeyPair::generate();
        let nonce = Nonce::generate();
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
            other_id: Some(server_id),
            remote: self.remote.into_encrypted(shared, nonce),
        };

        Ok(secure)
    }

    /// Treat other side of AsyncRW as client, try to upgrade connection to encrypted one
    ///
    /// By specifying `accept_only`, you can whitelist clients.
    pub async fn server_side_upgrade(
        mut self,
        accept_only: Option<&[SigningPubKey]>,
    ) -> Result<SecureConnection<T>, Error> {
        let proto_version = ProtocolVersion::v1();
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

        let keys = DhKeyPair::generate();
        let unsigned = UnsignedDH(keys.public(), nonce);
        let signature = self.id.sign(&unsigned);
        send!(self, ServerSays::DH(unsigned, signature));

        let shared = keys.dh(&client_key);

        let mut secure = SecureConnection {
            id: self.id,
            other_id: None,
            remote: self.remote.into_encrypted(shared, nonce),
        };

        Ok(secure)
    }
}
