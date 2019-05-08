#![feature(async_await, await_macro)]

//! **You must ensure that at least 1 side verifies other's identity,
//! otherwise man-in-the-middle attack can be done against your program.**
//!
//! ![diagram](/connection.png)

mod dh;
pub mod signature;

mod proto;

use derive_error::Error;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use protocol::{Parcel, Settings};

use crate::{
    dh::{DhKeyPair, SharedEncryptionKey},
    proto::{ClientSays, Nonce, ProtocolVersion, ServerSays, UnsignedDH},
    signature::{SigningKeyPair, SigningPubKey},
};

/// Wrapper for possible crate errors
#[derive(Debug, Error)]
pub enum Error {
    /// Async I/O error
    Io(futures::io::Error),
    /// Error originating in `protocol`
    Protocol(protocol::Error),
    /// Other side is speaking a different protocol or
    /// a different version of `fes`.
    LibVersion,
    /// Other side sent packet that was parsed correctly,
    /// but it was unexpected at this moment
    Logic,
    /// Other side did not allow us to connect or had invalid identity
    Rejected,
}

/// Auto-derived convenience extension for working with `protocol`
///
/// Parses and encodes Parcels with default settings.
pub trait ParcelExt<T> {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<T, Error>;
}

impl<T: Parcel> ParcelExt<T> for T {
    fn to_bytes(&self) -> Vec<u8> {
        self.raw_bytes(&Settings::default()).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Result<T, Error> {
        Ok(T::from_raw_bytes(bytes, &Settings::default())?)
    }
}

/// Alias for `AsyncReadExt + AsyncWriteExt`
///
/// See [romio] for example network implementation.
///
/// [romio]: https://crates.io/crates/romio
pub trait AsyncRW: AsyncReadExt + AsyncWriteExt + Unpin {}
impl<T: AsyncReadExt + AsyncWriteExt + Unpin> AsyncRW for T {}

/// Low level AsyncRW wrapper - sends and parses unencrypted Parcels and their size
#[derive(Debug, PartialEq)]
pub(crate) struct UnencryptedAsyncRW<T: AsyncRW>(pub T);

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

    fn into_encrypted(self, shared: SharedEncryptionKey, nonce: Nonce) -> EncryptedAsyncRW<T> {
        EncryptedAsyncRW {
            unencrypted: self,
            key: shared,
            nonce: u128::from(nonce.0),
        }
    }
}

/// AsyncRW wrapper - sends and parses encrypted Parcels and their size
#[derive(Debug, PartialEq)]
pub(crate) struct EncryptedAsyncRW<T: AsyncRW> {
    unencrypted: UnencryptedAsyncRW<T>,
    key: SharedEncryptionKey,
    nonce: u128,
}

impl<T: AsyncRW> EncryptedAsyncRW<T> {}

/// Established and encrypted 1:1 connection
#[derive(Debug)]
pub struct SecureConnection<T: AsyncRW> {
    pub id: SigningKeyPair,
    pub other_id: SigningPubKey,
    stream: EncryptedAsyncRW<T>,
}

/// Established but unencrypted 1:1 connection - start here
#[derive(Debug)]
pub struct Connection<T: AsyncRW> {
    pub id: SigningKeyPair,
    stream: UnencryptedAsyncRW<T>,
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

impl<T: AsyncRW> Connection<T> {
    pub fn new(id: SigningKeyPair, stream: T) -> Self {
        Self {
            id,
            stream: UnencryptedAsyncRW::new(stream),
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
            other_id: server_id,
            stream: self.stream.into_encrypted(shared, nonce),
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

        return Ok(SecureConnection {
            id: self.id,
            other_id: SigningPubKey {
                public_key: [0; 32],
            },
            stream: self.stream.into_encrypted(shared, nonce),
        });
    }
}
