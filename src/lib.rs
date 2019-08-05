#![feature(async_await, await_macro)]

//! **You must ensure that at least 1 side verifies other's identity,
//! otherwise man-in-the-middle attack can be done against your program.**
//!
//! ![diagram](/connection.png)

mod dh;
mod proto;
pub mod signature;
mod wrappers;

use derive_error::Error;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use protocol::{Parcel, Settings};

use crate::{
    dh::SharedEncryptionKey,
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

/// Alias for `AsyncReadExt + AsyncWriteExt + Unpin`
///
/// See [romio] for example network implementation.
///
/// [romio]: https://crates.io/crates/romio
pub trait AsyncRW: AsyncReadExt + AsyncWriteExt + Unpin {}
impl<T: AsyncReadExt + AsyncWriteExt + Unpin> AsyncRW for T {}

/// Low level AsyncRW wrapper - sends and parses unencrypted Parcels and their size
#[derive(Debug, PartialEq)]
pub(crate) struct UnencryptedAsyncRW<T: AsyncRW>(pub T);

/// AsyncRW wrapper - sends and parses encrypted Parcels and their size
#[derive(Debug, PartialEq)]
pub(crate) struct EncryptedAsyncRW<T: AsyncRW> {
    unencrypted: UnencryptedAsyncRW<T>,
    key: SharedEncryptionKey,
    nonce: u128,
}

/// Established and encrypted 1:1 connection
#[derive(Debug)]
pub struct SecureConnection<T: AsyncRW> {
    pub id: SigningKeyPair,
    pub other_id: Option<SigningPubKey>,
    remote: EncryptedAsyncRW<T>,
}

/// Established but unencrypted 1:1 connection - start here
#[derive(Debug)]
pub struct Connection<T: AsyncRW> {
    pub id: SigningKeyPair,
    remote: UnencryptedAsyncRW<T>,
}
