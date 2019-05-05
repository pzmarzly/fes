#![feature(async_await, await_macro)]

pub mod connection;
pub mod crypto;

mod proto;

use derive_error::Error;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use protocol::{Parcel, Settings};

/// Wrapper for possible crate errors
#[derive(Debug, Error)]
pub enum Error {
    /// Async I/O error
    Io(futures::io::Error),
    /// Error originating in `protocol`
    Protocol(protocol::Error),
    /// Other side is speaking a different protocol or
    /// a different version of fts.
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
        let data = item.to_bytes();
        let data_len = (data.len() as u32).to_le_bytes();
        await!(self.0.write_all(&data_len))?;
        await!(self.0.write_all(&data))?;
        Ok(())
    }

    pub async fn recv<P: Parcel>(&mut self) -> Result<P, Error> {
        let mut data_len = [0u8; 4];
        await!(self.0.read_exact(&mut data_len))?;

        let mut data = Vec::with_capacity(u32::from_le_bytes(data_len) as usize);
        await!(self.0.read_exact(&mut data))?;

        Ok(P::from_bytes(&data)?)
    }
}
