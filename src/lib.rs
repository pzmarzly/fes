#![feature(async_await, await_macro)]

pub mod connection;
pub mod dh;
pub mod prelude;
pub mod signature;
pub mod util;

mod proto;

use derive_error::Error;

/// Wrapper for possible crate errors
#[derive(Debug, Error)]
pub enum Error {
    /// Async I/O error
    Io(futures::io::Error),
    /// Error originating in protocol crate
    Protocol(protocol::Error),
    /// Other side sent correct packet, but it was unexpected in current content
    Logic,
    /// Other side was not allowed to connect (invalid SigningPubKey)
    Id,
}
