#![feature(async_await, await_macro)]

pub mod connection;
pub mod id;
pub mod prelude;
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
}
