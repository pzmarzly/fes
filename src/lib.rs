#![feature(futures_api)]

pub mod key;

use key::*;

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use protocol_derive::Protocol;

pub struct Connection;

pub struct Client {
    pub our_priv: PrivateKey,
    pub our_pub: PublicKey,
}

pub struct Server {
    pub our_priv: PrivateKey,
    pub our_pub: PublicKey,
    pub accepted_clients: Vec<PublicKey>,
}

impl Client {
    pub async fn into_secure_connection(other: PublicKey) {}
    pub async fn into_secure_connection_with_unknown() {}
}

impl Server {
    pub async fn into_secure_connection() {}
}
