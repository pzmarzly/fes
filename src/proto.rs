use protocol_derive::Protocol;

use crate::signature::SigningPubKey;

#[derive(Debug, PartialEq, Protocol)]
pub enum ClientSays {
    Hello(String),
    DH(String, String), // new key, signature
}

#[derive(Debug, PartialEq, Protocol)]
pub enum ServerSays {
    Hello(String, SigningPubKey),
    DH(String, String),
}
