use protocol_derive::Protocol;

use crate::dh::EncryptionPubKey;
use crate::signature::{SigningPubKey, Signature};

#[derive(Debug, PartialEq, Protocol)]
pub enum ClientSays {
    Hello(String),
    DH(EncryptionPubKey),
}

#[derive(Debug, PartialEq, Protocol)]
pub enum ServerSays {
    Hello(String, SigningPubKey),
    DH(EncryptionPubKey, Signature),
}
