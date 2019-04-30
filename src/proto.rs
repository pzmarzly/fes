use protocol_derive::Protocol;

use crate::dh::EncryptionPubKey;
use crate::signature::{Signature, SigningPubKey};

#[derive(Debug, PartialEq, Protocol)]
pub enum ClientSays {
    Hello(String),
    DH(EncryptionPubKey, u32),
}

#[derive(Debug, PartialEq, Protocol)]
pub struct UnsignedDH(EncryptionPubKey, u32);

#[derive(Debug, PartialEq, Protocol)]
pub enum ServerSays {
    Hello(String, SigningPubKey),
    DH(UnsignedDH, Signature<UnsignedDH>),
}
