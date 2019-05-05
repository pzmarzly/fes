use protocol_derive::Protocol;

use crate::dh::EncryptionPubKey;
use crate::signature::{Signature, SigningPubKey};

#[derive(Debug, PartialEq, Protocol)]
pub struct UnsignedDH(pub EncryptionPubKey, pub u32);

/// Message signaling supported protocol version.
///
/// Different values are used in case of connecting to an echo server.
#[derive(Debug, PartialEq, Protocol)]
pub struct ProtocolVersion(pub u64);

impl ProtocolVersion {
    pub fn reply(&self) -> ProtocolReply {
        ProtocolReply(self.0.wrapping_add(1));
    }
}

#[derive(Debug, PartialEq, Protocol)]
pub struct ProtocolReply(u64);

#[derive(Debug, PartialEq, Protocol)]
#[protocol(discriminant = "integer")]
pub enum ClientSays {
    Hello(ProtocolVersion),
    DH(UnsignedDH),
}

#[derive(Debug, PartialEq, Protocol)]
#[protocol(discriminant = "integer")]
pub enum ServerSays {
    Hello(ProtocolReply, Option<SigningPubKey>),
    DH(UnsignedDH, Signature<UnsignedDH>),
}
