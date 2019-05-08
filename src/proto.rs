use protocol_derive::Protocol;
use rand::{rngs::OsRng, RngCore};

use crate::{
    dh::DhPubKey,
    signature::{Signature, SigningPubKey},
};

/// Message signaling protocol version
///
/// Different data is sent back in case of connecting to an echo server.
///
/// https://random.org/bytes
#[derive(Debug, PartialEq, Protocol, Clone, Copy)]
pub struct ProtocolVersion(u64);

impl ProtocolVersion {
    pub fn v1() -> Self {
        Self(0xf8171202f71a39d5)
    }
    pub fn reply(&self) -> ProtocolReply {
        // match self { 0x... -> 0x... }
        ProtocolReply(0xc2df3fd948e534a2)
    }
}

#[derive(Debug, PartialEq, Protocol, Clone, Copy)]
pub struct ProtocolReply(u64);

#[derive(Debug, PartialEq, Protocol, Clone, Copy)]
pub struct Nonce(pub u64);

impl Nonce {
    pub fn generate() -> Self {
        let mut rng = OsRng::new().unwrap();
        Self(rng.next_u64())
    }
}

#[derive(Debug, PartialEq, Protocol)]
pub struct UnsignedDH(pub DhPubKey, pub Nonce);

#[derive(Debug, PartialEq, Protocol)]
#[protocol(discriminant = "integer")]
pub enum ClientSays {
    Hello(ProtocolVersion),
    DH(UnsignedDH),
}

#[derive(Debug, PartialEq, Protocol)]
#[protocol(discriminant = "integer")]
pub enum ServerSays {
    Hello(ProtocolReply, SigningPubKey),
    DH(UnsignedDH, Signature<UnsignedDH>),
}
