use protocol_derive::Protocol;
use rand::{rngs::OsRng, RngCore};

use crate::crypto::{
    dh::DhPubKey,
    signature::{Signature, SigningPubKey},
};

/// Message signaling supported protocol version.
///
/// Different type is sent back in case of connecting to an echo server.
#[derive(Debug, PartialEq, Protocol, Clone, Copy)]
pub struct ProtocolVersion(pub u64);

impl ProtocolVersion {
    pub fn reply(&self) -> ProtocolReply {
        ProtocolReply(self.0.wrapping_add(1))
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
