use protocol_derive::Protocol;

#[derive(Debug, PartialEq, Protocol)]
pub struct PartialIdentity {
    pub public_key: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Identity {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Identity {
    pub fn sign() {}
}

impl PartialIdentity {
    pub fn verify() {}
}
