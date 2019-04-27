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
    pub fn get_partial(&self) -> PartialIdentity {
        PartialIdentity {
            public_key: self.public_key.clone(),
        }
    }
}

impl PartialIdentity {
    pub fn verify() {}
}
