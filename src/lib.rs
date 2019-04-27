use protocol_derive::Protocol;

pub mod key;

use key::*;

pub struct Connection;
pub struct MutuallyTrusted {
    pub my_id: KeyPair,
    pub other_pub: PublicKey,
}
pub struct OtherTrusted;

impl Connection {
    pub fn encrypt() {}
    pub fn decrypt() {}
}

impl MutuallyTrusted {
    pub fn connect(self) {}
}

impl OtherTrusted {
    pub fn connect(self) {}
}
