use protocol_derive::Protocol;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Public key used for ephemeral key exchange
#[derive(Debug, PartialEq, Clone, Protocol)]
pub struct DhPubKey {
    pub public_key: [u8; 32],
}

/// Pair of public and private keys - used for ephemeral key exchange
#[derive(Clone)]
pub struct DhKeyPair {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

/// Shared, securely derived key for symmetric cryptography
#[derive(Clone)]
pub struct SharedEncryptionKey {
    pub key: [u8; 32],
}

impl DhKeyPair {
    pub fn generate() -> Self {
        let mut rng = OsRng::new().unwrap();
        let secret = StaticSecret::new(&mut rng);
        let public = PublicKey::from(&secret);
        Self {
            private_key: secret,
            public_key: public,
        }
    }
    pub fn dh(&self, other_public_key: &DhPubKey) -> SharedEncryptionKey {
        let mut other_public_key_c = [0u8; 32];
        other_public_key_c.copy_from_slice(&other_public_key.public_key[..]);

        let other = PublicKey::from(other_public_key_c);
        let shared = self.private_key.diffie_hellman(&other);
        let bytes = shared.as_bytes();

        let mut bytes_c = [0u8; 32];
        bytes_c.copy_from_slice(&bytes[..]);
        SharedEncryptionKey { key: bytes_c }
    }
    /// Clone `DhKeyPair` public key into new `DhPubKey`
    pub fn public(&self) -> DhPubKey {
        let bytes = self.public_key.as_bytes();

        let mut bytes_c = [0u8; 32];
        bytes_c.copy_from_slice(&bytes[..]);
        DhPubKey {
            public_key: bytes_c,
        }
    }
}
