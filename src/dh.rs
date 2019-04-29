use protocol_derive::Protocol;
use rand::rngs::OsRng;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

/// Public key used for encryption
#[derive(Debug, PartialEq, Clone, Protocol)]
pub struct EncryptionPubKey {
    pub public_key: [u8; 32],
}

/// Pair of public and private keys - used for encryption
#[derive(Clone)]
pub struct EncryptionKeyPair {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl EncryptionKeyPair {
    pub fn generate() -> Self {
        let mut rng: OsRng = OsRng::new().unwrap();
        let secret = StaticSecret::new(&mut rng);
        let public = PublicKey::from(&secret);
        Self {
            private_key: secret,
            public_key: public,
        }
    }
    pub fn dh(&self, other_public_key: &[u8]) -> [u8; 32] {
        let mut other_public_key_c = [0u8; 32];
        other_public_key_c.copy_from_slice(&other_public_key[..]);

        let other = PublicKey::from(other_public_key_c);
        let shared = self.private_key.diffie_hellman(&other);
        let bytes = shared.as_bytes();

        let mut bytes_c = [0u8; 32];
        bytes_c.copy_from_slice(&bytes[..]);
        bytes_c
    }
    /// Clone `EncryptionKeyPair` public key into new `EncryptionPubKey`
    pub fn get_partial(&self) -> EncryptionPubKey {
        let bytes = self.public_key.as_bytes();

        let mut bytes_c = [0u8; 32];
        bytes_c.copy_from_slice(&bytes[..]);
        EncryptionPubKey {
            public_key: bytes_c,
        }
    }
}
