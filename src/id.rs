use ed25519_dalek::{Keypair, SecretKey, PublicKey};
use protocol_derive::Protocol;
use rand::rngs::OsRng;
use sha2::Sha512;

/// Public key used to verify signatures
#[derive(Debug, PartialEq, Clone, Protocol)]
pub struct PartialIdentity {
    pub public_key: [u8; 32],
}

/// Pair of public and private keys - used to verify signatures
#[derive(Debug, PartialEq, Clone)]
pub struct Identity {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng: OsRng = OsRng::new().unwrap();
        let Keypair { secret, public } = Keypair::generate::<Sha512, _>(&mut rng);
        Self {
            private_key: secret.to_bytes(),
            public_key: public.to_bytes(),
        }
    }
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let keypair = Keypair {
            secret: SecretKey::from_bytes(&self.private_key).unwrap(),
            public: PublicKey::from_bytes(&self.public_key).unwrap(),
        };
        keypair.sign::<Sha512>(data).to_bytes()
    }
    /// Clone `Identity` public key into new `PartialIdentity`
    pub fn get_partial(&self) -> PartialIdentity {
        PartialIdentity {
            public_key: self.public_key.clone(),
        }
    }
}

impl PartialIdentity {
    pub fn verify() {}
}
