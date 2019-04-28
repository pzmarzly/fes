use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use protocol_derive::Protocol;
use rand::rngs::OsRng;
use sha2::Sha512;

/// Public key used to verify signatures
#[derive(Debug, PartialEq, Clone, Protocol)]
pub struct SigningPubKey {
    pub public_key: [u8; 32],
}

/// Pair of public and private keys - used to verify signatures
#[derive(Debug, PartialEq, Clone)]
pub struct SigningKeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl SigningKeyPair {
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
    /// Clone `SigningKeyPair` public key into new `SigningPubKey`
    pub fn get_partial(&self) -> SigningPubKey {
        SigningPubKey {
            public_key: self.public_key.clone(),
        }
    }
}

impl SigningPubKey {
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let signature = Signature::from_bytes(signature).unwrap();
        PublicKey::from_bytes(&self.public_key)
            .unwrap()
            .verify::<Sha512>(data, &signature)
            .is_ok()
    }
}
