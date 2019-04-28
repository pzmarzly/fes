use protocol_derive::Protocol;
use ed25519_dalek::SecretKey;
use rand::Rng;
use rand::OsRng;
use sha2::Sha512;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;

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
        let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut rng);
        let mut ret = Self { private_key: [0u8; 32], public_key: [0u8, 32] };
        let keypair_bytes = keypair.to_bytes();
        ret.private_key.copy_from_slice(&keypair_bytes[0..32]);
        ret.public_key.copy_from_slice(&keypair_bytes[32..64]);
        ret
    }
    pub fn sign() {}
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
