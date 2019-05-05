use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature as DSignature};
use protocol::Parcel;
use protocol_derive::Protocol;
use rand::rngs::OsRng;
use sha2::Sha512;

use crate::util::ParcelExt;

use std::{fmt, marker::PhantomData};

/// Signature over Parcel
#[derive(Clone, Protocol)]
pub struct Signature<T: Parcel> {
    pub bytes: [u8; 64],
    pub typed: PhantomData<T>,
}

impl<T: Parcel> fmt::Debug for Signature<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.bytes[..].fmt(formatter)
    }
}

impl<T: Parcel> PartialEq for Signature<T> {
    fn eq(&self, other: &Signature<T>) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

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
        let mut rng = OsRng::new().unwrap();
        let Keypair { secret, public } = Keypair::generate::<Sha512, _>(&mut rng);
        Self {
            private_key: secret.to_bytes(),
            public_key: public.to_bytes(),
        }
    }
    pub fn sign<T: Parcel>(&self, message: &T) -> Signature<T> {
        let data = message.to_bytes();
        let keypair = Keypair {
            secret: SecretKey::from_bytes(&self.private_key).unwrap(),
            public: PublicKey::from_bytes(&self.public_key).unwrap(),
        };
        Signature {
            bytes: keypair.sign::<Sha512>(&data).to_bytes(),
            typed: PhantomData,
        }
    }
    /// Clone `SigningKeyPair` public key into new `SigningPubKey`
    pub fn public(&self) -> SigningPubKey {
        SigningPubKey {
            public_key: self.public_key.clone(),
        }
    }
}

impl SigningPubKey {
    pub fn verify<T: Parcel>(&self, message: &T, signature: &Signature<T>) -> bool {
        let data = message.to_bytes();
        let signature = signature.to_bytes();

        let signature = DSignature::from_bytes(&signature).unwrap();
        PublicKey::from_bytes(&self.public_key)
            .unwrap()
            .verify::<Sha512>(&data, &signature)
            .is_ok()
    }
}
