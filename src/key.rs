pub struct PublicKey(pub Vec<u8>);

pub struct PrivateKey(pub Vec<u8>);

pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}
