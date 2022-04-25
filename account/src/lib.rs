use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

pub mod account;
pub mod confidential_transaction;
pub mod ring_confidential_transaction;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: RistrettoPoint,
    pub private_key: Scalar,
}

pub struct BlindPair(pub KeyPair);

impl BlindPair {
    pub fn get_blind_point(&self) -> RistrettoPoint {
        self.0.public_key
    }

    pub fn get_blind(&self) -> Scalar {
        self.0.private_key
    }
}
