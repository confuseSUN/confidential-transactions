use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::ristretto::RistrettoPoint;
use sha3::Sha3_512;

lazy_static! {
    pub static ref BASEPOINT_G1: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    pub static ref BASEPOINT_G2: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
}
