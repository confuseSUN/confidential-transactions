use ct_utils::{generator::BASEPOINT_G2, transcript::TranscriptProtocol};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;

use crate::get_random_scalars;

#[derive(Debug, Default)]
pub struct KeyPair {
    pub public_key: RistrettoPoint,
    pub private_key: Scalar,
}

impl KeyPair {
    pub fn compute_key_images(&self) -> RistrettoPoint {
        let hash_public_key = RistrettoPoint::hash_from_bytes::<sha3::Sha3_512>(
            self.public_key.compress().as_bytes(),
        );
        self.private_key * hash_public_key
    }
}

#[derive(Default)]
pub struct Material {
    pub key_pairs: Vec<KeyPair>,
    pub alpha_vec: Vec<Scalar>,
    pub s_vec: Vec<Scalar>,
}

impl Material {
    pub fn new_signer(key_pairs: Vec<KeyPair>) -> Self {
        let alpha_vec = get_random_scalars(key_pairs.len());
        Material {
            key_pairs: key_pairs,
            alpha_vec: alpha_vec,
            s_vec: Vec::default(),
        }
    }

    pub fn new_decoys(key_pairs: Vec<KeyPair>) -> Self {
        let s_vec = get_random_scalars(key_pairs.len());
        Material {
            key_pairs: key_pairs,
            alpha_vec: Vec::default(),
            s_vec: s_vec,
        }
    }

    pub fn compute_key_images(&self) -> Vec<RistrettoPoint> {
        self.key_pairs
            .iter()
            .map(|x| x.compute_key_images())
            .collect()
    }

    pub fn compute_signer_challenge(&self, msg: &[u8]) -> Scalar {
        let mut transcript = Transcript::new(b"mlsag");
        transcript.append_message(b"msg", msg);

        for (key, alpha) in self.key_pairs.iter().zip(self.alpha_vec.iter()) {
            transcript.append_scalar_mul_point(b"L", alpha, &BASEPOINT_G2);
            transcript.append_scalar_mul_point(
                b"R",
                alpha,
                &RistrettoPoint::hash_from_bytes::<sha3::Sha3_512>(
                    key.public_key.compress().as_bytes(),
                ),
            );
        }

        transcript.challenge_scalar(b"")
    }

    pub fn compute_decoy_challenge(
        &self,
        msg: &[u8],
        c_pai: &Scalar,
        key_images: &Vec<RistrettoPoint>,
    ) -> Scalar {
        let mut transcript = Transcript::new(b"mlsag");
        transcript.append_message(b"msg", msg);

        for ((key, s), key_image) in self
            .key_pairs
            .iter()
            .zip(self.s_vec.iter())
            .zip(key_images.iter())
        {
            transcript.append_double_scalar_mul_point(
                b"L",
                (s, c_pai),
                (&BASEPOINT_G2, &key.public_key),
            );
            transcript.append_double_scalar_mul_point(
                b"R",
                (s, c_pai),
                (
                    &RistrettoPoint::hash_from_bytes::<sha3::Sha3_512>(
                        key.public_key.compress().as_bytes(),
                    ),
                    &key_image,
                ),
            );
        }

        transcript.challenge_scalar(b"")
    }

    pub fn compute_signer_s_vec(&self, c_pai: &Scalar) -> Vec<Scalar> {
        let mut s_vec = Vec::with_capacity(self.alpha_vec.len());
        for (key, alpha) in self.key_pairs.iter().zip(self.alpha_vec.iter()) {
            let s = alpha - c_pai * key.private_key;
            s_vec.push(s);
        }
        s_vec
    }
}
