use ct_utils::{generator::BASEPOINT_G2, transcript::TranscriptProtocol};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;

pub struct Signarute {
    pub public_keys: Vec<Vec<RistrettoPoint>>,
    pub key_images: Vec<RistrettoPoint>,
    pub c: Scalar,
    pub s: Vec<Vec<Scalar>>,
}

impl Signarute {
    pub fn verify(&self, msg: &[u8]) -> bool {
        let mut c_pai = self.c.clone();
        for (s_vec, pk_vec) in self.s.iter().zip(self.public_keys.iter()) {
            let mut transcript = Transcript::new(b"mlsag");
            transcript.append_message(b"msg", msg);

            for ((pk, s), key_image) in pk_vec.iter().zip(s_vec.iter()).zip(self.key_images.iter())
            {
                transcript.append_double_scalar_mul_point(b"L", (s, &c_pai), (&BASEPOINT_G2, &pk));
                transcript.append_double_scalar_mul_point(
                    b"R",
                    (s, &c_pai),
                    (
                        &RistrettoPoint::hash_from_bytes::<sha3::Sha3_512>(
                            pk.compress().as_bytes(),
                        ),
                        &key_image,
                    ),
                );
            }

            c_pai = transcript.challenge_scalar(b"");
        }

        c_pai == self.c
    }
}
