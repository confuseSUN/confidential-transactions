use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;

pub trait TranscriptProtocol {
    fn append_scalar_mul_point(
        &mut self,
        label: &'static [u8],
        scalar: &Scalar,
        point: &RistrettoPoint,
    );

    fn append_double_scalar_mul_point(
        &mut self,
        label: &'static [u8],
        scalars: (&Scalar, &Scalar),
        points: (&RistrettoPoint, &RistrettoPoint),
    );

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn append_scalar_mul_point(
        &mut self,
        label: &'static [u8],
        scalar: &Scalar,
        point: &RistrettoPoint,
    ) {
        let point = scalar * point;
        self.append_message(label, point.compress().as_bytes());
    }

    fn append_double_scalar_mul_point(
        &mut self,
        label: &'static [u8],
        scalars: (&Scalar, &Scalar),
        points: (&RistrettoPoint, &RistrettoPoint),
    ) {
        let point = scalars.0 * points.0 + scalars.1 * points.1;
        self.append_message(label, point.compress().as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 32];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order(buf)
    }
}
